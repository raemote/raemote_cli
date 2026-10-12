//! Pairing tokens and the set of authorized devices.
//!
//! [`AuthState`] mints short-lived, multi-use pairing tokens, validates bind
//! attempts in constant time, locks out brute force, and persists authorized
//! device identities to disk.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::identity;

/// Outcome of a bind attempt presented by a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// The node was newly authorized and persisted.
    Bound,
    /// The node was newly authorized by redeeming a one-time invitation.
    BoundViaInvitation,
    /// The node was already authorized; nothing changed.
    AlreadyAuthorized,
    /// No token is active (never minted, expired, or revoked).
    NoActiveToken,
    /// The presented token did not match; the attempt budget is not yet exhausted.
    TokenMismatch,
    /// Too many failed attempts; the token has been revoked for this process.
    Revoked,
}

impl BindOutcome {
    /// Whether the attempt grants access.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            BindOutcome::Bound | BindOutcome::BoundViaInvitation | BindOutcome::AlreadyAuthorized
        )
    }

    /// A short reason to send back when the attempt is denied.
    pub fn deny_reason(&self) -> &'static str {
        match self {
            BindOutcome::NoActiveToken => "no active token",
            BindOutcome::TokenMismatch => "invalid token",
            BindOutcome::Revoked => "token revoked",
            BindOutcome::Bound
            | BindOutcome::BoundViaInvitation
            | BindOutcome::AlreadyAuthorized => "",
        }
    }
}

/// Everything the operator (or a QR code) needs to bind a client.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// The token value, hex-encoded.
    pub token_hex: String,
    /// Wall-clock unix seconds at which the token expires (display only; the
    /// server itself enforces a monotonic deadline).
    pub expires_at_unix: u64,
    /// The token lifetime.
    pub ttl: Duration,
    /// What a device pairing with this token may reach. Never embedded in the
    /// URI — it lives server-side.
    pub scope: Scope,
}

impl TokenInfo {
    /// A compact, QR-ready binding URI encoding node id, token, and expiry.
    pub fn uri(&self, node: EndpointId) -> String {
        format!(
            "raemote://bind?node={node}&token={}&exp={}",
            self.token_hex, self.expires_at_unix
        )
    }
}

/// What a paired device may reach: every app, or only apps on specific ports.
///
/// A device's scope is fixed by the credential it binds with (the pairing token
/// or invitation carries one) and can be changed by the owner via
/// `raemote devices access`. It is persisted per-device in
/// `~/.raemote/device_scopes`; a device absent from that file has [`Scope::All`]
/// (every device paired before scopes existed keeps full access).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Every app in the catalog.
    All,
    /// Only apps whose origin port is in this set.
    Ports(BTreeSet<u16>),
}

impl Scope {
    /// Whether an app on `port` is reachable under this scope.
    pub fn allows_port(&self, port: u16) -> bool {
        match self {
            Scope::All => true,
            Scope::Ports(ports) => ports.contains(&port),
        }
    }

    /// Whether every port allowed by `self` is also allowed by `other`.
    ///
    /// Used to clamp invitations: an inviter may only narrow its own grant,
    /// never widen it.
    pub fn is_subset_of(&self, other: &Scope) -> bool {
        match (self, other) {
            (_, Scope::All) => true,
            (Scope::All, Scope::Ports(_)) => false,
            (Scope::Ports(a), Scope::Ports(b)) => a.is_subset(b),
        }
    }

    /// The restricted port set, or `None` for [`Scope::All`].
    pub fn ports(&self) -> Option<&BTreeSet<u16>> {
        match self {
            Scope::All => None,
            Scope::Ports(ports) => Some(ports),
        }
    }
}

/// Build a [`Scope`] from a comma-separated port list.
///
/// `None` means [`Scope::All`]. An empty list is a valid (if drastic) scope:
/// the device pairs but sees no apps.
pub fn scope_from_ports(ports: Option<Vec<u16>>) -> Scope {
    match ports {
        None => Scope::All,
        Some(ports) => Scope::Ports(ports.into_iter().collect()),
    }
}

/// A compact JSON form of a scope, for `/_hub/info` and IPC.
pub fn scope_json(scope: &Scope) -> serde_json::Value {
    match scope {
        Scope::All => serde_json::json!({ "all": true }),
        Scope::Ports(ports) => serde_json::json!({ "all": false, "ports": ports }),
    }
}

/// A paired device and its (display-only) name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The device's node id.
    pub node_id: EndpointId,
    /// Human-readable name. Always non-empty: unnamed devices get a default.
    pub name: String,
}

/// Longest accepted device name, in characters.
const MAX_DEVICE_NAME: usize = 64;

/// The name shown for a device that has not been named, for example
/// `device-6caf`.
pub fn default_device_name(node: EndpointId) -> String {
    let hex = node.to_string();
    format!("device-{}", &hex[..hex.len().min(4)])
}

/// Normalize a user-supplied device name.
///
/// Trims, collapses whitespace, drops control characters, and caps the length.
/// Returns `None` for an empty result, which means "clear the name".
pub fn sanitize_device_name(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut prev_space = false;
    for ch in name.chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = true;
        } else if ch.is_control() {
            // Non-whitespace control characters are dropped entirely.
            continue;
        } else {
            out.push(ch);
            prev_space = false;
        }
        if out.chars().count() >= MAX_DEVICE_NAME {
            break;
        }
    }
    let out = out.trim();
    if out.is_empty() {
        None
    } else {
        Some(out.to_string())
    }
}

/// Token-based binding state plus the persisted set of authorized node IDs.
///
/// Security properties:
/// - Tokens are 256 bits from the OS CSPRNG and are **multi-use until expiry**;
///   they are never consumed by a successful bind.
/// - Comparison is constant-time.
/// - After `max_attempts` failed attempts the token is revoked for the
///   remainder of the process (restart mints a fresh one).
/// - Expiry uses a monotonic [`Instant`], immune to wall-clock changes.
/// - The token is compared and the authorized set updated under a single lock,
///   so racing bind attempts cannot double-spend anything.
#[derive(Debug)]
pub struct AuthState {
    inner: Mutex<Inner>,
    store_path: std::path::PathBuf,
    names_path: std::path::PathBuf,
    scopes_path: std::path::PathBuf,
    max_attempts: AtomicU32,
}

#[derive(Debug)]
struct Inner {
    pending: Option<PendingToken>,
    authenticated: HashSet<EndpointId>,
    /// Display-only names for authorized devices.
    names: HashMap<EndpointId, String>,
    /// Outstanding one-time invitations, keyed by their token (hex).
    invitations: HashMap<String, Invitation>,
    failed_attempts: u32,
    /// Revoked nodes mapped to the generation of the token that was live at
    /// revocation time; presenting a token minted at or before that generation
    /// is denied for that node. In-memory only: a restart has no live token
    /// to resurrect (startup mints fresh), which matches the design where a
    /// restart invalidates in-memory pairing state.
    revoked: HashMap<EndpointId, u64>,
    /// Per-device access scopes. A device absent from this map has
    /// [`Scope::All`]. Persisted to `device_scopes` alongside the authorized
    /// set, so a restart keeps every device's restriction.
    scopes: HashMap<EndpointId, Scope>,
    /// Next token generation counter, bumped on every mint.
    next_generation: u64,
}

/// Credentials revoked along with a device: the generation of the pairing
/// token that was live when the device was revoked. The revoked node may not
/// present that token (or any earlier generation) again; a token minted
/// *after* the revocation is a fresh capability and works normally.
///
/// Check `generation` and `revoked` under the same lock, so an expired token
/// presentation and a concurrent revocation cannot double-spend.
#[derive(Debug)]
#[derive(Clone)]
struct PendingToken {
    token_hex: String,
    expires_at: Instant,
    /// Wall-clock expiry captured at mint time, so the value embedded in the
    /// pairing URI does not drift as time passes.
    expires_at_unix: u64,
    /// Monotonic generation, bumped on every mint. `revoke()` marks a revoked
    /// node with the generation that was live at revocation time; presenting a
    /// token whose generation is at or below that mark is denied.
    generation: u64,
    /// What a device pairing with this token may reach.
    scope: Scope,
}

/// A one-time invitation: whoever redeems it first becomes an authorized
/// device. Held only in memory, so a restart invalidates outstanding invites.
#[derive(Debug)]
struct Invitation {
    expires_at: Instant,
    /// The already-authorized device that asked for this invitation.
    created_by: EndpointId,
    /// What the redeeming device may reach: a subset of the inviter's scope,
    /// fixed at mint time. The redeemer never supplies a scope, so there is
    /// nothing to forge at redemption.
    scope: Scope,
}

impl AuthState {
    /// Load the persisted authorized set from `~/.raemote/authorized_nodes`.
    ///
    /// A corrupt or unreadable store is treated as empty: access is denied until
    /// clients re-bind, which fails safe.
    pub fn load(max_attempts: u32) -> Result<Self> {
        let dir = identity::ensure_data_dir()?;
        let store_path = dir.join("authorized_nodes");
        let names_path = dir.join("device_names");
        let scopes_path = dir.join("device_scopes");
        Self::load_at(store_path, names_path, scopes_path, max_attempts)
    }

    /// Load from explicit store paths. Used by tests and by callers that own
    /// the paths themselves.
    pub fn load_at(
        store_path: std::path::PathBuf,
        names_path: std::path::PathBuf,
        scopes_path: std::path::PathBuf,
        max_attempts: u32,
    ) -> Result<Self> {
        let authenticated = load_authorized(&store_path);
        let mut names = load_names(&names_path);
        // Drop names for devices that are no longer authorized.
        names.retain(|id, _| authenticated.contains(id));
        let scopes = load_scopes(&scopes_path);
        tracing::info!(
            "loaded {} authorized node(s) from {}",
            authenticated.len(),
            store_path.display()
        );
        Ok(Self {
            inner: Mutex::new(Inner {
                pending: None,
                authenticated,
                names,
                invitations: HashMap::new(),
                failed_attempts: 0,
                revoked: HashMap::new(),
                scopes,
                next_generation: 0,
            }),
            store_path,
            names_path,
            scopes_path,
            max_attempts: AtomicU32::new(max_attempts),
        })
    }

    /// Update max failed attempts (hot-reloaded from config).
    pub fn set_max_attempts(&self, val: u32) {
        self.max_attempts.store(val, Ordering::Relaxed);
    }

    /// Return the current token info (for status/IPC queries).
    pub fn current_token_info(&self) -> Option<TokenInfo> {
        let inner = self.inner.lock().expect("auth state poisoned");
        inner.pending.as_ref().and_then(|p| {
            if Instant::now() < p.expires_at {
                let ttl = p.expires_at.duration_since(Instant::now());
                Some(TokenInfo {
                    token_hex: p.token_hex.clone(),
                    expires_at_unix: p.expires_at_unix,
                    ttl,
                    scope: p.scope.clone(),
                })
            } else {
                None
            }
        })
    }

    /// Return the count of currently authorized nodes.
    pub fn authorized_count(&self) -> usize {
        self.inner
            .lock()
            .expect("auth state poisoned")
            .authenticated
            .len()
    }

    /// Return the list of currently authorized node IDs.
    pub fn list_authorized(&self) -> Vec<EndpointId> {
        self.inner
            .lock()
            .expect("auth state poisoned")
            .authenticated
            .iter()
            .copied()
            .collect()
    }

    /// Remove `node` from the authorized set and persist the change.
    ///
    /// Returns `true` if the device was authorized (and is now revoked).
    ///
    /// The in-memory set is updated before persisting, so a failed disk write
    /// can never let a revoked device keep access; the warning signals that the
    /// change may not survive a restart.
    pub fn revoke(&self, node: EndpointId) -> bool {
        let (entries, names, scopes): (Vec<String>, HashMap<String, String>, HashMap<String, Scope>) = {
            let mut inner = self.inner.lock().expect("auth state poisoned");
            if !inner.authenticated.remove(&node) {
                return false;
            }
            inner.names.remove(&node);
            // The scope belongs to the identity, not the device record: drop it
            // with the device so a restart cannot resurrect a restriction (or,
            // worse, leave a stale grant behind for a re-paired device).
            inner.scopes.remove(&node);
            // Revocation must not be reversible by the revoked party: mark the
            // node with the current token generation, so the still-live
            // multi-use token no longer re-binds it. A token minted *after*
            // the revocation is a fresh capability (other devices may still be
            // pairing); the marker does not block that. In-memory only — a
            // restart has no live token to resurrect.
            if let Some(generation) = inner.pending.as_ref().map(|p| p.generation) {
                inner.revoked.insert(node, generation);
            }
            (
                inner.authenticated.iter().map(|id| id.to_string()).collect(),
                inner
                    .names
                    .iter()
                    .map(|(id, n)| (id.to_string(), n.clone()))
                    .collect(),
                inner
                    .scopes
                    .iter()
                    .map(|(id, s)| (id.to_string(), s.clone()))
                    .collect(),
            )
        };
        match save_authorized(&self.store_path, &entries) {
            Ok(()) => tracing::info!(node = %node.fmt_short(), "revoked authorized device"),
            Err(err) => {
                tracing::warn!("failed to persist authorized nodes after revoke: {err:#}")
            }
        }
        if let Err(err) = save_names(&self.names_path, &names) {
            tracing::warn!("failed to persist device names after revoke: {err:#}");
        }
        if let Err(err) = save_scopes(&self.scopes_path, &scopes) {
            tracing::warn!("failed to persist device scopes after revoke: {err:#}");
        }
        true
    }

    /// Set (or clear) the display name of an authorized device.
    ///
    /// An empty name clears it, so the default (`device-<hex>`) is shown again.
    pub fn set_device_name(&self, node: EndpointId, name: &str) -> Result<()> {
        let sanitized = sanitize_device_name(name);
        let names: HashMap<String, String> = {
            let mut inner = self.inner.lock().expect("auth state poisoned");
            if !inner.authenticated.contains(&node) {
                anyhow::bail!("device {} is not authorized", node.fmt_short());
            }
            match sanitized {
                Some(name) => {
                    inner.names.insert(node, name);
                }
                None => {
                    inner.names.remove(&node);
                }
            }
            inner
                .names
                .iter()
                .map(|(id, n)| (id.to_string(), n.clone()))
                .collect()
        };
        save_names(&self.names_path, &names)
    }

    /// Every authorized device with a resolved, never-empty display name.
    pub fn device_infos(&self) -> Vec<DeviceInfo> {
        let inner = self.inner.lock().expect("auth state poisoned");
        let mut devices: Vec<DeviceInfo> = inner
            .authenticated
            .iter()
            .map(|id| DeviceInfo {
                node_id: *id,
                name: inner
                    .names
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| default_device_name(*id)),
            })
            .collect();
        devices.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.node_id.to_string().cmp(&b.node_id.to_string()))
        });
        devices
    }

    /// Mint a fresh token, replacing (invalidating) any previous one.
    pub fn mint_token(&self, ttl: Duration) -> TokenInfo {
        self.mint_token_with(ttl, None, Scope::All)
    }

    /// Longest token lifetime we accept (~100 years).
    ///
    /// Clamping avoids `Instant` overflow when an operator sets an
    /// effectively-permanent `token_ttl_secs`.
    pub const MAX_TTL: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

    /// Mint a token, optionally reusing a caller-supplied fixed value.
    ///
    /// A fixed token keeps the pairing link stable across daemon restarts, which
    /// is useful when a link must remain valid for a long time. `ttl` is clamped
    /// to [`Self::MAX_TTL`]. `scope` is what devices pairing with this token may
    /// reach; it lives server-side and is never embedded in the link.
    pub fn mint_token_with(&self, ttl: Duration, fixed: Option<&str>, scope: Scope) -> TokenInfo {
        let ttl = ttl.min(Self::MAX_TTL);
        let token_hex = match fixed {
            Some(value) => value.to_string(),
            None => {
                let token: [u8; 32] = rand::random();
                to_hex(&token)
            }
        };
        let info = TokenInfo {
            token_hex,
            expires_at_unix: unix_now().saturating_add(ttl.as_secs()),
            ttl,
            scope: scope.clone(),
        };
        let mut inner = self.inner.lock().expect("auth state poisoned");
        inner.next_generation += 1;
        inner.pending = Some(PendingToken {
            token_hex: info.token_hex.clone(),
            expires_at: Instant::now() + ttl,
            expires_at_unix: info.expires_at_unix,
            generation: inner.next_generation,
            scope,
        });
        inner.failed_attempts = 0;
        info
    }

    /// Mint a one-time invitation: the first device to redeem it becomes
    /// authorized, and the invitation is consumed. Bounded by `max_pending` so
    /// a device can't pile up capabilities.
    ///
    /// `scope` is what the redeeming device may reach. The caller must already
    /// have clamped it to the inviter's own scope (see
    /// [`Scope::is_subset_of`]); this method stores it verbatim, so the
    /// invitation can never widen the inviter's grant.
    pub fn mint_invitation(
        &self,
        ttl: Duration,
        created_by: EndpointId,
        max_pending: usize,
        scope: Scope,
    ) -> Result<TokenInfo> {
        let ttl = ttl.min(Self::MAX_TTL);
        let mut inner = self.inner.lock().expect("auth state poisoned");
        let now = Instant::now();
        inner
            .invitations
            .retain(|_, invitation| now < invitation.expires_at);
        if inner.invitations.len() >= max_pending.max(1) {
            anyhow::bail!("too many outstanding invitations");
        }

        let token: [u8; 32] = rand::random();
        let token_hex = to_hex(&token);
        let info = TokenInfo {
            token_hex: token_hex.clone(),
            expires_at_unix: unix_now().saturating_add(ttl.as_secs()),
            ttl,
            scope: scope.clone(),
        };
        inner.invitations.insert(
            token_hex,
            Invitation {
                expires_at: now + ttl,
                created_by,
                scope,
            },
        );
        tracing::info!(inviter = %created_by.fmt_short(), "minted a one-time invitation");
        Ok(info)
    }

    /// Validate a bind attempt and authorize the node on success.
    ///
    /// Accepts either the multi-use pairing token or a one-time invitation.
    /// Everything runs under one lock, so an invitation can't be redeemed twice.
    pub fn authenticate(&self, node: EndpointId, presented: &str) -> BindOutcome {
        let mut inner = self.inner.lock().expect("auth state poisoned");

        if inner.authenticated.contains(&node) {
            return BindOutcome::AlreadyAuthorized;
        }

        let now = Instant::now();
        // Drop expired invitations; there are at most a handful.
        inner
            .invitations
            .retain(|_, invitation| now < invitation.expires_at);

        // 1. The multi-use pairing token (valid until it expires).
        let active = inner.pending.clone().filter(|pending| now < pending.expires_at);

        if let Some(pending) = active.as_ref()
            && constant_time_eq(presented.as_bytes(), pending.token_hex.as_bytes())
        {
            // A node revoked while this token generation was live cannot use
            // the token to re-authorize itself; only a token minted after the
            // revocation (a fresh capability) may do so.
            if inner
                .revoked
                .get(&node)
                .is_some_and(|marker| *marker >= pending.generation)
            {
                return BindOutcome::NoActiveToken;
            }
            let scope = pending.scope.clone();
            let (entries, scopes) = Self::authorize(&mut inner, node, scope);
            drop(inner);
            if let Err(err) = save_authorized(&self.store_path, &entries) {
                tracing::warn!("failed to persist authorized nodes: {err:#}");
            }
            if let Err(err) = save_scopes(&self.scopes_path, &scopes) {
                tracing::warn!("failed to persist device scopes: {err:#}");
            }
            return BindOutcome::Bound;
        }

        // 2. One-time invitations. Scan every entry (constant-time each, with no
        //    early exit) so which one matched isn't leaked.
        let mut matched = None;
        for (token_hex, invitation) in &inner.invitations {
            if constant_time_eq(presented.as_bytes(), token_hex.as_bytes()) {
                matched = Some((token_hex.clone(), invitation.created_by, invitation.scope.clone()));
            }
        }
        if let Some((token_hex, created_by, scope)) = matched {
            inner.invitations.remove(&token_hex);
            let (entries, scopes) = Self::authorize(&mut inner, node, scope);
            tracing::info!(
                node = %node.fmt_short(),
                inviter = %created_by.fmt_short(),
                "device authorized via one-time invitation"
            );
            drop(inner);
            if let Err(err) = save_authorized(&self.store_path, &entries) {
                tracing::warn!("failed to persist authorized nodes: {err:#}");
            }
            if let Err(err) = save_scopes(&self.scopes_path, &scopes) {
                tracing::warn!("failed to persist device scopes: {err:#}");
            }
            return BindOutcome::BoundViaInvitation;
        }

        // 3. No match.
        if active.is_none() {
            // Absent or expired: drop it so later attempts fail fast.
            inner.pending = None;
            return BindOutcome::NoActiveToken;
        }
        inner.failed_attempts += 1;
        if inner.failed_attempts >= self.max_attempts.load(Ordering::Relaxed) {
            inner.pending = None;
            tracing::warn!(
                attempts = inner.failed_attempts,
                "bind token revoked after too many failed attempts"
            );
            BindOutcome::Revoked
        } else {
            BindOutcome::TokenMismatch
        }
    }

    /// Insert `node` into the authorized set (the caller holds the lock), reset
    /// the failure counter, record its scope, and return the entries to persist.
    fn authorize(
        inner: &mut Inner,
        node: EndpointId,
        scope: Scope,
    ) -> (Vec<String>, HashMap<String, Scope>) {
        inner.authenticated.insert(node);
        // The node is authorized again; the revocation marker is moot (and
        // would otherwise grow without bound).
        inner.revoked.remove(&node);
        inner.failed_attempts = 0;
        inner.scopes.insert(node, scope);
        let entries = inner.authenticated.iter().map(|id| id.to_string()).collect();
        let scopes = inner
            .scopes
            .iter()
            .map(|(id, s)| (id.to_string(), s.clone()))
            .collect();
        (entries, scopes)
    }

    /// Whether a connection from `node` may use the serve ALPN.
    pub fn is_authorized(&self, node: EndpointId) -> bool {
        self.inner
            .lock()
            .expect("auth state poisoned")
            .authenticated
            .contains(&node)
    }

    /// The scope a device was granted. Defaults to [`Scope::All`] for devices
    /// paired before scopes existed (or whose scope line was lost).
    pub fn scope_for(&self, node: EndpointId) -> Scope {
        self.inner
            .lock()
            .expect("auth state poisoned")
            .scopes
            .get(&node)
            .cloned()
            .unwrap_or(Scope::All)
    }

    /// Whether `node` may reach an app on `port` right now.
    pub fn can_access_port(&self, node: EndpointId, port: u16) -> bool {
        self.scope_for(node).allows_port(port)
    }

    /// Change a device's scope (owner-only, via IPC).
    ///
    /// The device must already be authorized. The change is immediate and
    /// persisted, so it survives a restart. A device can never change its own
    /// scope — this is reachable only from the owner's CLI.
    pub fn set_scope(&self, node: EndpointId, scope: Scope) -> Result<()> {
        let scopes: HashMap<String, Scope> = {
            let mut inner = self.inner.lock().expect("auth state poisoned");
            if !inner.authenticated.contains(&node) {
                anyhow::bail!("device {} is not authorized", node.fmt_short());
            }
            inner.scopes.insert(node, scope);
            inner
                .scopes
                .iter()
                .map(|(id, s)| (id.to_string(), s.clone()))
                .collect()
        };
        save_scopes(&self.scopes_path, &scopes)
    }
}

fn load_authorized(path: &Path) -> HashSet<EndpointId> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    let mut set = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match EndpointId::from_str(line) {
            Ok(id) => {
                set.insert(id);
            }
            Err(_) => tracing::warn!(
                "ignoring invalid node id in {}: {line}",
                path.display()
            ),
        }
    }
    set
}

fn save_authorized(path: &Path, entries: &[String]) -> Result<()> {
    let mut content = entries.join("\n");
    content.push('\n');
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    identity::restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load the per-device scope map from `device_scopes`.
///
/// Format: one line per device, `<node-hex> <scope>` where scope is `all` or a
/// comma-separated port list. A missing file yields an empty map (every device
/// has [`Scope::All`]). A malformed line for a live node is **fail-closed**:
/// the node gets an empty port set (deny all apps) plus a loud warning, rather
/// than being treated as unrestricted.
fn load_scopes(path: &Path) -> HashMap<EndpointId, Scope> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((id_part, scope_part)) = line.split_once(char::is_whitespace) else {
            tracing::warn!("ignoring malformed scope line in {}: {line}", path.display());
            continue;
        };
        let Ok(id) = EndpointId::from_str(id_part) else {
            tracing::warn!("ignoring invalid node id in {}: {id_part}", path.display());
            continue;
        };
        let scope = match parse_scope(scope_part.trim()) {
            Some(scope) => scope,
            None => {
                tracing::warn!(
                    node = id_part,
                    file = %path.display(),
                    "malformed scope; denying all apps for this device"
                );
                Scope::Ports(BTreeSet::new())
            }
        };
        map.insert(id, scope);
    }
    map
}

/// Parse the scope half of a `device_scopes` line.
fn parse_scope(text: &str) -> Option<Scope> {
    if text == "all" {
        return Some(Scope::All);
    }
    let ports: BTreeSet<u16> = text
        .split(',')
        .map(str::trim)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    Some(Scope::Ports(ports))
}

/// Persist the scope map atomically with `0600` permissions.
fn save_scopes(path: &Path, scopes: &HashMap<String, Scope>) -> Result<()> {
    let mut entries: Vec<(&String, &Scope)> = scopes.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut content = String::new();
    for (id, scope) in entries {
        let scope_str = match scope {
            Scope::All => "all".to_string(),
            Scope::Ports(ports) => ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        };
        content.push_str(&format!("{id} {scope_str}\n"));
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    identity::restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load the device-name map.
///
/// Best-effort: a missing or corrupt file yields an empty map. Names are
/// display-only and never gate access, so this must not fail closed on the
/// trust set.
fn load_names(path: &Path) -> HashMap<EndpointId, String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    let raw: HashMap<String, String> = match toml::from_str(&content) {
        Ok(map) => map,
        Err(err) => {
            tracing::warn!("ignoring corrupt device names in {}: {err}", path.display());
            return HashMap::new();
        }
    };
    raw.into_iter()
        .filter_map(|(id, name)| match EndpointId::from_str(&id) {
            Ok(id) => Some((id, name)),
            Err(_) => {
                tracing::warn!("ignoring invalid node id in {}: {id}", path.display());
                None
            }
        })
        .collect()
}

/// Persist the device-name map atomically with `0600` permissions.
fn save_names(path: &Path, names: &HashMap<String, String>) -> Result<()> {
    let content = toml::to_string(names)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    identity::restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Length-safe constant-time equality for secret comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(name: &str) -> AuthState {
        AuthState {
            inner: Mutex::new(Inner {
                pending: None,
                authenticated: HashSet::new(),
                names: HashMap::new(),
                invitations: HashMap::new(),
                failed_attempts: 0,
                revoked: HashMap::new(),
                scopes: HashMap::new(),
                next_generation: 0,
            }),
            store_path: std::env::temp_dir().join(format!("raemote-test-{name}")),
            names_path: std::env::temp_dir().join(format!("raemote-test-{name}.names")),
            scopes_path: std::env::temp_dir().join(format!("raemote-test-{name}.scopes")),
            max_attempts: AtomicU32::new(3),
        }
    }

    fn node(tag: u8) -> EndpointId {
        // Derive from a secret key so the result is a valid ed25519 public key.
        iroh::SecretKey::from_bytes(&[tag; 32]).public()
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn multi_use_token_binds_multiple_nodes() {
        let state = test_state("multi-use");
        let info = state.mint_token(Duration::from_secs(60));

        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        // Same token remains valid for a second node.
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);
        // Already-bound node is idempotent even with a wrong token.
        assert_eq!(state.authenticate(node(1), "nope"), BindOutcome::AlreadyAuthorized);
        assert!(state.is_authorized(node(1)));
        assert!(state.is_authorized(node(2)));
        assert!(!state.is_authorized(node(3)));
    }

    #[test]
    fn expired_token_is_denied() {
        let state = test_state("expired");
        let info = state.mint_token(Duration::from_secs(60));
        if let Some(pending) = state.inner.lock().unwrap().pending.as_mut() {
            pending.expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::NoActiveToken);
        assert!(!state.is_authorized(node(1)));
    }

    #[test]
    fn failed_attempts_revoke_token() {
        let state = test_state("revoke");
        let info = state.mint_token(Duration::from_secs(60));

        assert_eq!(state.authenticate(node(1), "wrong"), BindOutcome::TokenMismatch);
        assert_eq!(state.authenticate(node(1), "wrong"), BindOutcome::TokenMismatch);
        // Third failure hits the cap (max_attempts = 3) and revokes.
        assert_eq!(state.authenticate(node(1), "wrong"), BindOutcome::Revoked);
        // Even the correct token is now useless.
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::NoActiveToken);
        assert!(!state.is_authorized(node(1)));
    }

    #[test]
    fn no_active_token_denies() {
        let state = test_state("no-token");
        assert_eq!(state.authenticate(node(1), "whatever"), BindOutcome::NoActiveToken);
    }

    #[test]
    fn mint_replaces_previous_token() {
        let state = test_state("mint");
        let first = state.mint_token(Duration::from_secs(60));
        let second = state.mint_token(Duration::from_secs(60));
        assert_ne!(first.token_hex, second.token_hex);
        assert_eq!(state.authenticate(node(1), &first.token_hex), BindOutcome::TokenMismatch);
        assert_eq!(state.authenticate(node(1), &second.token_hex), BindOutcome::Bound);
    }

    #[test]
    fn revoke_removes_and_persists() {
        let state = test_state("revoke-persist");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);

        assert!(state.revoke(node(1)));
        assert!(!state.is_authorized(node(1)));
        assert_eq!(state.authorized_count(), 0);

        // A fresh load from the same store must not resurrect the device.
        let reloaded = AuthState::load_at(
            state.store_path.clone(),
            state.names_path.clone(),
            state.scopes_path.clone(),
            3,
        )
        .unwrap();
        assert!(!reloaded.is_authorized(node(1)));
        assert_eq!(reloaded.authorized_count(), 0);
    }

    #[test]
    fn revoke_unknown_returns_false() {
        let state = test_state("revoke-unknown");
        assert!(!state.revoke(node(9)));
    }

    #[test]
    fn revoked_device_cannot_reuse_the_old_token_until_a_fresh_mint() {
        let state = test_state("revoke-rebind");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert!(state.revoke(node(1)));

        // Revocation is not reversible by the revoked party: the token that
        // was live at revocation time no longer re-binds the device (this used
        // to succeed — see the security audit finding about the rebind
        // window).
        assert_eq!(
            state.authenticate(node(1), &info.token_hex),
            BindOutcome::NoActiveToken
        );
        assert!(!state.is_authorized(node(1)));

        // A freshly minted token is a new capability; the revoked node may be
        // re-paired deliberately by the owner.
        let fresh = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &fresh.token_hex), BindOutcome::Bound);
        assert!(state.is_authorized(node(1)));
    }

    #[test]
    fn other_paired_devices_survive_one_device_revocation_during_paring() {
        let state = test_state("revoke-rebind-multi");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);
        assert!(state.revoke(node(1)));
        // The same token generation stays live and solely node(1)'s re-bind is
        // denied; other nodes may still pair.
        assert_eq!(state.authenticate(node(3), &info.token_hex), BindOutcome::Bound);
        assert!(state.is_authorized(node(3)));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::NoActiveToken);
    }

    #[test]
    fn fixed_token_is_used_verbatim() {
        let state = test_state("fixed-token");
        let info = state.mint_token_with(Duration::from_secs(60), Some("deadbeefdeadbeef"), Scope::All);
        assert_eq!(info.token_hex, "deadbeefdeadbeef");
        assert_eq!(
            state.authenticate(node(1), "deadbeefdeadbeef"),
            BindOutcome::Bound
        );
    }

    #[test]
    fn huge_ttl_is_clamped_without_overflow() {
        let state = test_state("ttl-clamp");
        // u64::MAX would overflow `Instant::now() + ttl`; it must be clamped.
        let info = state.mint_token_with(Duration::from_secs(u64::MAX), None, Scope::All);
        assert_eq!(info.ttl, AuthState::MAX_TTL);
        assert!(state.current_token_info().is_some());
    }

    #[test]
    fn current_token_info_preserves_minted_expiry() {
        let state = test_state("expiry-stable");
        let info = state.mint_token(Duration::from_secs(60));
        let current = state.current_token_info().expect("token is active");
        // The URI's `exp` must not drift between minting and a later read.
        assert_eq!(current.expires_at_unix, info.expires_at_unix);
    }

    #[test]
    fn default_device_name_uses_node_prefix() {
        let name = default_device_name(node(0xab));
        assert!(name.starts_with("device-"));
        assert_eq!(name.len(), "device-".len() + 4);
        assert!(name.len() <= MAX_DEVICE_NAME);
    }

    #[test]
    fn sanitize_device_name_normalizes() {
        assert_eq!(sanitize_device_name("  Leo's  iPhone "), Some("Leo's iPhone".into()));
        assert_eq!(sanitize_device_name("a\nb\tc"), Some("a b c".into()));
        assert_eq!(sanitize_device_name("   "), None);
        assert_eq!(sanitize_device_name(""), None);
        // Control characters are dropped, not turned into spaces.
        assert_eq!(sanitize_device_name("a\u{0}b"), Some("ab".into()));
        // Length is capped.
        let long = "x".repeat(200);
        assert_eq!(sanitize_device_name(&long).unwrap().chars().count(), MAX_DEVICE_NAME);
    }

    #[test]
    fn device_name_round_trips_and_persists() {
        let state = test_state("names-roundtrip");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);

        // Unnamed devices fall back to the default.
        let unnamed = state
            .device_infos()
            .into_iter()
            .find(|d| d.node_id == node(1))
            .unwrap();
        assert_eq!(unnamed.name, default_device_name(node(1)));

        state.set_device_name(node(2), "Leo's iPhone").unwrap();
        let infos = state.device_infos();
        assert!(infos.iter().any(|d| d.node_id == node(2) && d.name == "Leo's iPhone"));

        // Persisted and reloaded with the same names.
        let reloaded =
            AuthState::load_at(state.store_path.clone(), state.names_path.clone(), state.scopes_path.clone(), 3).unwrap();
        assert!(reloaded
            .device_infos()
            .iter()
            .any(|d| d.node_id == node(2) && d.name == "Leo's iPhone"));
    }

    #[test]
    fn clearing_a_name_restores_the_default() {
        let state = test_state("names-clear");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        state.set_device_name(node(1), "Named").unwrap();
        state.set_device_name(node(1), "   ").unwrap();
        assert_eq!(state.device_infos()[0].name, default_device_name(node(1)));
    }

    #[test]
    fn naming_an_unauthorized_device_fails() {
        let state = test_state("names-unauthorized");
        assert!(state.set_device_name(node(7), "Nope").is_err());
    }

    #[test]
    fn revoke_drops_the_name() {
        let state = test_state("names-revoke");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        state.set_device_name(node(1), "Gone soon").unwrap();
        assert!(state.revoke(node(1)));

        let reloaded =
            AuthState::load_at(state.store_path.clone(), state.names_path.clone(), state.scopes_path.clone(), 3).unwrap();
        assert!(reloaded.device_infos().is_empty());
    }

    #[test]
    fn corrupt_names_file_is_ignored() {
        let state = test_state("names-corrupt");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        // Corrupt the names file, then reload: trust survives, and only the
        // (display-only) name is lost.
        std::fs::write(&state.names_path, "not = [valid toml").unwrap();
        let reloaded =
            AuthState::load_at(state.store_path.clone(), state.names_path.clone(), state.scopes_path.clone(), 3).unwrap();
        assert!(reloaded.is_authorized(node(1)));
        assert_eq!(reloaded.device_infos()[0].name, default_device_name(node(1)));
    }

    #[test]
    fn devices_are_isolated_from_each_other() {
        // Act on one node and make sure the other's trust and name are untouched.
        let state = test_state("device-isolation");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);
        state.set_device_name(node(1), "Alpha").unwrap();
        state.set_device_name(node(2), "Bravo").unwrap();

        assert!(state.revoke(node(1)));

        assert!(!state.is_authorized(node(1)));
        assert!(state.is_authorized(node(2)));
        let infos = state.device_infos();
        assert!(infos.iter().any(|d| d.node_id == node(2) && d.name == "Bravo"));
        assert!(!infos.iter().any(|d| d.node_id == node(1)));
    }

    #[test]
    fn invitation_authorizes_a_device_once() {
        let state = test_state("invite-once");
        let invite = state
            .mint_invitation(Duration::from_secs(60), node(9), 3, Scope::All)
            .unwrap();

        assert_eq!(
            state.authenticate(node(1), &invite.token_hex),
            BindOutcome::BoundViaInvitation
        );
        assert!(state.is_authorized(node(1)));

        // A second device can't reuse the consumed invitation.
        assert_eq!(
            state.authenticate(node(2), &invite.token_hex),
            BindOutcome::NoActiveToken
        );
        assert!(!state.is_authorized(node(2)));
    }

    #[test]
    fn invitation_survives_a_rescan_by_an_authorized_device() {
        let state = test_state("invite-existing");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);

        let invite = state
            .mint_invitation(Duration::from_secs(60), node(1), 3, Scope::All)
            .unwrap();
        // The already-paired device re-scans: nothing changes, invite not spent.
        assert_eq!(
            state.authenticate(node(1), &invite.token_hex),
            BindOutcome::AlreadyAuthorized
        );
        assert_eq!(
            state.authenticate(node(2), &invite.token_hex),
            BindOutcome::BoundViaInvitation
        );
    }

    #[test]
    fn expired_invitation_is_rejected() {
        let state = test_state("invite-expired");
        let invite = state
            .mint_invitation(Duration::from_secs(60), node(9), 3, Scope::All)
            .unwrap();
        if let Some(invitation) = state
            .inner
            .lock()
            .unwrap()
            .invitations
            .values_mut()
            .next()
        {
            invitation.expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(
            state.authenticate(node(1), &invite.token_hex),
            BindOutcome::NoActiveToken
        );
        assert!(!state.is_authorized(node(1)));
    }

    #[test]
    fn outstanding_invitations_are_bounded() {
        let state = test_state("invite-bound");
        assert!(state.mint_invitation(Duration::from_secs(60), node(9), 2, Scope::All).is_ok());
        assert!(state.mint_invitation(Duration::from_secs(60), node(9), 2, Scope::All).is_ok());
        assert!(state.mint_invitation(Duration::from_secs(60), node(9), 2, Scope::All).is_err());
    }

    #[test]
    fn invitations_are_independent() {
        let state = test_state("invite-independent");
        let first = state
            .mint_invitation(Duration::from_secs(60), node(9), 3, Scope::All)
            .unwrap();
        let second = state
            .mint_invitation(Duration::from_secs(60), node(9), 3, Scope::All)
            .unwrap();
        assert_ne!(first.token_hex, second.token_hex);

        assert_eq!(
            state.authenticate(node(1), &first.token_hex),
            BindOutcome::BoundViaInvitation
        );
        // Consuming one doesn't consume the other.
        assert_eq!(
            state.authenticate(node(2), &second.token_hex),
            BindOutcome::BoundViaInvitation
        );
    }

    // ------------------------------------------------------------------
    // Device scopes
    // ------------------------------------------------------------------

    fn ports_scope(ports: &[u16]) -> Scope {
        Scope::Ports(ports.iter().copied().collect())
    }

    #[test]
    fn scope_from_ports_maps_none_to_all() {
        assert_eq!(scope_from_ports(None), Scope::All);
        assert_eq!(
            scope_from_ports(Some(vec![3000, 8080])),
            ports_scope(&[3000, 8080])
        );
        // An empty list is a valid (drastic) scope: paired but sees nothing.
        assert_eq!(scope_from_ports(Some(vec![])), ports_scope(&[]));
    }

    #[test]
    fn scope_allows_port_and_subset() {
        let all = Scope::All;
        let restricted = ports_scope(&[3000, 8080]);

        assert!(all.allows_port(3000));
        assert!(all.allows_port(1));
        assert!(restricted.allows_port(3000));
        assert!(restricted.allows_port(8080));
        assert!(!restricted.allows_port(9999));

        // Subset: restricted ⊆ all, but not the reverse.
        assert!(restricted.is_subset_of(&all));
        assert!(!all.is_subset_of(&restricted));
        // A scope is a subset of itself.
        assert!(restricted.is_subset_of(&restricted));
        // Empty set is a subset of everything.
        assert!(ports_scope(&[]).is_subset_of(&restricted));
        // A superset is not a subset.
        assert!(!ports_scope(&[3000, 8080, 9999]).is_subset_of(&restricted));
    }

    #[test]
    fn token_scope_is_granted_at_bind() {
        let state = test_state("token-scope");
        let info = state.mint_token_with(Duration::from_secs(60), None, ports_scope(&[3000]));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);

        assert_eq!(state.scope_for(node(1)), ports_scope(&[3000]));
        assert!(state.can_access_port(node(1), 3000));
        assert!(!state.can_access_port(node(1), 8080));
    }

    #[test]
    fn invitation_scope_is_granted_at_redemption() {
        let state = test_state("invite-scope");
        // A full-access inviter mints a restricted invitation.
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        let invite = state
            .mint_invitation(Duration::from_secs(60), node(1), 3, ports_scope(&[8080]))
            .unwrap();

        assert_eq!(
            state.authenticate(node(2), &invite.token_hex),
            BindOutcome::BoundViaInvitation
        );
        assert_eq!(state.scope_for(node(2)), ports_scope(&[8080]));
        assert!(state.can_access_port(node(2), 8080));
        assert!(!state.can_access_port(node(2), 3000));
        // The inviter is unaffected.
        assert_eq!(state.scope_for(node(1)), Scope::All);
    }

    #[test]
    fn repairing_with_a_different_token_does_not_change_scope() {
        let state = test_state("repair-scope");
        let restricted = state.mint_token_with(Duration::from_secs(60), None, ports_scope(&[3000]));
        assert_eq!(state.authenticate(node(1), &restricted.token_hex), BindOutcome::Bound);

        // The device re-pairs with a full-access token: AlreadyAuthorized, and
        // the original (narrower) scope is kept. There is no self-escalation.
        let full = state.mint_token_with(Duration::from_secs(60), None, Scope::All);
        assert_eq!(state.authenticate(node(1), &full.token_hex), BindOutcome::AlreadyAuthorized);
        assert_eq!(state.scope_for(node(1)), ports_scope(&[3000]));
    }

    #[test]
    fn set_scope_changes_and_persists() {
        let state = test_state("set-scope");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);

        // Starts full.
        assert_eq!(state.scope_for(node(1)), Scope::All);

        // Owner narrows it.
        state.set_scope(node(1), ports_scope(&[3000])).unwrap();
        assert_eq!(state.scope_for(node(1)), ports_scope(&[3000]));
        assert!(state.can_access_port(node(1), 3000));
        assert!(!state.can_access_port(node(1), 8080));

        // Owner widens it back.
        state.set_scope(node(1), Scope::All).unwrap();
        assert_eq!(state.scope_for(node(1)), Scope::All);

        // Persisted across a reload.
        let reloaded = AuthState::load_at(
            state.store_path.clone(),
            state.names_path.clone(),
            state.scopes_path.clone(),
            3,
        )
        .unwrap();
        assert_eq!(reloaded.scope_for(node(1)), Scope::All);
    }

    #[test]
    fn set_scope_on_unauthorized_device_fails() {
        let state = test_state("set-scope-unauthorized");
        assert!(state.set_scope(node(7), ports_scope(&[3000])).is_err());
    }

    #[test]
    fn revoke_removes_the_scope() {
        let state = test_state("revoke-scope");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        state.set_scope(node(1), ports_scope(&[3000])).unwrap();
        assert!(state.revoke(node(1)));

        // A fresh load has no scope for the revoked device (and it is not
        // authorized, so scope_for would not be called in production — but the
        // file must not carry a stale grant).
        let reloaded = AuthState::load_at(
            state.store_path.clone(),
            state.names_path.clone(),
            state.scopes_path.clone(),
            3,
        )
        .unwrap();
        assert!(!reloaded.is_authorized(node(1)));
        assert!(!reloaded
            .scopes_path
            .exists()
            || std::fs::read_to_string(&reloaded.scopes_path)
                .unwrap()
                .lines()
                .all(|l| !l.starts_with(&node(1).to_string())));
    }

    #[test]
    fn corrupt_scope_line_fails_closed() {
        let state = test_state("scope-corrupt");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        state.set_scope(node(1), ports_scope(&[3000])).unwrap();

        // Corrupt the scope line for node(1), then reload.
        let content = std::fs::read_to_string(&state.scopes_path).unwrap();
        let corrupted = content
            .replace(&format!("{} ", node(1)), &format!("{} not-a-scope", node(1)));
        std::fs::write(&state.scopes_path, corrupted).unwrap();

        let reloaded = AuthState::load_at(
            state.store_path.clone(),
            state.names_path.clone(),
            state.scopes_path.clone(),
            3,
        )
        .unwrap();
        // Fail-closed: the device is still authorized but sees no apps.
        assert!(reloaded.is_authorized(node(1)));
        assert_eq!(reloaded.scope_for(node(1)), ports_scope(&[]));
        assert!(!reloaded.can_access_port(node(1), 3000));
    }

    #[test]
    fn two_devices_with_different_scopes_are_isolated() {
        let state = test_state("scope-isolation");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);

        state.set_scope(node(1), ports_scope(&[3000])).unwrap();
        state.set_scope(node(2), ports_scope(&[8080])).unwrap();

        assert!(state.can_access_port(node(1), 3000));
        assert!(!state.can_access_port(node(1), 8080));
        assert!(state.can_access_port(node(2), 8080));
        assert!(!state.can_access_port(node(2), 3000));

        // Changing one does not affect the other.
        state.set_scope(node(1), Scope::All).unwrap();
        assert_eq!(state.scope_for(node(2)), ports_scope(&[8080]));
    }

    #[test]
    fn scope_json_shape() {
        assert_eq!(scope_json(&Scope::All), serde_json::json!({ "all": true }));
        assert_eq!(
            scope_json(&ports_scope(&[3000, 8080])),
            serde_json::json!({ "all": false, "ports": [3000, 8080] })
        );
    }

    #[test]
    fn scope_roundtrips_through_the_store_file() {
        let state = test_state("scope-roundtrip");
        let info = state.mint_token(Duration::from_secs(60));
        assert_eq!(state.authenticate(node(1), &info.token_hex), BindOutcome::Bound);
        assert_eq!(state.authenticate(node(2), &info.token_hex), BindOutcome::Bound);
        state.set_scope(node(1), ports_scope(&[3000, 8080])).unwrap();
        state.set_scope(node(2), Scope::All).unwrap();

        let reloaded = AuthState::load_at(
            state.store_path.clone(),
            state.names_path.clone(),
            state.scopes_path.clone(),
            3,
        )
        .unwrap();
        assert_eq!(reloaded.scope_for(node(1)), ports_scope(&[3000, 8080]));
        assert_eq!(reloaded.scope_for(node(2)), Scope::All);
    }
}
