//! The local reverse-proxy web client behind `raemote connect`.
//!
//! [`run`] pairs this machine's CLI identity with a remote `raemoted` (when a
//! `raemote://bind?…` URI is given), then serves a tiny embedded web UI on
//! `127.0.0.1:<port>` that lists the server's apps and proxies every request to
//! them over the same iroh connection the iOS app uses. The index is only the
//! launcher: **each app gets its own stable loopback port** (allocated from
//! `APP_PORT_FIRST..=APP_PORT_LAST` and persisted in `connector.json`) whose
//! whole origin maps to the app's root, so relative *and* root-absolute URLs,
//! cookies and site data behave exactly as they do on the server — the same
//! scheme the iOS app uses. It is deliberately minimal: one iroh endpoint, one
//! QUIC connection reused across requests, a hand-rolled HTTP/1.1 pump for app
//! traffic (no extra dependencies, bodies and WebSockets stream through
//! untouched), and a single embedded HTML template with no JavaScript.
//!
//! Each local listener answers only requests whose `Host` is
//! `127.0.0.1:<its port>` (DNS-rebinding protection) and holds no secrets of
//! its own — access control is the server's device authorization, keyed by
//! this machine's `~/.raemote/client.key` identity.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use iroh::endpoint::presets;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::iroh_stream::IrohStream;

const SERVE_ALPN: &[u8] = b"raemote/0";
const BIND_ALPN: &[u8] = b"raemote/bind/0";

/// Default port for the local web UI (`--port` overrides it).
pub const DEFAULT_PORT: u16 = 7788;

/// Inclusive range each app's own loopback port is allocated from. The index
/// keeps `--port`; an app's port is stable (persisted, keyed `node/app`) so its
/// origin — and with it cookies and site data — survives reconnects.
const APP_PORT_FIRST: u16 = 7790;
const APP_PORT_LAST: u16 = 7999;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEAD: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Pair (optionally) with a server and serve its apps on `127.0.0.1:<port>`.
///
/// `target` is a `raemote://bind?…` pairing URI (binds first), the node id of
/// an already-paired server, or `None` to reuse the server remembered in
/// `~/.raemote/connector.json`. Runs until the process is interrupted.
pub async fn run(target: Option<&str>, port: u16, open: bool) -> Result<()> {
    let (node, token) = resolve_target(target)?;
    let endpoint = build_endpoint().await?;
    println!("device node id: {}", endpoint.id());

    if let Some(token) = token {
        bind(&endpoint, node, &token).await?;
        println!("paired with {}", node.fmt_short());
    }

    let remote = Arc::new(Remote {
        endpoint,
        node,
        conn: tokio::sync::Mutex::new(None),
    });

    let info = fetch_info(&remote).await.with_context(|| {
        format!(
            "could not reach server {} — is raemoted running? If this device \
             is not paired yet, pass the link printed by `raemote pair`",
            node.fmt_short()
        )
    })?;
    if let Err(err) = save_last(node, &info.name) {
        eprintln!("warning: could not remember this server: {err:#}");
    }
    let ports = Arc::new(AppPorts::new(node, port, state_path()?));

    let url = format!("http://127.0.0.1:{port}");
    println!("Raemote Connector — {}", info.name);
    println!("  web UI: {url}");
    println!("Press Ctrl-C to stop.");
    if open {
        open_browser(&url);
    }

    serve(remote, ports, port).await
}

/// `raemote://bind?node=<id>&token=<hex>&exp=<unix>` → `(node id, token)`.
///
/// Shared with the dev client example so both accept the same link shape.
pub fn parse_bind_uri(uri: &str) -> Result<(EndpointId, String)> {
    let query = uri
        .strip_prefix("raemote://bind?")
        .context("not a raemote bind URI")?;
    let mut node = None;
    let mut token = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').context("malformed bind URI")?;
        match key {
            "node" => node = Some(parse_node(value)?),
            "token" => token = Some(value.to_string()),
            _ => {}
        }
    }
    Ok((
        node.context("bind URI is missing the node id")?,
        token.context("bind URI is missing the token")?,
    ))
}

fn parse_node(s: &str) -> Result<EndpointId> {
    EndpointId::from_str(s).context("invalid node id")
}

fn resolve_target(target: Option<&str>) -> Result<(EndpointId, Option<String>)> {
    match target {
        Some(uri) if uri.starts_with("raemote://") => {
            let (node, token) = parse_bind_uri(uri)?;
            Ok((node, Some(token)))
        }
        Some(s) => Ok((parse_node(s)?, None)),
        None => {
            let node = load_last().context(
                "no server remembered — pass a raemote://bind?… URI (from \
                 `raemote pair`) or a node id",
            )?;
            Ok((node, None))
        }
    }
}

// ---------------------------------------------------------------------------
// Last-used server state
// ---------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct LastServer {
    node: String,
    #[serde(default)]
    name: Option<String>,
    /// Stable per-app loopback ports, keyed `"<node-id>/<app-name>"` so two
    /// servers running the same app name never share an origin.
    #[serde(default)]
    ports: HashMap<String, u16>,
}

fn state_path() -> Result<PathBuf> {
    Ok(crate::identity::data_dir()?.join("connector.json"))
}

fn load_last() -> Option<EndpointId> {
    load_last_from(&state_path().ok()?)
}

fn read_state(path: &Path) -> Option<LastServer> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_state(path: &Path, state: &LastServer) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn load_last_from(path: &Path) -> Option<EndpointId> {
    EndpointId::from_str(&read_state(path)?.node).ok()
}

fn save_last(node: EndpointId, name: &str) -> Result<()> {
    let path = state_path()?;
    crate::identity::ensure_data_dir()?;
    save_last_to(&path, node, name)
}

/// Remember the server, preserving any per-app port assignments already on
/// disk (they are keyed by node, so another server's map round-trips too).
fn save_last_to(path: &Path, node: EndpointId, name: &str) -> Result<()> {
    let mut state = read_state(path).unwrap_or_default();
    state.node = node.to_string();
    state.name = Some(name.to_string());
    write_state(path, &state)
}

// ---------------------------------------------------------------------------
// Endpoint + identity
// ---------------------------------------------------------------------------

async fn build_endpoint() -> Result<Endpoint> {
    let secret = load_or_create_client_key()?;
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);

    // Mirror the daemon's outbound-proxy and relay settings so a server that
    // is only reachable through a private relay (or a configured proxy) still
    // dials from the CLI. Config problems warn instead of aborting: the
    // connector must stay usable with no config file at all.
    let cfg = match crate::config::load(&crate::config::config_path(None)?) {
        Ok(cfg) => Some(cfg),
        Err(err) => {
            eprintln!("warning: ignoring config ({err:#}); using environment only");
            None
        }
    };
    let explicit = cfg.as_ref().and_then(|c| c.network.proxy.clone());
    if let Some(url) = crate::proxy::resolve(explicit.as_deref())? {
        builder = builder.proxy_url(url);
    }
    if let Some(relay) = cfg.as_ref().and_then(|c| c.network.relay_url.clone()) {
        let url: iroh::RelayUrl = relay
            .parse()
            .with_context(|| format!("invalid network.relay_url: {relay}"))?;
        builder = builder.relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(url)));
    }

    Ok(builder.bind().await?)
}

/// Load this machine's connector identity (`~/.raemote/client.key`), creating
/// it on first run. Shared with the dev client example: one machine, one
/// device entry on the server.
fn load_or_create_client_key() -> Result<SecretKey> {
    let path = client_key_path()?;
    if path.exists() {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("client key must be 32 bytes"))?;
        Ok(SecretKey::from_bytes(&bytes))
    } else {
        let key = SecretKey::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            crate::identity::restrict(parent, 0o700);
        }
        write_private(&path, &key.to_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(key)
    }
}

/// Write secret key material 0600 regardless of the ambient umask.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn client_key_path() -> Result<PathBuf> {
    Ok(crate::identity::data_dir()?.join("client.key"))
}

// ---------------------------------------------------------------------------
// Pairing (bind ALPN)
// ---------------------------------------------------------------------------

async fn bind(endpoint: &Endpoint, node: EndpointId, token: &str) -> Result<()> {
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(node, BIND_ALPN))
        .await
        .context("timed out connecting for pairing")?
        .context("failed to reach the server for pairing")?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(format!("{token}\n").as_bytes())
        .await
        .context("failed to send token")?;
    send.finish()?;

    let reply = tokio::time::timeout(CONNECT_TIMEOUT, recv.read_to_end(1024))
        .await
        .context("timed out waiting for the pairing reply")?
        .context("failed to read the pairing reply")?;
    let reply = String::from_utf8_lossy(&reply);
    let reply = reply.trim();
    if reply == "OK" {
        Ok(())
    } else {
        anyhow::bail!("pairing failed: {reply}")
    }
}

// ---------------------------------------------------------------------------
// Remote: one cached QUIC connection to the server
// ---------------------------------------------------------------------------

struct Remote {
    endpoint: Endpoint,
    node: EndpointId,
    conn: tokio::sync::Mutex<Option<iroh::endpoint::Connection>>,
}

impl Remote {
    async fn connection(&self) -> Result<iroh::endpoint::Connection> {
        if let Some(conn) = self.conn.lock().await.clone() {
            return Ok(conn);
        }
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.endpoint.connect(self.node, SERVE_ALPN))
            .await
            .context("timed out connecting to the server")?
            .context("failed to reach the server — is raemoted running, and this device paired?")?;
        *self.conn.lock().await = Some(conn.clone());
        Ok(conn)
    }

    async fn invalidate(&self) {
        *self.conn.lock().await = None;
    }

    /// Open a bidirectional stream on the cached connection, redialing once if
    /// the cached connection has gone stale (a server restart leaves the old
    /// QUIC connection *looking* alive until its own idle timeout).
    async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        let cached = self.conn.lock().await.is_some();
        let conn = self.connection().await?;
        match conn.open_bi().await {
            Ok(bi) => Ok(bi),
            Err(err) if cached => {
                self.invalidate().await;
                let conn = self.connection().await?;
                conn.open_bi()
                    .await
                    .map_err(|err| anyhow::anyhow!("the server closed the connection: {err}"))
                    .with_context(|| format!("{err} (redial failed)"))
            }
            Err(err) => Err(err).context("failed to open a stream to the server"),
        }
    }

    /// Issue one buffered HTTP request over the serve ALPN and collect the
    /// response body (used for the small JSON routes only; app traffic is
    /// pumped raw by [`forward`]).
    async fn fetch(&self, method: &str, path: &str) -> Result<(StatusCode, Bytes)> {
        let (send, recv) = self.open_bi().await?;
        let io = TokioIo::new(IrohStream::new(send, recv));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender.ready().await.context("connection not ready")?;
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "raemote")
            .header("Connection", "close")
            .body(Empty::<Bytes>::new())
            .expect("static request is valid");
        let resp = sender
            .send_request(req)
            .await
            .context("request failed (was this device revoked?)")?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        Ok((status, body))
    }
}

async fn fetch_ok(remote: &Remote, method: &str, path: &str, what: &str) -> Result<Bytes> {
    let (status, body) = remote.fetch(method, path).await?;
    match status {
        StatusCode::OK => Ok(body),
        StatusCode::UNAUTHORIZED => anyhow::bail!(
            "{what}: this device is no longer authorized — run `raemote pair` \
             on the server and pair again"
        ),
        other => anyhow::bail!("{what} failed with HTTP {other}"),
    }
}

#[derive(Deserialize)]
struct ServerInfo {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

async fn fetch_info(remote: &Remote) -> Result<ServerInfo> {
    let body = fetch_ok(remote, "GET", "/_hub/info", "server info").await?;
    serde_json::from_slice(&body).context("the server sent malformed info")
}

// ---------------------------------------------------------------------------
// Per-app loopback ports
// ---------------------------------------------------------------------------

/// Stable loopback ports for the apps themselves.
///
/// The index lives on `--port`; every app gets its own port whose entire
/// origin maps to the app's root (`/x` on this port is forwarded as
/// `/app/<name>/x`), exactly like the iOS app's per-app proxy ports. That is
/// what makes both relative and root-absolute URLs inside a page resolve to
/// the right app, and it keeps two apps' cookies and site data from sharing
/// one origin. Assignments are persisted in `connector.json` under the key
/// `<node-id>/<app-name>` so they are stable across runs and never collide
/// across servers.
struct AppPorts {
    node: EndpointId,
    index_port: u16,
    state_path: PathBuf,
    first: u16,
    last: u16,
    inner: Mutex<PortsInner>,
}

#[derive(Default)]
struct PortsInner {
    /// Persisted assignments (all nodes' entries are preserved; only ours are
    /// added or replaced).
    stored: HashMap<String, u16>,
    /// Apps that have a live listener this run.
    live: HashMap<String, u16>,
    /// Every local port already taken by one of our listeners.
    bound: HashSet<u16>,
}

/// A freshly bound app listener awaiting its accept loop: (app, port, socket).
type PendingListener = (String, u16, std::net::TcpListener);

impl AppPorts {
    fn new(node: EndpointId, index_port: u16, state_path: PathBuf) -> Self {
        let stored = read_state(&state_path)
            .map(|state| state.ports)
            .unwrap_or_default();
        Self {
            node,
            index_port,
            state_path,
            first: APP_PORT_FIRST,
            last: APP_PORT_LAST,
            inner: Mutex::new(PortsInner {
                stored,
                ..PortsInner::default()
            }),
        }
    }

    fn key(&self, app: &str) -> String {
        format!("{}/{}", self.node, app)
    }

    /// The port an app of *this* server is being served on right now.
    fn live_port(&self, app: &str) -> Option<u16> {
        self.inner
            .lock()
            .expect("ports poisoned")
            .live
            .get(&self.key(app))
            .copied()
    }

    /// Give every app in `apps` a listener (allocating and persisting ports as
    /// needed) and return the name→port map the index renders links from. An
    /// app with no free port is simply absent — its link falls back to the
    /// path-form `/app/<name>` on the index port.
    fn ensure(&self, remote: &Arc<Remote>, apps: &[CatalogEntry]) -> HashMap<String, u16> {
        let (map, pending) = self.assign_all(apps);
        for (name, port, listener) in pending {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(err) => {
                    eprintln!("warning: could not serve app {name}: {err}");
                    continue;
                }
            };
            let remote = remote.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let (rd, wr) = sock.into_split();
                    let remote = remote.clone();
                    let name = name.clone();
                    tokio::spawn(async move {
                        handle_conn(rd, wr, remote, port, Route::App(name)).await;
                    });
                }
            });
        }
        map
    }

    /// The allocation half of [`ensure`](Self::ensure): bind a port for every
    /// app that doesn't have one yet, persist any changes, and return the
    /// name→port map plus the listeners still to be spawned (split out so the
    /// port logic is unit-testable without an iroh endpoint).
    fn assign_all(
        &self,
        apps: &[CatalogEntry],
    ) -> (HashMap<String, u16>, Vec<PendingListener>) {
        let mut pending = Vec::new();
        let mut changed = false;
        let (map, stored) = {
            let mut inner = self.inner.lock().expect("ports poisoned");
            for app in apps {
                let key = self.key(&app.name);
                if inner.live.contains_key(&key) {
                    continue;
                }
                let before = inner.stored.get(&key).copied();
                let Some(listener) = self.assign(&mut inner, &key) else {
                    continue;
                };
                let port = inner.live[&key];
                if before != Some(port) {
                    changed = true;
                }
                pending.push((app.name.clone(), port, listener));
            }
            let map = apps
                .iter()
                .filter_map(|app| {
                    inner
                        .live
                        .get(&self.key(&app.name))
                        .map(|&port| (app.name.clone(), port))
                })
                .collect();
            let stored = if changed {
                Some(inner.stored.clone())
            } else {
                None
            };
            (map, stored)
        };
        if let Some(ports) = stored {
            let mut state = read_state(&self.state_path).unwrap_or_default();
            state.ports = ports;
            if let Err(err) = write_state(&self.state_path, &state) {
                eprintln!("warning: could not remember app ports: {err:#}");
            }
        }
        (map, pending)
    }

    /// Pick a port for `key` and bind it, recording the assignment. The stored
    /// (previous) port is tried first for origin stability; otherwise the
    /// first free port in the range that collides with neither our listeners,
    /// the index, nor any other stored assignment is used.
    fn assign(&self, inner: &mut PortsInner, key: &str) -> Option<std::net::TcpListener> {
        let mut candidates = Vec::new();
        if let Some(&stored) = inner.stored.get(key) {
            candidates.push(stored);
        }
        for port in self.first..=self.last {
            let foreign = inner.stored.values().any(|&other| other == port);
            if port != self.index_port && !inner.bound.contains(&port) && !foreign {
                candidates.push(port);
            }
        }
        for port in candidates {
            if port == self.index_port || inner.bound.contains(&port) {
                continue;
            }
            let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) else {
                continue;
            };
            if listener.set_nonblocking(true).is_err() {
                continue;
            }
            if inner.stored.get(key) != Some(&port) {
                inner.stored.insert(key.to_string(), port);
            }
            inner.live.insert(key.to_string(), port);
            inner.bound.insert(port);
            return Some(listener);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Local server
// ---------------------------------------------------------------------------

async fn serve(remote: Arc<Remote>, ports: Arc<AppPorts>, port: u16) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("cannot listen on 127.0.0.1:{port} — already in use? try --port"))?;
    loop {
        let (sock, _) = listener.accept().await?;
        let remote = remote.clone();
        let ports = ports.clone();
        let (rd, wr) = sock.into_split();
        tokio::spawn(async move {
            handle_conn(rd, wr, remote, port, Route::Index(ports)).await;
        });
    }
}

/// What a local listener serves: the index (and legacy `/app/…` links) on
/// `--port`, or one app's whole origin on its own port.
enum Route {
    Index(Arc<AppPorts>),
    /// An app's own port: every path is forwarded under `/app/<name>/…`.
    App(String),
}

/// The origin-form target a request on an app's own port is forwarded as: the
/// app's whole origin maps to `/app/<name>/`, so relative *and* root-absolute
/// URLs inside the page reach the right app (`/` → `/app/<name>/`, matching
/// what the server proxies as the origin root).
fn app_target(name: &str, path: &str, query: &str) -> String {
    let mut target = if path == "/" {
        format!("/app/{name}/")
    } else {
        format!("/app/{name}{path}")
    };
    if !query.is_empty() {
        target.push('?');
        target.push_str(query);
    }
    target
}

async fn handle_conn(mut rd: OwnedReadHalf, wr: OwnedWriteHalf, remote: Arc<Remote>, port: u16, route: Route) {
    let mut wr = wr;
    let buf = match read_head(&mut rd).await {
        Some(buf) => buf,
        None => return,
    };
    let head_end = match find_head_end(&buf) {
        Some(pos) => pos,
        None => return,
    };
    let raw = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let leftover = buf[head_end + 4..].to_vec();

    let Some(mut head) = parse_head(&raw) else {
        let _ = write_error(&mut wr, "400 Bad Request", "malformed request").await;
        return;
    };
    if !host_allowed(&head, port) {
        let _ = write_error(
            &mut wr,
            "403 Forbidden",
            "this service only answers on 127.0.0.1",
        )
        .await;
        return;
    }

    let (path, query) = split_query(&head.target);
    match route {
        Route::App(name) => {
            head.set_target(&app_target(&name, path, query));
            forward(rd, &mut wr, &remote, head, leftover).await;
        }
        Route::Index(ports) => {
            if path == "/" {
                let refresh = query.split('&').any(|param| param == "refresh=1");
                handle_index(&mut wr, &remote, &ports, refresh, head.method == "HEAD").await;
                return;
            }
            if let Some(rest) = path.strip_prefix("/app/") {
                let app_name = rest.split('/').next().unwrap_or(rest);
                let port = ports.live_port(app_name);
                if let Some(location) = redirect_location(rest, query, port) {
                    let _ = write_redirect(&mut wr, &location).await;
                    return;
                }
            }
            forward(rd, &mut wr, &remote, head, leftover).await;
        }
    }
}

/// Read through to the end of the request head (bounded and timed).
async fn read_head(rd: &mut OwnedReadHalf) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if find_head_end(&buf).is_some() {
            return Some(buf);
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        match tokio::time::timeout(HEAD_TIMEOUT, rd.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

struct Head {
    first_line: String,
    method: String,
    target: String,
    version: String,
    headers: Vec<String>,
    upgrade: bool,
    has_body: bool,
}

impl Head {
    /// Point the request at a different origin-form target (used to mount an
    /// app's whole origin under `/app/<name>/…`).
    fn set_target(&mut self, target: &str) {
        self.target = target.to_string();
        self.first_line = format!("{} {} {}", self.method, target, self.version);
    }
}

fn parse_head(raw: &str) -> Option<Head> {
    let mut lines = raw.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = origin_form(parts.next()?);
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/1.") {
        return None;
    }

    let mut headers = Vec::new();
    let mut upgrade = false;
    let mut has_body = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "connection" && value.to_ascii_lowercase().contains("upgrade") {
            upgrade = true;
        }
        if name == "upgrade" {
            upgrade = true;
        }
        if name == "content-length" && value != "0" {
            has_body = true;
        }
        if name == "transfer-encoding" {
            has_body = true;
        }
        headers.push(line.to_string());
    }

    Some(Head {
        first_line: format!("{method} {target} {version}"),
        method,
        target,
        version,
        headers,
        upgrade,
        has_body,
    })
}

/// Absolute-form targets (`GET http://host/path`) arrive only from proxies and
/// test clients; normalize to origin form before routing and forwarding.
fn origin_form(target: &str) -> String {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        && let Some(slash) = rest.find('/')
    {
        return rest[slash..].to_string();
    }
    target.to_string()
}

fn split_query(target: &str) -> (&str, &str) {
    target.split_once('?').unwrap_or((target, ""))
}

/// Only requests addressed to `127.0.0.1:<port>` are served. A *wrong* Host
/// (a DNS-rebinding page) is refused; a *missing* Host (HTTP/1.0 tools) passes,
/// since HTTP/1.1 browsers always send the attacker's domain.
fn host_allowed(head: &Head, port: u16) -> bool {
    let expected = format!("127.0.0.1:{port}");
    for line in &head.headers {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            return value.trim().eq_ignore_ascii_case(&expected);
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Index page
// ---------------------------------------------------------------------------

async fn handle_index(
    wr: &mut OwnedWriteHalf,
    remote: &Arc<Remote>,
    ports: &AppPorts,
    refresh: bool,
    head_only: bool,
) {
    let (status, page) = match build_page(remote, ports, refresh).await {
        Ok(page) => ("200 OK", page),
        Err(err) => (
            "502 Bad Gateway",
            render_error("Could not reach the server", &format!("{err:#}")),
        ),
    };
    let _ = write_response(wr, status, "text/html; charset=utf-8", page.as_bytes(), !head_only)
        .await;
}

async fn build_page(remote: &Arc<Remote>, ports: &AppPorts, refresh: bool) -> Result<String> {
    if refresh {
        fetch_ok(remote, "POST", "/_hub/discover", "discovery refresh").await?;
    }
    let info = fetch_info(remote).await?;
    let body = fetch_ok(remote, "GET", "/_hub/catalog", "app catalog").await?;
    let catalog: CatalogResponse =
        serde_json::from_slice(&body).context("the server sent a malformed catalog")?;
    // Anything the catalog gained (e.g. via Refresh) gets its listener now,
    // before the links to it are rendered.
    let app_ports = ports.ensure(remote, &catalog.apps);
    Ok(render_page(&info, &catalog.apps, &app_ports))
}

/// `GET /app/<name>[/sub]` on the index port (an old bookmark, a stale tab,
/// an icon URL) → the same place on the app's own port, where the app's whole
/// origin lives. `app_port` is `None` for a name this server doesn't run —
/// forwarding then lets the server answer authoritatively (404 JSON).
fn redirect_location(rest: &str, query: &str, app_port: Option<u16>) -> Option<String> {
    let app_port = app_port?;
    let sub = rest.split_once('/').map(|(_, sub)| sub).unwrap_or("");
    let mut location = format!("http://127.0.0.1:{app_port}/");
    if !sub.is_empty() {
        location.push_str(sub);
    }
    if !query.is_empty() {
        location.push('?');
        location.push_str(query);
    }
    Some(location)
}

async fn write_redirect(wr: &mut OwnedWriteHalf, location: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    wr.write_all(head.as_bytes()).await?;
    let _ = wr.shutdown().await;
    Ok(())
}

#[derive(Deserialize)]
struct CatalogResponse {
    #[serde(default)]
    apps: Vec<CatalogEntry>,
}

#[derive(Deserialize)]
struct CatalogEntry {
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    port: u16,
}

/// Render the index. `ports` maps each app to its own loopback port (apps
/// without one — no free port left — fall back to path links on the index
/// port, which the index redirects to the app port when it exists).
fn render_page(info: &ServerInfo, apps: &[CatalogEntry], ports: &HashMap<String, u16>) -> String {
    let count = format!("{} app{}", apps.len(), if apps.len() == 1 { "" } else { "s" });
    let summary = match &info.version {
        Some(version) => format!("{count} · raemote {version}"),
        None => count,
    };
    let content = if apps.is_empty() {
        "<p class=\"empty\">No apps yet. The server rescans every 30 seconds — \
         start one and hit Refresh.</p>"
            .to_string()
    } else {
        apps.iter()
            .map(|app| app_row(app, ports.get(&app.name).copied()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    fill(
        PAGE,
        &[
            ("__TITLE__", &esc(&info.name)),
            ("__SUMMARY__", &summary),
            ("__APPS__", &content),
        ],
    )
}

fn render_error(title: &str, message: &str) -> String {
    let content = format!(
        "<div class=\"error\"><h2>{}</h2><p>{}</p></div>",
        esc(title),
        esc(message)
    );
    fill(
        PAGE,
        &[
            ("__TITLE__", "Raemote Connector"),
            ("__SUMMARY__", "error"),
            ("__APPS__", &content),
        ],
    )
}

fn app_row(app: &CatalogEntry, port: Option<u16>) -> String {
    let label = app
        .title
        .as_deref()
        .filter(|title| !title.is_empty())
        .unwrap_or(&app.name);
    let media = match &app.icon {
        Some(icon) => format!(
            "<img src=\"/app/{}{}\" alt=\"\" width=\"36\" height=\"36\" loading=\"lazy\">",
            esc(&app.name),
            esc(icon)
        ),
        None => {
            let monogram: String = label.chars().next().unwrap_or('?').to_uppercase().collect();
            format!("<span class=\"mono\">{}</span>", esc(&monogram))
        }
    };
    let href = match port {
        Some(port) => format!("http://127.0.0.1:{port}/"),
        None => format!("/app/{}", esc(&app.name)),
    };
    format!(
        "<a class=\"app\" href=\"{href}\">{}<span><b>{}</b><small>:{}</small></span></a>",
        media,
        esc(label),
        app.port
    )
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Replace the template tokens in a single left-to-right pass. Inserted text
/// is never rescanned, so a server named `__APPS__` cannot inject markup.
fn fill(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let earliest = replacements
            .iter()
            .filter_map(|(token, _)| rest.find(token).map(|pos| (pos, *token)))
            .min_by_key(|(pos, _)| *pos);
        match earliest {
            None => {
                out.push_str(rest);
                return out;
            }
            Some((pos, token)) => {
                out.push_str(&rest[..pos]);
                let value = replacements
                    .iter()
                    .find(|(candidate, _)| *candidate == token)
                    .map(|(_, value)| *value)
                    .unwrap_or_default();
                out.push_str(value);
                rest = &rest[pos + token.len()..];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Forwarding raw app traffic
// ---------------------------------------------------------------------------

struct FwdErr {
    responded: bool,
    stalled: bool,
    message: String,
}

impl FwdErr {
    fn new(message: impl Into<String>) -> Self {
        Self {
            responded: false,
            stalled: false,
            message: message.into(),
        }
    }
}

enum PumpKind {
    Stalled,
    Io(std::io::Error),
}

struct PumpErr {
    responded: bool,
    kind: PumpKind,
}

async fn forward(
    mut rd: OwnedReadHalf,
    wr: &mut OwnedWriteHalf,
    remote: &Remote,
    head: Head,
    leftover: Vec<u8>,
) {
    let prepared = prepare_forward_head(&head);
    // Only bodyless, non-upgrade requests may be replayed: a GET the server
    // never saw is safe to send again; a POST or a half-open WebSocket is not.
    let retryable = !head.has_body && !head.upgrade;
    let mut attempt = 0;
    loop {
        let result = try_forward_once(
            &mut rd,
            wr,
            remote,
            prepared.as_bytes(),
            &leftover,
            head.has_body,
            head.upgrade,
        )
        .await;
        let err = match result {
            Ok(true) => return,
            Ok(false) => FwdErr::new("the server closed the connection without responding"),
            Err(err) if err.responded => return,
            Err(err) if retryable && !err.stalled && attempt == 0 => {
                attempt += 1;
                remote.invalidate().await;
                continue;
            }
            Err(err) => err,
        };
        let status = if err.stalled {
            "504 Gateway Timeout"
        } else {
            "502 Bad Gateway"
        };
        let page = render_error("Could not reach the server", &err.message);
        let _ = write_response(wr, status, "text/html; charset=utf-8", page.as_bytes(), true).await;
        return;
    }
}

async fn try_forward_once(
    rd: &mut OwnedReadHalf,
    wr: &mut OwnedWriteHalf,
    remote: &Remote,
    prepared: &[u8],
    leftover: &[u8],
    has_body: bool,
    upgrade: bool,
) -> Result<bool, FwdErr> {
    let (mut send, recv) = remote
        .open_bi()
        .await
        .map_err(|err| FwdErr::new(format!("{err:#}")))?;
    send.write_all(prepared)
        .await
        .map_err(|err| FwdErr::new(format!("failed to send the request: {err}")))?;
    if !leftover.is_empty() {
        send.write_all(leftover)
            .await
            .map_err(|err| FwdErr::new(format!("failed to send the request: {err}")))?;
    }

    // Pump the rest of the request (body, or an endless WebSocket upload) while
    // the response streams back; a bodyless request just half-closes.
    let pump_upload = has_body || upgrade;
    let upload = async move {
        if pump_upload {
            let _ = tokio::io::copy(rd, &mut send).await;
        }
        let _ = send.finish();
    };
    tokio::pin!(upload);
    let download = pump_response(recv, wr);
    tokio::pin!(download);

    let first = tokio::select! {
        res = &mut download => Some(res),
        _ = &mut upload => None,
    };
    let outcome = match first {
        Some(res) => res,
        // The request side finished first (typical for bodyless GETs):
        // keep waiting for the response.
        None => download.await,
    };
    match outcome {
        Ok(responded) => Ok(responded),
        Err(err) => Err(FwdErr {
            responded: err.responded,
            stalled: matches!(err.kind, PumpKind::Stalled),
            message: match err.kind {
                PumpKind::Stalled => {
                    "the server accepted the connection but sent no response \
                     within 15 seconds"
                        .to_string()
                }
                PumpKind::Io(_) if err.responded => {
                    "the connection to the app was lost mid-response".to_string()
                }
                PumpKind::Io(io) => format!("the server closed the connection: {io}"),
            },
        }),
    }
}

/// Stream the response head+body back to the browser, reporting whether any
/// byte reached it. The first byte is bounded by [`FIRST_BYTE_TIMEOUT`]; after
/// that the pump runs until the server finishes (QUIC's own idle timeout
/// handles a dead peer).
async fn pump_response(
    mut recv: RecvStream,
    wr: &mut OwnedWriteHalf,
) -> Result<bool, PumpErr> {
    let mut responded = false;
    let mut first = true;
    let mut buf = [0u8; 8192];
    loop {
        let n = if first {
            match tokio::time::timeout(FIRST_BYTE_TIMEOUT, recv.read(&mut buf)).await {
                Err(_) => {
                    return Err(PumpErr {
                        responded,
                        kind: PumpKind::Stalled,
                    })
                }
                Ok(res) => res,
            }
        } else {
            recv.read(&mut buf).await
        };
        match n {
            Ok(Some(0)) | Ok(None) => break,
            Ok(Some(n)) => {
                first = false;
                if let Err(err) = wr.write_all(&buf[..n]).await {
                    return Err(PumpErr {
                        responded,
                        kind: PumpKind::Io(err),
                    });
                }
                responded = true;
            }
            Err(err) => {
                return Err(PumpErr {
                    responded,
                    kind: PumpKind::Io(std::io::Error::other(err)),
                })
            }
        }
    }
    let _ = wr.shutdown().await;
    Ok(responded)
}

/// Rebuild the request head for the server: `Host` becomes `raemote`, and
/// (unless this is an upgrade) `Connection: close` is forced so the response
/// ends the exchange. The request target is already origin-form.
fn prepare_forward_head(head: &Head) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(&head.first_line);
    out.push_str("\r\n");
    for line in &head.headers {
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("host") {
            out.push_str("Host: raemote\r\n");
            continue;
        }
        if !head.upgrade && name.eq_ignore_ascii_case("connection") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !head.upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out
}

// ---------------------------------------------------------------------------
// Local response helpers
// ---------------------------------------------------------------------------

async fn write_response(
    wr: &mut OwnedWriteHalf,
    status_line: &str,
    content_type: &str,
    body: &[u8],
    send_body: bool,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    wr.write_all(head.as_bytes()).await?;
    if send_body {
        wr.write_all(body).await?;
    }
    let _ = wr.shutdown().await;
    Ok(())
}

async fn write_error(wr: &mut OwnedWriteHalf, status_line: &str, message: &str) -> std::io::Result<()> {
    let body = format!("{status_line}: {message}\n");
    write_response(wr, status_line, "text/plain; charset=utf-8", body.as_bytes(), true).await
}

// ---------------------------------------------------------------------------
// Browser
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn spawn_browser(url: &str) -> std::io::Result<std::process::Child> {
    std::process::Command::new("open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

#[cfg(target_os = "linux")]
fn spawn_browser(url: &str) -> std::io::Result<std::process::Child> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn spawn_browser(_url: &str) -> std::io::Result<std::process::Child> {
    Err(std::io::Error::other("no browser launcher for this platform"))
}

fn open_browser(url: &str) {
    match spawn_browser(url) {
        Ok(mut child) => {
            // Reap the launcher so a long-lived connector never accumulates
            // zombies.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => eprintln!("could not open a browser ({err}); open {url} yourself"),
    }
}

// ---------------------------------------------------------------------------
// Embedded page
// ---------------------------------------------------------------------------

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · Raemote</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2016%2016'%3E%3Ccircle%20cx='8'%20cy='8'%20r='7'%20fill='%233478f6'/%3E%3C/svg%3E">
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 28px 18px 40px; }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 14px; margin-bottom: 22px; }
h1 { font-size: 21px; font-weight: 650; margin: 0; }
.sub { margin: 0; font-size: 13px; opacity: .6; }
.btn { margin-left: auto; font-size: 13px; text-decoration: none; padding: 6px 14px;
  border-radius: 999px; color: inherit; border: 1px solid rgba(127,127,127,.45); }
.btn:hover { background: rgba(127,127,127,.15); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 10px; }
.app { display: flex; align-items: center; gap: 11px; padding: 11px 13px;
  border: 1px solid rgba(127,127,127,.28); border-radius: 13px;
  color: inherit; text-decoration: none; }
.app:hover { background: rgba(127,127,127,.12); }
.app img, .app .mono { width: 36px; height: 36px; border-radius: 9px; flex: none; }
.app img { object-fit: cover; background: rgba(127,127,127,.2); }
.mono { display: grid; place-items: center; font-weight: 600; font-size: 17px;
  background: #3478f6; color: #fff; }
.app b { display: block; font-weight: 600; font-size: 14.5px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.app small { display: block; font-size: 12px; opacity: .55; }
.empty { opacity: .6; font-size: 14px; border: 1px dashed rgba(127,127,127,.4);
  border-radius: 13px; padding: 18px; }
.error { border: 1px solid rgba(200,60,60,.5); border-radius: 13px; padding: 16px 18px; }
.error h2 { margin: 0 0 6px; font-size: 16px; color: #e5484d; }
.error p { margin: 0; font-size: 13.5px; opacity: .8; overflow-wrap: anywhere; }
footer { margin-top: 26px; font-size: 12px; opacity: .5; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<main>
<header>
  <h1>__TITLE__</h1>
  <p class="sub">__SUMMARY__</p>
  <a class="btn" href="/?refresh=1">Refresh</a>
</header>
<section class="grid">__APPS__</section>
<footer>Bridged locally by <code>raemote connect</code> over an encrypted iroh tunnel.</footer>
</main>
</body>
</html>
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn node(tag: u8) -> EndpointId {
        // Derive from a secret key so the result is a valid ed25519 public key.
        SecretKey::from_bytes(&[tag; 32]).public()
    }

    #[test]
    fn parse_bind_uri_accepts_the_pair_link() {
        let uri = format!("raemote://bind?node={}&token=abc123&exp=1700000000", node(1));
        let (parsed, token) = parse_bind_uri(&uri).unwrap();
        assert_eq!(parsed, node(1));
        assert_eq!(token, "abc123");
    }

    #[test]
    fn parse_bind_uri_rejects_bad_input() {
        assert!(parse_bind_uri("https://example.com").is_err());
        assert!(parse_bind_uri("raemote://bind?token=abc").is_err());
        assert!(parse_bind_uri("raemote://bind?node=nope").is_err());
        assert!(parse_bind_uri(&format!("raemote://bind?node={}", node(2))).is_err());
    }

    #[test]
    fn forward_head_rewrites_host_and_forces_close() {
        let head = parse_head(
            "GET /app/wiki/Main HTTP/1.1\r\nHost: 127.0.0.1:7788\r\nConnection: keep-alive\r\nAccept: */*\r\n",
        )
        .unwrap();
        let out = prepare_forward_head(&head);
        assert!(out.starts_with("GET /app/wiki/Main HTTP/1.1\r\n"));
        assert!(out.contains("Host: raemote\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.to_ascii_lowercase().contains("connection: keep-alive"));
        assert!(out.ends_with("\r\n\r\n"));
        let lower = out.to_ascii_lowercase();
        assert_eq!(lower.matches("connection:").count(), 1, "exactly one Connection");
    }

    #[test]
    fn forward_head_keeps_upgrade_headers() {
        let head = parse_head(
            "GET /app/chat/socket HTTP/1.1\r\nHost: 127.0.0.1:7788\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        )
        .unwrap();
        assert!(head.upgrade);
        let out = prepare_forward_head(&head);
        assert!(out.contains("Connection: Upgrade\r\n"));
        assert!(out.contains("Upgrade: websocket\r\n"));
        assert!(out.contains("Host: raemote\r\n"));
        assert!(!out.to_ascii_lowercase().contains("connection: close"));
    }

    #[test]
    fn parse_head_flags_bodies_and_absolutizes_targets() {
        let head = parse_head("POST /app/api/submit HTTP/1.1\r\nContent-Length: 0\r\n").unwrap();
        assert!(!head.has_body);
        let head = parse_head("POST /app/api/submit HTTP/1.1\r\nContent-Length: 12\r\n").unwrap();
        assert!(head.has_body);
        let head = parse_head("PUT /app/api/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n").unwrap();
        assert!(head.has_body);
        let head =
            parse_head("GET http://127.0.0.1:7788/app/wiki/Main HTTP/1.1\r\nHost: x\r\n").unwrap();
        assert_eq!(head.target, "/app/wiki/Main");
        assert!(head.first_line.starts_with("GET /app/wiki/Main HTTP/1.1"));
        assert!(parse_head("GET / HTTP/1.0\r\n").is_some(), "1.0 is still HTTP");
        assert!(parse_head("GET /\r\n").is_none(), "missing version");
        assert!(parse_head("not a request\r\n").is_none());
    }

    #[test]
    fn host_gate_accepts_only_our_listener() {
        let port = 7788;
        let allowed = parse_head("GET / HTTP/1.1\r\nHost: 127.0.0.1:7788\r\n").unwrap();
        assert!(host_allowed(&allowed, port));
        let rebound = parse_head("GET / HTTP/1.1\r\nHost: evil.example\r\n").unwrap();
        assert!(!host_allowed(&rebound, port));
        let other_port = parse_head("GET / HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n").unwrap();
        assert!(!host_allowed(&other_port, port));
        let hostless = parse_head("GET / HTTP/1.1\r\nAccept: */*\r\n").unwrap();
        assert!(host_allowed(&hostless, port));
    }

    #[test]
    fn index_escapes_hostile_names_and_fills_once() {
        let info = ServerInfo {
            name: "__APPS__ <script>".to_string(),
            version: Some("0.1.3".to_string()),
        };
        let apps = vec![
            CatalogEntry {
                name: "wiki".to_string(),
                title: Some("Main & <Page>".to_string()),
                icon: Some("/favicon.ico".to_string()),
                port: 8080,
            },
            CatalogEntry {
                name: "notes".to_string(),
                title: None,
                icon: None,
                port: 3000,
            },
        ];
        let mut ports = HashMap::new();
        ports.insert("wiki".to_string(), 7791u16);
        let page = render_page(&info, &apps, &ports);
        assert!(!page.contains("<script>"), "raw script must be escaped");
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("__APPS__ &lt;script&gt;"), "title token not re-expanded");
        assert!(page.contains("Main &amp; &lt;Page&gt;"));
        assert!(
            page.contains("href=\"http://127.0.0.1:7791/\""),
            "an app with a port links to its own origin"
        );
        assert!(
            page.contains("href=\"/app/notes\""),
            "an app without a port falls back to the path link"
        );
        assert!(page.contains("src=\"/app/wiki/favicon.ico\""));
        assert!(page.contains("<span class=\"mono\">N</span>"), "monogram fallback");
        assert!(page.contains(":8080"));
        assert!(page.contains("raemote 0.1.3"));
        assert!(!page.contains("__SUMMARY__"), "all tokens replaced");
    }

    #[test]
    fn empty_catalog_offers_refresh_hint() {
        let info = ServerInfo {
            name: "server".to_string(),
            version: None,
        };
        let page = render_page(&info, &[], &HashMap::new());
        assert!(page.contains("No apps yet"));
        assert!(!page.contains("__SUMMARY__"));
    }

    #[test]
    fn error_page_is_plain_html() {
        let page = render_error("Could not reach the server", "closed <now>");
        assert!(page.contains("closed &lt;now&gt;"));
        assert!(!page.contains("<now>"));
    }

    #[test]
    fn state_roundtrips_and_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.json");
        save_last_to(&path, node(7), "Mac mini").unwrap();
        assert_eq!(load_last_from(&path), Some(node(7)));
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(load_last_from(&path), None);
        assert_eq!(load_last_from(&dir.path().join("missing.json")), None);
    }

    #[test]
    fn app_port_mounts_the_whole_origin_under_the_app_path() {
        // The app's origin root lives at /app/<name>/ — trailing slash, so the
        // server strips the prefix down to the origin's "/".
        assert_eq!(app_target("wiki", "/", ""), "/app/wiki/");
        assert_eq!(app_target("wiki", "/", "q=1"), "/app/wiki/?q=1");
        // Relative *and* root-absolute refs from a page arrive as plain paths
        // on the app's port (the old /app/lib/… 404 case) and are re-mounted.
        assert_eq!(app_target("wiki", "/lib/x.css", ""), "/app/wiki/lib/x.css");
        assert_eq!(app_target("wiki", "/lib/x.css", "v=2"), "/app/wiki/lib/x.css?v=2");
        assert_eq!(
            app_target("miniwerm", "/lib/@wterm/dom/src/terminal.css", ""),
            "/app/miniwerm/lib/@wterm/dom/src/terminal.css"
        );

        let mut head =
            parse_head("GET /lib/x.css HTTP/1.1\r\nHost: 127.0.0.1:7791\r\nAccept: */*\r\n")
                .unwrap();
        head.set_target(&app_target("wiki", "/lib/x.css", ""));
        assert_eq!(head.target, "/app/wiki/lib/x.css");
        assert_eq!(head.first_line, "GET /app/wiki/lib/x.css HTTP/1.1");
    }

    #[test]
    fn stale_app_links_redirect_to_the_app_port() {
        // /app/wiki → the app's whole origin
        assert_eq!(
            redirect_location("wiki", "", Some(7791)),
            Some("http://127.0.0.1:7791/".to_string())
        );
        // /app/wiki/favicon.ico?v=2 → same path+query on the app port
        assert_eq!(
            redirect_location("wiki/favicon.ico", "v=2", Some(7791)),
            Some("http://127.0.0.1:7791/favicon.ico?v=2".to_string())
        );
        // A name this server doesn't run is not redirected — the server
        // answers authoritatively when the request is forwarded as-is.
        assert_eq!(redirect_location("lib/@wterm/x.css", "", None), None);
    }

    #[test]
    fn state_preserves_app_ports_when_remembering_a_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.json");
        save_last_to(&path, node(7), "Mac mini").unwrap();
        let mut state = read_state(&path).unwrap();
        state.ports.insert(format!("{}/wiki", node(7)), 7791);
        write_state(&path, &state).unwrap();

        save_last_to(&path, node(7), "Mac mini renamed").unwrap();
        let state = read_state(&path).unwrap();
        assert_eq!(state.ports.get(&format!("{}/wiki", node(7))), Some(&7791));
        assert_eq!(state.name.as_deref(), Some("Mac mini renamed"));
        assert_eq!(load_last_from(&path), Some(node(7)));
    }

    #[test]
    fn app_ports_allocate_stably_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.json");
        let apps = || {
            vec![
                CatalogEntry {
                    name: "alpha".to_string(),
                    title: None,
                    icon: None,
                    port: 1,
                },
                CatalogEntry {
                    name: "beta".to_string(),
                    title: None,
                    icon: None,
                    port: 2,
                },
            ]
        };

        let mut ports = AppPorts::new(node(9), 7788, path.clone());
        ports.first = 23100;
        ports.last = 23109;
        let (map, listeners) = ports.assign_all(&apps());
        assert_eq!(map.len(), 2, "both apps got a port");
        let (alpha, beta) = (map["alpha"], map["beta"]);
        assert_ne!(alpha, beta, "apps never share an origin");
        for port in [alpha, beta] {
            assert!((23100..=23109).contains(&port));
        }
        let state = read_state(&path).unwrap();
        assert_eq!(state.ports.get(&format!("{}/alpha", node(9))), Some(&alpha));

        // A fresh run reads the same file and reuses the same ports.
        drop(listeners);
        let mut ports2 = AppPorts::new(node(9), 7788, path.clone());
        ports2.first = 23100;
        ports2.last = 23109;
        let (map2, _keep) = ports2.assign_all(&apps());
        assert_eq!(map2["alpha"], alpha, "ports are stable across runs");
        assert_eq!(map2["beta"], beta);

        // Re-assigning on the same instance changes nothing.
        let (again, pending) = ports.assign_all(&apps());
        assert_eq!(again, map);
        assert!(pending.is_empty(), "already-served apps are not re-bound");

        // A *different* server with the same app names gets its own ports
        // (the NodeId-isolation rule): its keys differ, its origins differ.
        let mut ports3 = AppPorts::new(node(10), 7788, path);
        ports3.first = 23100;
        ports3.last = 23109;
        let (map3, _keep3) = ports3.assign_all(&apps());
        assert_ne!(map3["alpha"], alpha, "two servers stay isolated");
        assert_ne!(map3["alpha"], beta);
    }
}
