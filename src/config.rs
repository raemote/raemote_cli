//! On-disk configuration (`~/.raemote/config.toml`) and `RAEMOTE_*` overrides.
//!
//! [`Config`] loads from TOML, with environment variables taking precedence,
//! and is validated before use.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// The complete server configuration, as stored in `~/.raemote/config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Display name for this server, shown to paired phones. Defaults to the
    /// machine's hostname when unset.
    #[serde(default)]
    pub name: Option<String>,
    /// Identity/key storage.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// Network (relay, outbound proxy).
    #[serde(default)]
    pub network: NetworkConfig,
    /// Pairing tokens and bind connections.
    #[serde(default)]
    pub bind: BindConfig,
    /// HTTP serving limits.
    #[serde(default)]
    pub serve: ServeConfig,
    /// Local web-app discovery.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    /// Logging.
    #[serde(default)]
    pub log: LogConfig,
    /// Manually configured apps.
    #[serde(default)]
    pub apps: Vec<AppConfig>,
}

/// Identity settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityConfig {
    /// Override the default secret-key path (`~/.raemote/secret.key`).
    pub key_path: Option<PathBuf>,
}

/// Network settings for the iroh endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    /// Custom relay URL (advanced; requires a restart to change).
    pub relay_url: Option<String>,
    /// Outbound proxy for iroh relay/discovery traffic (HTTP CONNECT). Falls
    /// back to `ALL_PROXY`/`HTTP_PROXY`/`HTTPS_PROXY` env vars when unset.
    pub proxy: Option<String>,
}

/// Pairing-token and bind-connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindConfig {
    /// Lifetime of a pairing token, in seconds.
    pub token_ttl_secs: u64,
    /// Failed bind attempts before the token is revoked.
    pub max_failed_attempts: u32,
    /// Maximum concurrent bind connections.
    pub max_concurrent_connections: usize,
    /// Fixed pairing token. When set, the daemon uses this value instead of a
    /// fresh random token, so the pairing link stays valid across restarts.
    ///
    /// It is a long-lived credential: keep the config file private and unset it
    /// when it is no longer needed.
    #[serde(default)]
    pub token: Option<String>,
    /// Whether an authorized device may mint one-time invitations that pair
    /// another device (device-to-device onboarding).
    #[serde(default = "default_true")]
    pub allow_invites: bool,
    /// Lifetime of a one-time invitation, in seconds.
    #[serde(default = "default_invite_ttl_secs")]
    pub invite_ttl_secs: u64,
    /// Maximum number of outstanding invitations at once.
    #[serde(default = "default_max_pending_invites")]
    pub max_pending_invites: usize,
}

fn default_true() -> bool {
    true
}

fn default_invite_ttl_secs() -> u64 {
    300
}

fn default_max_pending_invites() -> usize {
    3
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            token_ttl_secs: 300,
            max_failed_attempts: 10,
            max_concurrent_connections: 50,
            token: None,
            allow_invites: true,
            invite_ttl_secs: default_invite_ttl_secs(),
            max_pending_invites: default_max_pending_invites(),
        }
    }
}

/// HTTP serving limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServeConfig {
    /// Maximum concurrent streams per device.
    pub max_concurrent_streams: usize,
    /// Per-device rate limit.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Leaky-bucket rate limit parameters, applied per device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Tokens added on each refill.
    pub refill: usize,
    /// Interval between refills, in milliseconds.
    pub interval_ms: u64,
    /// Maximum burst size.
    pub max: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            refill: 100,
            interval_ms: 1000,
            max: 1000,
        }
    }
}

/// Local web-app discovery settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Whether discovery runs at all.
    pub enabled: bool,
    /// Seconds between scans.
    pub interval_secs: u64,
    /// Seconds before a known app is re-probed.
    pub recheck_secs: u64,
    /// Per-probe timeout, in milliseconds.
    pub probe_timeout_ms: u64,
    /// Maximum probes in flight at once.
    pub max_concurrent_probes: usize,
    /// Ignore listening ports below this value.
    pub min_port: u16,
    /// Probe candidates over HTTP.
    pub http_probe: bool,
    /// Probe candidates over HTTPS (not implemented yet).
    pub https_probe: bool,
    /// Only consider loopback/wildcard binds.
    pub loopback_only: bool,
    /// Also consider listening sockets whose owning process can't be read —
    /// another user's, or a root-owned system service such as the `nginx` in
    /// front of an app. The process name is unavailable then (the HTTP probe
    /// usually supplies the name instead), and every other filter still
    /// applies. Linux only: elsewhere the process list is already complete.
    #[serde(default = "default_true")]
    pub include_unattributed: bool,
    /// Ports to exclude, in addition to the built-in denylist.
    #[serde(default)]
    pub exclude_ports: Vec<u16>,
    /// Process names to exclude.
    #[serde(default)]
    pub exclude_processes: Vec<String>,
    /// Origins to hide, as `host:port` (for example `127.0.0.1:10808`). Use
    /// this to drop a false positive such as a local proxy.
    #[serde(default)]
    pub exclude_origins: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            recheck_secs: 300,
            probe_timeout_ms: 400,
            max_concurrent_probes: 16,
            min_port: 1024,
            http_probe: true,
            https_probe: false,
            loopback_only: true,
            include_unattributed: true,
            exclude_ports: Vec::new(),
            exclude_processes: Vec::new(),
            exclude_origins: Vec::new(),
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogConfig {
    /// Log level override (for example `info` or `debug`).
    pub level: Option<String>,
}

/// A manually configured app: `/app/{name}` proxies to `127.0.0.1:{port}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// URL-safe name.
    pub name: String,
    /// Loopback port the app listens on.
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// The config file path: `<config_dir>/config.toml`, or `~/.raemote/config.toml`
/// when no directory is given.
pub fn config_path(config_dir: Option<&Path>) -> Result<PathBuf> {
    let base = match config_dir {
        Some(dir) => dir.to_path_buf(),
        None => crate::identity::data_dir()?,
    };
    Ok(base.join("config.toml"))
}

/// Ensure the data directory exists and return it.
pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = crate::identity::ensure_data_dir()?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

/// Serialize `config` to `path` atomically (temp file + rename, mode `0600`).
pub fn save(config: &Config, path: &Path) -> Result<()> {
    let content = toml::to_string_pretty(config)
        .context("failed to serialize config")?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &content)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    crate::identity::restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Load the config at `path`, applying `RAEMOTE_*` overrides. A missing file
/// yields [`Config::default`].
pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: Config = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    env_override(&mut config);
    Ok(config)
}

/// Reload config from disk, preserving the original `loaded_from` path.
pub fn reload(path: &Path) -> Result<Config> {
    let mut config = load(path)?;
    config.identity.key_path = None; // ensure loaded_from stays consistent
    Ok(config)
}

/// Load config for the CLI: from disk + env overrides, or generate a default.
pub fn load_or_init(path: &Path) -> Result<Config> {
    if path.exists() {
        load(path)
    } else {
        Ok(Config::default())
    }
}

// ---------------------------------------------------------------------------
// Env overrides
// ---------------------------------------------------------------------------

fn env_override(config: &mut Config) {
    override_from_env(&mut config.bind.token_ttl_secs, "RAEMOTE_BIND_TTL_SECS");
    if let Ok(token) = std::env::var("RAEMOTE_BIND_TOKEN")
        && !token.trim().is_empty()
    {
        config.bind.token = Some(token);
    }
    override_from_env(&mut config.bind.max_failed_attempts, "RAEMOTE_BIND_MAX_ATTEMPTS");
    override_from_env(
        &mut config.bind.max_concurrent_connections,
        "RAEMOTE_MAX_BIND_CONNECTIONS",
    );
    override_from_env(&mut config.bind.allow_invites, "RAEMOTE_BIND_ALLOW_INVITES");
    override_from_env(
        &mut config.bind.invite_ttl_secs,
        "RAEMOTE_BIND_INVITE_TTL_SECS",
    );
    override_from_env(
        &mut config.bind.max_pending_invites,
        "RAEMOTE_BIND_MAX_INVITES",
    );
    override_from_env(
        &mut config.serve.max_concurrent_streams,
        "RAEMOTE_MAX_CONCURRENT_STREAMS",
    );
    override_from_env(&mut config.serve.rate_limit.refill, "RAEMOTE_RATE_LIMIT_REFILL");
    override_from_env(
        &mut config.serve.rate_limit.interval_ms,
        "RAEMOTE_RATE_LIMIT_INTERVAL_MS",
    );
    override_from_env(&mut config.serve.rate_limit.max, "RAEMOTE_RATE_LIMIT_MAX");
    override_from_env(&mut config.discovery.enabled, "RAEMOTE_DISCOVERY_ENABLED");
    override_from_env(&mut config.discovery.interval_secs, "RAEMOTE_DISCOVERY_INTERVAL_SECS");
    override_from_env(
        &mut config.discovery.probe_timeout_ms,
        "RAEMOTE_DISCOVERY_PROBE_TIMEOUT_MS",
    );
    override_from_env(
        &mut config.discovery.max_concurrent_probes,
        "RAEMOTE_DISCOVERY_MAX_CONCURRENT_PROBES",
    );
    // RUST_LOG is handled by tracing-subscriber EnvFilter, not stored in config.
}

/// Apply an environment override if the variable is set and parses.
fn override_from_env<T: std::str::FromStr>(val: &mut T, key: &str) {
    if let Some(parsed) = std::env::var(key).ok().and_then(|s| s.parse::<T>().ok()) {
        *val = parsed;
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the config, returning an error that lists every problem found.
pub fn validate(config: &Config) -> Result<()> {
    let mut errors = Vec::new();

    if config.bind.token_ttl_secs == 0 {
        errors.push("bind.token_ttl_secs must be > 0".into());
    }
    if let Some(token) = &config.bind.token
        && token.trim().len() < 16
    {
        errors.push("bind.token must be at least 16 characters".into());
    }
    if config.bind.max_failed_attempts == 0 {
        errors.push("bind.max_failed_attempts must be > 0".into());
    }
    if config.bind.max_concurrent_connections == 0 {
        errors.push("bind.max_concurrent_connections must be > 0".into());
    }
    if config.bind.invite_ttl_secs == 0 {
        errors.push("bind.invite_ttl_secs must be > 0".into());
    }
    if config.bind.max_pending_invites == 0 {
        errors.push("bind.max_pending_invites must be > 0".into());
    }
    if config.serve.max_concurrent_streams == 0 {
        errors.push("serve.max_concurrent_streams must be > 0".into());
    }
    if config.serve.rate_limit.refill == 0 {
        errors.push("serve.rate_limit.refill must be > 0".into());
    }
    if config.serve.rate_limit.interval_ms == 0 {
        errors.push("serve.rate_limit.interval_ms must be > 0".into());
    }
    if config.serve.rate_limit.max == 0 {
        errors.push("serve.rate_limit.max must be > 0".into());
    }
    if config.discovery.interval_secs == 0 {
        errors.push("discovery.interval_secs must be > 0".into());
    }
    if config.discovery.recheck_secs == 0 {
        errors.push("discovery.recheck_secs must be > 0".into());
    }
    if config.discovery.probe_timeout_ms == 0 {
        errors.push("discovery.probe_timeout_ms must be > 0".into());
    }
    if config.discovery.max_concurrent_probes == 0 {
        errors.push("discovery.max_concurrent_probes must be > 0".into());
    }

    let mut names = std::collections::HashSet::new();
    for app in &config.apps {
        if !names.insert(&app.name) {
            errors.push(format!("duplicate app name: {}", app.name));
        }
        if app.port == 0 {
            errors.push(format!("app '{}' port must be > 0", app.name));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("config validation failed:\n  {}", errors.join("\n  ")))
    }
}

// ---------------------------------------------------------------------------
// TOML templates (for CLI init)
// ---------------------------------------------------------------------------

/// A commented default configuration file, used by `raemote config init`.
pub fn default_toml() -> &'static str {
    r#"# raemote server configuration
# See https://github.com/raemote/raemote_cli for documentation.

# Name this server shows to your paired phones (defaults to the hostname).
# name = "my-server"

[identity]
# key_path = "~/.raemote/secret.key"

[network]
# relay_url = ""
# proxy = "http://127.0.0.1:10808"   # outbound HTTP CONNECT proxy; falls back to ALL_PROXY/HTTP(S)_PROXY

[bind]
token_ttl_secs = 300
max_failed_attempts = 10
max_concurrent_connections = 50
# Allow an already-paired device to invite another device (one-time link).
allow_invites = true
# Lifetime of a one-time invitation, and how many can be outstanding.
invite_ttl_secs = 300
max_pending_invites = 3
# Fixed pairing token (optional). When set, the pairing link is stable across
# restarts and lives as long as token_ttl_secs. Treat it as a long-lived secret.
# token = "0123456789abcdef... (64+ random hex chars)"
# token_ttl_secs = 3153600000   # ~100 years (clamped) for an effectively permanent link

[serve]
max_concurrent_streams = 100

[serve.rate_limit]
refill = 100
interval_ms = 1000
max = 1000

[discovery]
enabled = true
interval_secs = 30
recheck_secs = 300
probe_timeout_ms = 400
max_concurrent_probes = 16
min_port = 1024
http_probe = true
https_probe = false
loopback_only = true
# Also pick up listeners owned by another user (e.g. a root-owned nginx).
include_unattributed = true
exclude_ports = []
exclude_processes = []
exclude_origins = []

[log]
# level = "info"

# [[apps]]
# name = "my_app"
# port = 3000
"#
}

/// The name this server presents to paired devices.
///
/// A configured `name` wins; otherwise the machine hostname; otherwise
/// `raemote-server`.
pub fn server_name(cfg: &Config) -> String {
    if let Some(name) = cfg
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        return name.to_string();
    }
    hostname().unwrap_or_else(|| "raemote-server".to_string())
}

/// The machine hostname, or `None` if it cannot be determined.
fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is valid and writable for `buf.len()` bytes.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
        if name.is_empty() {
            return None;
        }
        // Drop a trailing `.local` for a friendlier default.
        Some(name.strip_suffix(".local").unwrap_or(&name).to_string())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate process-global environment variables, which
    /// otherwise race when the test harness runs them in parallel.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn default_config_valid() {
        let config = Config::default();
        validate(&config).unwrap();
    }

    #[test]
    fn env_override_applied() {
        let _guard = env_guard();
        // SAFETY: guarded by ENV_LOCK, no concurrent env access
        unsafe {
            std::env::set_var("RAEMOTE_BIND_TTL_SECS", "123");
        }
        let mut config = Config::default();
        env_override(&mut config);
        assert_eq!(config.bind.token_ttl_secs, 123);
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::remove_var("RAEMOTE_BIND_TTL_SECS");
        }
    }

    #[test]
    fn env_override_invalid_ignored() {
        let _guard = env_guard();
        // SAFETY: guarded by ENV_LOCK, no concurrent env access
        unsafe {
            std::env::set_var("RAEMOTE_BIND_TTL_SECS", "not_a_number");
        }
        let mut config = Config::default();
        env_override(&mut config);
        assert_eq!(config.bind.token_ttl_secs, 300);
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::remove_var("RAEMOTE_BIND_TTL_SECS");
        }
    }

    #[test]
    fn roundtrip_toml() {
        let original = Config::default();
        let toml_str = toml::to_string_pretty(&original).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(original.bind.token_ttl_secs, parsed.bind.token_ttl_secs);
        assert_eq!(original.serve.max_concurrent_streams, parsed.serve.max_concurrent_streams);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = Config::default();
        save(&config, &path).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(config.bind.token_ttl_secs, loaded.bind.token_ttl_secs);
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        let config = load(&path).unwrap();
        assert_eq!(config.bind.token_ttl_secs, 300);
    }

    #[test]
    fn validation_rejects_zero_ttl() {
        let mut config = Config::default();
        config.bind.token_ttl_secs = 0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_app_names() {
        let mut config = Config::default();
        config.apps.push(AppConfig { name: "a".into(), port: 1000 });
        config.apps.push(AppConfig { name: "a".into(), port: 2000 });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validation_accepts_config_with_apps() {
        let mut config = Config::default();
        config.apps.push(AppConfig { name: "web".into(), port: 3000 });
        config.apps.push(AppConfig { name: "api".into(), port: 8080 });
        validate(&config).unwrap();
    }

    #[test]
    fn default_toml_is_parseable() {
        let toml_str = default_toml();
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.bind.token_ttl_secs, 300);
    }

    #[test]
    fn server_name_prefers_config_then_falls_back() {
        let cfg = Config {
            name: Some("  My Server  ".to_string()),
            ..Default::default()
        };
        assert_eq!(server_name(&cfg), "My Server");

        // Blank config values fall back to a non-empty resolved name.
        let blank = Config {
            name: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(!server_name(&blank).trim().is_empty());
    }

    #[test]
    fn bind_token_env_override() {
        let _guard = env_guard();
        // SAFETY: guarded by ENV_LOCK, no concurrent env access
        unsafe {
            std::env::set_var("RAEMOTE_BIND_TOKEN", "0123456789abcdef");
        }
        let mut config = Config::default();
        env_override(&mut config);
        assert_eq!(config.bind.token.as_deref(), Some("0123456789abcdef"));
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::remove_var("RAEMOTE_BIND_TOKEN");
        }
    }

    #[test]
    fn validation_rejects_short_fixed_token() {
        let mut config = Config::default();
        config.bind.token = Some("short".into());
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validation_accepts_long_fixed_token() {
        let mut config = Config::default();
        config.bind.token = Some("0123456789abcdef0123456789abcdef".into());
        validate(&config).unwrap();
    }

    #[test]
    fn discovery_defaults() {
        let config = Config::default();
        assert!(config.discovery.enabled);
        assert_eq!(config.discovery.interval_secs, 30);
        assert_eq!(config.discovery.recheck_secs, 300);
        assert_eq!(config.discovery.probe_timeout_ms, 400);
        assert_eq!(config.discovery.max_concurrent_probes, 16);
        assert_eq!(config.discovery.min_port, 1024);
        assert!(config.discovery.loopback_only);
        assert!(!config.discovery.https_probe);
        assert!(config.discovery.exclude_ports.is_empty());
    }

    #[test]
    fn discovery_env_override() {
        let _guard = env_guard();
        // SAFETY: guarded by ENV_LOCK, no concurrent env access
        unsafe {
            std::env::set_var("RAEMOTE_DISCOVERY_ENABLED", "false");
            std::env::set_var("RAEMOTE_DISCOVERY_INTERVAL_SECS", "45");
        }
        let mut config = Config::default();
        env_override(&mut config);
        assert!(!config.discovery.enabled);
        assert_eq!(config.discovery.interval_secs, 45);
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::remove_var("RAEMOTE_DISCOVERY_ENABLED");
            std::env::remove_var("RAEMOTE_DISCOVERY_INTERVAL_SECS");
        }
    }

    #[test]
    fn validation_rejects_zero_discovery_interval() {
        let mut config = Config::default();
        config.discovery.interval_secs = 0;
        assert!(validate(&config).is_err());
    }
}
