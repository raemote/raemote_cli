//! Local IPC between the CLI and a running daemon.
//!
//! The daemon listens on a Unix socket and speaks newline-delimited JSON after
//! a `Hello` handshake authenticated by a per-process token (see
//! [`DaemonInfo`]).

pub mod unix;

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// IPC request from CLI to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Authenticate with the IPC secret.
    Hello {
        /// The IPC secret from `daemon.json`.
        token: String,
    },
    /// Get daemon status.
    Status,
    /// Get the current binding token URI.
    GetToken,
    /// Mint a fresh binding token and return its URI.
    RefreshToken {
        /// Override the configured token lifetime (seconds).
        ttl_secs: Option<u64>,
    },
    /// Reload config from disk.
    Reload,
    /// List authorized node IDs.
    ListAuthorized,
    /// Revoke a previously authorized device by node id.
    RevokeAuthorized {
        /// The device node id to revoke.
        node_id: String,
    },
    /// Set (or clear) the display name of an authorized device.
    RenameAuthorized {
        /// The device node id.
        node_id: String,
        /// The new name; empty clears it.
        name: String,
    },
    /// List the merged catalog (manual + discovered apps).
    ListApps,
    /// Trigger a discovery scan and return the resulting catalog.
    DiscoverNow,
    /// Trigger a discovery scan and return the catalog plus why listening
    /// sockets were skipped (`raemote discover --verbose`).
    DiscoverReport,
    /// Shut down the daemon.
    Shutdown,
}

/// IPC response from daemon to CLI.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Authentication accepted.
    Ok,
    /// Authentication rejected.
    Denied,
    /// Error message.
    Error(String),
    /// Daemon status.
    Status(StatusResponse),
    /// Token info.
    Token(TokenResponse),
    /// Authorized devices with resolved display names.
    Devices(Vec<DeviceInfo>),
    /// Reload result.
    Reload(ReloadResponse),
    /// Merged catalog apps.
    Apps(Vec<AppInfoResponse>),
    /// Merged catalog apps plus the discovery skip report.
    DiscoverReport(DiscoverReportResponse),
}

/// Daemon status, returned for [`Request::Status`].
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// The server's display name (configured, else the hostname).
    pub name: String,
    /// The server's iroh node id (hex).
    pub node_id: String,
    /// Seconds the daemon has been running.
    pub uptime_secs: u64,
    /// Path to the config file in use.
    pub config_path: String,
    /// Number of authorized devices.
    pub authorized_count: usize,
    /// Number of discovered (non-manual) apps.
    pub discovered_count: usize,
    /// Unix expiry of the active pairing token, if any.
    pub token_expires_at_unix: Option<u64>,
    /// TTL of the active pairing token, in seconds, if any.
    pub token_ttl_secs: Option<u64>,
    /// Number of live serve connections (authorized devices currently connected).
    pub active_connections: usize,
    /// Relay URLs the endpoint is configured to use.
    pub relay_urls: Vec<String>,
    /// Local socket addresses the endpoint is bound to.
    pub bound_sockets: Vec<String>,
}

/// Result of [`Request::DiscoverReport`]: the catalog, plus what was skipped.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoverReportResponse {
    /// The merged catalog, as [`AppInfoResponse`]s.
    pub apps: Vec<AppInfoResponse>,
    /// Listening sockets that did not become apps, with the reason.
    pub skipped: Vec<crate::discovery::listener::Skipped>,
}

/// A catalog entry, returned by [`Request::ListApps`] and [`Request::DiscoverNow`].
#[derive(Debug, Serialize, Deserialize)]
pub struct AppInfoResponse {
    /// URL-safe app name.
    pub name: String,
    /// Catalog host.
    pub host: String,
    /// Catalog port.
    pub port: u16,
    /// Scheme (`http`).
    pub scheme: String,
    /// `manual` or `discovered`.
    pub source: String,
    /// Page title, when known.
    pub title: Option<String>,
    /// Same-origin path of the app's declared icon, when known.
    pub icon: Option<String>,
    /// Owning process name, when known.
    pub process: Option<String>,
}

/// A paired device and its display name, returned by
/// [`Request::ListAuthorized`].
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The device node id (hex).
    pub node_id: String,
    /// Human-readable name (`device-<hex>` when the device has no name).
    pub name: String,
}

/// Pairing token details, returned by [`Request::GetToken`] and
/// [`Request::RefreshToken`].
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The QR-ready `raemote://bind?...` URI.
    pub uri: String,
    /// Unix expiry of the token.
    pub expires_at_unix: u64,
}

/// Result of [`Request::Reload`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ReloadResponse {
    /// Whether the new config was applied.
    pub applied: bool,
    /// Config fields whose changes require a restart.
    pub restart_required: Vec<String>,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Path to `~/.raemote/daemon.json` (the daemon's metadata file).
pub fn daemon_json_path() -> Result<PathBuf> {
    let dir = crate::identity::data_dir()?;
    Ok(dir.join("daemon.json"))
}

/// Path to `~/.raemote/daemon.sock` (the IPC socket).
pub fn socket_path() -> Result<PathBuf> {
    let dir = crate::identity::data_dir()?;
    Ok(dir.join("daemon.sock"))
}

// ---------------------------------------------------------------------------
// Daemon JSON metadata
// ---------------------------------------------------------------------------

/// Metadata a running daemon writes to `~/.raemote/daemon.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonInfo {
    /// Daemon process id.
    pub pid: u32,
    /// Unix start time.
    pub started_at_unix: u64,
    /// IPC socket path.
    pub socket_path: PathBuf,
    /// Per-process secret used for the IPC `Hello` handshake.
    pub ipc_token: String,
    /// Daemon version.
    pub version: String,
}

/// Write [`DaemonInfo`] atomically (temp file + rename, mode `0600`).
pub fn write_daemon_json(path: &Path, info: &DaemonInfo) -> Result<()> {
    let content = serde_json::to_string_pretty(info)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &content)?;
    crate::identity::restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read [`DaemonInfo`] from `path`.
pub fn read_daemon_json(path: &Path) -> Result<DaemonInfo> {
    let content = std::fs::read_to_string(path)?;
    let info: DaemonInfo = serde_json::from_str(&content)?;
    Ok(info)
}

/// Best-effort removal of `daemon.json` (called on shutdown).
pub fn remove_daemon_json(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.json");
        let info = DaemonInfo {
            pid: 12345,
            started_at_unix: 1700000000,
            socket_path: PathBuf::from("/tmp/test.sock"),
            ipc_token: "abc123".to_string(),
            version: "0.1.0".to_string(),
        };
        write_daemon_json(&path, &info).unwrap();
        let loaded = read_daemon_json(&path).unwrap();
        assert_eq!(loaded.pid, 12345);
        assert_eq!(loaded.ipc_token, "abc123");
    }

    #[test]
    fn daemon_json_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        assert!(read_daemon_json(&path).is_err());
    }
}
