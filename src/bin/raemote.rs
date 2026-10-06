use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use raemote::config::{self, AppConfig};
use raemote::discovery::listener::Skipped;
use raemote::discovery::model::Origin;
use raemote::ipc::{self, AppInfoResponse, Request, Response, StatusResponse};
use raemote::ipc::unix::IpcClient;

#[derive(Parser)]
#[command(name = "raemote", version, about = "raemote management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status
    Status {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Reload daemon configuration
    Reload,
    /// Pair a phone: show the pairing link and QR code
    #[command(alias = "qr")]
    Pair {
        /// Show the current link without minting a new one
        #[arg(long)]
        no_refresh: bool,
        /// Print machine-readable JSON (skips the QR graphic)
        #[arg(long)]
        json: bool,
        /// Lifetime of the newly minted link in seconds (overrides config)
        #[arg(long, value_name = "SECS")]
        ttl: Option<u64>,
    },
    /// Pair with a server and browse its apps in a local web UI
    Connect {
        /// `raemote://bind?…` pairing URI, or the node id of a paired server
        /// (defaults to the last server this command used)
        target: Option<String>,
        /// Local port for the web UI
        #[arg(long, default_value_t = raemote::connector::DEFAULT_PORT)]
        port: u16,
        /// Print the URL without opening a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Manage paired devices
    #[command(alias = "authorized")]
    Devices {
        #[command(subcommand)]
        command: DevicesCommands,
    },
    /// Manage the daemon service
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    /// Start the daemon
    Start,
    /// Stop the daemon
    Stop,
    /// Restart the daemon
    Restart,
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// App management
    Apps {
        #[command(subcommand)]
        command: AppsCommands,
    },
    /// Run a discovery scan and list the resulting apps
    Discover {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Also list the listening sockets that were skipped, and why
        #[arg(long)]
        verbose: bool,
    },
    /// Show the daemon log
    Logs {
        /// Number of trailing lines to show
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
        /// Keep printing new lines as they are written
        #[arg(short, long)]
        follow: bool,
    },
    /// Check the daemon, configuration, and connectivity
    Doctor {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Show extra detail (all relays and sockets)
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum DevicesCommands {
    /// List paired devices
    List {
        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Rename a paired device (display only)
    Rename {
        /// The device node id
        node_id: String,
        /// The new name (use "" to clear it)
        name: String,
    },
    /// Revoke a device's access by its node id
    Revoke {
        /// The node id to revoke
        node_id: String,
    },
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Install the daemon as a system service
    Install,
    /// Uninstall the daemon service
    Uninstall,
    /// Show service status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Get a configuration value
    Get { key: String },
    /// Set a configuration value
    Set { key: String, value: String },
    /// Open config in editor
    Edit,
    /// Initialize default config file
    Init,
    /// Show config file path
    Path,
}

#[derive(Subcommand)]
enum AppsCommands {
    /// List configured apps
    List,
    /// Add an app
    Add {
        /// App name
        name: String,
        /// Port number
        port: u16,
    },
    /// Remove an app
    Remove {
        /// App name
        name: String,
    },
    /// Hide a discovered app (by name or host:port) from the catalog
    Hide {
        /// App name, host:port, or a bare loopback port
        target: String,
    },
    /// Unhide a previously hidden origin
    Unhide {
        /// host:port or a bare loopback port
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { json } => cmd_status(json).await,
        Commands::Reload => cmd_reload().await,
        Commands::Pair { no_refresh, json, ttl } => cmd_pair(no_refresh, json, ttl).await,
        Commands::Connect { target, port, no_open } => {
            raemote::connector::run(target.as_deref(), port, !no_open).await
        }
        Commands::Devices { command } => match command {
            DevicesCommands::List { json } => cmd_devices_list(json).await,
            DevicesCommands::Rename { node_id, name } => cmd_devices_rename(&node_id, &name).await,
            DevicesCommands::Revoke { node_id } => cmd_devices_revoke(&node_id).await,
        },
        Commands::Service { command } => match command {
            ServiceCommands::Install => cmd_service_install(),
            ServiceCommands::Uninstall => cmd_service_uninstall(),
            ServiceCommands::Status => cmd_service_status(),
        },
        Commands::Start => cmd_start(),
        Commands::Stop => cmd_stop().await,
        Commands::Restart => cmd_restart().await,
        Commands::Config { command } => match command {
            ConfigCommands::Show => cmd_config_show(),
            ConfigCommands::Get { key } => cmd_config_get(&key),
            ConfigCommands::Set { key, value } => cmd_config_set(&key, &value).await,
            ConfigCommands::Edit => cmd_config_edit(),
            ConfigCommands::Init => cmd_config_init(),
            ConfigCommands::Path => cmd_config_path(),
        },
        Commands::Apps { command } => match command {
            AppsCommands::List => cmd_apps_list().await,
            AppsCommands::Add { name, port } => cmd_apps_add(&name, port).await,
            AppsCommands::Remove { name } => cmd_apps_remove(&name).await,
            AppsCommands::Hide { target } => cmd_apps_hide(&target).await,
            AppsCommands::Unhide { target } => cmd_apps_unhide(&target).await,
        },
        Commands::Discover { json, verbose } => cmd_discover(json, verbose).await,
        Commands::Logs { lines, follow } => cmd_logs(lines, follow).await,
        Commands::Doctor { json, verbose } => cmd_doctor(json, verbose).await,
    }
}

// ---------------------------------------------------------------------------
// IPC helpers
// ---------------------------------------------------------------------------

fn load_ipc_token() -> Result<String> {
    let path = ipc::daemon_json_path()?;
    let info = ipc::read_daemon_json(&path)
        .with_context(|| "daemon not running (no daemon.json found)")?;
    Ok(info.ipc_token)
}

/// Whether a live daemon is reachable. `daemon.json` can be left behind by a
/// daemon that died without cleanup, so verify the IPC socket actually accepts
/// a connection rather than trusting the file's existence.
fn daemon_running() -> bool {
    let path = match ipc::daemon_json_path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if ipc::read_daemon_json(&path).is_err() {
        return false;
    }
    let socket = match ipc::socket_path() {
        Ok(s) => s,
        Err(_) => return false,
    };
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(&socket).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        true
    }
}

async fn ipc_request(req: Request) -> Result<Response> {
    let token = load_ipc_token()?;
    let socket = ipc::socket_path()?;
    let mut client = IpcClient::connect(&socket, &token).await?;
    client.request(req).await
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async fn cmd_status(json: bool) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    match ipc_request(Request::Status).await? {
        Response::Status(s) => {
            if json {
                println!("{}", serde_json::to_string(&s)?);
                return Ok(());
            }
            println!("name       : {}", s.name);
            println!("node id    : {}", s.node_id);
            println!("uptime     : {}s", s.uptime_secs);
            println!("config     : {}", s.config_path);
            println!("paired     : {} device(s)", s.authorized_count);
            println!("connected  : {} live connection(s)", s.active_connections);
            println!("limiters   : {} cached (one per connected device)", s.cached_limiters);
            println!("discovered : {} app(s)", s.discovered_count);
            match s.token_expires_at_unix {
                Some(exp) if exp > unix_now() => {
                    println!("pairing    : expires in {}", humanize_duration(exp - unix_now()))
                }
                _ => println!("pairing    : no active token (run `raemote pair`)"),
            }
            if let Some(relay) = s.relay_urls.first() {
                println!("relay      : {relay}");
            }
            Ok(())
        }
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

async fn cmd_reload() -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    // First, write the current config to disk (in case CLI modified it).
    let config_path = config::config_path(None)?;
    let cfg = config::load(&config_path)?;
    config::validate(&cfg)?;

    match ipc_request(Request::Reload).await? {
        Response::Reload(r) => {
            if r.applied {
                println!("config reloaded");
                if !r.restart_required.is_empty() {
                    println!("restart required for: {}", r.restart_required.join(", "));
                }
            } else {
                eprintln!("reload failed");
            }
            Ok(())
        }
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

/// Current unix time in whole seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Humanize a duration in seconds (for example `45s`, `4m 58s`, `3h 12m`, `42d`).
fn humanize_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs < 31_536_000 {
        format!("{}d", secs / 86_400)
    } else {
        format!("~{:.1} years", secs as f64 / 31_536_000.0)
    }
}

async fn cmd_pair(no_refresh: bool, json: bool, ttl: Option<u64>) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    let req = if no_refresh {
        Request::GetToken
    } else {
        Request::RefreshToken { ttl_secs: ttl }
    };
    match ipc_request(req).await? {
        Response::Token(t) => {
            if json {
                println!("{}", serde_json::to_string(&t)?);
                return Ok(());
            }

            let now = unix_now();
            let remaining = t.expires_at_unix.saturating_sub(now);

            println!("link    : {}", t.uri);
            if remaining == 0 {
                println!("expires : already expired — run `raemote pair` to mint a new one");
            } else {
                println!(
                    "expires : in {} (unix {})",
                    humanize_duration(remaining),
                    t.expires_at_unix
                );
            }
            println!("note    : one link can pair more than one device until it expires");

            // Render QR code
            match qrcode::QrCode::new(t.uri.as_bytes()) {
                Ok(code) => {
                    let qr = code
                        .render::<qrcode::render::unicode::Dense1x2>()
                        .quiet_zone(true)
                        .build();
                    println!("\n{qr}");
                }
                Err(e) => println!("\n(could not render QR code: {e})"),
            }
            println!("In the Raemote app, tap +, then scan the code above or paste the link.");
            Ok(())
        }
        Response::Error(message) => Err(anyhow::anyhow!("{message}")),
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

async fn cmd_devices_list(json: bool) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    match ipc_request(Request::ListAuthorized).await? {
        Response::Devices(devices) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
                return Ok(());
            }
            if devices.is_empty() {
                println!("no paired devices yet");
                println!("Pair one with `raemote pair`.");
            } else {
                println!("{} paired device(s):", devices.len());
                for device in &devices {
                    println!("  {:<24} {}", device.name, device.node_id);
                }
            }
            Ok(())
        }
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

async fn cmd_devices_rename(node_id: &str, name: &str) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return Err(anyhow::anyhow!("no node id given"));
    }
    let request = Request::RenameAuthorized {
        node_id: node_id.to_string(),
        name: name.to_string(),
    };
    match ipc_request(request).await? {
        Response::Ok => {
            if name.trim().is_empty() {
                println!("cleared the name of {node_id}");
            } else {
                println!("renamed {node_id} to \"{}\"", name.trim());
            }
            Ok(())
        }
        Response::Error(message) => Err(anyhow::anyhow!("{message}")),
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

async fn cmd_devices_revoke(node_id: &str) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return Err(anyhow::anyhow!("no node id given"));
    }
    let request = Request::RevokeAuthorized {
        node_id: node_id.to_string(),
    };
    match ipc_request(request).await? {
        Response::Ok => {
            println!("revoked device {node_id}");
            Ok(())
        }
        Response::Error(message) => Err(anyhow::anyhow!("{message}")),
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

/// Show the daemon log, optionally following it.
async fn cmd_logs(lines: usize, follow: bool) -> Result<()> {
    let dir = raemote::identity::data_dir()?;
    let Some(path) = raemote::logs::latest_log_file(&dir) else {
        eprintln!("no daemon log yet in {}", dir.display());
        return Ok(());
    };

    for line in raemote::logs::tail_lines(&path, lines)? {
        println!("{line}");
    }

    if follow {
        follow_log(&dir).await?;
    }
    Ok(())
}

/// Follow the newest daemon log, switching files if it rotates.
async fn follow_log(dir: &std::path::Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut current: Option<std::path::PathBuf> = None;
    let mut offset: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let Some(path) = raemote::logs::latest_log_file(dir) else {
            continue;
        };
        if current.as_deref() != Some(path.as_path()) {
            // A new file appeared (rotation): start from its beginning.
            current = Some(path.clone());
            offset = 0;
        }
        let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) else {
            continue;
        };
        if len < offset {
            // File was truncated/replaced.
            offset = 0;
        }
        if len == offset {
            continue;
        }
        let Ok(mut file) = std::fs::File::open(&path) else {
            continue;
        };
        if file.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_ok() {
            let text = String::from_utf8_lossy(&buf);
            print!("{}", raemote::logs::strip_ansi(&text));
            let _ = std::io::stdout().flush();
        }
        offset = len;
    }
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Result of a single health check.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

/// A single health check.
#[derive(serde::Serialize)]
struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

impl Check {
    fn new(name: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.into(),
            hint: None,
        }
    }
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Ok, detail)
    }
    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Warn, detail)
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Fail, detail)
    }
    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// The unix permission bits of a path, or `None` if it cannot be stat'd.
#[cfg(unix)]
fn file_mode(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

/// Resolve and TCP-connect to a URL's host and port; returns the address that
/// answered. Used for relay and proxy reachability.
async fn probe_tcp_url(url_str: &str, timeout: Duration) -> Result<String> {
    let parsed = url::Url::parse(url_str).with_context(|| format!("invalid URL: {url_str}"))?;
    let host = parsed.host_str().context("URL has no host")?.to_string();
    let port = parsed.port_or_known_default().context("URL has no port")?;

    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("could not resolve {host}"))?;

    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(addr.to_string()),
            Ok(Err(e)) => last_err = Some(e.to_string()),
            Err(_) => last_err = Some(format!("timed out after {}s", timeout.as_secs())),
        }
    }
    Err(anyhow::anyhow!(
        last_err.unwrap_or_else(|| "no addresses resolved".into())
    ))
}

async fn cmd_doctor(json: bool, verbose: bool) -> Result<()> {
    let mut checks: Vec<Check> = Vec::new();
    let mut status: Option<StatusResponse> = None;

    // The configured outbound proxy, if any (changes what "reachable" means).
    let proxy: Option<String> = config::config_path(None)
        .ok()
        .and_then(|p| config::load(&p).ok())
        .and_then(|c| c.network.proxy);

    // Daemon reachability (also gives us the counts used below).
    if daemon_running() {
        match ipc_request(Request::Status).await? {
            Response::Status(s) => {
                checks.push(Check::ok("daemon", "running"));
                status = Some(s);
            }
            other => checks.push(Check::fail("daemon", format!("unexpected response: {other:?}"))),
        }
    } else {
        checks.push(
            Check::fail("daemon", "not running").with_hint(
                "start it with `raemote start`, or install the service: `raemote service install`",
            ),
        );
    }

    // Data directory + identity key.
    match raemote::identity::data_dir() {
        Ok(dir) if dir.exists() => {
            #[cfg(unix)]
            match file_mode(&dir) {
                Some(0o700) => {
                    checks.push(Check::ok("data dir", format!("{} (0700)", dir.display())))
                }
                Some(mode) => checks.push(
                    Check::warn(
                        "data dir",
                        format!("{} has mode {mode:o} (expected 0700)", dir.display()),
                    )
                    .with_hint(format!("chmod 700 {}", dir.display())),
                ),
                None => {
                    checks.push(Check::warn("data dir", format!("could not stat {}", dir.display())))
                }
            }
            #[cfg(not(unix))]
            checks.push(Check::ok("data dir", dir.display().to_string()));

            let key = dir.join("secret.key");
            if key.exists() {
                #[cfg(unix)]
                match file_mode(&key) {
                    Some(0o600) => checks.push(Check::ok("identity", "secret.key present (0600)")),
                    Some(mode) => checks.push(
                        Check::warn(
                            "identity",
                            format!("secret.key has mode {mode:o} (expected 0600)"),
                        )
                        .with_hint(format!("chmod 600 {}", key.display())),
                    ),
                    None => checks.push(Check::warn("identity", "could not stat secret.key")),
                }
                #[cfg(not(unix))]
                checks.push(Check::ok("identity", "secret.key present"));
            } else {
                checks.push(Check::ok("identity", "no key yet (created on first start)"));
            }
        }
        Ok(dir) => checks.push(
            Check::fail("data dir", format!("{} does not exist", dir.display()))
                .with_hint("run `raemote config init`"),
        ),
        Err(e) => checks.push(Check::fail("data dir", e.to_string())),
    }

    // Config file.
    match config::config_path(None) {
        Ok(path) if path.exists() => {
            match config::load(&path).and_then(|cfg| config::validate(&cfg).map(|_| cfg)) {
                Ok(_) => {
                    #[cfg(unix)]
                    let perm_note = match file_mode(&path) {
                        Some(0o600) | None => String::new(),
                        Some(mode) => format!(" (mode {mode:o}, expected 0600)"),
                    };
                    #[cfg(not(unix))]
                    let perm_note = String::new();

                    if perm_note.is_empty() {
                        checks.push(Check::ok("config", format!("{} is valid", path.display())));
                    } else {
                        checks.push(Check::warn(
                            "config",
                            format!("{}{perm_note}", path.display()),
                        ));
                    }
                }
                Err(e) => checks.push(
                    Check::fail("config", format!("invalid: {e}"))
                        .with_hint("edit it with `raemote config edit`"),
                ),
            }
        }
        Ok(path) => checks.push(
            Check::warn("config", format!("{} not found", path.display()))
                .with_hint("run `raemote config init`"),
        ),
        Err(e) => checks.push(Check::fail("config", e.to_string())),
    }

    // Service.
    if raemote::service::is_installed() {
        checks.push(Check::ok("service", "installed"));
    } else {
        checks.push(
            Check::warn("service", "not installed")
                .with_hint("install it so it starts at login: `raemote service install`"),
        );
    }

    // Daemon-derived checks.
    if let Some(s) = &status {
        if s.authorized_count == 0 {
            checks.push(
                Check::warn("paired devices", "none yet")
                    .with_hint("pair a phone with `raemote pair`"),
            );
        } else {
            checks.push(Check::ok(
                "paired devices",
                format!("{} device(s)", s.authorized_count),
            ));
        }

        checks.push(Check::ok(
            "connected",
            format!("{} live connection(s)", s.active_connections),
        ));

        checks.push(Check::ok(
            "device state",
            format!(
                "{} cached limiter(s) for {} paired device(s)",
                s.cached_limiters, s.authorized_count
            ),
        ));

        if s.discovered_count == 0 {
            checks.push(
                Check::warn("discovery", "no web apps found").with_hint(
                    "make sure your app is running on localhost, then run `raemote discover`",
                ),
            );
        } else {
            checks.push(Check::ok(
                "discovery",
                format!("{} app(s) found", s.discovered_count),
            ));
        }

        match s.token_expires_at_unix {
            Some(exp) if exp > unix_now() => checks.push(Check::ok(
                "pairing token",
                format!("active, expires in {}", humanize_duration(exp - unix_now())),
            )),
            _ => checks.push(Check::ok(
                "pairing token",
                "none active (mint one with `raemote pair`)",
            )),
        }

        // Outbound relay reachability. Skipped when a proxy is configured,
        // because the daemon reaches the relay through the proxy.
        if proxy.is_some() {
            checks.push(Check::ok(
                "relay",
                "direct probe skipped (outbound proxy configured)",
            ));
        } else {
            match s.relay_urls.first() {
                Some(relay) => match probe_tcp_url(relay, Duration::from_secs(3)).await {
                    Ok(addr) => checks.push(Check::ok("relay", format!("reachable via {addr}"))),
                    Err(e) => checks.push(
                        Check::fail("relay", format!("unreachable: {e}")).with_hint(
                            "if your network blocks iroh, set an outbound proxy: \
                             `raemote config set network.proxy http://host:port`",
                        ),
                    ),
                },
                None => checks.push(Check::warn("relay", "no relay URL configured")),
            }
        }
    }

    // Outbound proxy reachability, when configured.
    if let Some(proxy) = proxy.as_deref() {
        match probe_tcp_url(proxy, Duration::from_secs(3)).await {
            Ok(addr) => checks.push(Check::ok("proxy", format!("reachable via {addr}"))),
            Err(e) => checks.push(Check::fail("proxy", format!("unreachable: {e}"))),
        }
    }

    let failed = checks
        .iter()
        .filter(|c| matches!(c.status, CheckStatus::Fail))
        .count();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": failed == 0,
                "checks": &checks,
            }))?
        );
    } else {
        for c in &checks {
            let marker = match c.status {
                CheckStatus::Ok => "ok  ",
                CheckStatus::Warn => "warn",
                CheckStatus::Fail => "FAIL",
            };
            println!("[{marker}] {:<15} {}", c.name, c.detail);
            if let Some(hint) = &c.hint {
                println!("       {:<15} hint: {hint}", "");
            }
        }
        if verbose
            && let Some(s) = &status
        {
            println!();
            println!("relays  : {}", s.relay_urls.join(", "));
            println!("sockets : {}", s.bound_sockets.join(", "));
            println!("config  : {}", s.config_path);
        }
        println!();
        if failed == 0 {
            println!("all checks passed");
        } else {
            println!("{failed} check(s) failed");
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_service_install() -> Result<()> {
    // Detect platform
    #[cfg(target_os = "macos")]
    {
        raemote::service::launchd::install()
    }
    #[cfg(target_os = "linux")]
    {
        raemote::service::systemd::install()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow::anyhow!("service install is only supported on macOS and Linux"))
    }
}

fn cmd_service_uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        raemote::service::launchd::uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        raemote::service::systemd::uninstall()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow::anyhow!("service uninstall is only supported on macOS and Linux"))
    }
}

fn cmd_service_status() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        raemote::service::launchd::status()
    }
    #[cfg(target_os = "linux")]
    {
        raemote::service::systemd::status()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow::anyhow!("service status is only supported on macOS and Linux"))
    }
}

fn cmd_start() -> Result<()> {
    // Check if already running: either the IPC socket answers, or the instance
    // lock is held by a daemon whose socket isn't (e.g. still starting/hung).
    if daemon_running() || raemote::lock::is_held() {
        eprintln!("raemoted is already running");
        std::process::exit(1);
    }

    // Find the raemoted binary next to this CLI binary
    let exe = std::env::current_exe().context("failed to find current exe")?;
    let dir = exe.parent().context("failed to get exe parent")?;
    let raemoted = dir.join("raemoted");

    if !raemoted.exists() {
        eprintln!("raemoted not found at {}", raemoted.display());
        eprintln!("install raemoted or run it directly");
        std::process::exit(1);
    }

    // Spawn as a background process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&raemoted)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn()?;
        println!("daemon started (pid {})", err.id());
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let child = std::process::Command::new(&raemoted)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        println!("daemon started (pid {})", child.id());
        Ok(())
    }
}

async fn cmd_stop() -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    match ipc_request(Request::Shutdown).await? {
        Response::Ok => {
            println!("daemon stopped");
            Ok(())
        }
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

async fn cmd_restart() -> Result<()> {
    let _ = cmd_stop().await;
    // Wait a bit for the socket to be cleaned up
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cmd_start()
}

// ---------------------------------------------------------------------------
// Config commands
// ---------------------------------------------------------------------------

fn cmd_config_show() -> Result<()> {
    let path = config::config_path(None)?;
    let cfg = config::load(&path)?;
    let toml = toml::to_string_pretty(&cfg)?;
    print!("{toml}");
    Ok(())
}

fn cmd_config_get(key: &str) -> Result<()> {
    let path = config::config_path(None)?;
    let cfg = config::load(&path)?;
    let value = match key {
        "name" => Some(cfg.name.clone().unwrap_or_default()),
        "bind.token_ttl_secs" => Some(cfg.bind.token_ttl_secs.to_string()),
        "bind.max_failed_attempts" => Some(cfg.bind.max_failed_attempts.to_string()),
        "bind.max_concurrent_connections" => Some(cfg.bind.max_concurrent_connections.to_string()),
        "bind.allow_invites" => Some(cfg.bind.allow_invites.to_string()),
        "bind.invite_ttl_secs" => Some(cfg.bind.invite_ttl_secs.to_string()),
        "bind.max_pending_invites" => Some(cfg.bind.max_pending_invites.to_string()),
        "serve.max_concurrent_streams" => Some(cfg.serve.max_concurrent_streams.to_string()),
        "serve.rate_limit.refill" => Some(cfg.serve.rate_limit.refill.to_string()),
        "serve.rate_limit.interval_ms" => Some(cfg.serve.rate_limit.interval_ms.to_string()),
        "serve.rate_limit.max" => Some(cfg.serve.rate_limit.max.to_string()),
        "network.proxy" => Some(cfg.network.proxy.clone().unwrap_or_default()),
        "network.relay_url" => Some(cfg.network.relay_url.clone().unwrap_or_default()),
        "discovery.loopback_only" => Some(cfg.discovery.loopback_only.to_string()),
        "discovery.include_unattributed" => Some(cfg.discovery.include_unattributed.to_string()),
        _ => None,
    };
    match value {
        Some(v) => { println!("{v}"); Ok(()) }
        None => Err(anyhow::anyhow!("unknown key: {key}")),
    }
}

async fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    let path = config::config_path(None)?;
    let mut cfg = config::load(&path)?;
    match key {
        "name" => {
            cfg.name = (!value.trim().is_empty()).then(|| value.to_string());
        }
        "bind.token_ttl_secs" => {
            cfg.bind.token_ttl_secs = value.parse().context("invalid value")?;
        }
        "bind.max_failed_attempts" => {
            cfg.bind.max_failed_attempts = value.parse().context("invalid value")?;
        }
        "bind.max_concurrent_connections" => {
            cfg.bind.max_concurrent_connections = value.parse().context("invalid value")?;
        }
        "bind.allow_invites" => {
            cfg.bind.allow_invites = value.parse().context("invalid value")?;
        }
        "bind.invite_ttl_secs" => {
            cfg.bind.invite_ttl_secs = value.parse().context("invalid value")?;
        }
        "bind.max_pending_invites" => {
            cfg.bind.max_pending_invites = value.parse().context("invalid value")?;
        }
        "serve.max_concurrent_streams" => {
            cfg.serve.max_concurrent_streams = value.parse().context("invalid value")?;
        }
        "serve.rate_limit.refill" => {
            cfg.serve.rate_limit.refill = value.parse().context("invalid value")?;
        }
        "serve.rate_limit.interval_ms" => {
            cfg.serve.rate_limit.interval_ms = value.parse().context("invalid value")?;
        }
        "serve.rate_limit.max" => {
            cfg.serve.rate_limit.max = value.parse().context("invalid value")?;
        }
        "discovery.loopback_only" => {
            cfg.discovery.loopback_only = value.parse().context("invalid value")?;
        }
        "discovery.include_unattributed" => {
            cfg.discovery.include_unattributed = value.parse().context("invalid value")?;
        }
        "network.proxy" => {
            cfg.network.proxy = (!value.is_empty()).then(|| value.to_string());
        }
        "network.relay_url" => {
            cfg.network.relay_url = (!value.is_empty()).then(|| value.to_string());
        }
        _ => return Err(anyhow::anyhow!("unknown key: {key}")),
    }
    config::validate(&cfg)?;
    let dir = config::ensure_config_dir()?;
    let config_path = dir.join("config.toml");
    config::save(&cfg, &config_path)?;
    println!("set {key} = {value}");

    // Auto-reload if daemon is running
    if daemon_running()
        && let Ok(Response::Reload(r)) = ipc_request(Request::Reload).await
        && !r.restart_required.is_empty()
    {
        println!(
            "note: restart required for: {}",
            r.restart_required.join(", ")
        );
    }
    Ok(())
}

fn cmd_config_edit() -> Result<()> {
    let path = config::config_path(None)?;
    if !path.exists() {
        let dir = config::ensure_config_dir()?;
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, config::default_toml())?;
        raemote::identity::restrict(&config_path, 0o600);
    }
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .with_context(|| format!("failed to open editor: {editor}"))?;
    if !status.success() {
        eprintln!("editor exited with {status}");
    }
    Ok(())
}

fn cmd_config_init() -> Result<()> {
    let path = config::config_path(None)?;
    if path.exists() {
        eprintln!("config already exists at {}", path.display());
        eprintln!("delete it first or use `raemote config edit`");
        std::process::exit(1);
    }
    let dir = config::ensure_config_dir()?;
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, config::default_toml())?;
    raemote::identity::restrict(&config_path, 0o600);
    println!("wrote default config to {}", config_path.display());
    Ok(())
}

fn cmd_config_path() -> Result<()> {
    let path = config::config_path(None)?;
    println!("{}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Apps commands
// ---------------------------------------------------------------------------

async fn cmd_apps_list() -> Result<()> {
    // Prefer the daemon's merged catalog (manual + discovered).
    if daemon_running() {
        match ipc_request(Request::ListApps).await? {
            Response::Apps(apps) => {
                print_apps(&apps);
                return Ok(());
            }
            resp => return Err(anyhow::anyhow!("unexpected response: {resp:?}")),
        }
    }
    // Daemon down: show manual apps from config only.
    let path = config::config_path(None)?;
    let cfg = config::load(&path)?;
    if cfg.apps.is_empty() {
        println!("no apps configured (daemon not running)");
    } else {
        for app in &cfg.apps {
            println!("{:<24} {:<10} port={}", app.name, "manual", app.port);
        }
    }
    Ok(())
}

async fn cmd_discover(json: bool, verbose: bool) -> Result<()> {
    if !daemon_running() {
        eprintln!("daemon is not running");
        std::process::exit(1);
    }
    let request = if verbose {
        Request::DiscoverReport
    } else {
        Request::DiscoverNow
    };
    match ipc_request(request).await? {
        Response::Apps(apps) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&apps)?);
            } else {
                print_apps(&apps);
            }
            Ok(())
        }
        Response::DiscoverReport(report) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_apps(&report.apps);
                print_skipped(&report.skipped);
            }
            Ok(())
        }
        resp => Err(anyhow::anyhow!("unexpected response: {resp:?}")),
    }
}

/// Print why listening sockets did not become apps.
///
/// Sockets below `discovery.min_port` are included on purpose: "my app is on
/// port 80" is exactly the kind of thing this report is for.
fn print_skipped(skipped: &[Skipped]) {
    const LIMIT: usize = 50;

    if skipped.is_empty() {
        println!("nothing skipped: every listening socket became an app");
        return;
    }
    println!();
    println!("{} listening socket(s) skipped:", skipped.len());
    for entry in skipped.iter().take(LIMIT) {
        println!(
            "  {:<22} {:<16} {}",
            entry.origin,
            entry.process.as_deref().unwrap_or("-"),
            entry.reason.describe()
        );
    }
    if skipped.len() > LIMIT {
        println!("  ... and {} more", skipped.len() - LIMIT);
    }
}

fn print_apps(apps: &[AppInfoResponse]) {
    if apps.is_empty() {
        println!("no apps");
        return;
    }
    for app in apps {
        let title = app.title.as_deref().unwrap_or("-");
        let process = app.process.as_deref().unwrap_or("-");
        let icon = app.icon.as_deref().unwrap_or("-");
        println!(
            "{:<24} {:<10} {}://{}:{}  title={}  icon={}  process={}",
            app.name, app.source, app.scheme, app.host, app.port, title, icon, process
        );
    }
}

async fn cmd_apps_add(name: &str, port: u16) -> Result<()> {
    let path = config::config_path(None)?;
    let mut cfg = config::load(&path)?;
    if cfg.apps.iter().any(|a| a.name == name) {
        eprintln!("app '{name}' already exists");
        std::process::exit(1);
    }
    cfg.apps.push(AppConfig {
        name: name.to_string(),
        port,
    });
    config::validate(&cfg)?;
    save_and_wait(&cfg, |apps| apps.iter().any(|a| a.name == name)).await?;
    println!("added app {name} on port {port}");
    Ok(())
}

async fn cmd_apps_remove(name: &str) -> Result<()> {
    let path = config::config_path(None)?;
    let mut cfg = config::load(&path)?;
    let before = cfg.apps.len();
    cfg.apps.retain(|a| a.name != name);
    if cfg.apps.len() == before {
        eprintln!("app '{name}' not found");
        std::process::exit(1);
    }
    save_and_wait(&cfg, |apps| !apps.iter().any(|a| a.name == name)).await?;
    println!("removed app {name}");
    Ok(())
}

/// Resolve a CLI argument to an origin: `host:port`, a bare loopback port, or a
/// catalog app name.
async fn resolve_origin(target: &str) -> Result<Origin> {
    let target = target.trim();
    if let Some(origin) = Origin::parse_authority(target) {
        return Ok(origin);
    }
    if let Ok(port) = target.parse::<u16>() {
        return Ok(Origin::http("127.0.0.1", port));
    }

    if daemon_running() {
        if let Response::Apps(apps) = ipc_request(Request::ListApps).await?
            && let Some(app) = apps.iter().find(|a| a.name == target)
        {
            return Ok(Origin::http(app.host.clone(), app.port));
        }
    } else {
        let path = config::config_path(None)?;
        let cfg = config::load(&path)?;
        if cfg.apps.iter().any(|a| a.name == target) {
            return Err(anyhow::anyhow!(
                "'{target}' is a manual app; remove it with `raemote apps remove {target}`"
            ));
        }
    }
    Err(anyhow::anyhow!(
        "no app or origin named '{target}' (try `raemote apps list`)"
    ))
}

/// Persist a config change, then hot-reload the daemon and wait until the
/// catalog reflects it.
///
/// A plain reload only *triggers* a rescan, so an immediate `apps list` can
/// still be stale (and a scan already in flight may have started with the old
/// config). Polling until `check` passes gives deterministic CLI output.
async fn save_and_wait(cfg: &config::Config, check: impl Fn(&[AppInfoResponse]) -> bool) -> Result<()> {
    let dir = config::ensure_config_dir()?;
    config::save(cfg, &dir.join("config.toml"))?;
    if !daemon_running() {
        return Ok(());
    }

    let _ = ipc_request(Request::Reload).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        if let Ok(Response::Apps(apps)) = ipc_request(Request::ListApps).await
            && check(&apps)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn cmd_apps_hide(target: &str) -> Result<()> {
    let origin = resolve_origin(target).await?;
    let key = origin.authority();

    let path = config::config_path(None)?;
    let mut cfg = config::load(&path)?;
    let already = cfg.discovery.exclude_origins.iter().any(|s| {
        Origin::parse_authority(s)
            .map(|o| o.authority() == key)
            .unwrap_or(false)
    });
    if already {
        println!("already hidden: {key}");
        return Ok(());
    }

    cfg.discovery.exclude_origins.push(key.clone());
    let (host, port) = (origin.host.clone(), origin.port);
    save_and_wait(&cfg, |apps| {
        !apps.iter().any(|a| a.host == host && a.port == port)
    })
    .await?;
    println!("hid the app at {key}");
    Ok(())
}

async fn cmd_apps_unhide(target: &str) -> Result<()> {
    let origin = Origin::parse_authority(target)
        .or_else(|| {
            target
                .trim()
                .parse::<u16>()
                .ok()
                .map(|p| Origin::http("127.0.0.1", p))
        })
        .with_context(|| format!("'{target}' is not a host:port or port"))?;
    let key = origin.authority();

    let path = config::config_path(None)?;
    let mut cfg = config::load(&path)?;
    let before = cfg.discovery.exclude_origins.len();
    cfg.discovery.exclude_origins.retain(|s| {
        Origin::parse_authority(s)
            .map(|o| o.authority() != key)
            .unwrap_or(true)
    });
    if cfg.discovery.exclude_origins.len() == before {
        eprintln!("{key} was not hidden");
        std::process::exit(1);
    }

    let (host, port) = (origin.host.clone(), origin.port);
    save_and_wait(&cfg, |apps| {
        apps.iter().any(|a| a.host == host && a.port == port)
    })
    .await?;
    println!("unhid {key}");
    Ok(())
}
