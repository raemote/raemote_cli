//! The `raemoted` daemon: assembles the endpoint, protocol handlers, discovery
//! engine, and IPC server, then runs until shutdown.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use tokio::sync::{mpsc, Notify};
use tracing_subscriber::EnvFilter;

use crate::auth::{scope_from_ports, AuthState};
use crate::bind::{BindHandler, BIND_ALPN};
use crate::catalog::Catalog;
use crate::config::{self, Config};
use crate::discovery::{self, DiscoveryEngine};
use crate::http::{AppState, ServeHandler, SERVE_ALPN};
use crate::ipc::unix::IpcHandler;
use crate::ipc::{
    self, AppInfoResponse, DiscoverReportResponse, ReloadResponse, Request, Response,
    StatusResponse, TokenResponse,
};
use crate::qr::print_binding;
use crate::watchdog::{EndpointHandle, HealRequest, RelayActorSignal, RelayActorWedgeLayer};

/// How long `DiscoverNow` waits for a scan to complete.
const DISCOVER_NOW_TIMEOUT: Duration = Duration::from_secs(3);

/// Daemon state shared with the IPC handler.
#[derive(Clone)]
struct DaemonState {
    config: Arc<RwLock<Config>>,
    config_generation: Arc<AtomicU64>,
    catalog: Arc<RwLock<Catalog>>,
    catalog_generation: Arc<AtomicU64>,
    discovery_trigger: Arc<Notify>,
    auth: Arc<AuthState>,
    /// The live endpoint (replaced in place by the watchdog), shared so status
    /// always reports the running node.
    endpoints: EndpointHandle,
    active_connections: Arc<AtomicUsize>,
    /// Per-node rate/concurrency limiters, shared with the serve handler so a
    /// revoked device's entry can be dropped (a client that merely
    /// disconnects and reconnects keeps its limiter — that is intended).
    limiters: crate::http::LimiterRegistry,
    started_at: Instant,
    config_path: std::path::PathBuf,
    shutdown: Arc<Notify>,
    /// Why the last discovery scan skipped each listening socket.
    last_scan: Arc<RwLock<Vec<discovery::listener::Skipped>>>,
}

impl DaemonState {
    fn apps_snapshot(&self) -> Vec<AppInfoResponse> {
        let catalog = self.catalog.read().expect("catalog poisoned");
        catalog
            .apps()
            .iter()
            .map(|app| AppInfoResponse {
                name: app.name.clone(),
                host: app.origin.host.clone(),
                port: app.origin.port,
                scheme: app.origin.scheme.as_str().to_string(),
                source: app.source.as_str().to_string(),
                title: app.title.clone(),
                icon: app.icon.clone(),
                process: app.process.clone(),
            })
            .collect()
    }
}

impl IpcHandler for DaemonState {
    async fn handle(&self, req: Request, _ipc_token: &str) -> Response {
        match req {
            Request::Hello { .. } => Response::Ok, // already handled by server
            Request::Status => {
                let token_info = self.auth.current_token_info();
                let discovered_count = self
                    .catalog
                    .read()
                    .expect("catalog poisoned")
                    .discovered_count();
                let server_name = {
                    let cfg = self.config.read().expect("config poisoned");
                    config::server_name(&cfg)
                };
                Response::Status(StatusResponse {
                    name: server_name,
                    node_id: self.endpoints.id().to_string(),
                    uptime_secs: self.started_at.elapsed().as_secs(),
                    config_path: self.config_path.display().to_string(),
                    authorized_count: self.auth.authorized_count(),
                    discovered_count,
                    token_expires_at_unix: token_info.as_ref().map(|t| t.expires_at_unix),
                    token_ttl_secs: token_info.as_ref().map(|t| t.ttl.as_secs()),
                    active_connections: self.active_connections.load(Ordering::Relaxed),
                    cached_limiters: self.limiters.len(),
                    relay_urls: {
                        let endpoint = self.endpoints.endpoint();
                        endpoint
                            .addr()
                            .addrs
                            .iter()
                            .filter_map(|a| match a {
                                iroh::TransportAddr::Relay(url) => Some(url.to_string()),
                                _ => None,
                            })
                            .collect()
                    },
                    bound_sockets: self
                        .endpoints
                        .endpoint()
                        .bound_sockets()
                        .iter()
                        .map(|a| a.to_string())
                        .collect(),
                    relay_connected: crate::watchdog::relay_connected(&self.endpoints.endpoint()),
                    endpoint_uptime_secs: self.endpoints.uptime().as_secs(),
                    endpoint_restarts: self.endpoints.restarts(),
                    endpoint_last_restart: self
                        .endpoints
                        .last_restart()
                        .map(|r| ipc::EndpointRestart {
                            reason: r.reason,
                            at_unix: r.at_unix,
                        }),
                })
            }
            Request::GetToken => match self.auth.current_token_info() {
                Some(info) => {
                    let uri = info.uri(self.endpoints.id());
                    Response::Token(TokenResponse {
                        uri,
                        expires_at_unix: info.expires_at_unix,
                        scope: info.scope,
                    })
                }
                None => Response::Error("no active token".into()),
            },
            Request::RefreshToken {
                ttl_secs,
                allow_ports,
                full_access,
            } => {
                let (default_ttl, fixed, pinned_ports) = {
                    let cfg = self.config.read().expect("config poisoned");
                    (
                        cfg.bind.token_ttl_secs,
                        cfg.bind.token.clone(),
                        cfg.bind.allow_ports.clone(),
                    )
                };
                let ttl = Duration::from_secs(ttl_secs.unwrap_or(default_ttl));
                // Precedence: an explicit --ports, then an explicit --all,
                // then the configured bind.allow_ports default, then full
                // access (both when the config default is empty).
                let config_scope = scope_from_ports(if pinned_ports.is_empty() {
                    None
                } else {
                    Some(pinned_ports)
                });
                let scope = match (allow_ports, full_access) {
                    (Some(ports), _) => scope_from_ports(Some(ports)),
                    (None, true) => crate::auth::Scope::All,
                    (None, false) => config_scope.clone(),
                };
                // A pinned link has the same value after a restart, so the
                // config scope (applied at startup) is what will actually
                // survive: warn when an ad-hoc restriction would be lost.
                if fixed.is_some() && scope != config_scope {
                    tracing::warn!(
                        scope = %crate::auth::scope_json(&scope),
                        restart_scope = %crate::auth::scope_json(&config_scope),
                        "bind.token is pinned: this link's restriction differs from \
                         bind.allow_ports and will be reset to it on restart"
                    );
                }
                let info = self.auth.mint_token_with(ttl, fixed.as_deref(), scope);
                let uri = info.uri(self.endpoints.id());
                Response::Token(TokenResponse {
                    uri,
                    expires_at_unix: info.expires_at_unix,
                    scope: info.scope,
                })
            }
            Request::SetDeviceAccess {
                node_id,
                allow_ports,
            } => match node_id.parse::<iroh::EndpointId>() {
                Ok(id) => {
                    let scope = scope_from_ports(allow_ports);
                    match self.auth.set_scope(id, scope) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    }
                }
                Err(_) => Response::Error(format!("invalid node id: {node_id}")),
            },
            Request::Reload => match config::reload(&self.config_path) {
                Ok(new_cfg) => {
                    if let Err(e) = config::validate(&new_cfg) {
                        return Response::Error(format!("config validation failed: {e}"));
                    }
                    // Check restart-required fields.
                    let mut restart_required = Vec::new();
                    {
                        let cfg = self.config.read().expect("config poisoned");
                        if cfg.network.relay_url != new_cfg.network.relay_url {
                            restart_required.push("network.relay_url".into());
                        }
                        if cfg.network.proxy != new_cfg.network.proxy {
                            restart_required.push("network.proxy".into());
                        }
                        if cfg.bind.max_concurrent_connections
                            != new_cfg.bind.max_concurrent_connections
                        {
                            restart_required.push("bind.max_concurrent_connections".into());
                        }
                    }
                    // Apply hot-reloadable fields.
                    {
                        let mut cfg = self.config.write().expect("config poisoned");
                        *cfg = new_cfg;
                    }
                    self.auth.set_max_attempts(
                        self.config
                            .read()
                            .expect("config poisoned")
                            .bind
                            .max_failed_attempts,
                    );
                    self.config_generation.fetch_add(1, Ordering::Relaxed);
                    // Rebuild catalog + rescan so manual/discovery changes apply.
                    self.discovery_trigger.notify_one();
                    tracing::info!("config reloaded from {}", self.config_path.display());
                    Response::Reload(ReloadResponse {
                        applied: true,
                        restart_required,
                    })
                }
                Err(e) => Response::Error(format!("reload failed: {e}")),
            },
            Request::ListAuthorized => {
                let devices = self
                    .auth
                    .device_infos()
                    .into_iter()
                    .map(|d| ipc::DeviceInfo {
                        node_id: d.node_id.to_string(),
                        name: d.name,
                        access: self.auth.scope_for(d.node_id),
                    })
                    .collect();
                Response::Devices(devices)
            }
            Request::RevokeAuthorized { node_id } => match node_id.parse::<iroh::EndpointId>() {
                Ok(id) => {
                    if self.auth.revoke(id) {
                        // The device's per-node limiter belongs to an identity
                        // that will never be authorized again: drop it now
                        // rather than hold it for the daemon's lifetime.
                        self.limiters.forget(id);
                        // A pinned pairing token cannot have its value
                        // rotated by the daemon: the owner must unset it or
                        // re-mint deliberately.
                        if self.config.read().expect("config poisoned").bind.token.is_some() {
                            tracing::warn!(
                                "device {node_id} revoked; note: bind.token is pinned, so the token value stays valid until the config changes"
                            );
                        }
                        Response::Ok
                    } else {
                        Response::Error(format!("device {node_id} is not authorized"))
                    }
                }
                Err(_) => Response::Error(format!("invalid node id: {node_id}")),
            },
            Request::RenameAuthorized { node_id, name } => {
                match node_id.parse::<iroh::EndpointId>() {
                    Ok(id) => match self.auth.set_device_name(id, &name) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Err(_) => Response::Error(format!("invalid node id: {node_id}")),
                }
            }
            Request::ListApps => Response::Apps(self.apps_snapshot()),
            Request::DiscoverReport => {
                // Same scan-and-wait as DiscoverNow, plus the skip report.
                let before = self.catalog_generation.load(Ordering::Relaxed);
                self.discovery_trigger.notify_one();
                let deadline = Instant::now() + DISCOVER_NOW_TIMEOUT;
                while self.catalog_generation.load(Ordering::Relaxed) == before
                    && Instant::now() < deadline
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Response::DiscoverReport(DiscoverReportResponse {
                    apps: self.apps_snapshot(),
                    skipped: self.last_scan.read().expect("last_scan poisoned").clone(),
                })
            }
            Request::DiscoverNow => {
                let before = self.catalog_generation.load(Ordering::Relaxed);
                self.discovery_trigger.notify_one();
                let deadline = Instant::now() + DISCOVER_NOW_TIMEOUT;
                while self.catalog_generation.load(Ordering::Relaxed) == before
                    && Instant::now() < deadline
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Response::Apps(self.apps_snapshot())
            }
            Request::Shutdown => {
                tracing::info!("IPC shutdown requested");
                self.shutdown.notify_one();
                Response::Ok
            }
        }
    }
}

/// How long retiring a replaced endpoint may take before it is abandoned.
const RETIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// A bound endpoint and the router serving it. Kept together so a rebuild
/// swaps both at once.
struct RunningNode {
    endpoint: Endpoint,
    router: Router,
}

/// Bind a fresh endpoint from `cfg`, sharing this server's key.
///
/// Called at startup and again by the watchdog: the same secret key means the
/// same node id, so paired devices keep working across a rebuild.
async fn bind_endpoint(cfg: &Config, secret_key: &iroh::SecretKey) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0);
    // A configured private relay replaces N0's default relay map; the preset
    // otherwise pins endpoint relay discovery to the default N0 set.
    if let Some(relay) = &cfg.network.relay_url {
        let url: iroh::RelayUrl = relay
            .parse()
            .with_context(|| format!("invalid network.relay_url: {relay}"))?;
        tracing::info!("using configured relay {url}");
        builder = builder.relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(url)));
    }
    if let Some(proxy) = crate::proxy::resolve(cfg.network.proxy.as_deref())? {
        tracing::info!(
            "using outbound proxy {} for iroh relay/discovery",
            crate::proxy::redacted(&proxy)
        );
        builder = builder.proxy_url(proxy);
    }
    let endpoint = builder.secret_key(secret_key.clone()).bind().await?;

    tracing::info!("node id: {}", endpoint.id());
    tracing::info!("addr: {:?}", endpoint.addr());
    tracing::info!("sockets: {:?}", endpoint.bound_sockets());
    Ok(endpoint)
}

/// Spawn the protocol router (bind + serve ALPNs) on `endpoint`.
fn spawn_router(
    endpoint: &Endpoint,
    auth: Arc<AuthState>,
    bind_concurrency: usize,
    state: Arc<AppState>,
    config_generation: Arc<AtomicU64>,
    active_connections: Arc<AtomicUsize>,
    limiters: crate::http::LimiterRegistry,
) -> Router {
    Router::builder(endpoint.clone())
        .accept(BIND_ALPN, BindHandler::new(auth.clone(), bind_concurrency))
        .accept(
            SERVE_ALPN,
            ServeHandler::new(
                state,
                auth,
                config_generation,
                active_connections,
                limiters,
            ),
        )
        .spawn()
}

/// Run the daemon until shutdown.
pub async fn run() -> Result<()> {
    let log_dir = crate::identity::ensure_data_dir()?;
    // Peek at the config's log level before tracing is initialised: `RUST_LOG`
    // still wins below, but the `[log] level` knob needs to reach EnvFilter. A
    // missing/broken config falls back to the `info` default (validated again
    // below where config load can fail loudly).
    let config_log_level = config::load(&config::config_path(None)?)
        .ok()
        .and_then(|c| c.log.level.clone());
    let relay_signal = Arc::new(RelayActorSignal::default());
    let _log_guard = init_tracing(
        &log_dir,
        config_log_level.as_deref(),
        relay_signal.clone(),
    )?;

    // Single-instance guard: refuse to start a second daemon against the same
    // state directory (the OS releases this lock if we exit or crash).
    let _instance_lock = match crate::lock::acquire()? {
        Some(lock) => lock,
        None => {
            let pid = crate::lock::owner_pid()
                .map(|p| format!(" (pid {p})"))
                .unwrap_or_default();
            anyhow::bail!(
                "raemoted is already running{pid}; refusing to start a second instance"
            );
        }
    };

    let config_path = config::config_path(None)?;
    let cfg = config::load(&config_path)?;
    config::validate(&cfg)?;

    tracing::info!("loaded config from {}", config_path.display());

    let secret_key = crate::identity::load_or_create_secret_key()?;
    let endpoint = bind_endpoint(&cfg, &secret_key).await?;
    let endpoints = EndpointHandle::new(endpoint.clone());

    // Pin down the bind-level values before `cfg` is moved into the shared
    // config (the bind handler cannot change mid-run; reload reports the
    // fields as restart-required).
    let bind_concurrency = cfg.bind.max_concurrent_connections;

    let auth = Arc::new(AuthState::load(cfg.bind.max_failed_attempts)?);
    let ttl = Duration::from_secs(cfg.bind.token_ttl_secs);
    // `bind.allow_ports` is the default scope for every link this daemon
    // mints (pinned or not); an explicit `raemote pair --ports`/`--all`
    // overrides it per link.
    let startup_scope = if cfg.bind.allow_ports.is_empty() {
        crate::auth::Scope::All
    } else {
        crate::auth::scope_from_ports(Some(cfg.bind.allow_ports.clone()))
    };
    let token = auth.mint_token_with(ttl, cfg.bind.token.as_deref(), startup_scope);

    let config = Arc::new(RwLock::new(cfg));
    let config_generation = Arc::new(AtomicU64::new(0));

    let initial_catalog = {
        let cfg = config.read().expect("config poisoned");
        Catalog::rebuild(&cfg.apps, &[])
    };
    let catalog = Arc::new(RwLock::new(initial_catalog));
    let catalog_generation = Arc::new(AtomicU64::new(0));
    let discovery_trigger = Arc::new(Notify::new());
    let active_connections = Arc::new(AtomicUsize::new(0));
    // Shared with the serve handler: one limiter per device identity, dropped
    // when that device is revoked.
    let limiters = crate::http::LimiterRegistry::new();

    let state = Arc::new(AppState::with_discovery(
        config.clone(),
        catalog.clone(),
        endpoint.id(),
        Some(crate::http::DiscoveryHandle {
            trigger: discovery_trigger.clone(),
            generation: catalog_generation.clone(),
        }),
    ));

    // The knob is applied at handler construction (it cannot change during a
    // run; reload reports it as restart-required instead of silently relying
    // on the default). Same for the endpoint: a rebuild re-uses this closure so
    // the new node accepts the same two ALPNs with the same handlers.
    let make_router = {
        let auth = auth.clone();
        let state = state.clone();
        let config_generation = config_generation.clone();
        let active_connections = active_connections.clone();
        let limiters = limiters.clone();
        move |endpoint: &Endpoint| {
            spawn_router(
                endpoint,
                auth.clone(),
                bind_concurrency,
                state.clone(),
                config_generation.clone(),
                active_connections.clone(),
                limiters.clone(),
            )
        }
    };
    let node = Arc::new(tokio::sync::Mutex::new(RunningNode {
        endpoint: endpoint.clone(),
        router: make_router(&endpoint),
    }));

    print_binding(&endpoint, &token);

    let shutdown = Arc::new(Notify::new());

    // Endpoint self-healing: when iroh's relay task wedges (or the relay has
    // been unreachable for a long time), bind a fresh endpoint with the same
    // key, swap the router onto it, and retire the old one. Identity, token,
    // paired devices and the catalog all live outside the endpoint, so nothing
    // else changes; a rebuild waits for connected devices to leave.
    let (heal_tx, mut heal_rx) = mpsc::channel::<HealRequest>(1);
    let heal_handle = tokio::spawn({
        let config = config.clone();
        let endpoints = endpoints.clone();
        let make_router = make_router.clone();
        async move {
            while let Some(request) = heal_rx.recv().await {
                let cfg = {
                    let cfg = config.read().expect("config poisoned");
                    cfg.clone()
                };
                let new_endpoint = match bind_endpoint(&cfg, &secret_key).await {
                    Ok(endpoint) => endpoint,
                    Err(e) => {
                        tracing::error!(
                            reason = %request.reason,
                            "endpoint watchdog: rebuild failed, keeping the current endpoint: {e:#}"
                        );
                        continue;
                    }
                };
                let new_router = make_router(&new_endpoint);
                let previous = {
                    let mut node = node.lock().await;
                    std::mem::replace(
                        &mut *node,
                        RunningNode {
                            endpoint: new_endpoint.clone(),
                            router: new_router,
                        },
                    )
                };
                endpoints.replace(new_endpoint.clone(), request.reason.as_str());
                tracing::warn!(
                    reason = %request.reason,
                    node_id = %new_endpoint.id(),
                    sockets = ?new_endpoint.bound_sockets(),
                    "endpoint watchdog: endpoint rebuilt; new sockets and relay connection are live"
                );
                // Retire the old node in the background so a slow close cannot
                // delay a later heal. No device is attached at this point (the
                // watchdog only heals while `active_connections` is zero).
                let RunningNode {
                    endpoint: old_endpoint,
                    router: old_router,
                } = previous;
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(RETIRE_TIMEOUT, old_router.shutdown()).await;
                    let _ = tokio::time::timeout(RETIRE_TIMEOUT, old_endpoint.close()).await;
                });
            }
        }
    });
    let watchdog_handle = tokio::spawn(
        crate::watchdog::Watchdog::new(
            config.clone(),
            relay_signal,
            endpoints.clone(),
            active_connections.clone(),
            heal_tx,
        )
        .run(shutdown.clone()),
    );

    let last_scan = Arc::new(RwLock::new(Vec::new()));
    let discovery_engine = DiscoveryEngine::new(
        config.clone(),
        catalog.clone(),
        discovery_trigger.clone(),
        shutdown.clone(),
        catalog_generation.clone(),
        last_scan.clone(),
    );
    let discovery_handle = tokio::spawn(discovery_engine.run());

    // Generate IPC token and write daemon.json
    let ipc_token: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let daemon_info = ipc::DaemonInfo {
        pid: std::process::id(),
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        socket_path: ipc::socket_path()?,
        ipc_token: ipc_token.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let daemon_json = ipc::daemon_json_path()?;
    ipc::write_daemon_json(&daemon_json, &daemon_info)?;

    let daemon_state = DaemonState {
        config,
        config_generation,
        catalog,
        catalog_generation,
        discovery_trigger,
        auth,
        endpoints,
        active_connections,
        limiters,
        started_at: Instant::now(),
        config_path,
        shutdown: shutdown.clone(),
        last_scan,
    };

    // Spawn IPC server
    let socket = ipc::socket_path()?;
    let socket_cleanup = socket.clone();
    let ipc_token_clone = ipc_token.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc::unix::serve(&socket, daemon_state, ipc_token_clone).await {
            tracing::error!("IPC server error: {e:#}");
        }
    });

    // Wait for shutdown signal
    shutdown.notified().await;
    tracing::info!("shutting down...");

    // Cleanup
    ipc_handle.abort();
    discovery_handle.abort();
    watchdog_handle.abort();
    heal_handle.abort();
    let _ = std::fs::remove_file(&socket_cleanup);
    ipc::remove_daemon_json(&daemon_json);

    Ok(())
}

/// Initialise logging to both stderr and a rotating file under `log_dir`.
///
/// The returned guard must be kept alive for the process lifetime so buffered
/// records are flushed on shutdown. Log files live in `~/.raemote` (mode
/// `0700`), so their contents stay user-only.
///
/// The watchdog's [`RelayActorWedgeLayer`] is installed *before* the level
/// filter: the stall warning is the only signal that iroh's relay task wedged,
/// and the watchdog must see it even when the user has raised the level (or
/// `RUST_LOG=error`). The `iroh::socket::transports::relay` target is also kept
/// at `warn` so the line still reaches the log file and a human can see why the
/// endpoint was rebuilt.
fn init_tracing(
    log_dir: &std::path::Path,
    config_level: Option<&str>,
    relay_signal: Arc<RelayActorSignal>,
) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::prelude::*;

    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("raemoted")
        .filename_suffix("log")
        .max_log_files(5)
        .build(log_dir)
        .context("failed to create the log file appender")?;
    let (file_writer, guard) = tracing_appender::non_blocking(appender);

    // `RUST_LOG` wins; otherwise the `[log] level` config knob applies; when
    // neither is set the default is `info` so the log file is useful out of the
    // box.
    let mut filter = EnvFilter::try_from_default_env().or_else(|_| {
        config_level
            .and_then(|level| EnvFilter::try_new(level).ok())
            .ok_or(())
    }).unwrap_or_else(|_| EnvFilter::new("info"));
    if let Ok(directive) = "iroh::socket::transports::relay=warn".parse() {
        filter = filter.add_directive(directive);
    }

    tracing_subscriber::registry()
        .with(RelayActorWedgeLayer::new(relay_signal))
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false),
        )
        .init();

    Ok(guard)
}
