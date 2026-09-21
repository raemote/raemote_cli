//! The HTTP ALPN (`raemote/0`): a hub API and reverse proxy for authorized
//! devices.
//!
//! Only authorized device identities are served. Routes: `/_hub/catalog`,
//! `/_hub/discover`, and `/app/{name}/...` (proxied to the local app).

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use iroh::endpoint::{Connection, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use leaky_bucket::RateLimiter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::auth::{default_device_name, sanitize_device_name, AuthState};
use crate::catalog::Catalog;
use crate::config::Config;
use crate::discovery::model::Origin;
use crate::iroh_stream::IrohStream;

/// ALPN for serving the HTTP API to authorized clients only.
pub const SERVE_ALPN: &[u8] = b"raemote/0";

/// Application error codes used when closing connections.
const ERR_UNAUTHORIZED: u32 = 401;
const ERR_TOO_MANY_STREAMS: u32 = 503;

/// Max time to wait for the local origin to produce a response head.
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `/_hub/discover` waits for a scan to complete.
const DISCOVER_WAIT: Duration = Duration::from_secs(3);

type ResBody = BoxBody<Bytes, io::Error>;

/// Per-node limiter combining a concurrency cap (Semaphore) and a rate limit
/// (leaky bucket). Created on first use for each authorized node, lives for
/// process lifetime (until config reload invalidates the cache).
struct NodeLimiter {
    semaphore: Arc<Semaphore>,
    rate: Arc<RateLimiter>,
}

impl NodeLimiter {
    fn new(max_concurrent: usize, rate_refill: usize, rate_interval: Duration, rate_max: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            rate: Arc::new(
                RateLimiter::builder()
                    .initial(rate_refill)
                    .refill(rate_refill)
                    .interval(rate_interval)
                    .max(rate_max)
                    .build(),
            ),
        }
    }

    fn try_acquire_concurrency(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    async fn acquire_rate_token(&self) {
        self.rate.clone().acquire_owned(1).await;
    }
}

/// Cache of per-node limiters, shared between the serve handler and the daemon.
///
/// A limiter is created on a node's first authorized connection and **reused
/// for that node's lifetime**, so a client that disconnects and reconnects —
/// the normal case for a phone — never accumulates state. The daemon drops a
/// node's limiter when it revokes the device: that identity is never
/// authorized again, so its entry would otherwise live until the next config
/// reload.
#[derive(Clone, Default)]
pub struct LimiterRegistry {
    limiters: Arc<Mutex<HashMap<EndpointId, Arc<NodeLimiter>>>>,
    /// The config generation the cache was built at; compared against the
    /// shared `config_generation` to invalidate on reload.
    generation: Arc<AtomicU64>,
}

impl LimiterRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop one node's limiter (used when its device is revoked).
    pub fn forget(&self, node: EndpointId) {
        let removed = self
            .limiters
            .lock()
            .expect("limiters poisoned")
            .remove(&node);
        if removed.is_some() {
            tracing::debug!(node = %node.fmt_short(), "dropped limiter for revoked device");
        }
    }

    /// How many limiters are cached (diagnostics and tests).
    pub fn len(&self) -> usize {
        self.limiters.lock().expect("limiters poisoned").len()
    }

    /// Whether no limiter is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the cache when the config generation advanced (settings such as
    /// the stream cap or rate limit changed). Returns `true` when it cleared.
    fn sync_generation(&self, current: u64) -> bool {
        if self.generation.load(Ordering::Relaxed) == current {
            return false;
        }
        let mut limiters = self.limiters.lock().expect("limiters poisoned");
        // Re-check under the lock to avoid two threads both clearing.
        if self.generation.load(Ordering::Relaxed) == current {
            return false;
        }
        limiters.clear();
        self.generation.store(current, Ordering::Relaxed);
        true
    }
}

/// Handle to the discovery engine, so the HTTP API can trigger a scan.
#[derive(Clone)]
pub struct DiscoveryHandle {
    /// Signalled to request an immediate scan.
    pub trigger: Arc<Notify>,
    /// Bumped after each scan; used to wait for one to finish.
    pub generation: Arc<AtomicU64>,
}

/// Shared state for every request served over an iroh stream.
pub struct AppState {
    client: Client<HttpConnector, ResBody>,
    config: Arc<RwLock<Config>>,
    catalog: Arc<RwLock<Catalog>>,
    /// This server's own node id, needed to build pairing/invitation URIs.
    node_id: EndpointId,
    discovery: Option<DiscoveryHandle>,
}

impl AppState {
    /// Build state without a discovery handle.
    pub fn new(
        config: Arc<RwLock<Config>>,
        catalog: Arc<RwLock<Catalog>>,
        node_id: EndpointId,
    ) -> Self {
        Self::with_discovery(config, catalog, node_id, None)
    }

    /// Build state, optionally wired to the discovery engine.
    pub fn with_discovery(
        config: Arc<RwLock<Config>>,
        catalog: Arc<RwLock<Catalog>>,
        node_id: EndpointId,
        discovery: Option<DiscoveryHandle>,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            config,
            catalog,
            node_id,
            discovery,
        }
    }
}

/// Handler for [`SERVE_ALPN`]: the HTTP API, gated on the caller's node ID
/// being in the authorized set. Unauthorized connections are closed with
/// `ERR_UNAUTHORIZED` before any stream is served. Each authorized node
/// gets a per-node concurrency cap and rate limit.
pub struct ServeHandler {
    state: Arc<AppState>,
    auth: Arc<AuthState>,
    limiters: LimiterRegistry,
    /// Shared config generation counter; incremented on reload.
    config_generation: Arc<AtomicU64>,
    /// Number of live authorized serve connections (for status/diagnostics).
    active_connections: Arc<AtomicUsize>,
}

impl ServeHandler {
    /// Build a serve handler over shared state and auth. `limiters` is shared
    /// with the daemon so a revoked device's limiter can be dropped.
    pub fn new(
        state: Arc<AppState>,
        auth: Arc<AuthState>,
        config_generation: Arc<AtomicU64>,
        active_connections: Arc<AtomicUsize>,
        limiters: LimiterRegistry,
    ) -> Self {
        Self {
            state,
            auth,
            limiters,
            config_generation,
            active_connections,
        }
    }

    fn get_or_create_limiter(&self, node: EndpointId) -> Arc<NodeLimiter> {
        // Settings that shape a limiter (stream cap, rate limit) can change on
        // reload; a stale cache is dropped wholesale.
        let current_gen = self.config_generation.load(Ordering::Relaxed);
        if self.limiters.sync_generation(current_gen) {
            tracing::debug!(generation = current_gen, "cleared limiter cache on config reload");
        }

        let cfg = self.state.config.read().expect("config poisoned");
        let serve = &cfg.serve;

        let mut limiters = self.limiters.limiters.lock().expect("limiters poisoned");
        limiters
            .entry(node)
            .or_insert_with(|| {
                Arc::new(NodeLimiter::new(
                    serve.max_concurrent_streams,
                    serve.rate_limit.refill,
                    Duration::from_millis(serve.rate_limit.interval_ms),
                    serve.rate_limit.max,
                ))
            })
            .clone()
    }
}

impl std::fmt::Debug for ServeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeHandler").finish_non_exhaustive()
    }
}

/// Decrements the live serve-connection count when the connection ends,
/// including on early return or panic.
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ProtocolHandler for ServeHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let node = connection.remote_id();
        if !self.auth.is_authorized(node) {
            tracing::warn!(
                node = %node.fmt_short(),
                "closing unauthorized serve connection"
            );
            connection.close(VarInt::from_u32(ERR_UNAUTHORIZED), b"unauthorized");
            return Ok(());
        }
        tracing::info!(node = %node.fmt_short(), "serving authorized node");
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        let _connection_guard = ConnectionGuard(self.active_connections.clone());
        let limiter = self.get_or_create_limiter(node);
        loop {
            match connection.accept_bi().await {
                Ok((mut send, recv)) => {
                    // Re-check on every stream: a device revoked after the
                    // connection was established must lose access on its next
                    // request, not keep a live connection forever.
                    if !self.auth.is_authorized(node) {
                        tracing::warn!(
                            node = %node.fmt_short(),
                            "closing serve connection for revoked device"
                        );
                        connection.close(VarInt::from_u32(ERR_UNAUTHORIZED), b"revoked");
                        break;
                    }
                    tracing::info!(node = %node.fmt_short(), "accepted bi-stream");
                    let state = self.state.clone();
                    let auth = self.auth.clone();
                    let limiter = limiter.clone();
                    tokio::spawn(async move {
                        let _concurrency_permit = match limiter.try_acquire_concurrency() {
                            Some(permit) => permit,
                            None => {
                                tracing::warn!(
                                    node = %node.fmt_short(),
                                    "rejecting stream: too many concurrent streams"
                                );
                                let _ = send.reset(VarInt::from_u32(ERR_TOO_MANY_STREAMS));
                                return;
                            }
                        };
                        limiter.acquire_rate_token().await;
                        serve_stream(state, auth, IrohStream::new(send, recv), node).await;
                    });
                }
                Err(err) => {
                    tracing::debug!(?err, "serve connection closed");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Serve HTTP/1.1 requests arriving on one iroh bidirectional stream.
///
/// `node` is the authenticated caller, passed so routes like `/_hub/device`
/// can act on "this device".
pub async fn serve_stream(
    state: Arc<AppState>,
    auth: Arc<AuthState>,
    stream: IrohStream,
    node: EndpointId,
) {
    let service = service_fn(move |req| {
        let state = state.clone();
        let auth = auth.clone();
        async move { handle(req, state, auth, node).await }
    });
    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .half_close(true)
        .serve_connection(TokioIo::new(stream), service)
        // Required for WebSocket/upgrade support; plain `serve_connection`
        // can't perform upgrades.
        .with_upgrades()
        .await
    {
        tracing::debug!("stream closed: {err}");
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
    auth: Arc<AuthState>,
    node: EndpointId,
) -> Result<Response<ResBody>, io::Error> {
    // Revocation is enforced per request, matching the comment on the accept
    // loop: a device revoked mid-connection must lose access on its next
    // request even when it is multiplexed on an already-accepted stream.
    if !auth.is_authorized(node) {
        tracing::warn!(node = %node.fmt_short(), "denying request from revoked device");
        return Ok(error_response_with_close(
            StatusCode::UNAUTHORIZED,
            "revoked",
            "this device is no longer authorized",
        ));
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Credential-bearing headers (cookies, authorization) and query strings are
    // omitted from metadata logs; full headers only at debug level. This keeps
    // default (`info`) logs free of live session credentials.
    tracing::info!(%method, %path, "HTTP request received");
    tracing::debug!(
        ?method,
        ?path,
        headers = tracing::field::debug(
            req.headers()
                .iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str().to_ascii_lowercase().as_str(),
                        "cookie" | "authorization"
                    )
                })
                .map(|(k, v)| format!("{k}: {v:?}"))
                .collect::<Vec<_>>()
        ),
        "credential-filtered headers"
    );

    if path == "/_hub/catalog" {
        let resp = catalog(&state);
        tracing::info!(status = %resp.status(), "responding with catalog");
        return Ok(resp);
    }

    if path == "/_hub/discover" {
        let resp = discover(&state).await;
        tracing::info!(status = %resp.status(), "responding with discovery result");
        return Ok(resp);
    }

    if path == "/_hub/info" {
        return Ok(info(&state));
    }

    if path == "/_hub/devices" {
        return Ok(devices(&auth, node));
    }

    if path == "/_hub/device" {
        if method == Method::PUT || method == Method::POST {
            return Ok(rename_self(&auth, node, req).await);
        }
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "use PUT to set this device's name",
            None,
        ));
    }

    if path == "/_hub/invite" {
        if method == Method::POST {
            return Ok(create_invite(&state, &auth, node));
        }
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "use POST to create an invitation",
            None,
        ));
    }

    if let Some(rest) = path.strip_prefix("/app/") {
        let mut segments = rest.splitn(2, '/');
        let name = segments.next().unwrap_or_default();
        let sub_path = segments.next().unwrap_or_default();
        // Look up the origin, clone it, then drop the guard before any await.
        let origin = {
            let catalog = state.catalog.read().expect("catalog poisoned");
            catalog.find(name).map(|app| app.origin.clone())
        };
        match origin {
            Some(origin) => {
                tracing::info!(app = %name, authority = %origin.authority(), sub_path, "proxying to origin");
                return proxy(&state, req, &origin, sub_path).await;
            }
            None => {
                tracing::warn!(app = %name, "unknown app");
                return Ok(error_response(
                    StatusCode::NOT_FOUND,
                    "unknown_app",
                    &format!("unknown app \"{name}\""),
                    Some("it may have stopped — refresh the app list, or run `raemote discover` on the server"),
                ));
            }
        }
    }

    tracing::warn!(path, "no matching route");
    Ok(error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        &format!("no such route: {path}"),
        None,
    ))
}

/// Trigger an immediate discovery scan (if wired) and wait briefly for it to
/// finish, then return the refreshed catalog.
async fn discover(state: &AppState) -> Response<ResBody> {
    let Some(handle) = &state.discovery else {
        return catalog(state);
    };
    let before = handle.generation.load(Ordering::Relaxed);
    handle.trigger.notify_one();
    let deadline = tokio::time::Instant::now() + DISCOVER_WAIT;
    while handle.generation.load(Ordering::Relaxed) == before
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    catalog(state)
}

fn catalog(state: &AppState) -> Response<ResBody> {
    let catalog = state.catalog.read().expect("catalog poisoned");
    let apps: Vec<_> = catalog.apps().iter().map(catalog_app_json).collect();
    json_response(StatusCode::OK, serde_json::json!({ "apps": apps }))
}

/// One catalog entry in the hub JSON shape the client decodes.
fn catalog_app_json(app: &crate::catalog::CatalogApp) -> serde_json::Value {
    serde_json::json!({
        "name": app.name,
        "path": format!("/app/{}", app.name),
        "port": app.origin.port,
        "scheme": app.origin.scheme.as_str(),
        "source": app.source.as_str(),
        "title": app.title,
        "icon": app.icon,
    })
}

/// `GET /_hub/info`: basic server identity for the app to display.
fn info(state: &AppState) -> Response<ResBody> {
    let name = {
        let cfg = state.config.read().expect("config poisoned");
        crate::config::server_name(&cfg)
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "name": name,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// `GET /_hub/devices`: the paired devices and their display names.
fn devices(auth: &AuthState, node: EndpointId) -> Response<ResBody> {
    let devices: Vec<_> = auth
        .device_infos()
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "node_id": d.node_id.to_string(),
                "name": d.name,
                "self": d.node_id == node,
            })
        })
        .collect();
    json_response(StatusCode::OK, serde_json::json!({ "devices": devices }))
}

/// Largest body accepted on the small JSON routes (rename); larger requests
/// are refused with 413 instead of being buffered in daemon memory.
const MAX_RENAME_BODY: usize = 8 * 1024;

enum LimitError {
    TooLarge,
    Io,
}

/// Collect a bounded amount of body, refusing past `MAX_RENAME_BODY` so an
/// oversized body cannot buffer unbounded daemon memory.
async fn collect_limited_body(req: Request<Incoming>) -> Result<Bytes, LimitError> {
    use hyper::body::Body as HyperBody;
    let mut collected = BytesMut::new();
    // A declared Content-Length past the cap is refused before reading.
    if let Some(len) = req.body().size_hint().exact()
        && len > MAX_RENAME_BODY as u64
    {
        return Err(LimitError::TooLarge);
    }
    let mut body = req.into_body();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let data = match frame.into_data() {
                    Ok(data) => data,
                    Err(_) => return Err(LimitError::Io),
                };
                collected.extend_from_slice(&data);
                if collected.len() > MAX_RENAME_BODY {
                    return Err(LimitError::TooLarge);
                }
            }
            Some(Err(_)) => return Err(LimitError::Io),
            None => return Ok(collected.freeze()),
        }
    }
}

/// `PUT /_hub/device`: let a device set its own display name.
async fn rename_self(
    auth: &AuthState,
    node: EndpointId,
    req: Request<Incoming>,
) -> Response<ResBody> {
    #[derive(serde::Deserialize)]
    struct RenameBody {
        name: String,
    }

    // Bound the body: the payload is one short display name, so anything
    // larger is refused before buffering (a paired device could otherwise
    // hold an unbounded buffer — and a concurrency permit — in daemon memory).
    // The declared Content-Length is checked inside `collect_limited_body`.
    let body = match collect_limited_body(req).await {
        Ok(body) => body,
        Err(LimitError::TooLarge) => return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "request body too large",
            None,
        ),
        Err(LimitError::Io) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "could not read the request body",
                None,
            );
        }
    };
    let parsed: RenameBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "expected a JSON body like {\"name\": \"My iPhone\"}",
                None,
            );
        }
    };

    match auth.set_device_name(node, &parsed.name) {
        Ok(()) => {
            let name =
                sanitize_device_name(&parsed.name).unwrap_or_else(|| default_device_name(node));
            json_response(StatusCode::OK, serde_json::json!({ "ok": true, "name": name }))
        }
        Err(err) => {
            error_response(StatusCode::BAD_REQUEST, "bad_request", &err.to_string(), None)
        }
    }
}

/// `POST /_hub/invite`: mint a one-time invitation so this (authorized) device
/// can introduce another device to the server. Whoever redeems the returned
/// link first becomes an authorized device; the invitation is then consumed.
fn create_invite(state: &AppState, auth: &AuthState, node: EndpointId) -> Response<ResBody> {
    let (allow, ttl_secs, max_pending) = {
        let cfg = state.config.read().expect("config poisoned");
        (
            cfg.bind.allow_invites,
            cfg.bind.invite_ttl_secs,
            cfg.bind.max_pending_invites,
        )
    };

    if !allow {
        return error_response(
            StatusCode::FORBIDDEN,
            "invites_disabled",
            "invitations are disabled on this server",
            Some("set bind.allow_invites = true to enable them"),
        );
    }

    match auth.mint_invitation(Duration::from_secs(ttl_secs), node, max_pending) {
        Ok(info) => {
            tracing::info!(node = %node.fmt_short(), "invitation requested");
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "uri": info.uri(state.node_id),
                    "expires_at_unix": info.expires_at_unix,
                }),
            )
        }
        Err(err) => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_invites",
            &err.to_string(),
            Some("wait for an outstanding invitation to expire or be used"),
        ),
    }
}

/// Tunnel an upgrade (WebSocket) request to the origin and splice the two
/// connections.
///
/// The upstream handshake runs over a raw TCP socket (hyper's client upgrade
/// path is restrictive); the client side uses hyper's server upgrade, so bytes
/// flow untouched in both directions once the 101 is returned.
async fn proxy_upgrade(
    mut req: Request<Incoming>,
    origin: &Origin,
    sub_path: &str,
) -> Result<Response<ResBody>, io::Error> {
    // Register the client-side upgrade before consuming the request.
    let client_upgrade = hyper::upgrade::on(&mut req);

    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let target = format!("/{sub_path}{query}");

    // Rebuild the request head for the origin, keeping the upgrade headers.
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method(), target);
    head.push_str(&format!("Host: {}\r\n", origin.authority()));
    for (name, value) in req.headers().iter() {
        if name.as_str() == "host" {
            continue;
        }
        let Ok(text) = value.to_str() else { continue };
        let line = match name.as_str() {
            "origin" => format!("origin: {}", rewrite_origin(text, origin)),
            "referer" => format!("referer: {}", rewrite_referer(text, origin)),
            other => format!("{other}: {text}"),
        };
        head.push_str(&line);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    tracing::info!(
        upstream = %format!("{}://{}/{}", origin.scheme.as_str(), origin.authority(), sub_path),
        "proxying upgrade"
    );
    tracing::debug!(
        upstream = %format!("{}://{}{}", origin.scheme.as_str(), origin.authority(), redact_query(&target)),
        "proxying upgrade target"
    );

    // Bound the handshake: connect + head read use the same deadline as the
    // buffered proxy path, so an origin that accepts and stalls cannot wedge a
    // per-node stream slot indefinitely.
    let handshake = tokio::time::timeout(
        PROXY_TIMEOUT,
        async {
            let mut upstream =
                tokio::net::TcpStream::connect((origin.host.as_str(), origin.port)).await?;
            upstream.write_all(head.as_bytes()).await?;

            // Read the origin's response head (through CRLFCRLF).
            let mut buf = Vec::with_capacity(1024);
            let mut tmp = [0u8; 1024];
            while buf.windows(4).all(|window| window != b"\r\n\r\n") {
                let n = upstream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(io::Error::other("the app closed the connection"));
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 64 * 1024 {
                    return Err(io::Error::other("the app sent an oversized upgrade response"));
                }
            }
            let pos = buf.windows(4).position(|window| window == b"\r\n\r\n");
            Ok::<_, io::Error>((upstream, buf, pos.expect("checked above") + 4))
        },
    )
    .await;

    let (mut upstream, buf, head_end) = match handshake {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            // The origin closed early or sent an oversized head: the same
            // 502 the buffered path would give.
            tracing::debug!(authority = %origin.authority(), ?err, "upgrade handshake failed");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "the app failed the WebSocket upgrade handshake",
                None,
            ));
        }
        // Deadline exceeded: the permit and origin socket are released here.
        Err(_elapsed) => {
            tracing::warn!(
                authority = %origin.authority(),
                "upgrade handshake exceeded the {PROXY_TIMEOUT:?} deadline"
            );
            return Ok(error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                &format!(
                    "the app at {} took too long to complete the WebSocket upgrade",
                    origin.authority()
                ),
                Some("it may be busy or stuck; try again"),
            ));
        }
    };

    let head_text = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let status_line = head_text.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY);

    if status != StatusCode::SWITCHING_PROTOCOLS {
        tracing::warn!(%status, "upstream refused the upgrade");
        return Ok(error_response(
            status,
            "upgrade_refused",
            "the app refused the WebSocket upgrade",
            Some(status_line),
        ));
    }

    // Return the 101 with the origin's headers so hyper performs the upgrade.
    let mut builder = Response::builder().status(status);
    {
        let headers = builder.headers_mut().expect("fresh builder");
        for line in head_text.split("\r\n").skip(1) {
            if let Some((key, value)) = line.split_once(':') {
                let (Ok(name), Ok(value)) = (
                    hyper::header::HeaderName::from_bytes(key.trim().as_bytes()),
                    hyper::header::HeaderValue::from_str(value.trim()),
                ) else {
                    continue;
                };
                headers.append(name, value);
            }
        }
    }
    let response = builder.body(full(Bytes::new())).map_err(io::Error::other)?;

    // Bytes past the head arrived before the handover; forward them first.
    let leftover = buf[head_end..].to_vec();

    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let upgraded = match client_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                tracing::debug!(?err, "client upgrade failed");
                return;
            }
        };
        let mut client = TokioIo::new(upgraded);
        if !leftover.is_empty()
            && let Err(err) = client.write_all(&leftover).await
        {
            tracing::debug!(?err, "failed to flush post-upgrade bytes");
            return;
        }
        match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            // Info, not debug: a tunneled WebSocket closing is rare enough to
            // be worth seeing by default, and the lifetime is exactly what
            // tells a client-side reconnect loop apart from a server-side drop.
            Ok((to_client, to_upstream)) => {
                tracing::info!(
                    lived_ms = started.elapsed().as_millis() as u64,
                    to_client,
                    to_upstream,
                    "upgrade tunnel closed"
                )
            }
            // A client that vanishes without a clean close (app backgrounded,
            // network changed, connection lost) lands here rather than in the
            // `Ok` branch, so this is logged at info with the lifetime too.
            Err(err) => tracing::info!(
                lived_ms = started.elapsed().as_millis() as u64,
                ?err,
                "upgrade tunnel error"
            ),
        }
    });

    Ok(response)
}

async fn proxy(
    state: &AppState,
    req: Request<Incoming>,
    origin: &Origin,
    sub_path: &str,
) -> Result<Response<ResBody>, io::Error> {
    // WebSocket and other upgrades can't go through the buffered hyper client;
    // tunnel them raw once the handshake succeeds.
    if req.headers().contains_key(hyper::header::UPGRADE) {
        return proxy_upgrade(req, origin, sub_path).await;
    }

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_uri = format!(
        "{}://{}/{}{}",
        origin.scheme.as_str(),
        origin.authority(),
        sub_path,
        query
    );
    // Log the path without any query string: token-bearing queries must not
    // reach default (info) logs. The debug line keeps parameter names but
    // redacts their values, because both layers are persisted to the log file.
    tracing::info!(
        upstream = %format!("{}://{}/{}", origin.scheme.as_str(), origin.authority(), sub_path),
        "proxying request to origin"
    );
    tracing::debug!(
        upstream = %redact_query(&upstream_uri),
        "proxying request with query"
    );

    let (parts, body) = req.into_parts();
    let mut builder = Request::builder().method(parts.method).uri(upstream_uri);
    {
        let headers = builder
            .headers_mut()
            .expect("uri is always valid in a fresh request builder");
        for (name, value) in parts.headers.iter() {
            if name.as_str() == "host" || is_hop_by_hop(name.as_str()) {
                continue;
            }
            // Point loopback Origin/Referer at the upstream so the app's own
            // CSRF checks pass.
            if let ("origin" | "referer", Ok(text)) = (name.as_str(), value.to_str()) {
                let rewritten = if name.as_str() == "origin" {
                    rewrite_origin(text, origin)
                } else {
                    rewrite_referer(text, origin)
                };
                if let Ok(header) = hyper::header::HeaderValue::from_str(&rewritten) {
                    headers.append(name, header);
                    continue;
                }
            }
            headers.append(name, value.clone());
        }
    }
    let body = body.map_err(io::Error::other).boxed();
    let upstream_req = builder.body(body).map_err(io::Error::other)?;

    match tokio::time::timeout(PROXY_TIMEOUT, state.client.request(upstream_req)).await {
        Ok(Ok(response)) => {
            let (mut parts, body) = response.into_parts();
            let mut headers = hyper::HeaderMap::new();
            for (name, value) in parts.headers.iter() {
                if name.as_str() == "host" || is_hop_by_hop(name.as_str()) {
                    continue;
                }
                // Keep absolute redirects on the loopback origin.
                if let ("location", Ok(text)) = (name.as_str(), value.to_str()) {
                    let rewritten = rewrite_location(text, origin);
                    if let Ok(header) = hyper::header::HeaderValue::from_str(&rewritten) {
                        headers.append(name, header);
                        continue;
                    }
                }
                headers.append(name, value.clone());
            }
            parts.headers = headers;
            Ok(Response::from_parts(parts, body.map_err(io::Error::other).boxed()))
        }
        Ok(Err(err)) => {
            tracing::warn!(authority = %origin.authority(), ?err, "upstream request failed");
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                &format!("could not reach the app at {}", origin.authority()),
                Some("make sure the app is still running on the server"),
            ))
        }
        Err(_) => Ok(error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
            &format!("the app at {} took too long to respond", origin.authority()),
            Some("it may be busy or stuck; try again"),
        )),
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// A path+query with query *values* removed, so tokens and API keys never
/// reach the log. Parameter names are kept, which is what makes a log useful
/// when debugging auth.
fn redact_query(path_and_query: &str) -> String {
    let Some((path, query)) = path_and_query.split_once('?') else {
        return path_and_query.to_string();
    };
    let redacted: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let name = pair.split('=').next().unwrap_or(pair);
            format!("{name}=…")
        })
        .collect();
    if redacted.is_empty() {
        format!("{path}?")
    } else {
        format!("{path}?{}", redacted.join("&"))
    }
}

/// The upstream base URL for an origin (`http://host:port`).
fn upstream_base(origin: &Origin) -> String {
    format!("{}://{}", origin.scheme.as_str(), origin.authority())
}

/// Whether a host string refers to the local machine (client loopback).
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Rewrite a client `Origin` header to the upstream origin.
///
/// The web view sends its loopback origin; apps that validate `Origin` against
/// their own host would otherwise reject state-changing requests.
fn rewrite_origin(value: &str, origin: &Origin) -> String {
    match url::Url::parse(value) {
        Ok(url) if url.host_str().is_some_and(is_loopback_host) => upstream_base(origin),
        _ => value.to_string(),
    }
}

/// Rewrite a client `Referer` to the upstream origin, keeping the path/query.
fn rewrite_referer(value: &str, origin: &Origin) -> String {
    match url::Url::parse(value) {
        Ok(url) if url.host_str().is_some_and(is_loopback_host) => {
            let mut out = upstream_base(origin);
            out.push_str(url.path());
            if let Some(query) = url.query() {
                out.push('?');
                out.push_str(query);
            }
            out
        }
        _ => value.to_string(),
    }
}

/// Rewrite an absolute `Location` that points back at the origin into a
/// relative one, so the client stays on the loopback origin instead of dialing
/// the machine's real address.
fn rewrite_location(value: &str, origin: &Origin) -> String {
    let Ok(url) = url::Url::parse(value) else {
        return value.to_string();
    };
    let Some(host) = url.host_str() else {
        return value.to_string();
    };
    let same_host = host.eq_ignore_ascii_case(&origin.host)
        || (is_loopback_host(host) && is_loopback_host(&origin.host));
    let same_port = url.port_or_known_default() == Some(origin.port);
    if !(same_host && same_port) {
        return value.to_string();
    }

    let mut out = url.path().to_string();
    if out.is_empty() {
        out.push('/');
    }
    if let Some(query) = url.query() {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<ResBody> {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full(body))
        .expect("static response is valid")
}

fn error_body(code: &str, message: &str, hint: Option<&str>) -> serde_json::Value {
    let mut value = serde_json::json!({ "error": message, "code": code });
    if let Some(hint) = hint {
        value["hint"] = serde_json::Value::String(hint.to_string());
    }
    value
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    hint: Option<&str>,
) -> Response<ResBody> {
    json_response(status, error_body(code, message, hint))
}

/// An error response that also ends the HTTP/1.1 connection, used for a
/// revocation that must end the accepted stream's serving session promptly.
fn error_response_with_close(status: StatusCode, code: &str, message: &str) -> Response<ResBody> {
    let body = serde_json::to_vec(&error_body(code, message, None)).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CONNECTION, "close")
        .body(full(body))
        .expect("static response is valid")
}

fn full(body: impl Into<Bytes>) -> ResBody {
    Full::new(body.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    #[test]
    fn redact_query_keeps_names_drops_values() {
        use super::redact_query;
        // Tokens and API keys ride in the query; the names still make a log
        // useful, the values must not be there.
        assert_eq!(redact_query("/socket?ApiKey=abc123"), "/socket?ApiKey=…");
        assert_eq!(
            redact_query("/x?a=1&b=2"),
            "/x?a=…&b=…"
        );
        // Also works on a whole URI, which is what the proxy logs.
        assert_eq!(
            redact_query("http://127.0.0.1:8096/socket?ApiKey=abc&x=1"),
            "http://127.0.0.1:8096/socket?ApiKey=…&x=…"
        );
        assert_eq!(redact_query("/plain"), "/plain");
        assert_eq!(redact_query("/?"), "/?");
    }

    use super::*;
    use std::time::Duration;

    fn test_node_id() -> EndpointId {
        iroh::SecretKey::from_bytes(&[7; 32]).public()
    }

    fn test_handler() -> ServeHandler {
        let config = Arc::new(RwLock::new(Config::default()));
        let catalog = Arc::new(RwLock::new(Catalog::empty()));
        let state = Arc::new(AppState::new(config, catalog, test_node_id()));
        let auth = Arc::new(AuthState::load(10).unwrap());
        ServeHandler::new(
            state,
            auth,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicUsize::new(0)),
            LimiterRegistry::new(),
        )
    }

    #[test]
    fn error_body_has_code_and_optional_hint() {
        let with_hint = error_body("unknown_app", "unknown app \"x\"", Some("refresh the list"));
        assert_eq!(with_hint["code"], "unknown_app");
        assert_eq!(with_hint["error"], "unknown app \"x\"");
        assert_eq!(with_hint["hint"], "refresh the list");

        let without_hint = error_body("not_found", "no such route", None);
        assert_eq!(without_hint["code"], "not_found");
        assert!(without_hint.get("hint").is_none());
    }

    #[test]
    fn catalog_json_carries_the_discovered_icon_and_omits_it_for_manual_apps() {
        use crate::catalog::Catalog;
        use crate::discovery::model::{DiscoveredApp, Origin};

        let catalog = Catalog::rebuild(
            &[],
            &[DiscoveredApp {
                origin: Origin::http("127.0.0.1", 3000),
                title: Some("My App".into()),
                icon: Some("/icons/app.png".into()),
                process: Some("node".into()),
                pid: Some(1),
            }],
        );
        let json = catalog_app_json(&catalog.apps()[0]);
        assert_eq!(json["name"], "my-app");
        assert_eq!(json["icon"], "/icons/app.png");

        // Manual apps are not probed, so they carry no icon (the client then
        // falls back to `/favicon.ico`).
        let manual = Catalog::rebuild(
            &[crate::config::AppConfig {
                name: "manual".into(),
                port: 8080,
            }],
            &[],
        );
        let json = catalog_app_json(&manual.apps()[0]);
        assert!(json["icon"].is_null());
    }

    #[test]
    fn rewrites_absolute_location_to_relative() {
        let origin = Origin::http("127.0.0.1", 8096);
        assert_eq!(
            rewrite_location("http://127.0.0.1:8096/web/index.html", &origin),
            "/web/index.html"
        );
        assert_eq!(rewrite_location("http://127.0.0.1:8096/", &origin), "/");
        assert_eq!(
            rewrite_location("http://127.0.0.1:8096/a?b=c#d", &origin),
            "/a?b=c#d"
        );
        // Loopback alias of the same host/port is also rewritten.
        assert_eq!(rewrite_location("http://localhost:8096/x", &origin), "/x");
        // Other host or port stays absolute.
        assert_eq!(
            rewrite_location("http://127.0.0.1:9999/x", &origin),
            "http://127.0.0.1:9999/x"
        );
        assert_eq!(
            rewrite_location("https://example.com/x", &origin),
            "https://example.com/x"
        );
        // Already-relative stays as-is.
        assert_eq!(rewrite_location("/already", &origin), "/already");
    }

    #[test]
    fn rewrites_location_for_lan_origin() {
        let origin = Origin::http("192.168.1.5", 8123);
        assert_eq!(
            rewrite_location("http://192.168.1.5:8123/panel", &origin),
            "/panel"
        );
        assert_eq!(
            rewrite_location("http://192.168.1.9:8123/panel", &origin),
            "http://192.168.1.9:8123/panel"
        );
    }

    #[test]
    fn rewrites_loopback_origin_and_referer() {
        let origin = Origin::http("127.0.0.1", 8096);
        assert_eq!(
            rewrite_origin("http://127.0.0.1:5523", &origin),
            "http://127.0.0.1:8096"
        );
        assert_eq!(
            rewrite_origin("http://localhost:1234", &origin),
            "http://127.0.0.1:8096"
        );
        // Non-loopback origins are left alone.
        assert_eq!(rewrite_origin("https://example.com", &origin), "https://example.com");
        assert_eq!(
            rewrite_referer("http://127.0.0.1:5523/web/index.html", &origin),
            "http://127.0.0.1:8096/web/index.html"
        );
    }

    #[test]
    fn node_limiter_concurrency_cap() {
        let limiter = NodeLimiter::new(2, 100, Duration::from_secs(1), 1000);
        let p1 = limiter.try_acquire_concurrency();
        assert!(p1.is_some());
        let p2 = limiter.try_acquire_concurrency();
        assert!(p2.is_some());
        let p3 = limiter.try_acquire_concurrency();
        assert!(p3.is_none());
        drop(p1);
        let p4 = limiter.try_acquire_concurrency();
        assert!(p4.is_some());
    }

    #[test]
    fn node_limiter_per_node_isolation() {
        let a = NodeLimiter::new(1, 100, Duration::from_secs(1), 1000);
        let b = NodeLimiter::new(1, 100, Duration::from_secs(1), 1000);
        assert!(a.try_acquire_concurrency().is_some());
        assert!(b.try_acquire_concurrency().is_some());
    }

    #[tokio::test]
    async fn node_limiter_rate_limit() {
        let limiter = NodeLimiter::new(100, 2, Duration::from_millis(50), 10);
        limiter.acquire_rate_token().await;
        limiter.acquire_rate_token().await;
        let start = std::time::Instant::now();
        limiter.acquire_rate_token().await;
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn serve_handler_get_or_create_limiter() {
        let handler = test_handler();
        let node_a = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let node_b = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let limiter_a1 = handler.get_or_create_limiter(node_a);
        let limiter_a2 = handler.get_or_create_limiter(node_a);
        let limiter_b = handler.get_or_create_limiter(node_b);
        assert!(Arc::ptr_eq(&limiter_a1, &limiter_a2));
        assert!(!Arc::ptr_eq(&limiter_a1, &limiter_b));
    }

    /// A client comes and goes constantly: reconnecting must reuse the one
    /// limiter for that node, never accumulate one per connection.
    #[test]
    fn reconnecting_reuses_one_limiter_per_node() {
        let handler = test_handler();
        let node = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let first = handler.get_or_create_limiter(node);
        for _ in 0..25 {
            let again = handler.get_or_create_limiter(node);
            assert!(Arc::ptr_eq(&first, &again));
        }
        assert_eq!(handler.limiters.len(), 1, "one entry per device identity");
    }

    /// Revoking a device drops its limiter: the identity is not authorized
    /// again, so holding it would leak for the daemon's lifetime.
    #[test]
    fn revoking_forgets_the_nodes_limiter() {
        let handler = test_handler();
        let revoked = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let kept = iroh::SecretKey::from_bytes(&[2; 32]).public();
        handler.get_or_create_limiter(revoked);
        let kept_limiter = handler.get_or_create_limiter(kept);
        assert_eq!(handler.limiters.len(), 2);

        handler.limiters.forget(revoked);
        assert_eq!(handler.limiters.len(), 1);
        // The other device keeps its limiter (and therefore its rate state).
        assert!(Arc::ptr_eq(
            &handler.get_or_create_limiter(kept),
            &kept_limiter
        ));
    }

    #[test]
    fn limiter_cache_invalidated_on_reload() {
        let config = Arc::new(RwLock::new(Config::default()));
        let catalog = Arc::new(RwLock::new(Catalog::empty()));
        let state = Arc::new(AppState::new(config.clone(), catalog, test_node_id()));
        let auth = Arc::new(AuthState::load(10).unwrap());
        let config_generation = Arc::new(AtomicU64::new(0));
        let handler = ServeHandler::new(
            state,
            auth,
            config_generation.clone(),
            Arc::new(AtomicUsize::new(0)),
            LimiterRegistry::new(),
        );

        let node = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let limiter1 = handler.get_or_create_limiter(node);

        // Simulate config reload
        config_generation.fetch_add(1, Ordering::Relaxed);
        let limiter2 = handler.get_or_create_limiter(node);

        // After reload, a new limiter should be created (old one dropped from cache)
        assert!(!Arc::ptr_eq(&limiter1, &limiter2));
    }
}
