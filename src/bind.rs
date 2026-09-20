//! The pairing ALPN (`raemote/bind/0`).
//!
//! A client opens one stream, writes the pairing token, and reads `OK` or
//! `DENY <reason>`. The token is checked by [`crate::auth`]; the client's
//! identity is authenticated by the iroh handshake.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::AuthState;

/// ALPN for the binding phase: the only place a token is ever accepted.
pub const BIND_ALPN: &[u8] = b"raemote/bind/0";

/// Maximum bytes accepted in a bind request (token line).
const MAX_BIND_REQUEST: usize = 512;
/// How long to keep the connection up after replying, so the reply is
/// guaranteed to reach the client even if it never closes promptly.
const FINISH_GRACE: Duration = Duration::from_secs(5);
/// Maximum time to wait for the client to send its token line.
const BIND_TIMEOUT: Duration = Duration::from_secs(10);
/// Default max concurrent bind connections, used by the daemon when the
/// configured `bind.max_concurrent_connections` value applies (the daemon
/// wires `RAEMOTE_MAX_BIND_CONNECTIONS`/config.toml at start; see daemon.rs).
pub const DEFAULT_MAX_BIND_CONNECTIONS: usize = 50;

/// Handler for [`BIND_ALPN`].
///
/// One bidirectional stream per connection carrying a plain-text workflow:
/// the client writes the token as a single line, the server answers
/// `OK` or `DENY <reason>`. The whole exchange happens inside the
/// end-to-end encrypted iroh connection, and the client's node ID is
/// authenticated by the QUIC/TLS handshake, so it cannot be spoofed.
#[derive(Debug)]
pub struct BindHandler {
    auth: Arc<AuthState>,
    concurrency: Arc<Semaphore>,
}

impl BindHandler {
    /// Build a bind handler over shared auth with a concurrency cap.
    pub fn new(auth: Arc<AuthState>, max_concurrent: usize) -> Self {
        Self {
            auth,
            concurrency: Arc::new(Semaphore::new(max_concurrent)),
        }
    }
}

impl ProtocolHandler for BindHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // 1. Concurrency cap: reject immediately if at capacity.
        let _permit: OwnedSemaphorePermit = match self.concurrency.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    node = %connection.remote_id().fmt_short(),
                    "rejecting bind: too many concurrent bind connections"
                );
                connection.close(
                    iroh::endpoint::VarInt::from_u32(503),
                    b"too many bind connections",
                );
                return Ok(());
            }
        };

        let node = connection.remote_id();

        // 2. Timeout the entire exchange (accept_bi + read_to_end).
        let result = tokio::time::timeout(BIND_TIMEOUT, async {
            let (mut send, mut recv) = connection.accept_bi().await?;

            let data = recv
                .read_to_end(MAX_BIND_REQUEST)
                .await
                .map_err(AcceptError::from_err)?;
            let presented = String::from_utf8_lossy(&data);
            let presented = presented.trim();
            tracing::info!(
                node = %node.fmt_short(),
                token_len = presented.len(),
                "bind token received"
            );

            let outcome = self.auth.authenticate(node, presented);
            let reply = if outcome.is_allowed() {
                "OK\n".to_string()
            } else {
                format!("DENY {}\n", outcome.deny_reason())
            };
            send.write_all(reply.as_bytes())
                .await
                .map_err(AcceptError::from_err)?;
            send.finish()?;

            // Hold the connection open until the client has the reply (or grace
            // expires) so dropping the connection cannot discard unacked data.
            let _ = tokio::time::timeout(FINISH_GRACE, connection.closed()).await;

            if outcome.is_allowed() {
                tracing::info!(node = %node.fmt_short(), ?outcome, "bind accepted");
            } else {
                tracing::warn!(node = %node.fmt_short(), ?outcome, "bind denied");
            }
            Ok::<(), AcceptError>(())
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                tracing::warn!(
                    node = %node.fmt_short(),
                    "bind timed out after {BIND_TIMEOUT:?}"
                );
                connection.close(
                    iroh::endpoint::VarInt::from_u32(408),
                    b"bind timeout",
                );
                Ok(())
            }
        }
    }
}
