//! Minimal dev client with a persistent identity (`~/.raemote/client.key`).
//!
//! Usage:
//!   cargo run --example client -- bind <node-id> <token>
//!   cargo run --example client -- bind <raemote://bind?... URI>
//!   cargo run --example client -- get <node-id> [path]
//!   cargo run --example client -- request <node-id> <METHOD> <path> [json-body]
//!
//! `bind` authorizes this client's node ID on the server (multi-use token,
//! valid until it expires). `get`/`request` then issue plain HTTP requests over
//! the serve ALPN. All commands reuse the same persistent key so the node ID —
//! and thus the authorization — survives across runs.

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh::endpoint::presets;
use iroh::SecretKey;
use iroh::Endpoint;

const SERVE_ALPN: &[u8] = b"raemote/0";
const BIND_ALPN: &[u8] = b"raemote/bind/0";

#[tokio::main]
async fn main() -> Result<()> {
    // Optional `--key <path>` (or RAEMOTE_CLIENT_KEY) lets two identities run
    // at once, which is how the invitation flow is tested end to end.
    let mut argv: Vec<String> = env::args().skip(1).collect();
    let mut key_path: Option<PathBuf> = std::env::var_os("RAEMOTE_CLIENT_KEY").map(PathBuf::from);
    if let Some(pos) = argv.iter().position(|arg| arg == "--key") {
        if pos + 1 >= argv.len() {
            anyhow::bail!("--key needs a path");
        }
        key_path = Some(PathBuf::from(argv.remove(pos + 1)));
        argv.remove(pos);
    }

    let mut args = argv.into_iter();
    let command = args.next().context(usage())?;

    let secret_key = load_or_create_client_key(key_path.as_deref())?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await?;
    println!("client node id: {}", endpoint.id());

    match command.as_str() {
        "bind" => {
            let arg = args.next().context(usage())?;
            let (node, token) = if arg.starts_with("raemote://") {
                parse_bind_uri(&arg)?
            } else {
                let token = args.next().context("bind needs a token")?;
                (parse_node(&arg)?, token)
            };
            bind(&endpoint, node, &token).await
        }
        "get" => {
            let node = args.next().context(usage())?;
            let path = args
                .next()
                .unwrap_or_else(|| "/_hub/catalog".to_string());
            request(&endpoint, parse_node(&node)?, "GET", &path, None, &[]).await
        }
        "request" => {
            let node = args.next().context(usage())?;
            let method = args.next().unwrap_or_else(|| "GET".to_string());
            let path = args.next().unwrap_or_else(|| "/".to_string());
            // "-" means no body; remaining args are extra "Header: value" lines.
            let body_arg = args.next();
            let body = body_arg.as_deref().filter(|b| *b != "-");
            let headers: Vec<String> = args.collect();
            request(
                &endpoint,
                parse_node(&node)?,
                &method,
                &path,
                body,
                &headers,
            )
            .await
        }
        "ws" => {
            let node = args.next().context(usage())?;
            let path = args.next().unwrap_or_else(|| "/app/app/socket".to_string());
            // `--idle <secs>` holds the socket open afterwards and reports
            // whether it survived, which is what a long-lived WebSocket
            // (Jellyfin's `/socket`) needs from the tunnel.
            let rest: Vec<String> = args.by_ref().collect();
            let idle = rest
                .iter()
                .position(|arg| arg == "--idle")
                .and_then(|i| rest.get(i + 1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            ws(&endpoint, parse_node(&node)?, &path, idle).await
        }
        _ => Err(anyhow::anyhow!(usage())),
    }
}

async fn bind(endpoint: &Endpoint, node: EndpointId, token: &str) -> Result<()> {
    let connection = endpoint
        .connect(node, BIND_ALPN)
        .await
        .context("failed to connect")?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(format!("{token}\n").as_bytes())
        .await
        .context("failed to send token")?;
    send.finish()?;

    let reply = recv
        .read_to_end(1024)
        .await
        .context("failed to read bind reply")?;
    print!("{}", String::from_utf8_lossy(&reply));
    Ok(())
}

async fn ws(endpoint: &Endpoint, node: EndpointId, path: &str, idle: u64) -> Result<()> {
    let connection = endpoint
        .connect(node, SERVE_ALPN)
        .await
        .context("failed to connect")?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // RFC 6455 handshake (key from the RFC example).
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: raemote\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    send.write_all(request.as_bytes()).await?;

    // Read the response head.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = recv.read(&mut tmp).await?.unwrap_or(0);
        if n == 0 {
            anyhow::bail!("connection closed during handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            println!("--- handshake ---\n{}", String::from_utf8_lossy(&buf[..pos + 4]));
            buf = buf[pos + 4..].to_vec();
            break;
        }
    }

    // Send a masked text frame "hello".
    let payload = b"hello";
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut frame = vec![0x81u8, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }
    send.write_all(&frame).await?;

    // With --idle, skip the echo expectation: just watch the socket and report
    // whether it is still open when the timer runs out.
    if idle > 0 {
        let start = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(idle);
        loop {
            match tokio::time::timeout_at(deadline, recv.read(&mut tmp)).await {
                Err(_) => {
                    println!("--- idle ---\nstill open after {idle}s");
                    break;
                }
                Ok(Ok(Some(0))) | Ok(Ok(None)) => {
                    println!("--- idle ---\nCLOSED after {:.1}s", start.elapsed().as_secs_f64());
                    break;
                }
                Ok(Ok(Some(n))) => {
                    println!("--- idle ---\nreceived {n} bytes at {:.1}s", start.elapsed().as_secs_f64());
                }
                Ok(Err(err)) => {
                    println!("--- idle ---\nERROR after {:.1}s: {err}", start.elapsed().as_secs_f64());
                    break;
                }
            }
        }
        send.finish()?;
        return Ok(());
    }

    // Read the (unmasked) echo frame.
    while buf.len() < 2 {
        let n = recv.read(&mut tmp).await?.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf.len() >= 2 {
        let len = (buf[1] & 0x7f) as usize;
        while buf.len() < 2 + len {
            let n = recv.read(&mut tmp).await?.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if buf.len() >= 2 + len {
            println!("--- echo ---\n{}", String::from_utf8_lossy(&buf[2..2 + len]));
        }
    }

    send.finish()?;
    Ok(())
}

async fn request(
    endpoint: &Endpoint,
    node: EndpointId,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra_headers: &[String],
) -> Result<()> {
    let connection = endpoint
        .connect(node, SERVE_ALPN)
        .await
        .context("failed to connect")?;
    let (mut send, mut recv) = connection.open_bi().await?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: raemote\r\nConnection: close\r\nAccept: */*\r\n"
    );
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for header in extra_headers {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }

    send.write_all(request.as_bytes())
        .await
        .context("failed to send request")?;
    send.finish()?;

    let body = recv
        .read_to_end(8 * 1024 * 1024)
        .await
        .context("failed to read response (is this client bound?)")?;
    println!("{}", String::from_utf8_lossy(&body));
    Ok(())
}

/// `raemote://bind?node=<id>&token=<hex>&exp=<unix>`
fn parse_bind_uri(uri: &str) -> Result<(EndpointId, String)> {
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

fn load_or_create_client_key(explicit: Option<&Path>) -> Result<SecretKey> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => client_key_path()?,
    };
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
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, key.to_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(key)
    }
}

fn client_key_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".raemote").join("client.key"))
}

fn usage() -> String {
    "usage: client bind <node-id> <token> | client bind <raemote://bind?...> | client get <node-id> [path] | client request <node-id> <METHOD> <path> [json-body|-] [Header: value]... | client ws <node-id> <path> [--idle <secs>]   [--key <path>]".to_string()
}
