//! A bounded HTTP probe: confirms an origin serves HTTP and finds a display
//! name for it.
//!
//! The probe follows a few **same-origin redirects** (many apps redirect `/`),
//! reads the whole `<head>`, and prefers `<title>`, then common `<meta>` title
//! tags (`og:title`, `twitter:title`, `application-name`,
//! `apple-mobile-web-app-title`) — which catch single-page apps whose title is
//! set by JavaScript.
//!
//! It also resolves the best declared icon (`apple-touch-icon` first, then
//! `icon`/`shortcut icon`) to a **same-origin path**, so a client can fetch it
//! through the app's `/app/{name}` route. Raster icons are preferred over
//! `sizes="any"` (SVG) — see [`IconRel`].

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

use super::model::Origin;

/// Hard cap on how many bytes we read from a probe response.
const MAX_PROBE_BYTES: usize = 96 * 1024;
/// Stop reading the body once the head ends (or this much, whichever first).
const HEAD_READ_CAP: usize = 64 * 1024;
/// Follow at most this many same-origin redirects.
const MAX_REDIRECTS: usize = 3;
/// Longest name we keep.
const MAX_NAME_CHARS: usize = 120;

/// What a successful HTTP probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// HTTP status code from the final response line.
    pub status: u16,
    /// Display name (page title, else a meta title), normalized, when found.
    pub title: Option<String>,
    /// `Server` response header, when present.
    pub server: Option<String>,
    /// Same-origin path of the best declared icon (e.g. `/favicon.ico`,
    /// `/assets/icon.png`), resolved against the final document path. `None`
    /// when the page declares no icon.
    pub icon: Option<String>,
}

/// Probe `origin` with a bounded `GET /` (following same-origin redirects) and
/// decide whether it is an HTTP server. Returns `None` if it is not HTTP or the
/// total budget elapses.
///
/// Whatever arrived is parsed even if the peer keeps the socket open past the
/// budget, so a slow-but-real server is still classified.
pub async fn probe_http(origin: &Origin, budget: Duration) -> Option<ProbeResult> {
    let deadline = Instant::now() + budget;
    let mut path = "/".to_string();

    for _ in 0..=MAX_REDIRECTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let response = request(origin, &path, remaining).await?;

        if (300..400).contains(&response.status)
            && let Some(location) = response.location.as_deref()
            && let Some(next) = same_origin_path(origin, &path, location)
        {
            path = next;
            continue;
        }

        // Resolve the declared icon against the path this final response came
        // from (a redirect may move the document into a subdirectory).
        let icon = response
            .icon_href
            .as_deref()
            .and_then(|href| same_origin_path(origin, &path, href));

        return Some(ProbeResult {
            status: response.status,
            title: response.title,
            server: response.server,
            icon,
        });
    }

    None
}

/// One HTTP exchange, without redirect handling.
struct RawResponse {
    status: u16,
    location: Option<String>,
    server: Option<String>,
    title: Option<String>,
    /// Raw `href` of the best declared icon, before same-origin resolution.
    icon_href: Option<String>,
}

async fn request(origin: &Origin, path: &str, budget: Duration) -> Option<RawResponse> {
    let mut stream = match timeout_at(
        Instant::now() + budget,
        TcpStream::connect((origin.host.as_str(), origin.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return None,
    };

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: raemote-discovery/0.1\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        origin.authority()
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }

    let deadline = Instant::now() + budget;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut headers_done = false;

    loop {
        let n = match timeout_at(deadline, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            // Timeout or error: parse what we already have.
            _ => break,
        };
        buf.extend_from_slice(&tmp[..n]);

        if !headers_done && find_slice(&buf, b"\r\n\r\n").is_some() {
            headers_done = true;
        }
        if headers_done
            && (find_ci(&buf, b"</head").is_some()
                || find_ci(&buf, b"</html").is_some()
                || buf.len() >= HEAD_READ_CAP)
        {
            break;
        }
        if buf.len() >= MAX_PROBE_BYTES {
            break;
        }
    }

    parse_response(&buf)
}

fn parse_response(buf: &[u8]) -> Option<RawResponse> {
    let header_end = find_slice(buf, b"\r\n\r\n");
    let header_bytes = match header_end {
        Some(i) => &buf[..i],
        None => buf,
    };

    let text = String::from_utf8_lossy(header_bytes);
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;

    let mut server = None;
    let mut location = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if key.eq_ignore_ascii_case("server") {
                server = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("location") {
                location = Some(value.to_string());
            }
        }
    }

    let body = match header_end {
        Some(i) => &buf[i + 4..],
        None => buf,
    };

    Some(RawResponse {
        status,
        location,
        server,
        title: extract_name(body),
        icon_href: extract_icon(body),
    })
}

/// Resolve a URL (a redirect `Location` or an icon `href`) against the current
/// document path, but only within the same host and port (never make the
/// server fetch an arbitrary address). Scheme differences are ignored because
/// Raemote only speaks HTTP. Returns a path-and-query string starting with `/`.
fn same_origin_path(origin: &Origin, base_path: &str, location: &str) -> Option<String> {
    let base = format!(
        "{}://{}{}",
        origin.scheme.as_str(),
        origin.authority(),
        base_path
    );
    let target = url::Url::parse(&base).ok()?.join(location).ok()?;

    let host = target.host_str()?.trim_matches(|c| c == '[' || c == ']');
    if !host.eq_ignore_ascii_case(&origin.host) {
        return None;
    }
    if target.port_or_known_default() != Some(origin.port) {
        return None;
    }

    let mut path = target.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = target.query() {
        path.push('?');
        path.push_str(query);
    }
    Some(path)
}

/// Icon `rel` categories, in preference order (best first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconRel {
    /// `apple-touch-icon` / `apple-touch-icon-precomposed`: opaque, home-screen
    /// sized — the best match for a web-app icon.
    AppleTouchIcon,
    /// `icon` / `shortcut icon`: the general favicon.
    Icon,
}

/// Categorize a `rel` attribute (a space-separated token list, e.g.
/// `"shortcut icon"`). `mask-icon` (Safari pinned-tab, monochrome SVG) is
/// deliberately ignored.
fn rel_category(rel: &str) -> Option<IconRel> {
    let mut apple = false;
    let mut icon = false;
    for token in rel.split_whitespace() {
        if token.eq_ignore_ascii_case("apple-touch-icon")
            || token.eq_ignore_ascii_case("apple-touch-icon-precomposed")
        {
            apple = true;
        } else if token.eq_ignore_ascii_case("icon") {
            icon = true;
        }
    }
    if apple {
        Some(IconRel::AppleTouchIcon)
    } else if icon {
        Some(IconRel::Icon)
    } else {
        None
    }
}

/// Largest pixel area a `sizes` attribute declares. Missing `sizes` counts as
/// 1 (declared but unsized), while `any` (SVG) counts as 0 so a raster icon of
/// the same category wins — clients cannot rasterize SVG.
fn sizes_area(sizes: Option<&str>) -> u32 {
    let Some(sizes) = sizes else { return 1 };
    let mut best = 0;
    for part in sizes.split_whitespace() {
        if let Some((w, h)) = part.split_once(['x', 'X']) {
            let area = w.trim().parse::<u32>().unwrap_or(0) * h.trim().parse::<u32>().unwrap_or(0);
            best = best.max(area);
        }
    }
    best
}

/// The best declared icon `href` in an HTML byte slice: prefer
/// `apple-touch-icon`, then `icon`; within a category prefer the largest
/// `sizes` (raster over `any`).
fn extract_icon(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let mut best: Option<(IconRel, u32, String)> = None;
    let mut search = 0;

    while let Some(offset) = lower[search..].find("<link") {
        let start = search + offset;
        let Some(end) = text[start..].find('>').map(|i| start + i + 1) else {
            break;
        };
        let tag = &text[start..end];

        if let Some(rel) = attribute_value(tag, "rel")
            && let Some(category) = rel_category(&rel)
            && let Some(href) = attribute_value(tag, "href")
            && !href.trim().is_empty()
        {
            let area = sizes_area(attribute_value(tag, "sizes").as_deref());
            // Better than the current pick: a higher-preference category, or
            // the same category with a larger area.
            let better = match &best {
                None => true,
                Some((best_rel, best_area, _)) => {
                    category_rank(category) > category_rank(*best_rel)
                        || (category == *best_rel && area > *best_area)
                }
            };
            if better {
                best = Some((category, area, href));
            }
        }

        search = end;
    }

    best.map(|(_, _, href)| href)
}

/// Preference rank for an icon category (higher wins).
fn category_rank(category: IconRel) -> u8 {
    match category {
        IconRel::AppleTouchIcon => 1,
        IconRel::Icon => 0,
    }
}

/// Best available display name for the page: `<title>`, else a common meta
/// title. Many single-page apps set the title from JavaScript, so the static
/// HTML only carries an `og:title`.
fn extract_name(body: &[u8]) -> Option<String> {
    if let Some(title) = extract_title(body) {
        return Some(title);
    }
    const META_KEYS: &[&str] = &[
        "og:title",
        "twitter:title",
        "application-name",
        "apple-mobile-web-app-title",
    ];
    for key in META_KEYS {
        if let Some(content) = extract_meta_content(body, key)
            && let Some(name) = normalize_name(&content)
        {
            return Some(name);
        }
    }
    None
}

/// Extract the first `<title>` from an HTML byte slice.
fn extract_title(bytes: &[u8]) -> Option<String> {
    let open = find_ci(bytes, b"<title")?;
    let after_open = open + b"<title".len();
    let gt = bytes[after_open..].iter().position(|&b| b == b'>')? + after_open + 1;
    let close = find_ci(&bytes[gt..], b"</title")? + gt;
    normalize_name(&String::from_utf8_lossy(&bytes[gt..close]))
}

/// Extract the `content` of the first `<meta>` whose `name`/`property` is `key`.
fn extract_meta_content(body: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let mut search = 0;

    while let Some(offset) = lower[search..].find("<meta") {
        let start = search + offset;
        let end = text[start..].find('>').map(|i| start + i + 1)?;
        let tag = &text[start..end];

        let matches = attribute_value(tag, "name").is_some_and(|v| v.eq_ignore_ascii_case(key))
            || attribute_value(tag, "property").is_some_and(|v| v.eq_ignore_ascii_case(key));
        if matches
            && let Some(content) = attribute_value(tag, "content")
        {
            return Some(content);
        }

        search = end;
    }
    None
}

/// Value of `attr` in `tag`, handling single/double quotes and unquoted values.
fn attribute_value(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut search = 0;

    while let Some(offset) = lower[search..].find(attr) {
        let idx = search + offset;
        // Must be a standalone attribute: preceded by whitespace (or tag start).
        let preceded_by_space = tag[..idx]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);
        let rest = tag[idx + attr.len()..].trim_start();
        if preceded_by_space
            && let Some(after_eq) = rest.strip_prefix('=')
        {
            let after_eq = after_eq.trim_start();
            let value = match after_eq.chars().next() {
                Some(quote @ ('"' | '\'')) => {
                    after_eq[1..].split(quote).next().unwrap_or_default()
                }
                _ => after_eq.split_whitespace().next().unwrap_or_default(),
            };
            return Some(value.to_string());
        }
        search = idx + attr.len();
    }
    None
}

/// Collapse whitespace, trim, drop empties, and cap the length.
fn normalize_name(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = true;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
        if out.chars().count() >= MAX_NAME_CHARS {
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

/// Exact byte-slice search.
fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// ASCII case-insensitive byte-slice search (no allocation).
fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Serve canned responses by path (each request opens a new connection).
    async fn serve_routes(routes: Vec<(&'static str, &'static str)>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let response = routes
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map(|(_, r)| *r)
                    .unwrap_or("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><head><title>  My   App </title></head></html>";

    #[tokio::test]
    async fn probes_http_and_extracts_title() {
        let port = serve_routes(vec![("/", OK_RESPONSE)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.status, 200);
        assert_eq!(result.title.as_deref(), Some("My App"));
        assert_eq!(result.server.as_deref(), Some("nginx/1.25"));
    }

    #[tokio::test]
    async fn follows_redirect_to_a_titled_page() {
        let routes = vec![
            ("/", "HTTP/1.1 302 Found\r\nLocation: /web/\r\nContent-Length: 0\r\n\r\n"),
            (
                "/web/",
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\n\r\n<html><head><title>Jellyfin</title></head></html>",
            ),
        ];
        let port = serve_routes(routes).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1500))
            .await
            .expect("should probe");
        assert_eq!(result.status, 200);
        assert_eq!(result.title.as_deref(), Some("Jellyfin"));
    }

    #[tokio::test]
    async fn uses_og_title_when_there_is_no_title_element() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 90\r\n\r\n<html><head><meta property=\"og:title\" content=\"Vite + React\"></head><body></body></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.title.as_deref(), Some("Vite + React"));
    }

    #[tokio::test]
    async fn prefers_title_over_meta() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\n<html><head><title>Real</title><meta name=\"application-name\" content=\"Meta\"></head></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.title.as_deref(), Some("Real"));
    }

    #[tokio::test]
    async fn rejects_non_http() {
        let port = serve_routes(vec![("/", "GARBAGE NOT HTTP\r\n\r\n")]).await;
        let origin = Origin::http("127.0.0.1", port);
        assert!(probe_http(&origin, Duration::from_millis(1000))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn times_out_on_silent_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(sock);
            }
        });
        let origin = Origin::http("127.0.0.1", port);
        let start = Instant::now();
        assert!(probe_http(&origin, Duration::from_millis(150)).await.is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn no_server_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let origin = Origin::http("127.0.0.1", port);
        assert!(probe_http(&origin, Duration::from_millis(200)).await.is_none());
    }

    #[test]
    fn redirect_stays_on_the_same_origin() {
        let origin = Origin::http("127.0.0.1", 8096);
        assert_eq!(
            same_origin_path(&origin, "/", "/web/index.html").as_deref(),
            Some("/web/index.html")
        );
        assert_eq!(
            same_origin_path(&origin, "/", "http://127.0.0.1:8096/a?b=c").as_deref(),
            Some("/a?b=c")
        );
        // Different host or port is not followed.
        assert!(same_origin_path(&origin, "/", "http://evil.example/").is_none());
        assert!(same_origin_path(&origin, "/", "http://127.0.0.1:9999/").is_none());
    }

    #[test]
    fn extract_title_handles_case_and_empty() {
        assert_eq!(
            extract_title(b"<HTML><TITLE>Hello</TITLE>"),
            Some("Hello".to_string())
        );
        assert_eq!(extract_title(b"<title>   </title>"), None);
        assert_eq!(extract_title(b"no title here"), None);
    }

    #[test]
    fn attribute_value_handles_quoting() {
        assert_eq!(
            attribute_value("<meta content=\"a b\" name=\"og:title\">", "content").as_deref(),
            Some("a b")
        );
        assert_eq!(
            attribute_value("<meta name='x'>", "name").as_deref(),
            Some("x")
        );
        // Doesn't match a substring attribute like `data-name`.
        assert_eq!(attribute_value("<meta data-name=\"y\">", "name"), None);
    }

    #[tokio::test]
    async fn probe_resolves_a_relative_icon_path() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>A</title><link rel=\"icon\" href=\"/static/icon.png\"></head></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.icon.as_deref(), Some("/static/icon.png"));
    }

    #[tokio::test]
    async fn probe_prefers_apple_touch_icon_over_icon() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>A</title><link rel=\"icon\" href=\"/f.ico\"><link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/apple.png\"></head></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.icon.as_deref(), Some("/apple.png"));
    }

    #[tokio::test]
    async fn probe_prefers_the_largest_raster_icon_over_svg() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>A</title><link rel=\"icon\" sizes=\"any\" href=\"/icon.svg\"><link rel=\"icon\" sizes=\"32x32\" href=\"/small.png\"><link rel=\"icon\" sizes=\"180x180\" href=\"/big.png\"></head></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.icon.as_deref(), Some("/big.png"));
    }

    #[tokio::test]
    async fn probe_resolves_icon_against_the_redirected_path() {
        let routes = vec![
            ("/", "HTTP/1.1 302 Found\r\nLocation: /web/\r\nContent-Length: 0\r\n\r\n"),
            (
                "/web/",
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>A</title><link rel=\"icon\" href=\"icon.png\"></head></html>",
            ),
        ];
        let port = serve_routes(routes).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1500))
            .await
            .expect("should probe");
        assert_eq!(result.icon.as_deref(), Some("/web/icon.png"));
    }

    #[tokio::test]
    async fn probe_drops_a_cross_origin_icon() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>A</title><link rel=\"icon\" href=\"https://cdn.example/icon.png\"></head></html>";
        let port = serve_routes(vec![("/", response)]).await;
        let origin = Origin::http("127.0.0.1", port);
        let result = probe_http(&origin, Duration::from_millis(1000))
            .await
            .expect("should probe");
        assert_eq!(result.icon, None);
    }

    #[test]
    fn extract_icon_handles_shortcut_rel_and_no_declaration() {
        assert_eq!(
            extract_icon(b"<link rel=\"shortcut icon\" href=\"/f.ico\">").as_deref(),
            Some("/f.ico")
        );
        assert_eq!(
            extract_icon(b"<link rel=\"mask-icon\" href=\"/mask.svg\">"),
            None
        );
        assert_eq!(extract_icon(b"<html><head></head></html>"), None);
    }
}
