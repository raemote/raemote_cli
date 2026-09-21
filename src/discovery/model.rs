//! Data types shared by the discovery pipeline.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Transport scheme used to reach a catalog app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    // Https is reserved for a future iteration (see discovery.https_probe).
}

impl Scheme {
    /// Lowercase scheme string for URLs.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
        }
    }
}

/// Where a catalog app lives. `host` is stored without brackets
/// (e.g. `127.0.0.1`, `::1`) so origins dedupe consistently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    /// Transport scheme.
    pub scheme: Scheme,
    /// Host without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Origin {
    /// An HTTP origin.
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme: Scheme::Http,
            host: host.into(),
            port,
        }
    }

    /// `host:port`, bracketing IPv6 literals for use in URLs.
    ///
    /// ```
    /// use raemote::discovery::model::Origin;
    ///
    /// assert_eq!(Origin::http("127.0.0.1", 3000).authority(), "127.0.0.1:3000");
    /// assert_eq!(Origin::http("::1", 3000).authority(), "[::1]:3000");
    /// ```
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Normalize a bound socket address into a locally reachable host string.
    ///
    /// Wildcard binds (`0.0.0.0` / `::`) map to IPv4 loopback; everything else
    /// (including a specific LAN IP the process chose to bind) is kept as-is.
    pub fn local_host(addr: SocketAddr) -> String {
        let ip = addr.ip();
        if ip.is_unspecified() {
            "127.0.0.1".to_string()
        } else {
            ip.to_string()
        }
    }

    /// Parse a `host:port` authority into an HTTP origin.
    ///
    /// IPv6 literals may be bracketed; `localhost` and wildcard hosts are
    /// normalized to `127.0.0.1` so they match how discovery reports origins.
    ///
    /// ```
    /// use raemote::discovery::model::Origin;
    ///
    /// assert_eq!(
    ///     Origin::parse_authority("127.0.0.1:10808").unwrap(),
    ///     Origin::http("127.0.0.1", 10808)
    /// );
    /// assert_eq!(Origin::parse_authority("localhost:3000").unwrap(), Origin::http("127.0.0.1", 3000));
    /// assert_eq!(Origin::parse_authority("[::1]:8080").unwrap(), Origin::http("::1", 8080));
    /// assert!(Origin::parse_authority("nope").is_none());
    /// ```
    pub fn parse_authority(s: &str) -> Option<Self> {
        let s = s.trim();
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, rest) = rest.split_once(']')?;
            (host.to_string(), rest.strip_prefix(':')?.parse::<u16>().ok()?)
        } else {
            let (host, port) = s.rsplit_once(':')?;
            (host.to_string(), port.parse::<u16>().ok()?)
        };
        if port == 0 || host.is_empty() {
            return None;
        }
        let host = match host.as_str() {
            "localhost" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
            other => other.to_string(),
        };
        Some(Origin::http(host, port))
    }
}

/// A locally discovered web app, before catalog naming/merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredApp {
    /// Where the app is reachable.
    pub origin: Origin,
    /// Page title, when the probe found one.
    pub title: Option<String>,
    /// Same-origin path of the page's declared icon, when one was found.
    pub icon: Option<String>,
    /// Owning process name, when known.
    pub process: Option<String>,
    /// Owning process id, when known.
    pub pid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_brackets_ipv6() {
        assert_eq!(Origin::http("127.0.0.1", 3000).authority(), "127.0.0.1:3000");
        assert_eq!(Origin::http("::1", 3000).authority(), "[::1]:3000");
    }

    #[test]
    fn local_host_normalizes_wildcard() {
        let v4: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(Origin::local_host(v4), "127.0.0.1");
        let v6: SocketAddr = "[::]:8080".parse().unwrap();
        assert_eq!(Origin::local_host(v6), "127.0.0.1");
        let lo: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(Origin::local_host(lo), "127.0.0.1");
        let lo6: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(Origin::local_host(lo6), "::1");
        let lan: SocketAddr = "192.168.1.5:8080".parse().unwrap();
        assert_eq!(Origin::local_host(lan), "192.168.1.5");
    }

    #[test]
    fn parse_authority_normalizes_and_rejects() {
        assert_eq!(
            Origin::parse_authority("127.0.0.1:10808").unwrap(),
            Origin::http("127.0.0.1", 10808)
        );
        assert_eq!(
            Origin::parse_authority(" localhost:3000 ").unwrap(),
            Origin::http("127.0.0.1", 3000)
        );
        assert_eq!(
            Origin::parse_authority("[::1]:8080").unwrap(),
            Origin::http("::1", 8080)
        );
        assert_eq!(
            Origin::parse_authority("0.0.0.0:5000").unwrap(),
            Origin::http("127.0.0.1", 5000)
        );
        // Missing host/port, zero port, and non-numeric port are all rejected.
        assert!(Origin::parse_authority("127.0.0.1").is_none());
        assert!(Origin::parse_authority("127.0.0.1:0").is_none());
        assert!(Origin::parse_authority(":8080").is_none());
        assert!(Origin::parse_authority("host:abc").is_none());
    }
}
