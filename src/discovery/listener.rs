//! Enumerating and filtering the OS listening-socket table.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::model::Origin;
use super::proc_sockets;

/// A candidate origin plus the process that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The listening origin.
    pub origin: Origin,
    /// Owning process name, when known.
    pub process: Option<String>,
    /// Owning process id, when known.
    pub pid: Option<u32>,
}

/// Filter applied to the OS listening-socket table.
#[derive(Debug, Clone)]
pub struct ListenerFilter {
    /// Ignore ports below this value.
    pub min_port: u16,
    /// Only keep loopback/wildcard binds.
    pub loopback_only: bool,
    /// Ports to skip (built-in denylist plus user excludes).
    pub exclude_ports: HashSet<u16>,
    /// Process names to skip (lowercased).
    pub exclude_processes: HashSet<String>,
    /// Origins to skip entirely (built-in none, user-configured).
    pub exclude_origins: HashSet<Origin>,
}

impl ListenerFilter {
    /// Build a filter, folding in the built-in denylists and lowercasing
    /// process names.
    pub fn new(
        min_port: u16,
        loopback_only: bool,
        exclude_ports: &[u16],
        exclude_processes: &[String],
        exclude_origins: &[String],
    ) -> Self {
        Self {
            min_port,
            loopback_only,
            // Ports that can never be a user web app.
            exclude_ports: BUILTIN_EXCLUDE_PORTS
                .iter()
                .copied()
                .chain(exclude_ports.iter().copied())
                .collect(),
            exclude_processes: BUILTIN_EXCLUDE_PROCESSES
                .iter()
                .map(|p| p.to_ascii_lowercase())
                .chain(exclude_processes.iter().map(|p| p.to_ascii_lowercase()))
                .collect(),
            exclude_origins: exclude_origins
                .iter()
                .filter_map(|s| {
                    let origin = Origin::parse_authority(s);
                    if origin.is_none() {
                        tracing::warn!(
                            value = %s,
                            "ignoring invalid discovery.exclude_origins entry (expected host:port)"
                        );
                    }
                    origin
                })
                .collect(),
        }
    }
}

/// Ports that are never exposed: remote-access, databases, printers, etc.
pub const BUILTIN_EXCLUDE_PORTS: &[u16] = &[
    22,    // ssh
    25,    // smtp
    53,    // dns
    88,    // kerberos
    110,   // pop3
    111,   // rpcbind
    135,   // msrpc
    137, 138, 139, // netbios
    143,   // imap
    161, 162, // snmp
    389,   // ldap
    445,   // smb
    465,   // smtps
    514,   // syslog
    515,   // lpd
    548,   // afp
    587,   // submission
    631,   // ipp
    636,   // ldaps
    873,   // rsync
    993,   // imaps
    995,   // pop3s
    1080,  // socks
    1433,  // mssql
    1521,  // oracle
    1723,  // pptp
    2049,  // nfs
    2375, 2376, // docker daemon
    3306,  // mysql
    3389,  // rdp
    5000,  // airplay receiver
    5353,  // mdns
    5432,  // postgres
    5900,  // vnc
    6379,  // redis
    7000,  // airplay
    9200, 9300, // elasticsearch
    27017, // mongodb
];

/// Local forward-proxy / tunnel processes that open a listening socket but are
/// not user web apps.
///
/// Deliberately conservative: only names that are essentially always a proxy or
/// tunnel. `docker-proxy` is intentionally **not** listed, because Docker
/// publishes real web apps through it. `raemote`/`raemoted` are Raemote's own
/// control-plane binaries — critically, the local listeners of `raemote
/// connect` (its index and per-app ports), which proxy rather than serve: if
/// they were catalogued, a connector running on the server machine would see
/// its own ports appear as new apps and bind listeners for those in turn, a
/// loop that grows every discovery cycle.
pub const BUILTIN_EXCLUDE_PROCESSES: &[&str] = &[
    "raemote",
    "raemoted",
    "xray",
    "v2ray",
    "v2ray-core",
    "sing-box",
    "clash",
    "clash-meta",
    "mihomo",
    "shadowsocks",
    "ss-local",
    "ssserver",
    "ss-tunnel",
    "trojan",
    "trojan-go",
    "hysteria",
    "hysteria2",
    "naive",
    "tun2socks",
    "mitmproxy",
    "mitmdump",
    "privoxy",
    "squid",
    "tinyproxy",
    "3proxy",
    "tor",
];

/// Enumerate locally-listening TCP sockets and filter them down to plausible
/// web-app candidates. Blocking (OS calls); call via `spawn_blocking`.
///
/// `include_unattributed` folds in listening sockets whose owning process we
/// can't read (see `merge_unattributed`); without it, a root-owned service like
/// a system `nginx` is invisible.
pub fn enumerate(
    filter: &ListenerFilter,
    include_unattributed: bool,
) -> Result<FilterOutcome> {
    let all: Vec<listeners::Listener> = listeners::get_all()
        .map_err(|e| anyhow::anyhow!("failed to enumerate listeners: {e}"))?
        .into_iter()
        .collect();
    let all = if include_unattributed {
        merge_unattributed(all, proc_sockets::listening_tcp())
    } else {
        all
    };
    Ok(filter_listeners_detailed(&all, filter))
}

/// Why a listening socket did not become a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Below `discovery.min_port`.
    BelowMinPort,
    /// On the built-in denylist or `discovery.exclude_ports`.
    ExcludedPort,
    /// On the built-in denylist or `discovery.exclude_processes`.
    ExcludedProcess,
    /// Bound to a specific address rather than loopback/wildcard, while
    /// `discovery.loopback_only` is on.
    NotLocalBind,
    /// On `discovery.exclude_origins`.
    ExcludedOrigin,
    /// Another socket already produced this origin.
    Duplicate,
    /// The HTTP probe got an error status and no page title.
    NotCredible,
    /// The HTTP probe got no usable response at all.
    Unreachable,
}

impl SkipReason {
    /// A short, user-facing explanation.
    pub fn describe(self) -> &'static str {
        match self {
            Self::BelowMinPort => "below discovery.min_port",
            Self::ExcludedPort => "port on the denylist",
            Self::ExcludedProcess => "process on the denylist",
            Self::NotLocalBind => "bound to a specific address (discovery.loopback_only)",
            Self::ExcludedOrigin => "on discovery.exclude_origins",
            Self::Duplicate => "duplicate origin",
            Self::NotCredible => "no usable page (error page, or an error status)",
            Self::Unreachable => "not HTTP / unreachable",
        }
    }
}

/// A listening socket that was considered and skipped, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// `host:port` of the socket.
    pub origin: String,
    /// Owning process, when it could be read.
    pub process: Option<String>,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// What a filtering pass produced: the candidates, and why the rest were
/// dropped. Only listening TCP sockets are reported — every established
/// connection would otherwise drown the list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterOutcome {
    /// Sockets worth probing.
    pub candidates: Vec<Candidate>,
    /// Listening sockets that were dropped, sorted by port.
    pub skipped: Vec<Skipped>,
}

/// Add listening sockets that `listeners` could not attribute to a process.
///
/// The synthetic entries carry no process name and no pid, so the process
/// denylist cannot apply to them — but every other filter (port, bind, origin
/// excludes) and the HTTP probe still do, and a missing process name costs
/// nothing when the probe finds a page title.
pub fn merge_unattributed(
    mut attributed: Vec<listeners::Listener>,
    extra: Vec<SocketAddr>,
) -> Vec<listeners::Listener> {
    let known: HashSet<SocketAddr> = attributed.iter().map(|l| l.socket).collect();
    attributed.extend(
        extra
            .into_iter()
            .filter(|socket| !known.contains(socket))
            .map(|socket| listeners::Listener {
                process: listeners::Process {
                    pid: 0,
                    name: String::new(),
                    path: String::new(),
                },
                socket,
                protocol: listeners::Protocol::TCP,
                state: listeners::SocketState::Listen,
            }),
    );
    attributed
}

/// Pure filtering step, split out for testing without OS access.
pub fn filter_listeners(
    all: &[listeners::Listener],
    filter: &ListenerFilter,
) -> Vec<Candidate> {
    filter_listeners_detailed(all, filter).candidates
}

/// The same filter, also reporting why each listening socket was dropped.
pub fn filter_listeners_detailed(
    all: &[listeners::Listener],
    filter: &ListenerFilter,
) -> FilterOutcome {
    let mut seen: HashSet<Origin> = HashSet::new();
    let mut out = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();

    for l in all {
        if l.protocol != listeners::Protocol::TCP {
            continue;
        }
        if l.state != listeners::SocketState::Listen {
            continue;
        }
        let process_name = l.process.name.trim();
        let process = (!process_name.is_empty()).then(|| process_name.to_string());
        let skip = |reason: SkipReason, skipped: &mut Vec<Skipped>| {
            skipped.push(Skipped {
                origin: l.socket.to_string(),
                process: process.clone(),
                reason,
            });
        };

        let port = l.socket.port();
        if port == 0 {
            continue;
        }
        if port < filter.min_port {
            skip(SkipReason::BelowMinPort, &mut skipped);
            continue;
        }
        if filter.exclude_ports.contains(&port) {
            skip(SkipReason::ExcludedPort, &mut skipped);
            continue;
        }
        if let Some(name) = process.as_deref()
            && filter.exclude_processes.contains(&name.to_ascii_lowercase())
        {
            skip(SkipReason::ExcludedProcess, &mut skipped);
            continue;
        }
        if filter.loopback_only && !is_local_bind(&l.socket) {
            skip(SkipReason::NotLocalBind, &mut skipped);
            continue;
        }

        let origin = Origin::http(Origin::local_host(l.socket), port);
        if filter.exclude_origins.contains(&origin) {
            skip(SkipReason::ExcludedOrigin, &mut skipped);
            continue;
        }
        if !seen.insert(origin.clone()) {
            skip(SkipReason::Duplicate, &mut skipped);
            continue;
        }
        out.push(Candidate {
            origin,
            process,
            // An unattributed socket (see `merge_unattributed`) has pid 0.
            pid: (l.process.pid != 0).then_some(l.process.pid),
        });
    }

    // Deterministic order (by port) so names/catalog stay stable across scans.
    out.sort_by(|a, b| a.origin.port.cmp(&b.origin.port));
    skipped.sort_by_key(|s| s.origin.clone());
    FilterOutcome {
        candidates: out,
        skipped,
    }
}

fn is_local_bind(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback() || addr.ip().is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use listeners::{Listener, Process, Protocol, SocketState};

    fn listener(addr: &str, proto: Protocol, state: SocketState, name: &str) -> Listener {
        Listener {
            process: Process {
                pid: 42,
                name: name.to_string(),
                path: String::new(),
            },
            socket: addr.parse().unwrap(),
            protocol: proto,
            state,
        }
    }

    fn filter() -> ListenerFilter {
        ListenerFilter::new(1024, true, &[], &[], &[])
    }

    #[test]
    fn keeps_normal_loopback_http_port() {
        let all = vec![listener(
            "127.0.0.1:5173",
            Protocol::TCP,
            SocketState::Listen,
            "node",
        )];
        let got = filter_listeners(&all, &filter());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].origin.host, "127.0.0.1");
        assert_eq!(got[0].origin.port, 5173);
        assert_eq!(got[0].process.as_deref(), Some("node"));
    }

    #[test]
    fn merge_keeps_unattributed_sockets_without_a_process() {
        // What an unreadable (e.g. root-owned) listener looks like: the socket
        // is in the table, no process could be attributed to it.
        let merged = merge_unattributed(
            vec![listener("127.0.0.1:5173", Protocol::TCP, SocketState::Listen, "node")],
            vec![
                "0.0.0.0:8080".parse().unwrap(),
                // Already attributed — must not be duplicated.
                "127.0.0.1:5173".parse().unwrap(),
            ],
        );
        let got = filter_listeners(&merged, &filter());
        assert_eq!(got.len(), 2);

        let nginx_like = got.iter().find(|c| c.origin.port == 8080).unwrap();
        assert_eq!(nginx_like.origin.host, "127.0.0.1");
        assert_eq!(nginx_like.process, None);
        assert_eq!(nginx_like.pid, None);

        let node = got.iter().find(|c| c.origin.port == 5173).unwrap();
        assert_eq!(node.process.as_deref(), Some("node"));
        assert_eq!(node.pid, Some(42));
    }

    #[test]
    fn unattributed_sockets_still_respect_the_bind_filter() {
        // A LAN-only bind is excluded whether or not we know its process.
        let merged = merge_unattributed(vec![], vec!["192.168.1.5:8080".parse().unwrap()]);
        assert!(filter_listeners(&merged, &filter()).is_empty());
    }

    #[test]
    fn skips_non_tcp_non_listen_and_zero_port() {
        let all = vec![
            listener("127.0.0.1:5173", Protocol::UDP, SocketState::Unknown, "x"),
            listener("127.0.0.1:5174", Protocol::TCP, SocketState::Established, "x"),
            listener("127.0.0.1:0", Protocol::TCP, SocketState::Listen, "x"),
        ];
        assert!(filter_listeners(&all, &filter()).is_empty());
    }

    #[test]
    fn skips_low_and_denylisted_ports() {
        let all = vec![
            listener("127.0.0.1:80", Protocol::TCP, SocketState::Listen, "x"),
            listener("127.0.0.1:3306", Protocol::TCP, SocketState::Listen, "mysql"),
        ];
        assert!(filter_listeners(&all, &filter()).is_empty());
    }

    #[test]
    fn skips_excluded_process() {
        let f = ListenerFilter::new(1024, true, &[], &["node".to_string()], &[]);
        let all = vec![listener(
            "127.0.0.1:5173",
            Protocol::TCP,
            SocketState::Listen,
            "Node",
        )];
        assert!(filter_listeners(&all, &f).is_empty());
    }

    #[test]
    fn loopback_only_skips_lan_bind() {
        let all = vec![listener(
            "192.168.1.5:8000",
            Protocol::TCP,
            SocketState::Listen,
            "x",
        )];
        assert!(filter_listeners(&all, &filter()).is_empty());

        // ...but is kept when loopback_only is off.
        let f = ListenerFilter::new(1024, false, &[], &[], &[]);
        let got = filter_listeners(&all, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].origin.host, "192.168.1.5");
    }

    #[test]
    fn skips_builtin_proxy_process() {
        let all = vec![listener(
            "127.0.0.1:10808",
            Protocol::TCP,
            SocketState::Listen,
            "xray",
        )];
        assert!(filter_listeners(&all, &filter()).is_empty());
    }

    #[test]
    fn skips_raemote_connect_listeners() {
        // The connector's own index and per-app ports must never be
        // catalogued: a `raemote connect` running on the server machine would
        // otherwise see its own listeners appear as new apps and bind
        // listeners for those in turn — a loop growing every discovery cycle.
        let all = vec![
            listener("127.0.0.1:7793", Protocol::TCP, SocketState::Listen, "raemote"),
            listener("127.0.0.1:7790", Protocol::TCP, SocketState::Listen, "raemote"),
            listener("127.0.0.1:5173", Protocol::TCP, SocketState::Listen, "node"),
        ];
        let got = filter_listeners(&all, &filter());
        assert_eq!(got.len(), 1, "only the real web app survives");
        assert_eq!(got[0].origin.port, 5173);
    }

    #[test]
    fn skips_excluded_origin() {
        let f = ListenerFilter::new(1024, true, &[], &[], &["127.0.0.1:10808".to_string()]);
        let all = vec![
            listener("127.0.0.1:10808", Protocol::TCP, SocketState::Listen, "x"),
            listener("127.0.0.1:3000", Protocol::TCP, SocketState::Listen, "x"),
        ];
        let got = filter_listeners(&all, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].origin.port, 3000);
    }

    #[test]
    fn excluded_origin_host_is_normalized() {
        // A wildcard bind is reported as 127.0.0.1, so excluding localhost works.
        let f = ListenerFilter::new(1024, true, &[], &[], &["localhost:8000".to_string()]);
        let all = vec![listener(
            "0.0.0.0:8000",
            Protocol::TCP,
            SocketState::Listen,
            "x",
        )];
        assert!(filter_listeners(&all, &f).is_empty());
    }

    #[test]
    fn dedupes_wildcard_v4_and_v6() {
        let all = vec![
            listener("0.0.0.0:8000", Protocol::TCP, SocketState::Listen, "x"),
            listener("[::]:8000", Protocol::TCP, SocketState::Listen, "x"),
        ];
        let got = filter_listeners(&all, &filter());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].origin.host, "127.0.0.1");
    }
}
