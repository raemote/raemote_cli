//! Local web-app discovery.
//!
//! [`DiscoveryEngine`] periodically enumerates the OS listening-socket table,
//! filters candidate web servers, probes them over HTTP, and publishes the
//! result to a [`crate::catalog::Catalog`].

pub mod listener;
pub mod model;
pub mod probe;
pub mod proc_sockets;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::catalog::Catalog;
use crate::config::Config;

use listener::{ListenerFilter, SkipReason, Skipped};
use model::{DiscoveredApp, Origin};

/// A verified app plus when we last confirmed it.
struct CachedApp {
    app: DiscoveredApp,
    last_verified: Instant,
}

/// Background discovery loop.
///
/// Each cycle enumerates the OS listening-socket table (cheap) and only probes
/// origins that are new or whose `recheck_secs` TTL has lapsed. The catalog is
/// rebuilt only when the set/identity of apps changes.
pub struct DiscoveryEngine {
    config: Arc<RwLock<Config>>,
    catalog: Arc<RwLock<Catalog>>,
    trigger: Arc<Notify>,
    shutdown: Arc<Notify>,
    /// Bumped after every catalog rebuild; lets callers wait for a scan.
    catalog_generation: Arc<AtomicU64>,
    /// Why the most recent scan skipped each listening socket, for
    /// `raemote discover --verbose`.
    last_scan: Arc<RwLock<Vec<Skipped>>>,
    cache: HashMap<Origin, CachedApp>,
}

impl DiscoveryEngine {
    /// Build an engine over shared config and catalog.
    pub fn new(
        config: Arc<RwLock<Config>>,
        catalog: Arc<RwLock<Catalog>>,
        trigger: Arc<Notify>,
        shutdown: Arc<Notify>,
        catalog_generation: Arc<AtomicU64>,
        last_scan: Arc<RwLock<Vec<Skipped>>>,
    ) -> Self {
        Self {
            config,
            catalog,
            trigger,
            shutdown,
            catalog_generation,
            last_scan,
            cache: HashMap::new(),
        }
    }

    /// Run until shutdown. Respects `discovery.enabled` at every cycle, so it
    /// can be toggled via config reload without restarting the task.
    pub async fn run(mut self) {
        // Scan immediately so apps appear at startup rather than only after a
        // full `interval_secs`.
        self.scan_once().await;
        loop {
            let interval_secs = {
                let cfg = self.config.read().expect("config poisoned");
                cfg.discovery.interval_secs.max(1)
            };
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = self.trigger.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
            }
            self.scan_once().await;
        }
    }

    /// Run a single discovery cycle.
    pub async fn scan_once(&mut self) {
        let (enabled, filter, include_unattributed, probe_timeout, max_concurrent, recheck) = {
            let cfg = self.config.read().expect("config poisoned");
            let d = &cfg.discovery;
            (
                d.enabled,
                ListenerFilter::new(
                    d.min_port,
                    d.loopback_only,
                    &d.exclude_ports,
                    &d.exclude_processes,
                    &d.exclude_origins,
                ),
                d.include_unattributed,
                Duration::from_millis(d.probe_timeout_ms.max(1)),
                d.max_concurrent_probes.max(1),
                Duration::from_secs(d.recheck_secs.max(1)),
            )
        };

        if !enabled {
            self.cache.clear();
            self.rebuild_catalog();
            return;
        }

        // Enumeration is blocking (OS calls); keep it off the async runtime.
        let outcome = match tokio::task::spawn_blocking(move || {
            listener::enumerate(&filter, include_unattributed)
        })
        .await
        {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                tracing::warn!("discovery enumeration failed: {e:#}");
                return;
            }
            Err(e) => {
                tracing::warn!("discovery enumeration task failed: {e}");
                return;
            }
        };
        let listener::FilterOutcome {
            candidates,
            mut skipped,
        } = outcome;

        // Drop cache entries whose socket is gone.
        let live: HashSet<Origin> = candidates.iter().map(|c| c.origin.clone()).collect();
        self.cache.retain(|origin, _| live.contains(origin));

        // Probe only new or TTL-expired origins.
        let now = Instant::now();
        let mut to_probe = Vec::new();
        for candidate in &candidates {
            let needs_probe = match self.cache.get(&candidate.origin) {
                Some(cached) => now.duration_since(cached.last_verified) >= recheck,
                None => true,
            };
            if needs_probe {
                to_probe.push(candidate.clone());
            }
        }

        if !to_probe.is_empty() {
            let semaphore = Arc::new(Semaphore::new(max_concurrent));
            let mut set = JoinSet::new();
            for candidate in to_probe {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                set.spawn(async move {
                    let _permit = permit;
                    let result = probe::probe_http(&candidate.origin, probe_timeout).await;
                    (candidate, result)
                });
            }

            while let Some(joined) = set.join_next().await {
                let Ok((candidate, result)) = joined else {
                    continue;
                };
                match result {
                    Some(result) if is_credible(&result) => {
                        self.cache.insert(
                            candidate.origin.clone(),
                            CachedApp {
                                app: DiscoveredApp {
                                    origin: candidate.origin,
                                    title: result.title,
                                    process: candidate.process,
                                    pid: candidate.pid,
                                },
                                last_verified: Instant::now(),
                            },
                        );
                    }
                    Some(_) => {
                        tracing::debug!(
                            origin = %candidate.origin.authority(),
                            "skipping low-confidence candidate (error status, no title)"
                        );
                        skipped.push(Skipped {
                            origin: candidate.origin.authority(),
                            process: candidate.process.clone(),
                            reason: SkipReason::NotCredible,
                        });
                        self.cache.remove(&candidate.origin);
                    }
                    None => {
                        // Not HTTP / unreachable: ensure it is not exposed.
                        skipped.push(Skipped {
                            origin: candidate.origin.authority(),
                            process: candidate.process.clone(),
                            reason: SkipReason::Unreachable,
                        });
                        self.cache.remove(&candidate.origin);
                    }
                }
            }
        }

        *self.last_scan.write().expect("last_scan poisoned") = skipped;
        self.rebuild_catalog();
    }

    fn rebuild_catalog(&self) {
        let manual = self.config.read().expect("config poisoned").apps.clone();
        let discovered: Vec<DiscoveredApp> =
            self.cache.values().map(|c| c.app.clone()).collect();
        // Carry the previous name→origin pins so a published name is never
        // silently handed to a different origin (name-squatting guard).
        let previous = self
            .catalog
            .read()
            .expect("catalog poisoned")
            .pinned()
            .clone();
        let catalog = Catalog::rebuild_with_pins(&manual, &discovered, &previous);
        *self.catalog.write().expect("catalog poisoned") = catalog;
        self.catalog_generation.fetch_add(1, Ordering::Relaxed);
    }
}

/// Whether a probe looks like a real web app rather than, say, a local HTTP
/// proxy answering `GET /` with an error, or a transient error page.
///
/// Kept: any non-error status (so JSON APIs and redirects count), any titled
/// page, and auth-required (401/403) even without a title — an auth-gated app
/// is still a web app.
///
/// Dropped: error statuses (the page is usually just the error, and its title
/// would otherwise make it look like an app — an nginx or Steam `404 Not
/// Found` is not something to show on a phone), and any page whose title is
/// itself an error (`Error response`, `Bad Gateway`, …).
fn is_credible(result: &probe::ProbeResult) -> bool {
    if let Some(title) = result.title.as_deref()
        && looks_like_error_page(title)
    {
        return false;
    }
    if matches!(result.status, 401 | 403) {
        return true;
    }
    if result.status >= 400 {
        return false;
    }
    result.title.is_some() || result.status < 400
}

/// Page titles that mean "something went wrong", not "here is an app".
///
/// Compared after lowercasing and trimming; a handful of exact phrases rather
/// than substrings, so a real app called "404 Not Found" (or a title that
/// merely contains "error") is unaffected.
fn looks_like_error_page(title: &str) -> bool {
    const ERROR_TITLES: &[&str] = &[
        "error",
        "error response",
        "internal server error",
        "500 internal server error",
        "bad gateway",
        "502 bad gateway",
        "service unavailable",
        "503 service unavailable",
        "gateway timeout",
        "504 gateway timeout",
        "bad request",
        "400 bad request",
        "unauthorized",
        "403 forbidden",
        "not found",
        "404 not found",
        "410 gone",
        "connection refused",
        "this site can't be reached",
        "this site can’t be reached",
        "web server is down",
        "page not found",
    ];
    let title = title.trim().to_ascii_lowercase();
    ERROR_TITLES.contains(&title.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: u16, title: Option<&str>) -> probe::ProbeResult {
        probe::ProbeResult {
            status,
            title: title.map(str::to_string),
            server: None,
        }
    }

    #[test]
    fn success_without_title_is_credible() {
        assert!(is_credible(&result(200, None)));
        assert!(is_credible(&result(302, None)));
    }

    #[test]
    fn error_with_title_is_credible() {
        // A login page often answers 401 but still has a title.
        assert!(is_credible(&result(401, Some("Sign in"))));
    }

    #[test]
    fn error_pages_are_not_apps() {
        // A titled error page is still an error page: nginx and Steam both
        // serve these on ports we probe.
        assert!(!is_credible(&result(404, Some("404 Not Found"))));
        assert!(!is_credible(&result(200, Some("Error response"))));
        assert!(!is_credible(&result(500, Some("Internal Server Error"))));
        assert!(!is_credible(&result(502, None)));
        // …but a real page that merely mentions a status is fine.
        assert!(is_credible(&result(200, Some("ETF 风险平价看板"))));
        assert!(is_credible(&result(200, Some("Untitled"))));
    }

    #[test]
    fn auth_required_without_title_is_credible() {
        // An auth-gated app may answer 401/403 with a plain-text body and no
        // HTML at all (e.g. a token-in-URL harness).
        assert!(is_credible(&result(401, None)));
        assert!(is_credible(&result(403, None)));
    }

    #[test]
    fn error_without_title_is_not_credible() {
        // e.g. a proxy answering a bare GET / with 400 and no page.
        assert!(!is_credible(&result(400, None)));
        assert!(!is_credible(&result(404, None)));
        assert!(!is_credible(&result(502, None)));
    }
}
