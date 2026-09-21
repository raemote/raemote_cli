//! The merged view of configured and discovered web apps.
//!
//! [`Catalog`] combines manual `[[apps]]` entries with apps found by
//! [`crate::discovery`], giving each a unique, URL-safe name that
//! `/app/{name}` can route to.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::discovery::model::{DiscoveredApp, Origin};

/// Where a catalog entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppSource {
    /// Configured by the user in `[[apps]]`.
    Manual,
    /// Found automatically by discovery.
    Discovered,
}

impl AppSource {
    /// Stable lowercase label used in the hub JSON and the CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            AppSource::Manual => "manual",
            AppSource::Discovered => "discovered",
        }
    }
}

/// A routable app entry: `/app/{name}` proxies to `origin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogApp {
    /// Unique, URL-safe name used as `/app/{name}`.
    pub name: String,
    /// Page title, when known (discovered apps only).
    pub title: Option<String>,
    /// Same-origin path of the app's declared icon, when known (discovered
    /// apps only). Manual apps have no probe, so this is `None` for them.
    pub icon: Option<String>,
    /// Where the app is reachable.
    pub origin: Origin,
    /// Whether the entry came from config or discovery.
    pub source: AppSource,
    /// Owning process name, when known.
    pub process: Option<String>,
    /// Owning process id, when known.
    pub pid: Option<u32>,
}

/// The merged view of manual config apps and discovered apps.
///
/// Rebuilt wholesale (cheap; tens of entries) whenever config or discovery
/// changes, so readers never see a partially updated catalog.
///
/// Discovered names are **pinned to their origin** for the lifetime of the
/// pin map: a name that was published for origin O is not handed to a
/// different origin on a later rebuild (a hostile local app cannot take over
/// an existing app's `/app/{name}` route — and with it the phone's per-app
/// web origin — by claiming the same title on a lower port).
#[derive(Debug, Default)]
pub struct Catalog {
    apps: Vec<CatalogApp>,
    /// Published name → origin bindings carried across rebuilds. A name is
    /// only reassignable when its pinned origin is no longer a candidate in
    /// this rebuild (one-rebuild grace: a real app that briefly disappears
    /// keeps its name; a claimant on a different origin is suffixed).
    pinned: HashMap<String, Origin>,
}

impl Catalog {
    /// An empty catalog.
    pub fn empty() -> Self {
        Self {
            apps: Vec::new(),
            pinned: HashMap::new(),
        }
    }

    /// Merge manual `[[apps]]` (authoritative) with discovered apps.
    ///
    /// - Manual entries keep their configured name and shadow any discovered
    ///   app on the same origin.
    /// - Discovered names are slugified and de-duplicated against manual and
    ///   other discovered names by appending the port (then a counter).
    /// - Names bound to an origin by a previous rebuild are pinned: an
    ///   existing name is not reassigned to a different origin while that
    ///   origin is still a candidate.
    pub fn rebuild(manual: &[AppConfig], discovered: &[DiscoveredApp]) -> Self {
        Self::rebuild_with_pins(manual, discovered, &HashMap::new())
    }

    /// [`Catalog::rebuild`] with name→origin pins carried over from the
    /// previous rebuild, for binding a published name to its origin.
    pub fn rebuild_with_pins(
        manual: &[AppConfig],
        discovered: &[DiscoveredApp],
        previous: &HashMap<String, Origin>,
    ) -> Self {
        let mut apps = Vec::with_capacity(manual.len() + discovered.len());
        let mut used: HashSet<String> = HashSet::new();
        let mut manual_origins: HashSet<Origin> = HashSet::new();

        for app in manual {
            let origin = Origin::http("127.0.0.1", app.port);
            manual_origins.insert(origin.clone());
            used.insert(app.name.clone());
            apps.push(CatalogApp {
                name: app.name.clone(),
                title: None,
                icon: None,
                origin,
                source: AppSource::Manual,
                process: None,
                pid: None,
            });
        }

        // `discovered` comes from a HashMap, so sort it first: otherwise which
        // of two same-named apps gets the plain name and which gets the port
        // suffix would depend on iteration order and flip between scans.
        let mut discovered: Vec<&DiscoveredApp> = discovered.iter().collect();
        discovered.sort_by(|a, b| {
            a.origin
                .port
                .cmp(&b.origin.port)
                .then_with(|| a.origin.host.cmp(&b.origin.host))
        });

        // Pins only bind while their origin is still a candidate. A pin whose
        // origin vanished (the app stopped) keeps its name reserved for one
        // rebuild grace — the name is not handed to a same-title newcomer in
        // that rebuild — and is dropped afterwards (a later claimant can take
        // the name, which is the deliberate "app moved" recovery).
        let candidates: HashSet<Origin> = discovered.iter().map(|d| d.origin.clone()).collect();
        let mut pinned: HashMap<String, Origin> = previous
            .iter()
            .filter(|(_, origin)| candidates.contains(origin))
            .map(|(n, o)| (n.clone(), o.clone()))
            .collect();
        // Pre-reserve pinned names so a lower-port impostor processed first
        // cannot take a name its origin did not own.
        let mut reserved_by_origin: HashMap<Origin, String> = HashMap::new();
        for (name, origin) in &pinned {
            used.insert(name.clone());
            reserved_by_origin.insert(origin.clone(), name.clone());
        }
        let grace: Vec<(String, Origin)> = previous
            .iter()
            .filter(|(_, origin)| !candidates.contains(origin))
            .map(|(n, o)| (n.clone(), o.clone()))
            .collect();
        // Reserve the grace names for this rebuild only: a same-title
        // newcomer is suffixed instead of claiming them right away.
        for (name, _) in &grace {
            used.insert(name.clone());
        }

        for d in discovered {
            // A manual entry on the same origin wins; don't expose it twice.
            if manual_origins.contains(&d.origin) {
                continue;
            }
            let name = match reserved_by_origin.remove(&d.origin) {
                Some(name) => name,
                None => unique_name(&name_base(d), d.origin.port, &mut used),
            };
            pinned.insert(name.clone(), d.origin.clone());
            apps.push(CatalogApp {
                name,
                title: d.title.clone(),
                icon: d.icon.clone(),
                origin: d.origin.clone(),
                source: AppSource::Discovered,
                process: d.process.clone(),
                pid: d.pid,
            });
        }

        Self { apps, pinned }
    }

    /// The name→origin pins this catalog is built on (carried across rebuilds).
    pub fn pinned(&self) -> &HashMap<String, Origin> {
        &self.pinned
    }

    /// All entries: manual first, then discovered.
    pub fn apps(&self) -> &[CatalogApp] {
        &self.apps
    }

    /// Look up an entry by its name.
    pub fn find(&self, name: &str) -> Option<&CatalogApp> {
        self.apps.iter().find(|a| a.name == name)
    }

    /// Number of discovered (non-manual) entries.
    pub fn discovered_count(&self) -> usize {
        self.apps
            .iter()
            .filter(|a| a.source == AppSource::Discovered)
            .count()
    }
}

/// Pick a display base name: page title, else process name, else "app".
fn name_base(d: &DiscoveredApp) -> String {
    if let Some(title) = d.title.as_deref() {
        let slug = slugify(title);
        if !slug.is_empty() {
            return slug;
        }
    }
    if let Some(process) = d.process.as_deref() {
        let slug = slugify(process);
        if !slug.is_empty() {
            return slug;
        }
    }
    "app".to_string()
}

/// Lowercase ASCII slug: `[a-z0-9]` runs joined by single `-`.
///
/// ```
/// use raemote::catalog::slugify;
///
/// assert_eq!(slugify("My App!"), "my-app");
/// assert_eq!(slugify("  Vite + React  "), "vite-react");
/// assert_eq!(slugify("!!!"), "");
/// ```
pub fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_dash = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    out
}

fn unique_name(base: &str, port: u16, used: &mut HashSet<String>) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let with_port = format!("{base}-{port}");
    if used.insert(with_port.clone()) {
        return with_port;
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{port}-{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::model::Origin;

    fn discovered(title: &str, port: u16) -> DiscoveredApp {
        DiscoveredApp {
            origin: Origin::http("127.0.0.1", port),
            title: Some(title.to_string()),
            icon: None,
            process: Some("node".to_string()),
            pid: Some(1),
        }
    }

    #[test]
    fn slugify_basics() {
        assert_eq!(slugify("My App!"), "my-app");
        assert_eq!(slugify("  Hello   World  "), "hello-world");
        assert_eq!(slugify("Vite + React"), "vite-react");
        assert_eq!(slugify(""), "");
        assert_eq!(slugify("!!!"), "");
    }

    #[test]
    fn name_prefers_title_then_process_then_default() {
        let mut d = discovered("Grafana", 3000);
        assert_eq!(name_base(&d), "grafana");

        d.title = Some("!!!".to_string());
        assert_eq!(name_base(&d), "node");

        d.process = Some("!!!".to_string());
        assert_eq!(name_base(&d), "app");
    }

    #[test]
    fn names_do_not_depend_on_the_order_discovered_arrives_in() {
        // The discovery cache is a HashMap, so the same two apps can arrive in
        // either order. Names must be identical either way — otherwise the
        // phone, which keys per-app state by name, would see them swap.
        let a = discovered("SPIS", 8080);
        let b = discovered("SPIS", 8081);

        let forward = Catalog::rebuild(&[], &[a.clone(), b.clone()]);
        let backward = Catalog::rebuild(&[], &[b, a]);

        let names = |c: &Catalog| -> Vec<String> {
            c.apps().iter().map(|app| app.name.clone()).collect()
        };
        assert_eq!(names(&forward), names(&backward));
        // The lower port keeps the plain name.
        assert_eq!(
            forward
                .find("spis")
                .expect("plain name exists")
                .origin
                .port,
            8080
        );
    }

    #[test]
    fn manual_apps_shadow_same_origin() {
        let manual = vec![AppConfig {
            name: "custom".to_string(),
            port: 3000,
        }];
        let catalog = Catalog::rebuild(&manual, &[discovered("Grafana", 3000)]);
        // Only the manual entry remains.
        assert_eq!(catalog.apps().len(), 1);
        assert_eq!(catalog.apps()[0].name, "custom");
        assert_eq!(catalog.apps()[0].source, AppSource::Manual);
    }

    #[test]
    fn discovered_kept_when_origin_differs() {
        let manual = vec![AppConfig {
            name: "custom".to_string(),
            port: 3000,
        }];
        let catalog = Catalog::rebuild(&manual, &[discovered("Grafana", 3001)]);
        assert_eq!(catalog.apps().len(), 2);
        assert_eq!(catalog.find("grafana").unwrap().origin.port, 3001);
        assert_eq!(catalog.discovered_count(), 1);
    }

    #[test]
    fn duplicate_names_disambiguated_by_port() {
        let catalog = Catalog::rebuild(
            &[],
            &[discovered("Dashboard", 3000), discovered("Dashboard", 3001)],
        );
        let names: Vec<_> = catalog.apps().iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["dashboard", "dashboard-3001"]);
    }

    #[test]
    fn discovered_name_collides_with_manual_name() {
        let manual = vec![AppConfig {
            name: "dashboard".to_string(),
            port: 9999,
        }];
        let catalog = Catalog::rebuild(&manual, &[discovered("Dashboard", 3000)]);
        let names: Vec<_> = catalog.apps().iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["dashboard", "dashboard-3000"]);
    }

    #[test]
    fn published_name_is_pinned_to_its_origin_across_rebuilds() {
        // First scan: SPIS on 8081 wins the plain name.
        let first = Catalog::rebuild(&[], &[discovered("SPIS", 8081)]);
        assert_eq!(first.find("spis").unwrap().origin.port, 8081);

        // Second scan: a lower-port impostor with the same title appears.
        // The pin keeps "spis" bound to 8081; the impostor is suffixed.
        let second = Catalog::rebuild_with_pins(
            &[],
            &[discovered("SPIS", 3000), discovered("SPIS", 8081)],
            first.pinned(),
        );
        assert_eq!(second.find("spis").unwrap().origin.port, 8081);
        let impostor = second
            .apps()
            .iter()
            .find(|a| a.origin.port == 3000)
            .expect("impostor entry exists");
        assert_ne!(impostor.name, "spis");
    }

    #[test]
    fn stopped_app_frees_its_name_after_one_rebuild_grace() {
        let first = Catalog::rebuild(&[], &[discovered("SPIS", 8081)]);
        assert_eq!(first.find("spis").unwrap().origin.port, 8081);
        // Real app stops; nothing on 8081 anymore: the name is *free*, not
        // handed to a same-title claimant on another origin.
        let second = Catalog::rebuild_with_pins(&[], &[discovered("SPIS", 3000)], first.pinned());
        assert!(second.find("spis").is_none());
        assert!(second.find("spis-3000").is_some());
        // The claimant's assigned name is stable from then on (a later reclaim
        // of the freed plain name would only churn the phone's per-app origin
        // again), so `spis` stays free while the surviving entry keeps its
        // suffixed name.
        let third = Catalog::rebuild_with_pins(&[], &[discovered("SPIS", 3000)], second.pinned());
        assert!(third.find("spis").is_none());
        assert_eq!(
            third.find("spis-3000").expect("name stable after grace").origin.port,
            3000
        );
    }
}
