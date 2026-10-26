//! Endpoint watchdog: keep `raemoted` reachable when iroh's relay task stalls.
//!
//! iroh's relay actor drains a bounded (256-slot) inbox that every network
//! report pushes into — roughly once every 20–25 seconds. Inside that actor a
//! few sends are awaited without a timeout (for example `set_home_relay`'s
//! `join_all(inbox.send(..).await)`): one stuck `ActiveRelayActor` therefore
//! stops the relay actor from ever draining again, the inbox fills up, and
//! every later report logs
//! `dropping message for relay actor, channel is full`. The endpoint is then
//! wedged: it keeps its identity and any established peer-to-peer connection,
//! but it can no longer reach the relay, so new clients cannot find it. Nothing
//! inside iroh recovers the endpoint (1.4.1 still has the same unbounded await),
//! and a restart used to be the only fix.
//!
//! This module closes that gap from the outside:
//!
//! * [`RelayActorWedgeLayer`] observes that warning in the log stream and
//!   counts it in a [`RelayActorSignal`] — the condition itself is not exposed
//!   through iroh's public API, so the log line is the only truthful signal;
//! * [`Watchdog::run`] turns a burst of those warnings — or a long relay outage
//!   — into a [`HealRequest`], and the daemon rebuilds its endpoint in-process:
//!   same node id, pairing token, authorized devices and catalog, new QUIC
//!   sockets and relay connection.
//!
//! A rebuild waits until no device is connected. An established direct
//! connection keeps working when only the relay leg is broken, so tearing it
//! down to "fix" something would hurt the user for nothing; the heal happens as
//! soon as the last client goes away.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::{Endpoint, EndpointId, Watcher};
use tokio::sync::{mpsc, Notify};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::config::Config;

/// How often the watchdog samples endpoint health.
const TICK: Duration = Duration::from_secs(10);
/// Window within which `warn_threshold` stall warnings must arrive.
///
/// The warnings follow the net-report cadence (20–25 s), so a stall shows up as
/// roughly one warning per report; a single stray warning far apart from any
/// other must not count.
const WEDGE_WINDOW: Duration = Duration::from_secs(90);
/// How long the endpoint must stay healthy before the rebuild backoff resets.
const HEALTHY_RESET: Duration = Duration::from_secs(3600);

// ---------------------------------------------------------------------------
// Detecting the stall warning
// ---------------------------------------------------------------------------

/// Counts iroh's "relay actor stopped reading its inbox" warnings.
///
/// Written by [`RelayActorWedgeLayer`] while logging is initialised, read by
/// the watchdog.
#[derive(Debug, Default)]
pub struct RelayActorSignal {
    wedges: AtomicU64,
}

impl RelayActorSignal {
    /// Record one observed stall warning.
    pub fn record_wedge(&self) {
        self.wedges.fetch_add(1, Ordering::Relaxed);
    }

    /// Total stall warnings observed since the daemon started.
    pub fn wedges(&self) -> u64 {
        self.wedges.load(Ordering::Relaxed)
    }
}

/// Whether a log message is iroh's relay-actor stall warning.
///
/// Deliberately a substring match on the message: iroh offers no API for "the
/// relay task stopped draining", and the wording has been stable across the
/// versions this crate supports (`dropping message for relay actor, channel is
/// full`). The sibling warning `unable to send to relay actor, already closed`
/// means the endpoint is shutting down, which is not a stall.
pub fn is_relay_actor_wedge(message: &str) -> bool {
    message.contains("dropping message for relay actor")
}

/// A tracing layer that feeds [`RelayActorSignal`] from the log stream.
///
/// The daemon installs it under the global `EnvFilter`, so it still sees the
/// warning when the user has raised the level: `init_tracing` always keeps the
/// `iroh::socket::transports::relay` target at `warn`.
#[derive(Debug, Clone)]
pub struct RelayActorWedgeLayer {
    signal: Arc<RelayActorSignal>,
}

impl RelayActorWedgeLayer {
    /// Build a layer that records into `signal`.
    pub fn new(signal: Arc<RelayActorSignal>) -> Self {
        Self { signal }
    }
}

impl<S: Subscriber> Layer<S> for RelayActorWedgeLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if *metadata.level() != tracing::Level::WARN || !metadata.target().starts_with("iroh") {
            return;
        }
        let mut fields = MessageField::default();
        event.record(&mut fields);
        if let Some(message) = fields.message.as_deref()
            && is_relay_actor_wedge(message)
        {
            self.signal.record_wedge();
        }
    }
}

/// Extracts the `message` field of a tracing event.
#[derive(Debug, Default)]
struct MessageField {
    message: Option<String>,
}

impl Visit for MessageField {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// The live endpoint
// ---------------------------------------------------------------------------

/// The daemon's current iroh endpoint, plus what the watchdog did to it.
///
/// Cloned freely (one [`Arc`] behind it) and shared with the IPC handler, so
/// `raemote status` always describes the endpoint that is actually running —
/// never the one replaced overnight.
#[derive(Debug, Clone)]
pub struct EndpointHandle {
    inner: Arc<RwLock<Slot>>,
}

#[derive(Debug)]
struct Slot {
    endpoint: Endpoint,
    started_at: Instant,
    restarts: u64,
    last_restart: Option<RestartInfo>,
}

/// One endpoint rebuild: why it happened, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartInfo {
    /// Human-readable trigger, for `raemote status`.
    pub reason: String,
    /// Unix timestamp of the rebuild.
    pub at_unix: u64,
}

impl EndpointHandle {
    /// Wrap a freshly bound endpoint.
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Slot {
                endpoint,
                started_at: Instant::now(),
                restarts: 0,
                last_restart: None,
            })),
        }
    }

    /// A clone of the current endpoint.
    pub fn endpoint(&self) -> Endpoint {
        self.inner
            .read()
            .expect("endpoint slot poisoned")
            .endpoint
            .clone()
    }

    /// This server's node id (constant across rebuilds: the key never changes).
    pub fn id(&self) -> EndpointId {
        self.endpoint().id()
    }

    /// How long the current endpoint has been up.
    pub fn uptime(&self) -> Duration {
        self.inner
            .read()
            .expect("endpoint slot poisoned")
            .started_at
            .elapsed()
    }

    /// How many times the watchdog rebuilt the endpoint.
    pub fn restarts(&self) -> u64 {
        self.inner.read().expect("endpoint slot poisoned").restarts
    }

    /// The most recent rebuild, if any.
    pub fn last_restart(&self) -> Option<RestartInfo> {
        self.inner
            .read()
            .expect("endpoint slot poisoned")
            .last_restart
            .clone()
    }

    /// Install a freshly bound endpoint and return the previous one.
    ///
    /// The caller owns the old endpoint's shutdown; it may already be closed.
    pub fn replace(&self, endpoint: Endpoint, reason: &str) -> Endpoint {
        let mut slot = self.inner.write().expect("endpoint slot poisoned");
        slot.restarts += 1;
        slot.last_restart = Some(RestartInfo {
            reason: reason.to_string(),
            at_unix: unix_now(),
        });
        slot.started_at = Instant::now();
        std::mem::replace(&mut slot.endpoint, endpoint)
    }
}

/// Whether the endpoint currently has a live home-relay connection.
///
/// `None` until iroh has selected a home relay (startup, or no relay
/// configured) — unknown is not unhealthy.
pub fn relay_connected(endpoint: &Endpoint) -> Option<bool> {
    let mut watcher = endpoint.home_relay_status();
    let statuses = watcher.get();
    if statuses.is_empty() {
        None
    } else {
        Some(statuses.iter().any(|s| s.is_connected()))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Watchdog thresholds, rebuilt from the live config on every tick so
/// `raemote config set watchdog.*` applies without a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogSettings {
    /// Whether the watchdog heals at all.
    pub enabled: bool,
    /// Stall warnings within [`WEDGE_WINDOW`] that mean the relay task wedged.
    pub warn_threshold: u64,
    /// Grace period without a relay connection; zero disables this trigger.
    pub offline: Duration,
    /// Minimum time between rebuilds.
    pub cooldown: Duration,
    /// Cap for the exponential backoff applied to repeated rebuilds.
    pub max_cooldown: Duration,
}

impl WatchdogSettings {
    /// Read the settings out of a loaded config.
    pub fn from_config(config: &Config) -> Self {
        let watchdog = &config.watchdog;
        Self {
            enabled: watchdog.enabled,
            warn_threshold: watchdog.warn_threshold,
            offline: Duration::from_secs(watchdog.offline_secs),
            cooldown: Duration::from_secs(watchdog.cooldown_secs),
            max_cooldown: Duration::from_secs(watchdog.max_cooldown_secs),
        }
    }

    /// Cooldown after `heals` rebuilds: doubles per consecutive rebuild, capped.
    fn cooldown_after(&self, heals: u32) -> Duration {
        let doublings = heals.saturating_sub(1).min(16);
        let secs = self.cooldown.as_secs().saturating_mul(1u64 << doublings);
        Duration::from_secs(secs.min(self.max_cooldown.as_secs().max(1)))
    }
}

/// Why the watchdog wants the endpoint rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealReason {
    /// iroh's relay task stopped draining its inbox.
    RelayActorStalled {
        /// Warnings observed in the triggering window.
        warnings: u64,
    },
    /// No live home-relay connection for longer than the grace period.
    RelayOffline {
        /// How long the endpoint had been offline.
        secs: u64,
    },
}

impl HealReason {
    /// Short label, used in `raemote status` and structured logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RelayActorStalled { .. } => "relay actor stalled",
            Self::RelayOffline { .. } => "relay offline",
        }
    }
}

impl fmt::Display for HealReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayActorStalled { warnings } => {
                write!(f, "relay actor stalled ({warnings} dropped-message warning(s))")
            }
            Self::RelayOffline { secs } => write!(f, "no relay connection for {secs}s"),
        }
    }
}

/// One observation of endpoint health.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Stall warnings seen since startup.
    pub wedges: u64,
    /// Live relay connection, `None` when not yet known.
    pub relay_connected: Option<bool>,
    /// Devices currently connected (a rebuild waits for zero).
    pub active_connections: usize,
    /// Clock for this sample (injected so the policy is testable).
    pub now: Instant,
}

/// A burst of stall warnings, while it is still "recent".
#[derive(Debug, Clone, Copy)]
struct WedgeRun {
    started: Instant,
    count: u64,
}

/// The watchdog's memory between ticks.
#[derive(Debug, Default)]
pub struct WatchdogState {
    /// How many warnings have been accounted for.
    seen_wedges: u64,
    /// Current run of warnings, if any.
    wedge_run: Option<WedgeRun>,
    /// A stall was detected and still needs a heal.
    wedge_pending: bool,
    /// When the relay was first seen disconnected (reset on reconnect).
    disconnected_since: Option<Instant>,
    /// When the last rebuild happened.
    last_heal: Option<Instant>,
    /// Rebuilds since the endpoint was last healthy for [`HEALTHY_RESET`].
    consecutive_heals: u32,
    /// When the endpoint last became (and stayed) healthy.
    healthy_since: Option<Instant>,
}

impl WatchdogState {
    /// Record that a heal was requested, so the cooldown applies.
    pub fn on_healed(&mut self, now: Instant) {
        self.last_heal = Some(now);
        self.consecutive_heals = self.consecutive_heals.saturating_add(1);
        self.wedge_pending = false;
        self.wedge_run = None;
        self.disconnected_since = None;
        self.healthy_since = None;
    }
}

/// Decide whether this sample calls for a rebuild.
///
/// Pure and deterministic: the async loop owns the clock, the endpoint and the
/// rebuild itself.
pub fn evaluate(
    settings: &WatchdogSettings,
    state: &mut WatchdogState,
    sample: Sample,
) -> Option<HealReason> {
    if !settings.enabled {
        return None;
    }
    let now = sample.now;

    // 1. A burst of stall warnings means the relay task stopped reading. The
    //    warnings keep coming one per net report, so count them in a window
    //    rather than per tick.
    if sample.wedges > state.seen_wedges {
        let delta = sample.wedges - state.seen_wedges;
        state.seen_wedges = sample.wedges;
        let run = match state.wedge_run {
            Some(run) if now.saturating_duration_since(run.started) <= WEDGE_WINDOW => WedgeRun {
                started: run.started,
                count: run.count.saturating_add(delta),
            },
            _ => WedgeRun {
                started: now,
                count: delta,
            },
        };
        state.wedge_run = Some(run);
        if run.count >= settings.warn_threshold.max(1) {
            state.wedge_pending = true;
        }
    } else if let Some(run) = state.wedge_run
        && now.saturating_duration_since(run.started) > WEDGE_WINDOW
    {
        // Quiet again: a later lone warning starts a fresh run.
        state.wedge_run = None;
    }

    // 2. Track how long the relay has been unreachable.
    match sample.relay_connected {
        Some(false) => {
            state.disconnected_since.get_or_insert(now);
        }
        Some(true) => state.disconnected_since = None,
        None => {}
    }

    // 3. Repeated heals back off; a healthy hour resets that.
    if sample.relay_connected == Some(true) && !state.wedge_pending {
        let since = *state.healthy_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= HEALTHY_RESET {
            state.consecutive_heals = 0;
        }
    } else {
        state.healthy_since = None;
    }

    // 4. Never rebuild twice in a row without the cooldown.
    if let Some(last) = state.last_heal
        && now.saturating_duration_since(last) < settings.cooldown_after(state.consecutive_heals)
    {
        return None;
    }

    // 5. Only rebuild with no client attached: a working direct connection
    //    must not be sacrificed to repair the relay leg. The state above keeps
    //    tracking, so the heal fires as soon as the last client disconnects.
    if sample.active_connections > 0 {
        return None;
    }

    if state.wedge_pending {
        let warnings = state
            .wedge_run
            .map(|run| run.count)
            .unwrap_or(settings.warn_threshold);
        return Some(HealReason::RelayActorStalled { warnings });
    }

    if let Some(since) = state.disconnected_since
        && !settings.offline.is_zero()
    {
        let offline = now.saturating_duration_since(since);
        if offline >= settings.offline {
            return Some(HealReason::RelayOffline {
                secs: offline.as_secs(),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// A rebuild request from the watchdog to the daemon.
#[derive(Debug, Clone, Copy)]
pub struct HealRequest {
    /// What tripped the watchdog.
    pub reason: HealReason,
    /// Unix timestamp of the detection, for the status line.
    pub at_unix: u64,
}

/// Samples endpoint health and asks the daemon to rebuild it when needed.
pub struct Watchdog {
    config: Arc<RwLock<Config>>,
    signal: Arc<RelayActorSignal>,
    endpoints: EndpointHandle,
    active_connections: Arc<AtomicUsize>,
    heal_tx: mpsc::Sender<HealRequest>,
}

impl Watchdog {
    /// Build a watchdog over the shared daemon state.
    pub fn new(
        config: Arc<RwLock<Config>>,
        signal: Arc<RelayActorSignal>,
        endpoints: EndpointHandle,
        active_connections: Arc<AtomicUsize>,
        heal_tx: mpsc::Sender<HealRequest>,
    ) -> Self {
        Self {
            config,
            signal,
            endpoints,
            active_connections,
            heal_tx,
        }
    }

    /// Run until `shutdown` fires.
    pub async fn run(self, shutdown: Arc<Notify>) {
        let mut state = WatchdogState::default();
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.notified() => return,
                _ = ticker.tick() => {
                    let settings = {
                        let config = self.config.read().expect("config poisoned");
                        WatchdogSettings::from_config(&config)
                    };
                    if !settings.enabled {
                        continue;
                    }
                    let sample = Sample {
                        wedges: self.signal.wedges(),
                        relay_connected: relay_connected(&self.endpoints.endpoint()),
                        active_connections: self.active_connections.load(Ordering::Relaxed),
                        now: Instant::now(),
                    };
                    let Some(reason) = evaluate(&settings, &mut state, sample) else {
                        if state_is_pending(&state) {
                            tracing::debug!(
                                connections = sample.active_connections,
                                "watchdog: heal deferred (a device is connected)"
                            );
                        }
                        continue;
                    };
                    state.on_healed(sample.now);
                    let request = HealRequest {
                        reason,
                        at_unix: unix_now(),
                    };
                    tracing::warn!(%reason, "endpoint watchdog: rebuilding the iroh endpoint");
                    if self.heal_tx.send(request).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Whether a heal is waiting on something (used only for the deferral log line).
fn state_is_pending(state: &WatchdogState) -> bool {
    state.wedge_pending || state.disconnected_since.is_some()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> WatchdogSettings {
        WatchdogSettings {
            enabled: true,
            warn_threshold: 3,
            offline: Duration::from_secs(900),
            cooldown: Duration::from_secs(300),
            max_cooldown: Duration::from_secs(1800),
        }
    }

    fn sample(now: Instant, wedges: u64, relay: Option<bool>, active: usize) -> Sample {
        Sample {
            wedges,
            relay_connected: relay,
            active_connections: active,
            now,
        }
    }

    #[test]
    fn recognises_the_relay_actor_warning() {
        assert!(is_relay_actor_wedge(
            "dropping message for relay actor, channel is full"
        ));
        // The endpoint shutting down is not a stall.
        assert!(!is_relay_actor_wedge(
            "unable to send to relay actor, already closed"
        ));
        assert!(!is_relay_actor_wedge("something else entirely"));
    }

    #[test]
    fn warns_below_the_threshold_do_not_heal() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        assert!(evaluate(&s, &mut state, sample(now, 1, Some(true), 0)).is_none());
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(20), 2, Some(true), 0)
            )
            .is_none()
        );
    }

    #[test]
    fn a_burst_of_warnings_heals() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        evaluate(&s, &mut state, sample(now, 1, Some(true), 0));
        evaluate(
            &s,
            &mut state,
            sample(now + Duration::from_secs(20), 2, Some(true), 0),
        );
        let reason = evaluate(
            &s,
            &mut state,
            sample(now + Duration::from_secs(40), 3, Some(true), 0),
        );
        assert_eq!(reason, Some(HealReason::RelayActorStalled { warnings: 3 }));
    }

    #[test]
    fn stray_warnings_far_apart_do_not_accumulate() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        for i in 0..10u64 {
            let at = now + WEDGE_WINDOW * 2 * i as u32;
            assert!(
                evaluate(&s, &mut state, sample(at, i + 1, Some(true), 0)).is_none(),
                "warning {i} alone must not heal"
            );
        }
    }

    #[test]
    fn never_heals_while_a_device_is_connected() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        evaluate(&s, &mut state, sample(now, 1, Some(true), 1));
        evaluate(
            &s,
            &mut state,
            sample(now + Duration::from_secs(20), 2, Some(true), 1),
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(40), 3, Some(true), 1)
            )
            .is_none(),
            "a working direct connection must not be torn down"
        );
        // The client leaves; the pending stall heals on the next tick.
        assert_eq!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(60), 3, Some(true), 0)
            ),
            Some(HealReason::RelayActorStalled { warnings: 3 })
        );
    }

    #[test]
    fn cooldown_prevents_immediate_reheals() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        evaluate(&s, &mut state, sample(now, 1, Some(true), 0));
        evaluate(
            &s,
            &mut state,
            sample(now + Duration::from_secs(20), 2, Some(true), 0),
        );
        let healed_at = now + Duration::from_secs(40);
        assert!(
            evaluate(&s, &mut state, sample(healed_at, 3, Some(true), 0)).is_some()
        );
        state.on_healed(healed_at);

        // Another burst right away is suppressed by the cooldown...
        evaluate(
            &s,
            &mut state,
            sample(healed_at + Duration::from_secs(10), 4, Some(false), 0),
        );
        evaluate(
            &s,
            &mut state,
            sample(healed_at + Duration::from_secs(20), 5, Some(false), 0),
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(healed_at + Duration::from_secs(180), 6, Some(false), 0)
            )
            .is_none()
        );
        // ...and fires once the cooldown has passed, on the next burst.
        let after_cooldown = healed_at + Duration::from_secs(400);
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(after_cooldown, 7, Some(false), 0)
            )
            .is_none()
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(after_cooldown + Duration::from_secs(20), 8, Some(false), 0)
            )
            .is_none()
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(after_cooldown + Duration::from_secs(40), 9, Some(false), 0)
            )
            .is_some()
        );
    }

    #[test]
    fn offline_relay_heals_after_the_grace_period() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        assert!(
            evaluate(&s, &mut state, sample(now, 0, Some(false), 0)).is_none(),
            "the first disconnected sample only starts the clock"
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(899), 0, Some(false), 0)
            )
            .is_none()
        );
        assert_eq!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(900), 0, Some(false), 0)
            ),
            Some(HealReason::RelayOffline { secs: 900 })
        );
    }

    #[test]
    fn reconnecting_clears_the_offline_clock() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        evaluate(&s, &mut state, sample(now, 0, Some(false), 0));
        evaluate(
            &s,
            &mut state,
            sample(now + Duration::from_secs(500), 0, Some(true), 0),
        );
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(1000), 0, Some(false), 0)
            )
            .is_none(),
            "the clock restarts after a reconnect"
        );
    }

    #[test]
    fn unknown_relay_state_never_heals() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = settings();
        for i in 0..10u32 {
            assert!(
                evaluate(
                    &s,
                    &mut state,
                    sample(now + Duration::from_secs(600 * i as u64), 0, None, 0)
                )
                .is_none()
            );
        }
    }

    #[test]
    fn disabled_watchdog_never_heals() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = WatchdogSettings {
            enabled: false,
            ..settings()
        };
        for i in 1..10u64 {
            assert!(evaluate(&s, &mut state, sample(now, i, Some(false), 0)).is_none());
        }
    }

    #[test]
    fn zero_offline_grace_disables_only_that_trigger() {
        let now = Instant::now();
        let mut state = WatchdogState::default();
        let s = WatchdogSettings {
            offline: Duration::ZERO,
            ..settings()
        };
        assert!(
            evaluate(
                &s,
                &mut state,
                sample(now + Duration::from_secs(10_000), 0, Some(false), 0)
            )
            .is_none()
        );
        for i in 1..=3u64 {
            evaluate(&s, &mut state, sample(now, i, Some(true), 0));
        }
        assert!(evaluate(&s, &mut state, sample(now, 3, Some(true), 0)).is_some());
    }

    #[test]
    fn backoff_doubles_per_rebuild_and_is_capped() {
        let s = settings();
        assert_eq!(s.cooldown_after(0), Duration::from_secs(300));
        assert_eq!(s.cooldown_after(1), Duration::from_secs(300));
        assert_eq!(s.cooldown_after(2), Duration::from_secs(600));
        assert_eq!(s.cooldown_after(3), Duration::from_secs(1200));
        assert_eq!(s.cooldown_after(4), Duration::from_secs(1800));
        assert_eq!(s.cooldown_after(99), Duration::from_secs(1800));
    }
}
