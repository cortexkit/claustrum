//! Per-connection fetch caps and rate-anomaly detection for the read surface.
//!
//! The vault cannot authenticate callers in v1 (trusted-unscoped), so the only
//! access-scoping signal it has is the TCP `connection_id` plus the requested
//! handle. This tracks, per connection, how many distinct credentials it has
//! fetched and how fast, and flags a connection that sweeps many credentials or
//! fetches at an anomalous rate — a statistically obvious enumeration attempt.
//!
//! This is an ANOMALY DETECTOR, not the access boundary (capability handles are):
//! it is evadable by reconnecting (a new connection_id resets the in-memory
//! counters), which is acceptable for v1 because (a) the hard boundary is the
//! future caller-identity work and (b) every anomaly raises a DURABLE audit-log
//! alarm that persists across connections, so a reconnect-churning sweep is still
//! recorded for cross-connection analysis.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// The maximum number of handles a single `get_many` call may carry. A call over
/// this is rejected (not truncated), so one call cannot sweep the whole vault.
pub const GET_MANY_MAX: usize = 8;

/// Default per-connection fetch ceiling: distinct credentials fetched within the
/// rolling window before the connection is flagged as anomalous.
pub const DEFAULT_DISTINCT_CEILING: usize = 16;

/// Default rolling window for the fetch-rate anomaly check.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Default maximum fetch COUNT within the window before flagging (catches a rapid
/// re-fetch of even a few handles, distinct from the distinct-credential spread).
pub const DEFAULT_RATE_CEILING: usize = 64;

/// The outcome of admitting one fetch on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The fetch is within limits; serve it normally.
    Ok,
    /// The fetch crossed an anomaly threshold: serve it (this is detection, not a
    /// hard block in v1) but raise a durable rate-anomaly alarm. The boolean marks
    /// the FIRST crossing so the caller alarms once per connection-anomaly rather
    /// than on every subsequent fetch.
    Anomaly { first: bool },
}

/// Caps configuration (overridable for tests).
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub distinct_ceiling: usize,
    pub window: Duration,
    pub rate_ceiling: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            distinct_ceiling: DEFAULT_DISTINCT_CEILING,
            window: DEFAULT_WINDOW,
            rate_ceiling: DEFAULT_RATE_CEILING,
        }
    }
}

/// Per-connection fetch state.
struct ConnState {
    /// Distinct credential ids fetched in the current window.
    distinct: HashSet<String>,
    /// Fetch timestamps in the current window (for the rate check).
    fetches: Vec<Instant>,
    /// Whether this connection has already been flagged (so we alarm once).
    flagged: bool,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            distinct: HashSet::new(),
            fetches: Vec::new(),
            flagged: false,
        }
    }

    /// Drop entries older than the window so the counters are rolling.
    fn prune(&mut self, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window);
        if let Some(cutoff) = cutoff {
            self.fetches.retain(|t| *t >= cutoff);
        }
        // The distinct set is window-scoped too: when no fetches remain in the
        // window, the spread resets (a connection that went quiet is no longer
        // mid-sweep).
        if self.fetches.is_empty() {
            self.distinct.clear();
            self.flagged = false;
        }
    }
}

/// Tracks fetch activity across connections and decides admission + anomaly.
pub struct FetchLimiter {
    caps: Caps,
    conns: HashMap<u64, ConnState>,
}

impl FetchLimiter {
    pub fn new(caps: Caps) -> Self {
        FetchLimiter {
            caps,
            conns: HashMap::new(),
        }
    }

    /// Record a fetch of `credential_id` on `connection_id` at `now` and decide
    /// whether it is within limits or crosses an anomaly threshold.
    pub fn admit(&mut self, connection_id: u64, credential_id: &str, now: Instant) -> Admission {
        let caps = self.caps;
        let state = self
            .conns
            .entry(connection_id)
            .or_insert_with(ConnState::new);
        state.prune(now, caps.window);
        state.fetches.push(now);
        state.distinct.insert(credential_id.to_string());

        let over =
            state.distinct.len() > caps.distinct_ceiling || state.fetches.len() > caps.rate_ceiling;
        if over {
            let first = !state.flagged;
            state.flagged = true;
            Admission::Anomaly { first }
        } else {
            Admission::Ok
        }
    }

    /// Forget a connection's state (called when the connection closes).
    pub fn drop_connection(&mut self, connection_id: u64) {
        self.conns.remove(&connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Caps {
        Caps {
            distinct_ceiling: 3,
            window: Duration::from_secs(60),
            rate_ceiling: 5,
        }
    }

    #[test]
    fn under_ceiling_is_ok() {
        let mut l = FetchLimiter::new(caps());
        let now = Instant::now();
        assert_eq!(l.admit(1, "a", now), Admission::Ok);
        assert_eq!(l.admit(1, "b", now), Admission::Ok);
        assert_eq!(l.admit(1, "c", now), Admission::Ok);
    }

    #[test]
    fn distinct_spread_over_ceiling_flags_once() {
        let mut l = FetchLimiter::new(caps());
        let now = Instant::now();
        l.admit(1, "a", now);
        l.admit(1, "b", now);
        l.admit(1, "c", now);
        // The 4th distinct credential crosses the distinct ceiling (3).
        assert_eq!(l.admit(1, "d", now), Admission::Anomaly { first: true });
        // A further fetch is still anomalous but no longer the FIRST crossing.
        assert_eq!(l.admit(1, "e", now), Admission::Anomaly { first: false });
    }

    #[test]
    fn rapid_refetch_over_rate_ceiling_flags() {
        let mut l = FetchLimiter::new(caps());
        let now = Instant::now();
        // Re-fetch the same handle quickly: distinct stays 1, but the rate climbs.
        for _ in 0..5 {
            assert_eq!(l.admit(1, "a", now), Admission::Ok);
        }
        // The 6th fetch in the window crosses the rate ceiling (5).
        assert_eq!(l.admit(1, "a", now), Admission::Anomaly { first: true });
    }

    #[test]
    fn distinct_connections_are_independent() {
        let mut l = FetchLimiter::new(caps());
        let now = Instant::now();
        l.admit(1, "a", now);
        l.admit(1, "b", now);
        l.admit(1, "c", now);
        // Connection 2 is fresh — its own counters, not connection 1's.
        assert_eq!(l.admit(2, "a", now), Admission::Ok);
    }

    #[test]
    fn window_expiry_resets_spread() {
        let mut l = FetchLimiter::new(caps());
        let t0 = Instant::now();
        l.admit(1, "a", t0);
        l.admit(1, "b", t0);
        l.admit(1, "c", t0);
        // Well past the window: the spread resets, so a new fetch is Ok again.
        let later = t0 + Duration::from_secs(120);
        assert_eq!(l.admit(1, "d", later), Admission::Ok);
    }

    #[test]
    fn drop_connection_forgets_state() {
        let mut l = FetchLimiter::new(caps());
        let now = Instant::now();
        l.admit(1, "a", now);
        l.admit(1, "b", now);
        l.admit(1, "c", now);
        l.drop_connection(1);
        // Reconnect (same id, fresh state): Ok again. This is the documented
        // reconnect-evasion — acceptable because each anomaly is a durable alarm.
        assert_eq!(l.admit(1, "a", now), Admission::Ok);
    }
}
