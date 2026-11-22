//! The outcomes channel: what the exec gate DID, as closed enums and counters,
//! posted to kub0 `POST /ingest/outcomes` (data boundary D9).
//!
//! The heartbeat says an endpoint is alive and what it holds; this channel says
//! what its rules achieved. kub0 learns "this host refused 3 executions since
//! the last window" and nothing else: the wire carries no path, host name,
//! address, hash, user, or note, and the server rejects any such field with a
//! 400 before reading it. A test here pins the key set and proves a deny
//! record's strings never reach the payload.
//!
//! Only the daemon running the gate reports (`ExecGateFrame.source == "live"`):
//! the user daemon mirrors the system daemon's state file and must not count
//! the same decisions twice. Reports flow on the heartbeat tick; one is built
//! when a window of at least [`DEFAULT_INTERVAL_SECS`] holds a non-zero delta,
//! or once every [`KEEPALIVE_SECS`] with a zero row so kub0's census still
//! lists an idle endpoint. The first live tick after a start reports at once,
//! so a fresh install proves its token, route and schema within a tick: an
//! idle endpoint that only spoke once a day would look the same to kub0 as
//! one whose outcomes never arrive. A report kub0 did not accept waits in a spool on
//! disk (oldest dropped past [`SPOOL_CAP`]), so an offline laptop reports its
//! blocks when it is back, restart or not.

use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::execgate::{ExecGateCounters, ExecGateFrame};

/// `agent` on the wire. Also the agent enum the kub0 API checks.
pub const AGENT: &str = "vallum";
/// Shortest window a non-zero delta is reported over.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;
pub const MIN_INTERVAL_SECS: u64 = 60;
/// An idle gate still reports once a day (a zero row) so the org census lists it.
pub const KEEPALIVE_SECS: u64 = 24 * 60 * 60;
/// Unsent windows kept on disk: 24 h at the default interval.
pub const SPOOL_CAP: usize = 288;
/// Reports sent per tick once the server answers again: a day's spool drains
/// in a few minutes instead of one burst.
pub const DRAIN_PER_TICK: usize = 8;
pub const SPOOL_FILE: &str = "outcomes-spool.json";

/// `platform` on the wire. The kub0 API accepts linux and macos only.
pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Root-hosted like the heartbeat; `/detonate` in front of it is a regression.
pub fn outcomes_url(server_url: &str) -> String {
    format!("{}/ingest/outcomes", server_url.trim_end_matches('/'))
}

/// `KUB0_OUTCOMES_INTERVAL` seconds, floored at [`MIN_INTERVAL_SECS`].
pub fn interval() -> Duration {
    interval_from(std::env::var("KUB0_OUTCOMES_INTERVAL").ok().as_deref())
}

pub fn interval_from(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .max(MIN_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// `KUB0_OUTCOMES=0` keeps every outcome on the host.
pub fn enabled() -> bool {
    enabled_from(crate::rename::env("KUB0_OUTCOMES").as_deref())
}

pub fn enabled_from(raw: Option<&str>) -> bool {
    raw.map(str::trim) != Some("0")
}

/// One `(kind, result, count)` row. `kind` and `result` are the kub0 API's closed
/// vocabulary; this module only ever writes `exec_gate` rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRow {
    pub kind: String,
    pub result: String,
    pub count: u64,
}

/// One report, serialised exactly as `POST /ingest/outcomes` reads it. The key
/// set is pinned by a test; the decoder refuses unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub agent: String,
    pub agent_version: String,
    pub platform: String,
    /// RFC 3339, UTC.
    pub window_start: String,
    pub window_end: String,
    pub outcomes: Vec<OutcomeRow>,
}

/// The gate's four decision counters: the only numbers that leave the host.
/// Hashing, cache and watchdog counters describe the gate, not an outcome, and
/// stay on the local fleet frame.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateTally {
    pub blocked: u64,
    pub allowed_once: u64,
    pub allowed_local_trust: u64,
    pub allowed_failopen: u64,
}

impl GateTally {
    pub fn from_counters(c: &ExecGateCounters) -> Self {
        Self {
            blocked: c.blocked,
            allowed_once: c.allowed_once,
            allowed_local_trust: c.trusted,
            allowed_failopen: c.failopen,
        }
    }

    /// Growth since `base`. A counter below its base means the gate restarted
    /// and counts from zero again, so its whole value is the growth.
    pub fn since(self, base: GateTally) -> GateTally {
        fn grow(cur: u64, base: u64) -> u64 {
            if cur >= base {
                cur - base
            } else {
                cur
            }
        }
        GateTally {
            blocked: grow(self.blocked, base.blocked),
            allowed_once: grow(self.allowed_once, base.allowed_once),
            allowed_local_trust: grow(self.allowed_local_trust, base.allowed_local_trust),
            allowed_failopen: grow(self.allowed_failopen, base.allowed_failopen),
        }
    }

    pub fn is_zero(self) -> bool {
        self == GateTally::default()
    }

    /// Non-zero counters as rows, in a fixed order. The kub0 API's result enum
    /// for `exec_gate` is blocked, allowed_once, allowed_local_trust,
    /// allowed_failopen (and monitor_hit, which this gate has no mode for).
    pub fn rows(self) -> Vec<OutcomeRow> {
        let mut rows = Vec::new();
        for (result, count) in [
            ("blocked", self.blocked),
            ("allowed_once", self.allowed_once),
            ("allowed_local_trust", self.allowed_local_trust),
            ("allowed_failopen", self.allowed_failopen),
        ] {
            if count > 0 {
                rows.push(OutcomeRow {
                    kind: "exec_gate".into(),
                    result: result.into(),
                    count,
                });
            }
        }
        rows
    }
}

/// What a send attempt came back with, as the ledger needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// 2xx: the report is kub0's now.
    Accepted,
    /// 400 or 413: this report can never be accepted (our schema is wrong, or
    /// a counter is absurd). Dropped, so one bad window cannot block the rest.
    Rejected,
    /// Anything else (no route, 5xx, 401, 429): keep it and stop for this tick.
    Retry,
}

/// Turns gate counters into windowed reports and keeps the unsent ones.
#[derive(Debug)]
pub struct Ledger {
    base: GateTally,
    window_start: u64,
    /// When the last report was queued; `None` until the first, which makes
    /// the first live tick after a start due at once.
    last_report: Option<u64>,
    interval: Duration,
    agent_version: String,
    pending: VecDeque<Report>,
    spool_path: Option<PathBuf>,
}

impl Ledger {
    /// `now` is seconds since the epoch. Reads a spool left by an earlier
    /// daemon from `state_dir`; `None` keeps everything in memory (tests).
    pub fn new(state_dir: Option<&Path>, agent_version: &str, interval: Duration, now: u64) -> Self {
        let spool_path = state_dir.map(|d| d.join(SPOOL_FILE));
        let pending = spool_path.as_deref().map(load_spool).unwrap_or_default();
        Self {
            base: GateTally::default(),
            window_start: now,
            last_report: None,
            interval,
            agent_version: agent_version.to_string(),
            pending,
            spool_path,
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// One tick with the live frame. A frame that is not this daemon's own gate
    /// (`mirror`, `stale`, `none`) is never counted: the system daemon reports
    /// those decisions itself. True when a report was queued.
    pub fn tick_frame(&mut self, frame: &ExecGateFrame, now: u64) -> bool {
        if frame.source != "live" {
            return false;
        }
        self.tick(&frame.counters, now)
    }

    /// One tick with the gate's counters. Queues a report when the window is
    /// at least `interval` old and holds a non-zero delta, when the last
    /// report is [`KEEPALIVE_SECS`] old, or when nothing has been reported
    /// since this ledger was made (a zero row when idle). Advances the window
    /// either way it reports.
    pub fn tick(&mut self, counters: &ExecGateCounters, now: u64) -> bool {
        let current = GateTally::from_counters(counters);
        let growth = current.since(self.base);
        let window_old = now.saturating_sub(self.window_start) >= self.interval.as_secs();
        let keepalive_due = self.last_report.is_none_or(|t| now.saturating_sub(t) >= KEEPALIVE_SECS);
        if !(window_old && !growth.is_zero()) && !keepalive_due {
            return false;
        }
        let outcomes = if growth.is_zero() {
            vec![OutcomeRow {
                kind: "exec_gate".into(),
                result: "blocked".into(),
                count: 0,
            }]
        } else {
            growth.rows()
        };
        let report = Report {
            agent: AGENT.into(),
            agent_version: self.agent_version.clone(),
            platform: platform().into(),
            window_start: rfc3339(self.window_start),
            window_end: rfc3339(now.max(self.window_start)),
            outcomes,
        };
        self.base = current;
        self.window_start = now;
        self.last_report = Some(now);
        self.pending.push_back(report);
        while self.pending.len() > SPOOL_CAP {
            self.pending.pop_front();
        }
        self.persist();
        true
    }

    /// Send queued reports oldest first, at most `max` per call, stopping at
    /// the first [`Delivery::Retry`]. Returns how many kub0 accepted.
    pub fn drain<F: FnMut(&Report) -> Delivery>(&mut self, max: usize, mut send: F) -> usize {
        let mut accepted = 0;
        let mut changed = false;
        for _ in 0..max {
            let Some(report) = self.pending.front() else { break };
            match send(report) {
                Delivery::Accepted => {
                    accepted += 1;
                    self.pending.pop_front();
                    changed = true;
                }
                Delivery::Rejected => {
                    self.pending.pop_front();
                    changed = true;
                }
                Delivery::Retry => break,
            }
        }
        if changed {
            self.persist();
        }
        accepted
    }

    fn persist(&self) {
        let Some(path) = &self.spool_path else { return };
        if let Err(e) = write_spool(path, &self.pending) {
            eprintln!("kub0d: outcomes: spool {} not written: {e}", path.display());
        }
    }
}

/// An unreadable or malformed spool is an empty one: the counters it held are
/// gone either way, and a report must not fail because of a stale file.
fn load_spool(path: &Path) -> VecDeque<Report> {
    let Ok(bytes) = std::fs::read(path) else {
        return VecDeque::new();
    };
    serde_json::from_slice::<Vec<Report>>(&bytes)
        .map(VecDeque::from)
        .unwrap_or_default()
}

/// Temp file beside the spool, 0600 at create, renamed over it: a daemon
/// killed mid-write leaves the previous spool, never half of this one.
fn write_spool(path: &Path, pending: &VecDeque<Report>) -> std::io::Result<()> {
    if pending.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let rows: Vec<&Report> = pending.iter().collect();
    let bytes = serde_json::to_vec(&rows)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Seconds since the epoch as RFC 3339 UTC (`2026-11-04T12:17:09Z`).
pub fn rfc3339(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execgate::{ExecGateDecision, ExecGateDeny};
    use std::collections::HashSet;

    fn counters(blocked: u64, once: u64, trusted: u64, failopen: u64) -> ExecGateCounters {
        ExecGateCounters {
            blocked,
            allowed_once: once,
            trusted,
            failopen,
            hashed: 400,
            cache_hit: 9_000,
            allowlisted: 300,
            over_cap: 3,
            error: 1,
            deadline: 2,
            overflow: 0,
            marks: 12,
            uncovered: 0,
            ..Default::default()
        }
    }

    fn ledger(now: u64) -> Ledger {
        Ledger::new(None, "0.3.0", Duration::from_secs(300), now)
    }

    /// A ledger whose start report is already out, for the steady-state rules.
    fn started(now: u64) -> Ledger {
        let mut l = ledger(now);
        assert!(l.tick(&counters(0, 0, 0, 0), now), "the first tick reports");
        assert_eq!(l.drain(1, |_| Delivery::Accepted), 1);
        l
    }

    #[test]
    fn the_first_live_tick_after_a_start_reports_at_once() {
        // Idle: one zero row over a zero-length window, which kub0 accepts (it
        // refuses only an end before the start), and only once per start.
        let mut l = ledger(5_000);
        assert!(l.tick(&counters(0, 0, 0, 0), 5_000));
        let r = l.pending.front().unwrap();
        assert_eq!((r.outcomes.len(), r.outcomes[0].count), (1, 0));
        assert_eq!(r.window_start, r.window_end);
        assert!(!l.tick(&counters(0, 0, 0, 0), 5_060), "once per start, not per tick");
        assert_eq!(l.pending(), 1);
        // Busy before the first tick: the start report carries the decisions
        // even though the window is younger than the interval.
        let mut l = ledger(5_000);
        assert!(l.tick(&counters(2, 0, 1, 0), 5_030));
        let rows: Vec<(String, u64)> =
            l.pending.front().unwrap().outcomes.iter().map(|o| (o.result.clone(), o.count)).collect();
        assert_eq!(rows, vec![("blocked".into(), 2), ("allowed_local_trust".into(), 1)]);
    }

    #[test]
    fn url_is_root_hosted_like_the_heartbeat() {
        assert_eq!(
            outcomes_url("https://api.example.com"),
            "https://api.example.com/ingest/outcomes"
        );
        assert_eq!(
            outcomes_url("https://api.example.com/"),
            outcomes_url("https://api.example.com")
        );
        assert!(!outcomes_url("https://api.example.com").contains("/detonate"));
    }

    #[test]
    fn interval_and_opt_out_env() {
        assert_eq!(interval_from(None).as_secs(), DEFAULT_INTERVAL_SECS);
        assert_eq!(interval_from(Some("900")).as_secs(), 900);
        assert_eq!(interval_from(Some("5")).as_secs(), MIN_INTERVAL_SECS, "floored");
        assert_eq!(interval_from(Some("nope")).as_secs(), DEFAULT_INTERVAL_SECS);
        assert!(enabled_from(None));
        assert!(enabled_from(Some("1")));
        assert!(!enabled_from(Some("0")));
        assert!(!enabled_from(Some(" 0 ")));
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_793_794_629), "2026-11-04T12:17:09Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn report_has_exactly_the_documented_keys_and_only_enums_and_counters() {
        let mut l = ledger(1_000);
        assert!(l.tick(&counters(2, 1, 0, 0), 1_400));
        let v = serde_json::to_value(l.pending.front().unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        let keys: HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let want: HashSet<&str> = [
            "agent",
            "agent_version",
            "platform",
            "window_start",
            "window_end",
            "outcomes",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, want, "{v}");
        assert_eq!(obj["agent"], "vallum");
        assert_eq!(obj["agent_version"], "0.3.0");
        assert!(obj["platform"] == "linux" || obj["platform"] == "macos");
        assert_eq!(obj["window_start"], "1970-01-01T00:16:40Z");
        assert_eq!(obj["window_end"], "1970-01-01T00:23:20Z");
        let rows = obj["outcomes"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            let keys: HashSet<&str> = row.as_object().unwrap().keys().map(|s| s.as_str()).collect();
            assert_eq!(keys, ["kind", "result", "count"].into_iter().collect::<HashSet<_>>());
            assert_eq!(row["kind"], "exec_gate");
        }
        assert_eq!(rows[0]["result"], "blocked");
        assert_eq!(rows[0]["count"], 2);
        assert_eq!(rows[1]["result"], "allowed_once");
        assert_eq!(rows[1]["count"], 1);
    }

    #[test]
    fn a_deny_records_strings_never_reach_the_wire() {
        // The frame a live gate hands the ledger carries the deny ring: path,
        // digest, reason, who promoted it. None of it may be in the report.
        let deny = ExecGateDeny {
            ts: 1,
            pid: 4242,
            ppid: 1,
            comm: "xmrig-secret-comm".into(),
            exe: "/home/someone/.cache/xmrig-secret-path".into(),
            sha256: "deadbeef".repeat(8),
            reason: "secret-reason".into(),
            promoted_by: "secret-promoter".into(),
            created_at: "2026-10-01T00:00:00Z".into(),
            decision: ExecGateDecision::Blocked,
        };
        let frame = ExecGateFrame {
            enabled: true,
            armed: true,
            keys: 7,
            source: "live".into(),
            observed_at: 1,
            counters: counters(1, 0, 0, 0),
            denies: vec![deny.clone()],
            trusted: Vec::new(),
            once_pending: 0,
            list_received_at: 0,
            list_restored: false,
        };
        let mut l = ledger(0);
        assert!(l.tick_frame(&frame, 600));
        let wire = serde_json::to_string(l.pending.front().unwrap()).unwrap();
        for secret in [
            deny.comm.as_str(),
            deny.exe.as_str(),
            deny.sha256.as_str(),
            deny.reason.as_str(),
            deny.promoted_by.as_str(),
            "4242",
        ] {
            assert!(!wire.contains(secret), "{secret} leaked into {wire}");
        }
    }

    #[test]
    fn only_a_live_frame_is_counted() {
        for source in ["mirror", "stale", "none", ""] {
            let frame = ExecGateFrame {
                source: source.into(),
                counters: counters(5, 0, 0, 0),
                ..Default::default()
            };
            let mut l = ledger(0);
            assert!(!l.tick_frame(&frame, 10_000), "{source:?} must not report");
            assert_eq!(l.pending(), 0);
        }
    }

    #[test]
    fn nothing_is_reported_before_the_window_is_old_or_while_the_delta_is_zero() {
        let mut l = started(1_000);
        assert!(!l.tick(&counters(3, 0, 0, 0), 1_100), "window too young");
        assert!(!l.tick(&counters(0, 0, 0, 0), 1_400), "zero delta");
        assert!(l.tick(&counters(3, 0, 0, 0), 1_400), "old window, non-zero delta");
        assert!(!l.tick(&counters(3, 0, 0, 0), 2_000), "already reported");
        assert_eq!(l.pending(), 1);
    }

    #[test]
    fn a_gate_restart_counts_from_zero_rather_than_underflowing() {
        let mut l = ledger(0);
        assert!(l.tick(&counters(10, 4, 0, 0), 300));
        // The gate restarted: counters dropped below the base.
        assert!(l.tick(&counters(2, 1, 0, 0), 600));
        let r = l.pending.back().unwrap();
        assert_eq!(r.outcomes[0].result, "blocked");
        assert_eq!(r.outcomes[0].count, 2);
        assert_eq!(r.outcomes[1].result, "allowed_once");
        assert_eq!(r.outcomes[1].count, 1);
    }

    #[test]
    fn an_idle_gate_sends_one_zero_row_a_day() {
        let mut l = started(0);
        assert!(!l.tick(&counters(0, 0, 0, 0), KEEPALIVE_SECS - 1));
        assert!(l.tick(&counters(0, 0, 0, 0), KEEPALIVE_SECS));
        let r = l.pending.front().unwrap();
        assert_eq!(r.outcomes.len(), 1);
        assert_eq!(r.outcomes[0].count, 0);
        assert_eq!(r.outcomes[0].result, "blocked");
        assert_eq!(r.window_start, rfc3339(0));
        assert_eq!(r.window_end, rfc3339(KEEPALIVE_SECS));
        assert!(!l.tick(&counters(0, 0, 0, 0), KEEPALIVE_SECS + 300), "not again until tomorrow");
    }

    #[test]
    fn drain_sends_oldest_first_drops_rejected_and_stops_on_retry() {
        let mut l = ledger(0);
        for i in 1..=4 {
            assert!(l.tick(&counters(i, 0, 0, 0), i * 300));
        }
        let mut seen = Vec::new();
        let n = l.drain(10, |r| {
            seen.push(r.window_end.clone());
            match seen.len() {
                1 => Delivery::Accepted,
                2 => Delivery::Rejected,
                _ => Delivery::Retry,
            }
        });
        assert_eq!(n, 1);
        assert_eq!(seen, vec![rfc3339(300), rfc3339(600), rfc3339(900)]);
        assert_eq!(l.pending(), 2, "the retried one and the one behind it stay");
        assert_eq!(l.pending.front().unwrap().window_end, rfc3339(900));
    }

    #[test]
    fn drain_honours_the_per_tick_cap() {
        let mut l = ledger(0);
        for i in 1..=20 {
            assert!(l.tick(&counters(i, 0, 0, 0), i * 300));
        }
        assert_eq!(l.drain(DRAIN_PER_TICK, |_| Delivery::Accepted), DRAIN_PER_TICK);
        assert_eq!(l.pending(), 20 - DRAIN_PER_TICK);
    }

    #[test]
    fn the_spool_is_capped_oldest_first() {
        let mut l = ledger(0);
        for i in 1..=(SPOOL_CAP as u64 + 5) {
            assert!(l.tick(&counters(i, 0, 0, 0), i * 300));
        }
        assert_eq!(l.pending(), SPOOL_CAP);
        assert_eq!(l.pending.front().unwrap().window_end, rfc3339(6 * 300));
    }

    #[test]
    fn the_spool_survives_a_restart_and_is_removed_once_drained() {
        let dir = std::env::temp_dir().join(format!("vallum-outcomes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SPOOL_FILE);
        {
            let mut l = Ledger::new(Some(&dir), "0.3.0", Duration::from_secs(300), 0);
            assert!(l.tick(&counters(1, 0, 0, 0), 300));
            assert!(l.tick(&counters(3, 0, 0, 0), 600));
            assert_eq!(l.drain(10, |_| Delivery::Retry), 0, "offline: nothing accepted");
        }
        let meta = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let mut l = Ledger::new(Some(&dir), "0.3.1", Duration::from_secs(300), 10_000);
        assert_eq!(l.pending(), 2, "a new daemon picks the spool up");
        assert_eq!(l.pending.front().unwrap().window_end, rfc3339(300));
        assert_eq!(l.drain(10, |_| Delivery::Accepted), 2);
        assert!(!path.exists(), "an empty spool is no file");
        // Garbage is an empty spool, not a crash.
        std::fs::write(&path, b"{not json").unwrap();
        let l = Ledger::new(Some(&dir), "0.3.1", Duration::from_secs(300), 10_000);
        assert_eq!(l.pending(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
