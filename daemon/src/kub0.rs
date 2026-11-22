//! Optional kub0 account file and heartbeat payload.
//!
//! Offline-first: sampling never waits on these helpers. HTTP lives in the
//! binary (`main.rs`); this module is pure file/JSON so tests stay off-network.

use crate::event::{AccountHello, DenylistEntry, Event, FleetEndpoint};
use crate::geo::AsnDb;
use crate::netpolicy::{self, ConnPolicy, Enforcement, EvalOpts, Floor, Ledger, MatchReport, PolicySet, PolicyView, Snoozes};
use crate::suggest::Kind;
use crate::tags::{self, TagStore};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const DEFAULT_AUTH_URL: &str = "https://kub0.ai";
pub const DEFAULT_SERVER_URL: &str = "https://api.kub0.io";
/// What `Kub0Runtime::data_dir` answers before a data dir is set. Absolute, and
/// never a real directory.
pub const NO_DATA_DIR: &str = "/nonexistent/kub0-data-dir-not-set";
/// The system daemon's account file, in the state directory in use
/// (`rename::state_root`: `/var/lib/kub0`, or `/var/lib/vallum` until it is
/// moved).
pub fn system_account_path() -> PathBuf {
    crate::rename::state_path("account.json")
}
pub const HTTP_TIMEOUT_SECS: u64 = 10;
pub const HEARTBEAT_INTERVAL_DEFAULT_SECS: u64 = 60;
pub const HEARTBEAT_INTERVAL_MIN_SECS: u64 = 15;
pub const DENYLIST_CAP: usize = 500;

/// On-disk account. Mode 0600. Never log `token`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountFile {
    pub schema: u32,
    pub token: String,
    pub github_username: String,
    pub connected_at: u64,
    pub server_url: String,
}

/// What the owner of a system daemon chose with `kub0 share on|off`, kept in the
/// daemon's state directory so it holds across restarts. A user daemon has no
/// such file: the panel that starts it passes `--share-destinations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub share_destinations: bool,
}

pub fn settings_path(state_dir: &Path) -> PathBuf {
    state_dir.join("settings.json")
}

/// The saved settings; the defaults when there is no file or it does not parse.
pub fn load_settings(state_dir: &Path) -> Settings {
    std::fs::read_to_string(settings_path(state_dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Written through a synced temp file and a rename, and the directory synced
/// after it: a power cut just after `kub0 share off` must not bring back the
/// file that said on.
pub fn save_settings(state_dir: &Path, settings: &Settings) -> std::io::Result<()> {
    let text = serde_json::to_string(settings).unwrap_or_else(|_| "{}".into());
    crate::trust::write_atomic(&settings_path(state_dir), text.as_bytes(), 0o644)?;
    std::fs::File::open(state_dir)?.sync_all()
}

/// Whose org data this is, for anything kept on disk between runs: the same login on
/// the same server. The server is the one the lists are fetched from
/// ([`heartbeat_server_url`], so `KUB0_SERVER_URL` counts), and the token is not part
/// of it: a rotated token is the same account.
pub fn account_id(a: &AccountFile) -> String {
    format!("{}@{}", a.github_username, heartbeat_server_url(a))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatPayload {
    pub node_name: String,
    pub probe_ver: String,
    pub lsm_active: bool,
    pub lsm_capable: bool,
    pub event_count: u64,
    /// Which agent is reporting. Always "vallum" from this binary. The API defaults a
    /// missing value to "vigiles", so sending it is what stops a vallum endpoint being
    /// described with eBPF wording and rendered as degraded.
    pub agent: String,
    pub agent_ver: String,
    pub kernel_version: String,
    pub arch: String,
    /// Apps this host is currently blocking. This is vallum's honest protection signal —
    /// it has no BPF_LSM to attach, so `lsm_active` is always false and means nothing.
    pub blocks_active: u64,
    /// User-authored tags this node is offering the rest of the org.
    ///
    /// Built only from [`TagStore`] entries whose source is User. A fleet tag
    /// re-uploaded as our own would inflate the distinct-reporter count that
    /// [`tags::score`] depends on, which is the failure the distinct-node rule
    /// exists to prevent. Always present on the wire (empty array when the
    /// account is disconnected or the store is empty/unreadable) so the
    /// payload key set stays exact.
    #[serde(default)]
    pub tags: Vec<HeartbeatTag>,
    /// Org network-policy match counts since the last successful heartbeat. Always
    /// present (empty when nothing matched), for the same exact-key-set reason as `tags`.
    #[serde(default)]
    pub policy_matches: Vec<MatchReport>,
    /// Network keys (/24 or /48) of public destinations first reached since the
    /// last successful heartbeat, for the org prevalence answer. Never an
    /// address, never an app. Always present; empty unless the user opted in
    /// with `--share-destinations` (docs/INTEL.md).
    #[serde(default)]
    pub dest_networks: Vec<String>,
}

/// Cap on destination networks per heartbeat. Beyond it the oldest are
/// dropped: the answer is a prevalence hint, not an inventory.
pub const DEST_NETWORKS_CAP: usize = 256;

/// How many other org endpoints have reached a network, as the server answers
/// on the heartbeat. `nodes` excludes this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prevalence {
    pub network_key: String,
    pub nodes: u64,
    /// Unix ms when any endpoint in the org first reported it; 0 if unknown.
    #[serde(default)]
    pub first_seen: u64,
}

/// Additive `prevalence` on a heartbeat response. `None` when the key is absent
/// (a server that does not answer prevalence), `Some(empty)` when it answered
/// with nothing. Rows missing a key or with a non-numeric count are skipped.
pub fn parse_prevalence(v: &serde_json::Value) -> Option<Vec<Prevalence>> {
    let arr = v.get("prevalence")?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|r| {
                let key = r.get("network_key").or_else(|| r.get("networkKey"))?.as_str()?;
                if key.is_empty() || key.len() > 64 {
                    return None;
                }
                let nodes = r.get("nodes")?.as_u64()?;
                let first_seen = r.get("first_seen").or_else(|| r.get("firstSeen")).and_then(|x| x.as_u64()).unwrap_or(0);
                Some(Prevalence {
                    network_key: key.to_string(),
                    nodes,
                    first_seen,
                })
            })
            .take(4096)
            .collect(),
    )
}

/// One user tag as uploaded on the heartbeat. Label, network key, kind, and
/// PTR suffix -- nothing else. `ts` and `source` stay local.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatTag {
    pub network_key: String,
    pub label: String,
    pub kind: Kind,
    pub ptr_suffix: String,
}

/// The agent name this binary reports. Must match the kub0 API's closed set.
pub const AGENT: &str = "vallum";

/// Last-good fleet numbers. Heartbeat failures keep these.
#[derive(Debug, Clone, PartialEq)]
pub struct FleetSnapshot {
    pub connected: bool,
    pub org_endpoints: u64,
    pub node_limit: u64,
    pub self_state: String,
    pub last_heartbeat_ok: Option<bool>,
    pub last_heartbeat_ts: u64,
    pub denylist_version: u64,
    pub denylist: Vec<DenylistEntry>,
    /// How many rows the org sent, before [`DENYLIST_CAP`]. The exec gate's
    /// breaker uses this; `denylist` stays capped for the panel. Not on the wire.
    pub denylist_reported: usize,
    pub endpoints: Vec<FleetEndpoint>,
    pub endpoints_updated_at: u64,
    pub endpoints_refresh_ok: Option<bool>,
    /// Whether the last network-policy fetch succeeded. On a failure the last policy
    /// received is still the one enforced.
    pub netpolicy_refresh_ok: Option<bool>,
    /// Latest `fleet_tags` from a successful heartbeat response. Empty when
    /// the API omitted the field (older servers) or the body was unreadable.
    pub fleet_tags: Vec<tags::FleetReport>,
    /// The org network policies this endpoint receives, with local match counts.
    pub netpolicies: Vec<PolicyView>,
    /// Whether and how this endpoint enforces its org's block rules.
    pub netpolicy_enforcement: Enforcement,
    /// Latest prevalence answers, merged across heartbeats (newest wins per key).
    pub prevalence: Vec<Prevalence>,
    /// Whether the server answered `prevalence` on the last 200: `None` until a
    /// heartbeat succeeded, `Some(false)` for a server that does not know the
    /// field. The panel says which rather than showing a blank.
    pub prevalence_supported: Option<bool>,
    /// Whether this daemon was started with `--share-destinations`.
    pub sharing_destinations: bool,
    /// Deny-list stream: `Some(true)` delivering, `Some(false)` down (the poll
    /// is the source), `None` not running. Filled by `fleet_event`.
    pub denylist_live: Option<bool>,
    /// The exec gate's frame for the local fleet event. The heartbeat payload
    /// does not carry it; `fleet_event` fills this from the running gate (or
    /// its mirror, in user mode).
    pub exec_gate: crate::execgate::ExecGateFrame,
}

impl Default for FleetSnapshot {
    fn default() -> Self {
        Self {
            connected: false,
            org_endpoints: 0,
            node_limit: 0,
            self_state: "unknown".into(),
            last_heartbeat_ok: None,
            last_heartbeat_ts: 0,
            denylist_version: 0,
            denylist: Vec::new(),
            denylist_reported: 0,
            endpoints: Vec::new(),
            endpoints_updated_at: 0,
            endpoints_refresh_ok: None,
            netpolicy_refresh_ok: None,
            fleet_tags: Vec::new(),
            netpolicies: Vec::new(),
            netpolicy_enforcement: Enforcement::default(),
            prevalence: Vec::new(),
            prevalence_supported: None,
            sharing_destinations: false,
            denylist_live: None,
            exec_gate: crate::execgate::ExecGateFrame::default(),
        }
    }
}

impl FleetSnapshot {
    pub fn to_event(&self, ts: u64) -> Event {
        Event::Fleet {
            ts,
            connected: self.connected,
            org_endpoints: self.org_endpoints,
            node_limit: self.node_limit,
            self_state: self.self_state.clone(),
            last_heartbeat_ok: self.last_heartbeat_ok,
            last_heartbeat_ts: self.last_heartbeat_ts,
            denylist_version: self.denylist_version,
            denylist: self.denylist.clone(),
            endpoints: self.endpoints.clone(),
            endpoints_updated_at: self.endpoints_updated_at,
            endpoints_refresh_ok: self.endpoints_refresh_ok,
            netpolicy_refresh_ok: self.netpolicy_refresh_ok,
            netpolicies: self.netpolicies.clone(),
            netpolicy_enforcement: self.netpolicy_enforcement.clone(),
            prevalence: self.prevalence.clone(),
            prevalence_supported: self.prevalence_supported,
            sharing_destinations: self.sharing_destinations,
            denylist_live: self.denylist_live,
            exec_gate: self.exec_gate.clone(),
        }
    }

    /// Fold a heartbeat's prevalence answer in: newest wins per key, the list
    /// stays bounded, and `None` (no key on the response) records that the
    /// server does not answer it.
    pub fn apply_prevalence(&mut self, answer: Option<Vec<Prevalence>>) {
        match answer {
            None => self.prevalence_supported = Some(false),
            Some(rows) => {
                self.prevalence_supported = Some(true);
                for r in rows {
                    self.prevalence.retain(|p| p.network_key != r.network_key);
                    self.prevalence.push(r);
                }
                if self.prevalence.len() > 4096 {
                    let excess = self.prevalence.len() - 4096;
                    self.prevalence.drain(..excess);
                }
            }
        }
    }
}

/// `kub0 sync` requests to the applier (the heartbeat thread): how many were
/// made, and the newest one it has served.
#[derive(Default)]
struct SyncTurn {
    asked: u64,
    served: u64,
}

pub struct Kub0Runtime {
    pub system_plan: crate::system_status::PlanState,
    connected: AtomicBool,
    /// -1 = never attempted (JSON null), 0 = last failed, 1 = last succeeded.
    last_ok: AtomicI8,
    node_name: Mutex<String>,
    github_username: Mutex<String>,
    event_count: AtomicU64,
    last_heartbeat_ts: AtomicU64,
    fleet: Mutex<FleetSnapshot>,
    fleet_gen: AtomicU64,
    policies: Mutex<Arc<PolicySet>>,
    policy_floor: Mutex<Arc<Floor>>,
    policy_ledger: Mutex<Ledger>,
    policy_asn: Mutex<Arc<AsnDb>>,
    snoozes: Mutex<Snoozes>,
    snooze_dir: Mutex<Option<PathBuf>>,
    enforcement: Mutex<Arc<Enforcement>>,
    data_dir: Mutex<Option<PathBuf>>,
    replan: AtomicBool,
    sync_turn: Mutex<SyncTurn>,
    sync_served: Condvar,
    /// Destination networks waiting for the next heartbeat; see `dest_networks`.
    pending_networks: Mutex<Vec<String>>,
    sharing_destinations: AtomicBool,
    /// -1 = no stream thread, 0 = down, 1 = delivering.
    denylist_live: AtomicI8,
    /// Set by the stream when the list changed: the heartbeat thread refreshes
    /// at once so the REST row metadata catches up with the keys.
    refresh_now: AtomicBool,
    /// This user daemon is leaving the heartbeat to the system daemon; see
    /// `defer_heartbeat_to_system`.
    heartbeat_deferred: AtomicBool,
}

impl Kub0Runtime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            system_plan: Default::default(),
            connected: AtomicBool::new(false),
            last_ok: AtomicI8::new(-1),
            node_name: Mutex::new(node_name()),
            github_username: Mutex::new(String::new()),
            event_count: AtomicU64::new(0),
            last_heartbeat_ts: AtomicU64::new(0),
            fleet: Mutex::new(FleetSnapshot::default()),
            fleet_gen: AtomicU64::new(0),
            policies: Mutex::new(Arc::new(PolicySet::default())),
            policy_floor: Mutex::new(Arc::new(Floor::default())),
            policy_ledger: Mutex::new(Ledger::default()),
            policy_asn: Mutex::new(Arc::new(AsnDb::empty())),
            snoozes: Mutex::new(Snoozes::new()),
            snooze_dir: Mutex::new(None),
            enforcement: Mutex::new(Arc::new(Enforcement::default())),
            pending_networks: Mutex::new(Vec::new()),
            sharing_destinations: AtomicBool::new(false),
            data_dir: Mutex::new(None),
            replan: AtomicBool::new(false),
            sync_turn: Mutex::new(SyncTurn::default()),
            sync_served: Condvar::new(),
            denylist_live: AtomicI8::new(-1),
            refresh_now: AtomicBool::new(false),
            heartbeat_deferred: AtomicBool::new(false),
        })
    }

    pub fn set_denylist_live(&self, live: Option<bool>) {
        let v = match live {
            None => -1,
            Some(false) => 0,
            Some(true) => 1,
        };
        if self.denylist_live.swap(v, Ordering::Relaxed) != v {
            self.fleet_gen.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn denylist_live(&self) -> Option<bool> {
        match self.denylist_live.load(Ordering::Relaxed) {
            1 => Some(true),
            0 => Some(false),
            _ => None,
        }
    }

    /// Ask the heartbeat thread to refresh the fleet before its next interval.
    pub fn request_refresh(&self) {
        self.refresh_now.store(true, Ordering::Relaxed);
    }

    pub fn take_refresh_request(&self) -> bool {
        self.refresh_now.swap(false, Ordering::Relaxed)
    }

    /// Re-broadcast the fleet frame without changing the snapshot (the exec
    /// gate changed and it is read at event time).
    pub fn touch_fleet(&self) {
        self.fleet_gen.fetch_add(1, Ordering::Relaxed);
    }

    /// Replace the deny-list rows from a stream snapshot. The REST poll's
    /// metadata is carried over by `(comm, path)`. Returns the rows installed.
    pub fn apply_denylist_snapshot(
        &self,
        mut rows: Vec<DenylistEntry>,
        reported: usize,
    ) -> Vec<DenylistEntry> {
        let mut snap = self.fleet_snapshot();
        crate::sse::merge_metadata(&mut rows, &snap.denylist);
        snap.denylist = rows.clone();
        snap.denylist_reported = reported;
        self.publish_fleet(snap);
        rows
    }

    /// Apply one stream update to the deny-list rows. Returns the rows now
    /// installed and the reported count the gate's breaker should see.
    pub fn apply_denylist_update(&self, u: &crate::sse::DenylistUpdate) -> (Vec<DenylistEntry>, usize) {
        let mut snap = self.fleet_snapshot();
        let before = snap.denylist.len();
        let changed = crate::sse::apply_update(&mut snap.denylist, u);
        let after = snap.denylist.len();
        // The uncapped count moves with the capped rows when it can; a list
        // already past the cap keeps its reported size until the next poll.
        if changed && snap.denylist_reported <= DENYLIST_CAP {
            snap.denylist_reported = (snap.denylist_reported + after).saturating_sub(before);
        }
        let out = (snap.denylist.clone(), snap.denylist_reported);
        if changed {
            self.publish_fleet(snap);
        }
        out
    }

    /// Everything network policy needs at boot: the ASN database for shared-infrastructure
    /// checks, the data dir the enforcer enumerates ranges from, and this device's snoozes.
    pub fn boot_netpolicy(&self, data_dir: &Path, state_dir: &Path) {
        self.set_asn(Arc::new(AsnDb::load(data_dir)));
        if let Ok(mut g) = self.data_dir.lock() {
            *g = Some(data_dir.to_path_buf());
        }
        self.load_snoozes(state_dir);
    }

    /// The data dir `boot_netpolicy` was given. Before that there is none,
    /// and the answer is a path that does not exist: an enforcer built from it
    /// finds no database and applies nothing. It used to be the relative path
    /// `data`, which for a system daemon is `/data`.
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| PathBuf::from(NO_DATA_DIR))
    }

    /// True once after a snooze changed: the enforcer should re-plan now.
    pub fn take_replan(&self) -> bool {
        self.replan.swap(false, Ordering::Relaxed)
    }

    /// `kub0 sync`: ask the applier to put the org's block rules in the kernel
    /// again now. The ticket is what `wait_sync` waits on.
    pub fn request_sync(&self) -> u64 {
        let mut turn = self.sync_turn.lock().unwrap_or_else(|e| e.into_inner());
        turn.asked += 1;
        turn.asked
    }

    /// The applier's side: the newest request it has not served, if any. One
    /// re-apply answers every request made before it.
    pub fn take_sync_request(&self) -> Option<u64> {
        let turn = self.sync_turn.lock().unwrap_or_else(|e| e.into_inner());
        (turn.asked > turn.served).then_some(turn.asked)
    }

    /// The applier's side: every request up to `ticket` has its answer in
    /// `enforcement()`.
    pub fn finish_sync(&self, ticket: u64) {
        let mut turn = self.sync_turn.lock().unwrap_or_else(|e| e.into_inner());
        turn.served = turn.served.max(ticket);
        drop(turn);
        self.sync_served.notify_all();
    }

    /// True once the applier has served `ticket`. False when `timeout` passed
    /// first; the request stays queued and is served when the applier is free.
    pub fn wait_sync(&self, ticket: u64, timeout: Duration) -> bool {
        let turn = self.sync_turn.lock().unwrap_or_else(|e| e.into_inner());
        let (turn, _) = self
            .sync_served
            .wait_timeout_while(turn, timeout, |t| t.served < ticket)
            .unwrap_or_else(|e| e.into_inner());
        turn.served >= ticket
    }

    /// Push the current policy view and enforcement into the fleet frame now, rather
    /// than at the next heartbeat.
    pub fn republish_policy_view(&self) {
        let mut snap = self.fleet_snapshot();
        snap.netpolicies = self.policy_view();
        snap.netpolicy_enforcement = (*self.enforcement()).clone();
        self.publish_fleet(snap);
    }

    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
        if !connected {
            // Keys noted under this account are not the next one's to receive.
            self.forget_networks();
            self.last_ok.store(-1, Ordering::Relaxed);
            if let Ok(mut g) = self.github_username.lock() {
                g.clear();
            }
        }
    }

    pub fn set_github_username(&self, name: &str) {
        if let Ok(mut g) = self.github_username.lock() {
            *g = name.to_string();
        }
    }

    pub fn set_last_ok(&self, ok: bool) {
        self.last_ok
            .store(if ok { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Back to "never attempted" (JSON null): nothing is known about the last heartbeat.
    pub fn clear_last_ok(&self) {
        self.last_ok.store(-1, Ordering::Relaxed);
    }

    /// Record whether the heartbeat is deferred; returns the previous value.
    pub fn set_heartbeat_deferred(&self, deferred: bool) -> bool {
        self.heartbeat_deferred.swap(deferred, Ordering::Relaxed)
    }

    pub fn heartbeat_deferred(&self) -> bool {
        self.heartbeat_deferred.load(Ordering::Relaxed)
    }

    pub fn set_last_heartbeat_ts(&self, ts: u64) {
        self.last_heartbeat_ts.store(ts, Ordering::Relaxed);
    }

    pub fn last_heartbeat_ok(&self) -> Option<bool> {
        if !self.connected.load(Ordering::Relaxed) {
            return None;
        }
        match self.last_ok.load(Ordering::Relaxed) {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub fn note_connection(&self) {
        self.event_count.fetch_add(1, Ordering::Relaxed);
    }

    /// A change is every client's to see: the fleet frame carries it. The flag
    /// is swapped under the fleet lock, which `publish_fleet` reads it under, so
    /// a snapshot published at the same moment cannot carry the old value.
    ///
    /// Off means off now: the keys queued for the next heartbeat are dropped.
    /// As a start-up flag, sharing only ever went off with the process, which
    /// took the queue with it; a setting changed on a running daemon must not
    /// send, a minute or a day later, what was collected before it was changed.
    pub fn set_sharing_destinations(&self, on: bool) {
        let was = {
            let mut g = self.fleet.lock().unwrap_or_else(|e| e.into_inner());
            g.sharing_destinations = on;
            self.sharing_destinations.swap(on, Ordering::Relaxed)
        };
        if !on {
            self.forget_networks();
        }
        if was != on {
            self.fleet_gen.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop every destination key queued for a heartbeat.
    pub fn forget_networks(&self) {
        if let Ok(mut g) = self.pending_networks.lock() {
            g.clear();
        }
    }

    pub fn sharing_destinations(&self) -> bool {
        self.sharing_destinations.load(Ordering::Relaxed)
    }

    /// Queue a public destination's network key for the next heartbeat. A
    /// no-op unless sharing is on and an account is connected (a key noted
    /// while logged out would go to whichever org logs in next); deduplicated;
    /// bounded.
    pub fn note_network(&self, key: &str) {
        if !self.sharing_destinations() || !self.connected.load(Ordering::Relaxed) || key.is_empty() {
            return;
        }
        if let Ok(mut g) = self.pending_networks.lock() {
            if g.iter().any(|k| k == key) {
                return;
            }
            g.push(key.to_string());
            if g.len() > DEST_NETWORKS_CAP {
                g.remove(0);
            }
        }
    }

    /// The keys for this heartbeat. None while sharing is off, whatever is
    /// queued: the queue is emptied either way.
    pub fn drain_networks(&self) -> Vec<String> {
        let keys = self.pending_networks.lock().map(|mut g| std::mem::take(&mut *g)).unwrap_or_default();
        if self.sharing_destinations() { keys } else { Vec::new() }
    }

    /// Undelivered keys go back ahead of the ones noted since, so the list
    /// stays oldest-first; over the cap the oldest are dropped, as in
    /// `note_network`, so the newest destinations always survive.
    ///
    /// Not while sharing is off: a heartbeat that failed before the owner
    /// switched it off must not bring its keys back for the next one.
    pub fn restore_networks(&self, keys: Vec<String>) {
        if !self.sharing_destinations() {
            return;
        }
        if let Ok(mut g) = self.pending_networks.lock() {
            let mut merged: Vec<String> = Vec::new();
            for k in keys {
                if !g.contains(&k) && !merged.contains(&k) {
                    merged.push(k);
                }
            }
            merged.append(&mut g);
            while merged.len() > DEST_NETWORKS_CAP {
                merged.remove(0);
            }
            *g = merged;
        }
    }

    /// Record a heartbeat's prevalence answer on the snapshot.
    pub fn apply_prevalence(&self, answer: Option<Vec<Prevalence>>) {
        if let Ok(mut g) = self.fleet.lock() {
            g.apply_prevalence(answer);
        }
    }

    pub fn prevalence(&self) -> (Vec<Prevalence>, Option<bool>) {
        self.fleet
            .lock()
            .map(|g| (g.prevalence.clone(), g.prevalence_supported))
            .unwrap_or_default()
    }

    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    pub fn hello_account(&self) -> AccountHello {
        let connected = self.connected.load(Ordering::Relaxed);
        AccountHello {
            connected,
            node_name: self
                .node_name
                .lock()
                .map(|g| g.clone())
                .unwrap_or_else(|_| node_name()),
            github_username: self
                .github_username
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default(),
            last_heartbeat_ok: self.last_heartbeat_ok(),
        }
    }

    pub fn fleet_snapshot(&self) -> FleetSnapshot {
        self.fleet
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn fleet_generation(&self) -> u64 {
        self.fleet_gen.load(Ordering::Relaxed)
    }

    pub fn publish_fleet(&self, mut snap: FleetSnapshot) {
        if let Ok(mut plan) = self.system_plan.lock() {
            plan.refresh_ok = snap.netpolicy_refresh_ok;
        }
        // The flag is this daemon's, not the server's: a snapshot built from
        // scratch (an account change) must not read as "not sharing". Read
        // under the lock `set_sharing_destinations` changes it under.
        if let Ok(mut g) = self.fleet.lock() {
            snap.sharing_destinations = self.sharing_destinations();
            *g = snap;
        }
        self.fleet_gen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fleet_event(&self, ts: u64) -> Event {
        let mut snap = self.fleet_snapshot();
        snap.exec_gate = crate::execgate::frame();
        snap.denylist_live = self.denylist_live();
        snap.to_event(ts)
    }

    /// Replace the org network policies. Pending match counts for rules that are gone
    /// still ship on the next heartbeat; the server drops ids it no longer knows.
    pub fn set_policies(&self, set: PolicySet) {
        if let Ok(mut g) = self.policies.lock() {
            *g = Arc::new(set);
        }
    }

    pub fn policies(&self) -> Arc<PolicySet> {
        self.policies
            .lock()
            .map(|g| Arc::clone(&g))
            .unwrap_or_default()
    }

    pub fn set_policy_floor(&self, floor: Floor) {
        if let Ok(mut g) = self.policy_floor.lock() {
            *g = Arc::new(floor);
        }
    }

    /// Evaluate one newly seen connection, record every match, and return the rules
    /// the panel should show on it. Floor addresses are counted, never shown as hits.
    pub fn evaluate_connection(
        &self,
        remote: &str,
        country: &str,
        exe: &str,
        ts: u64,
    ) -> Vec<ConnPolicy> {
        let set = self.policies();
        if set.is_empty() {
            return Vec::new();
        }
        let Ok(ip) = remote.parse::<std::net::IpAddr>() else {
            return Vec::new();
        };
        let floor = self
            .policy_floor
            .lock()
            .map(|g| Arc::clone(&g))
            .unwrap_or_default();
        let asn = self.asn();
        let enf = self.enforcement();
        let snoozes = self.snoozes();
        let opts = EvalOpts {
            asn: asn.asn(ip),
            enforcing: enf.enforcing,
            snoozes: Some(&snoozes),
            enforced_rules: Some(&enf.rules),
        };
        let hits = set.evaluate(ip, country, exe, &floor, &opts, ts);
        if hits.is_empty() {
            return Vec::new();
        }
        if let Ok(mut l) = self.policy_ledger.lock() {
            for h in &hits {
                l.record(h, ip, ts);
            }
        }
        hits.into_iter()
            .filter(|h| !h.suppressed)
            .map(|h| ConnPolicy {
                rule_id: h.rule_id,
                label: h.label,
            })
            .collect()
    }

    pub fn drain_policy_matches(&self) -> Vec<MatchReport> {
        self.policy_ledger
            .lock()
            .map(|mut l| l.drain())
            .unwrap_or_default()
    }

    /// Hand back counts a failed heartbeat did not deliver.
    pub fn restore_policy_matches(&self, reports: Vec<MatchReport>) {
        if reports.is_empty() {
            return;
        }
        if let Ok(mut l) = self.policy_ledger.lock() {
            l.restore(reports);
        }
    }

    pub fn policy_view(&self) -> Vec<PolicyView> {
        let set = self.policies();
        let snoozes = self.snoozes();
        let enf = self.enforcement();
        let now = crate::event::now_ms();
        self.policy_ledger
            .lock()
            .map(|l| set.view(&l, &snoozes, &enf, now))
            .unwrap_or_default()
    }

    pub fn set_asn(&self, asn: Arc<AsnDb>) {
        if let Ok(mut g) = self.policy_asn.lock() {
            *g = asn;
        }
    }

    pub fn asn(&self) -> Arc<AsnDb> {
        self.policy_asn
            .lock()
            .map(|g| Arc::clone(&g))
            .unwrap_or_else(|_| Arc::new(AsnDb::empty()))
    }

    pub fn enforcement(&self) -> Arc<Enforcement> {
        self.enforcement
            .lock()
            .map(|g| Arc::clone(&g))
            .unwrap_or_default()
    }

    pub fn set_enforcement(&self, e: Enforcement) {
        if let Ok(mut g) = self.enforcement.lock() {
            *g = Arc::new(e);
        }
    }

    /// Load this device's snoozes and remember where to save them.
    pub fn load_snoozes(&self, state_dir: &Path) {
        if let Ok(mut g) = self.snoozes.lock() {
            *g = netpolicy::load_snoozes(state_dir);
        }
        if let Ok(mut g) = self.snooze_dir.lock() {
            *g = Some(state_dir.to_path_buf());
        }
    }

    pub fn snoozes(&self) -> Snoozes {
        self.snoozes.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Snooze one rule on this device, if its policy allows it. Returns the end time.
    pub fn snooze_rule(&self, rule_id: &str, seconds: u64) -> Result<u64, String> {
        let set = self.policies();
        let now = crate::event::now_ms();
        let mut g = self.snoozes.lock().map_err(|_| "snooze state unavailable")?;
        let until = netpolicy::snooze(&set, &mut g, rule_id, seconds, now)?;
        self.persist_snoozes(&g, now);
        self.replan.store(true, Ordering::Relaxed);
        Ok(until)
    }

    /// End a snooze early. Always allowed: it only restores the org's rule.
    pub fn resume_rule(&self, rule_id: &str) {
        let now = crate::event::now_ms();
        if let Ok(mut g) = self.snoozes.lock() {
            g.remove(rule_id);
            self.persist_snoozes(&g, now);
        }
        self.replan.store(true, Ordering::Relaxed);
    }

    fn persist_snoozes(&self, snoozes: &Snoozes, now: u64) {
        let dir = self.snooze_dir.lock().ok().and_then(|g| g.clone());
        if let Some(dir) = dir {
            if let Err(e) = netpolicy::save_snoozes(&dir, snoozes, now) {
                eprintln!("kub0d: saving network-policy snoozes failed: {e}");
            }
        }
    }
}

/// Resolver files the floor reads: the stub file and, under systemd-resolved, the real
/// upstreams behind it. The stub file alone names only 127.0.0.53, which is how a
/// production canary on 2026-10-05 reported this host's own 1.1.1.1 resolver as a
/// destination. The same two files kub0-block's `host_critical` reads.
pub const RESOLV_FILES: &[&str] = &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];

/// The floor addresses only this host knows: the kub0 server it reports to and every
/// resolver in [`RESOLV_FILES`]. Re-read every refresh so a DNS change follows.
pub fn host_policy_floor(server_url: &str) -> Floor {
    let texts: Vec<String> = RESOLV_FILES
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect();
    host_policy_floor_from(server_url, &texts)
}

pub fn host_policy_floor_from(server_url: &str, resolv_texts: &[String]) -> Floor {
    let mut floor = Floor::default();
    floor.extra.extend(netpolicy::server_addrs(server_url));
    for text in resolv_texts {
        floor.extra.extend(netpolicy::resolvers_from(text));
    }
    floor
}

pub fn account_path_for(system: bool, user_state_dir: &Path) -> PathBuf {
    if system {
        system_account_path()
    } else {
        user_state_dir.join("account.json")
    }
}

pub fn node_name() -> String {
    match std::env::var("KUB0_NODE_NAME") {
        Ok(s) if !s.is_empty() => s,
        _ => hostname(),
    }
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes, including NUL.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

pub fn heartbeat_interval() -> Duration {
    let secs = std::env::var("KUB0_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(HEARTBEAT_INTERVAL_DEFAULT_SECS)
        .max(HEARTBEAT_INTERVAL_MIN_SECS);
    Duration::from_secs(secs)
}

/// A user daemon leaves the heartbeat to the system daemon on the same host when
/// that daemon is logged in and running. kub0 keys a heartbeat row on (org, node
/// name), and both daemons send the host name, so two senders overwrite one row
/// every interval: the census shows whichever wrote last, and while either one
/// keeps sending, the row stays fresh after the other dies. The system daemon is
/// the one that enforces, so it is the one kub0 should see.
pub fn defer_heartbeat_to_system(system: bool, system_account: bool, system_running: bool) -> bool {
    !system && system_account && system_running
}

/// What a deferring user daemon shows as its heartbeat: kub0's state for this
/// host's row, which the system daemon keeps. A row kub0 calls live is ok, a row
/// it calls `down` failed, and no row (or no answer) says nothing.
pub fn deferred_heartbeat_ok(self_state: &str) -> Option<bool> {
    match self_state {
        "enforced" | "monitored" | "enforcing" | "monitoring" => Some(true),
        "down" => Some(false),
        _ => None,
    }
}

/// A `kub0d --system` owned by root is running on this host. Only processes
/// owned by uid 0 count, so a user shell cannot fake one to silence another
/// user's daemon. With `/proc` mounted `hidepid` the answer is always no, and the
/// user daemon keeps sending as before.
#[cfg(target_os = "linux")]
pub fn system_daemon_running() -> bool {
    system_daemon_running_in(Path::new("/proc"), 0)
}

#[cfg(not(target_os = "linux"))]
pub fn system_daemon_running() -> bool {
    false
}

/// `system_daemon_running` over any proc-shaped directory and owner, for tests.
pub fn system_daemon_running_in(proc_root: &Path, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let numeric = name.to_str().is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
        numeric
            && std::fs::metadata(e.path()).is_ok_and(|m| m.uid() == owner)
            && std::fs::read(e.path().join("cmdline")).is_ok_and(|raw| is_system_daemon_cmdline(&raw))
    })
}

/// argv[0] is a `kub0d` and one later argument is `--system`. For one
/// release a 0.4.x system daemon counts too: a panel updated before
/// `kub0 install` runs again still finds the enforcer it sits beside.
pub fn is_system_daemon_cmdline(raw: &[u8]) -> bool {
    let mut args = raw.split(|&b| b == 0).filter(|a| !a.is_empty());
    let Some(argv0) = args.next() else {
        return false;
    };
    let base = argv0.rsplit(|&b| b == b'/').next().unwrap_or(argv0);
    base == b"kub0d" && args.any(|a| a == b"--system")
}

pub fn heartbeat_server_url(account: &AccountFile) -> String {
    match std::env::var("KUB0_SERVER_URL") {
        Ok(s) if !s.is_empty() => s,
        _ if !account.server_url.is_empty() => account.server_url.clone(),
        _ => DEFAULT_SERVER_URL.to_string(),
    }
}

/// Where each kub0 endpoint actually lives on the API host.
///
/// These are three functions rather than one base URL because the prefix is a
/// property of the *endpoint*, not of the host. Probed live 2026-09-20 against
/// `api.kub0.io`:
///
/// ```text
/// GET  /api/enforce/denylist           404   (identical to a made-up path)
/// GET  /detonate/api/enforce/denylist  200
/// GET  /api/nodes                      401   (routed; auth rejects it)
/// POST /ingest/heartbeat               401   (routed; auth rejects it)
/// POST /detonate/ingest/heartbeat      403   (the edge gate rejects it)
/// ```
///
/// So the deny-list is the one caller that needs `/detonate`, and moving the
/// shared base instead would fix the deny-list while silently breaking the
/// heartbeat -- 403 at the edge, never reaching the router.
///
/// 🔑 The discriminator is 404-vs-401 at the *same* prefix, not 401-vs-401
/// across two prefixes. An unrouted root `/api/*` path 404s, which is what
/// makes the 401 on `/api/nodes` evidence that it is routed at the root; two
/// 401s prove nothing, because host-scoped auth rejects before routing
/// resolves.
pub fn deny_list_url(server_url: &str) -> String {
    format!(
        "{}/detonate/api/enforce/denylist",
        server_url.trim_end_matches('/')
    )
}

/// Org network policy for this node. Served under `/detonate`, like the deny-list.
pub fn netpolicy_url(server_url: &str, node: &str) -> String {
    let mut enc = String::new();
    for b in node.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!(
        "{}/detonate/api/enforce/netpolicy?node={enc}",
        server_url.trim_end_matches('/')
    )
}

/// Fleet inventory. Root-hosted -- see [`deny_list_url`].
pub fn nodes_url(server_url: &str) -> String {
    format!("{}/api/nodes", server_url.trim_end_matches('/'))
}

/// Heartbeat ingest. Root-hosted -- see [`deny_list_url`]. Prefixing this with
/// `/detonate` is a regression, not a cleanup.
pub fn heartbeat_url(server_url: &str) -> String {
    format!("{}/ingest/heartbeat", server_url.trim_end_matches('/'))
}

/// `true` iff the comma-separated LSM list contains the token `bpf`.
pub fn lsm_capable_from(text: &str) -> bool {
    text.split(',').map(str::trim).any(|t| t == "bpf")
}

pub fn read_lsm_capable() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| lsm_capable_from(&s))
        .unwrap_or(false)
}

pub fn heartbeat_payload(
    node_name: impl Into<String>,
    probe_ver: impl Into<String>,
    lsm_capable: bool,
    event_count: u64,
    blocks_active: u64,
    tags: Vec<HeartbeatTag>,
    policy_matches: Vec<MatchReport>,
    dest_networks: Vec<String>,
) -> HeartbeatPayload {
    let ver = probe_ver.into();
    HeartbeatPayload {
        node_name: node_name.into(),
        probe_ver: ver.clone(),
        lsm_active: false,
        lsm_capable,
        event_count,
        agent: AGENT.to_string(),
        agent_ver: ver,
        kernel_version: read_kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        blocks_active,
        tags,
        policy_matches,
        dest_networks,
    }
}

/// User-sourced store entries as heartbeat tags. Fleet-sourced entries are
/// dropped: re-uploading them would claim another node's label as this
/// node's opinion.
pub fn user_heartbeat_tags(store: &TagStore) -> Vec<HeartbeatTag> {
    let mut tags: Vec<HeartbeatTag> = store
        .iter()
        .filter(|t| t.source == tags::Source::User)
        .map(|t| HeartbeatTag {
            network_key: t.network_key.clone(),
            label: t.label.clone(),
            kind: t.kind,
            ptr_suffix: t.ptr_suffix.clone(),
        })
        .collect();
    tags.sort_by(|a, b| a.network_key.cmp(&b.network_key));
    tags
}

/// Heartbeat tags for this tick. Disconnected accounts send an empty array
/// even if the store has user tags -- there is no org to share them with.
pub fn tags_for_heartbeat(connected: bool, store: &TagStore) -> Vec<HeartbeatTag> {
    if !connected {
        Vec::new()
    } else {
        user_heartbeat_tags(store)
    }
}

/// Load tags for a heartbeat from `state_dir`. Missing or unreadable is an
/// empty array, never an error: a heartbeat must not fail because of tags.
pub fn tags_for_heartbeat_dir(connected: bool, state_dir: &Path) -> Vec<HeartbeatTag> {
    tags_for_heartbeat(connected, &TagStore::load(state_dir))
}

/// `uname -r`, without spawning anything. Empty string when unreadable — the API treats
/// an empty value as "not reported" rather than overwriting a good stored one.
pub fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Count of apps with at least one live egress block, read from the helper's owner map —
/// the same file the panel rehydrates its blocked rows from, so the number the customer
/// sees in kub0 matches the number on their own screen.
///
/// Unreadable is 0, not an error: in user mode the helper may never have run, and a
/// heartbeat must never fail because a host has no blocks.
pub fn blocks_active_from(text: &str) -> u64 {
    #[derive(serde::Deserialize, Default)]
    struct OwnerFile {
        #[serde(default)]
        apps: std::collections::BTreeMap<String, Vec<String>>,
    }
    let parsed: OwnerFile = serde_json::from_str(text).unwrap_or_default();
    parsed.apps.values().filter(|ips| !ips.is_empty()).count() as u64
}

pub fn read_blocks_active(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .map(|t| blocks_active_from(&t))
        .unwrap_or(0)
}

/// Where the privileged helper persists its owner map.
pub fn owners_path() -> PathBuf {
    crate::rename::state_path("endpoint-owners.json")
}

/// Serialize account transitions across the daemon and the connect/disconnect
/// subprocesses. Lock a stable sibling, not account.json, which is deleted.
fn with_account_lock<T>(path: &Path, f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let lock_path = path.with_file_name("account.lock");
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Closing the file releases flock on success and on every error path.
    f()
}

/// Create/truncate with `OpenOptions` `mode(0o600)`. Never chmod after write.
/// Only explicit connect clears a disconnect marker; adoption calls the raw
/// writer while holding the same lock and cannot undo a disconnect.
pub fn write_account(path: &Path, account: &AccountFile) -> std::io::Result<()> {
    with_account_lock(path, || {
        write_account_raw(path, account)?;
        match std::fs::remove_file(disconnect_marker(path)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    })
}

fn write_account_raw(path: &Path, account: &AccountFile) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    let bytes = serde_json::to_vec(account)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    f.write_all(&bytes)?;
    Ok(())
}

/// Left beside the account file by a logout.
///
/// Deleting the account is not enough on its own: a running user daemon
/// re-adopts the token from ~/.kub0/config on its next check and recreates
/// the file, so heartbeats resumed within a minute of a disconnect and the
/// panel flipped back to connected. The marker says the user chose to leave,
/// and only an explicit connect clears it.
pub fn disconnect_marker(account_path: &Path) -> PathBuf {
    account_path.with_file_name("disconnected")
}

pub fn mark_disconnected(account_path: &Path) -> std::io::Result<()> {
    if let Some(dir) = account_path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(disconnect_marker(account_path), b"")
}

/// Mark first, then remove the account under one cross-process lock. A daemon
/// adoption that started earlier must finish before this transition begins.
pub fn disconnect_account(path: &Path) -> std::io::Result<bool> {
    with_account_lock(path, || {
        mark_disconnected(path)?;
        delete_account(path)
    })
}

pub fn read_account(path: &Path) -> Option<AccountFile> {
    load_account(path).ok().flatten()
}

/// The account file, and `Ok(None)` only when it is confirmed absent. One that exists
/// but cannot be read or parsed is an error, never "no account": `write_account_raw`
/// truncates before it writes, so a reader can catch it empty. The parse error names
/// only where it failed, never a value, so it cannot echo the token.
pub fn load_account(path: &Path) -> Result<Option<AccountFile>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| {
        format!(
            "cannot parse {}: {:?} error at line {} column {}",
            path.display(),
            e.classify(),
            e.line(),
            e.column()
        )
    })
}

pub fn delete_account(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Strip a secret out of a log line. Empty secret is a no-op.
pub fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "[redacted]")
}

/// NDJSON connect event, the shape the panel's `Kub0.applyConnectLine` reads
/// (it translates `kub0 --json login` frames into it), after device start.
pub fn connect_event_code(
    user_code: &str,
    connect_url: &str,
    expires_in: u64,
    interval: u64,
) -> String {
    serde_json::json!({
        "event": "code",
        "user_code": user_code,
        "connect_url": connect_url,
        "expires_in": expires_in,
        "interval": interval,
    })
    .to_string()
}

/// NDJSON connect event on completion. Never the token.
pub fn connect_event_connected(github_username: &str) -> String {
    serde_json::json!({
        "event": "connected",
        "github_username": github_username,
    })
    .to_string()
}

/// NDJSON connect event on failure. `secret` is redacted.
pub fn connect_event_error(message: &str, secret: &str) -> String {
    serde_json::json!({
        "event": "error",
        "message": redact_secret(message, secret),
    })
    .to_string()
}

/// `token=` line as written by https://kub0.ai/install into `$HOME/.kub0/config`.
pub fn token_from_kub0_config(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("token") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let tok = rest.trim().trim_matches('"').trim();
        if !tok.is_empty() {
            return Some(tok.to_string());
        }
    }
    None
}

/// User-mode only: copy a kub0 install token into the vallum account file.
///
/// Logs the source path once, never the token. System mode is a no-op.
/// Returns true when a new account file was written.
pub fn try_adopt_account(system: bool, account_path: &Path, home: &Path) -> bool {
    if system {
        return false;
    }
    match with_account_lock(account_path, || Ok(try_adopt_account_locked(account_path, home))) {
        Ok(adopted) => adopted,
        Err(e) => {
            eprintln!("kub0d: account lock failed: {e}");
            false
        }
    }
}

fn try_adopt_account_locked(account_path: &Path, home: &Path) -> bool {
    if account_path.is_file() {
        return false;
    }
    if disconnect_marker(account_path).exists() {
        return false;
    }
    let cfg = home.join(".kub0").join("config");
    let text = match std::fs::read_to_string(&cfg) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let Some(token) = token_from_kub0_config(&text) else {
        return false;
    };
    let account = AccountFile {
        schema: 0,
        token,
        github_username: String::new(),
        connected_at: crate::event::now_ms(),
        server_url: DEFAULT_SERVER_URL.to_string(),
    };
    match write_account_raw(account_path, &account) {
        Ok(()) => {
            eprintln!("kub0d: adopted account from {}", cfg.display());
            true
        }
        Err(e) => {
            eprintln!(
                "kub0d: adopt from {} failed: {e}",
                cfg.display()
            );
            false
        }
    }
}

fn as_u64(v: &serde_json::Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        .or_else(|| v.as_f64().and_then(|n| if n >= 0.0 { Some(n as u64) } else { None }))
        .unwrap_or(0)
}

fn nodes_array(v: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    v.get("nodes")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("items").and_then(|x| x.as_array()))
}

fn normalize_self_state(raw: &str) -> String {
    match raw {
        "enforced" | "monitored" | "enforcing" | "monitoring" | "down" => raw.to_string(),
        _ => "unknown".into(),
    }
}

/// `GET /api/nodes` → (orgEndpoints, nodeLimit, selfState).
/// Missing self node → `"unknown"`.
pub fn parse_nodes(v: &serde_json::Value, self_node: &str) -> (u64, u64, String) {
    let org_endpoints = v.get("count").map(as_u64).unwrap_or(0);
    let node_limit = v.get("node_limit").map(as_u64).unwrap_or(0);
    let mut self_state = "unknown".to_string();
    if let Some(arr) = nodes_array(v) {
        for n in arr {
            let name = n
                .get("node_name")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if name != self_node {
                continue;
            }
            let raw = n
                .get("state")
                .and_then(|x| x.as_str())
                .or_else(|| n.get("self_state").and_then(|x| x.as_str()))
                .unwrap_or("");
            self_state = normalize_self_state(raw);
            break;
        }
    }
    (org_endpoints, node_limit, self_state)
}

/// Keep only explicitly reported Vallum endpoints. Missing inventory is not an
/// empty tenant; callers retain the last successful snapshot on malformed data.
pub fn parse_endpoints(v: &serde_json::Value) -> Result<Vec<FleetEndpoint>, &'static str> {
    let rows = nodes_array(v).ok_or("endpoint inventory missing")?;
    let mut endpoints = Vec::new();
    let mut names = std::collections::HashSet::new();
    for row in rows {
        if !row.is_object() {
            return Err("invalid endpoint inventory row");
        }
        if row.get("agent").and_then(|x| x.as_str()) != Some(AGENT) {
            continue;
        }
        let name = row
            .get("node_name")
            .and_then(|x| x.as_str())
            .filter(|name| !name.trim().is_empty())
            .ok_or("endpoint name missing")?;
        if !names.insert(name.to_string()) {
            return Err("duplicate endpoint name");
        }
        let text = |key| {
            row.get(key)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        let raw_state = text("state");
        let state = match raw_state.as_str() {
            "enforcing" | "monitoring" | "down" => raw_state,
            _ => "unknown".into(),
        };
        endpoints.push(FleetEndpoint {
            node_name: name.to_string(),
            state,
            last_seen: text("last_seen"),
            agent_ver: text("agent_ver"),
            blocks_active: row.get("blocks_active").and_then(|x| x.as_u64()),
            kernel_version: text("kernel_version"),
            arch: text("arch"),
        });
    }
    Ok(endpoints)
}

/// Rows in the org deny-list body, before [`DENYLIST_CAP`]. The panel keeps
/// the capped vector; the exec gate's breaker needs this count.
pub fn denylist_reported_len(v: &serde_json::Value) -> usize {
    v.get("entries")
        .and_then(|x| x.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

/// `GET /api/enforce/denylist` → (version, entries capped at 500).
/// The uncapped length is [`denylist_reported_len`].
pub fn parse_denylist(v: &serde_json::Value) -> (u64, Vec<DenylistEntry>) {
    let version = v.get("version").map(as_u64).unwrap_or(0);
    let entries = v
        .get("entries")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    // The panel stops at DENYLIST_CAP. The exec gate must still see
    // `denylist_reported_len`, or a 501-row list looks like a full page of 500.
    for e in entries.iter().take(DENYLIST_CAP) {
        let mut entry = DenylistEntry {
            // `name` is what the org calls the policy. Several API shapes are in
            // the wild for the same idea, so accept any of them rather than
            // showing a matcher because the key was spelled differently.
            name: ["name", "title", "label"]
                .iter()
                .find_map(|k| e.get(*k).and_then(|x| x.as_str()))
                .unwrap_or("")
                .trim()
                .to_string(),
            comm: e
                .get("comm")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            path: e
                .get("path")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            action: e
                .get("action")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            reason: e
                .get("reason")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            promoted_by: e
                .get("promoted_by")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            created_at: e
                .get("created_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        };
        // Settle the display name HERE, once, so the panel renders one field and
        // there is exactly one implementation of the fallback -- a second copy in
        // QML could not be tested and would drift the first time either changed.
        if entry.name.is_empty() {
            entry.name = entry.label();
        }
        out.push(entry);
    }
    (version, out)
}

fn parse_kind(v: Option<&serde_json::Value>) -> Kind {
    v.and_then(|x| x.as_str())
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
        .unwrap_or(Kind::Service)
}

/// Additive `fleet_tags` on a heartbeat response. Missing, null, or not an
/// array yields an empty vec -- an older API will not send the field, and
/// that is not an error.
pub fn parse_fleet_tags(v: &serde_json::Value) -> Vec<tags::FleetReport> {
    let Some(arr) = v.get("fleet_tags").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in arr {
        let network_key = e
            .get("network_key")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let label = e
            .get("label")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let node = e
            .get("node")
            .and_then(|x| x.as_str())
            .or_else(|| e.get("node_name").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        if network_key.is_empty() || label.is_empty() || node.is_empty() {
            continue;
        }
        out.push(tags::FleetReport {
            network_key,
            label,
            node,
            kind: parse_kind(e.get("kind")),
            ptr_suffix: e
                .get("ptr_suffix")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    out
}

/// `{"status":"ok"}` with no `fleet_tags` -- or a body that is not JSON --
/// is an empty report list, never a parse failure.
pub fn parse_fleet_tags_body(text: &str) -> Vec<tags::FleetReport> {
    serde_json::from_str::<serde_json::Value>(text)
        .map(|v| parse_fleet_tags(&v))
        .unwrap_or_default()
}

/// Build a fleet snapshot from the two verified API bodies.
pub fn build_fleet_snapshot(
    nodes: &serde_json::Value,
    denylist: &serde_json::Value,
    self_node: &str,
    connected: bool,
    last_heartbeat_ok: Option<bool>,
    last_heartbeat_ts: u64,
) -> FleetSnapshot {
    let (org_endpoints, node_limit, self_state) = parse_nodes(nodes, self_node);
    let denylist_reported = denylist_reported_len(denylist);
    let (denylist_version, denylist) = parse_denylist(denylist);
    let endpoints = parse_endpoints(nodes);
    let endpoints_ok = endpoints.is_ok();
    FleetSnapshot {
        connected,
        org_endpoints,
        node_limit,
        self_state,
        last_heartbeat_ok,
        last_heartbeat_ts,
        denylist_version,
        denylist,
        denylist_reported,
        endpoints: endpoints.unwrap_or_default(),
        endpoints_updated_at: if endpoints_ok { last_heartbeat_ts } else { 0 },
        endpoints_refresh_ok: Some(endpoints_ok),
        netpolicy_refresh_ok: None,
        prevalence: Vec::new(),
        prevalence_supported: None,
        sharing_destinations: false,
        fleet_tags: Vec::new(),
        netpolicies: Vec::new(),
        netpolicy_enforcement: Enforcement::default(),
        denylist_live: None,
        exec_gate: crate::execgate::ExecGateFrame::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Before `boot_netpolicy` there is no data dir. The answer used to be the
    /// relative path `data`, which a system daemon resolves against `/`: an
    /// enforcer built from it would have read `/data/geoip/…`.
    #[test]
    fn a_runtime_with_no_data_dir_does_not_name_one_under_the_working_directory() {
        let rt = Kub0Runtime::new();
        let unset = rt.data_dir();
        assert!(unset.is_absolute(), "{}", unset.display());
        assert!(!unset.exists(), "{} is not a real directory", unset.display());
        let dir = std::env::temp_dir().join(format!("kub0-data-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        rt.boot_netpolicy(&dir, &dir);
        assert_eq!(rt.data_dir(), dir, "once set, it is the one that was given");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_account_id_is_the_login_on_its_server_and_not_the_token() {
        if std::env::var_os("KUB0_SERVER_URL").is_some() {
            return; // the override names one server for every account
        }
        let a = AccountFile {
            schema: 1,
            token: "t1".into(),
            github_username: "fixture".into(),
            connected_at: 1,
            server_url: "https://api.example".into(),
        };
        assert_eq!(account_id(&a), "fixture@https://api.example");
        let rotated = AccountFile { token: "t2".into(), connected_at: 2, ..a.clone() };
        assert_eq!(account_id(&rotated), account_id(&a));
        let moved = AccountFile { server_url: "https://other.example".into(), ..a.clone() };
        assert_ne!(account_id(&moved), account_id(&a));
        let someone = AccountFile { github_username: "someone".into(), ..a.clone() };
        assert_ne!(account_id(&someone), account_id(&a));
    }
    use std::collections::HashSet;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_policy_name_survives_whichever_key_the_api_spells_it_with() {
        for key in ["name", "title", "label"] {
            let v = serde_json::json!({
                "version": 1,
                "entries": [{ key: "Block crypto miners", "comm": "xmrig", "action": "block" }],
            });
            let (_, out) = parse_denylist(&v);
            assert_eq!(out[0].name, "Block crypto miners", "key {key}");
        }
    }

    #[test]
    fn an_unnamed_policy_arrives_already_named() {
        // The panel renders one field. If the fallback lived in QML it could not
        // be tested, and the two copies would drift the first time either moved.
        let v = serde_json::json!({
            "version": 1,
            "entries": [
                { "comm": "xmrig", "action": "block" },
                { "path": "/usr/local/bin/nc", "action": "warn" },
                { "action": "block" },
            ],
        });
        let (ver, out) = parse_denylist(&v);
        assert_eq!(ver, 1);
        assert_eq!(out[0].name, "Block xmrig");
        assert_eq!(out[1].name, "Warn on nc");
        // The row that used to render as a bare "--".
        assert_eq!(out[2].name, "Unnamed rule");
    }

    #[test]
    fn naming_a_policy_never_costs_the_matcher() {
        let v = serde_json::json!({
            "version": 1,
            "entries": [{ "name": "Block crypto miners", "comm": "xmrig",
                          "path": "/usr/bin/xmrig", "action": "block" }],
        });
        let (_, out) = parse_denylist(&v);
        assert_eq!(out[0].comm, "xmrig");
        assert_eq!(out[0].path, "/usr/bin/xmrig");
        assert_eq!(out[0].matcher(), "xmrig  /usr/bin/xmrig");
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum-kub0-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // The deny-list is the ONLY kub0 endpoint served under /detonate. These
    // three assertions exist to break the tempting "cleanup" that moves the
    // prefix onto the shared base: that fixes the deny-list and regresses the
    // heartbeat to a 403 at the edge, which fails silently because the
    // heartbeat's own failures are logged and never surfaced to sampling.
    #[test]
    fn deny_list_is_the_only_endpoint_under_detonate() {
        let base = "https://api.example.com";
        assert_eq!(
            deny_list_url(base),
            "https://api.example.com/detonate/api/enforce/denylist"
        );
        assert_eq!(nodes_url(base), "https://api.example.com/api/nodes");
        assert_eq!(
            heartbeat_url(base),
            "https://api.example.com/ingest/heartbeat"
        );
    }

    #[test]
    fn root_hosted_endpoints_never_carry_the_detonate_prefix() {
        let base = "https://api.example.com";
        assert!(
            !nodes_url(base).contains("/detonate"),
            "nodes is routed at the root: /api/nodes answers 401, not 404"
        );
        assert!(
            !heartbeat_url(base).contains("/detonate"),
            "prefixing the heartbeat gets 403 from the edge gate"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_server_url_does_not_double_up() {
        assert_eq!(
            deny_list_url("https://api.example.com/"),
            deny_list_url("https://api.example.com")
        );
        assert_eq!(
            heartbeat_url("https://api.example.com/"),
            heartbeat_url("https://api.example.com")
        );
    }

    #[test]
    fn only_a_user_daemon_with_a_logged_in_running_system_daemon_defers() {
        for system in [false, true] {
            for account in [false, true] {
                for running in [false, true] {
                    let want = !system && account && running;
                    assert_eq!(
                        defer_heartbeat_to_system(system, account, running),
                        want,
                        "system={system} account={account} running={running}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_deferring_daemon_reads_its_heartbeat_off_kub0s_row() {
        for live in ["enforced", "monitored", "enforcing", "monitoring"] {
            assert_eq!(deferred_heartbeat_ok(live), Some(true), "{live}");
        }
        assert_eq!(deferred_heartbeat_ok("down"), Some(false));
        assert_eq!(deferred_heartbeat_ok("unknown"), None, "no row, or the GET failed");
        assert_eq!(deferred_heartbeat_ok(""), None);
    }

    #[test]
    fn the_system_daemon_cmdline_is_a_kub0d_with_system() {
        assert!(is_system_daemon_cmdline(b"/usr/lib/kub0/kub0d\0--system\0--interval-ms\0500\0"));
        assert!(is_system_daemon_cmdline(b"kub0d\0--interval-ms\0500\0--system\0"));
        // A 0.4.x system daemon counted for 0.4.5 and 0.4.6. It is not a
        // kub0d: this daemon no longer leaves its heartbeat to one.
        assert!(!is_system_daemon_cmdline(b"/usr/lib/vallum/vallumd\0--system\0--interval-ms\0500\0"));
        // The panel's own daemon.
        assert!(!is_system_daemon_cmdline(
            b"/home/u/.config/omarchy/plugins/ai.kub0.agent/bin/kub0d\0--socket\0/run/user/1000/kub0.sock\0"
        ));
        // Another program that merely mentions it.
        assert!(!is_system_daemon_cmdline(b"/usr/bin/grep\0kub0d\0--system\0"));
        assert!(!is_system_daemon_cmdline(b"/usr/lib/kub0/kub0d-old\0--system\0"));
        assert!(!is_system_daemon_cmdline(b"--system\0"), "argv[0] alone is never the flag");
        assert!(!is_system_daemon_cmdline(b""), "kernel threads have an empty cmdline");
    }

    #[test]
    fn a_system_daemon_counts_only_under_the_wanted_owner() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("vallum-proc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = std::fs::metadata(&dir).unwrap().uid();
        let proc_entry = |name: &str, cmdline: &[u8]| {
            let p = dir.join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("cmdline"), cmdline).unwrap();
        };
        proc_entry("self", b"/usr/lib/kub0/kub0d\0--system\0");
        proc_entry("12", b"/usr/bin/bash\0");
        assert!(!system_daemon_running_in(&dir, owner), "non-numeric entries are not processes");
        proc_entry("4242", b"/usr/lib/kub0/kub0d\0--system\0--interval-ms\0500\0");
        assert!(system_daemon_running_in(&dir, owner));
        assert!(
            !system_daemon_running_in(&dir, owner.wrapping_add(1)),
            "a process owned by anyone else does not count"
        );
        assert!(!system_daemon_running_in(&dir.join("absent"), owner));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_payload_has_exactly_documented_keys() {
        let p = heartbeat_payload("node-a", "0.1.0", true, 42, 3, Vec::new(), Vec::new(), Vec::new());
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        let keys: HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let want: HashSet<&str> = [
            "node_name",
            "probe_ver",
            "lsm_active",
            "lsm_capable",
            "event_count",
            // Additive: the kub0 API defaults each of these when absent, so an older API
            // ignores them and a newer one stops calling this endpoint degraded.
            "agent",
            "agent_ver",
            "kernel_version",
            "arch",
            "blocks_active",
            // Additive: user tags this node offers the org. Always present (empty
            // array when none) so the key set stays exact against the kub0 API.
            "tags",
            // Additive: org network-policy match counts. The kub0 API decodes without
            // DisallowUnknownFields, so an API that predates them ignores the key.
            "policy_matches",
            // Additive: destination network keys for org prevalence, empty unless the
            // user opted in. An API that predates it ignores the key.
            "dest_networks",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, want, "{v}");
        assert_eq!(obj["node_name"], "node-a");
        assert_eq!(obj["probe_ver"], "0.1.0");
        assert_eq!(obj["lsm_active"], false);
        assert_eq!(obj["lsm_capable"], true);
        assert_eq!(obj["event_count"], 42);
        assert_eq!(obj["agent"], "vallum");
        assert_eq!(obj["agent_ver"], "0.1.0");
        assert_eq!(obj["blocks_active"], 3);
        assert_eq!(obj["arch"], std::env::consts::ARCH);
        assert_eq!(obj["tags"], serde_json::json!([]));
        assert_eq!(obj["policy_matches"], serde_json::json!([]));
        assert_eq!(obj["dest_networks"], serde_json::json!([]));
    }

    #[test]
    fn destination_networks_queue_only_when_sharing_and_stay_bounded() {
        let rt = Kub0Runtime::new();
        rt.set_connected(true);
        rt.note_network("203.0.113.0/24");
        assert!(rt.drain_networks().is_empty(), "off by default: nothing is queued");
        rt.set_sharing_destinations(true);
        assert!(rt.fleet_snapshot().sharing_destinations);
        rt.note_network("203.0.113.0/24");
        rt.note_network("203.0.113.0/24");
        rt.note_network("");
        for i in 0..DEST_NETWORKS_CAP + 10 {
            rt.note_network(&format!("10.{}.{}.0/24", i / 256, i % 256));
        }
        let keys = rt.drain_networks();
        assert_eq!(keys.len(), DEST_NETWORKS_CAP);
        assert!(!keys.contains(&"203.0.113.0/24".to_string()), "the oldest fell off the cap");
        assert!(rt.drain_networks().is_empty());
        rt.restore_networks(vec!["1.1.1.0/24".into(), "1.1.1.0/24".into()]);
        assert_eq!(rt.drain_networks(), vec!["1.1.1.0/24".to_string()]);
        // A failed heartbeat with a full batch in flight plus new keys since:
        // the restored old keys go first and the cap drops the oldest, so the
        // keys noted since the failure are the ones that survive.
        let old: Vec<String> = (0..DEST_NETWORKS_CAP).map(|i| format!("172.16.{}.0/24", i)).collect();
        rt.note_network("198.51.100.0/24");
        rt.restore_networks(old);
        let keys = rt.drain_networks();
        assert_eq!(keys.len(), DEST_NETWORKS_CAP);
        assert_eq!(keys.last().map(String::as_str), Some("198.51.100.0/24"));
        assert!(!keys.contains(&"172.16.0.0/24".to_string()), "the oldest restored key fell off");
        // A fresh snapshot (account change) keeps saying this daemon shares.
        rt.publish_fleet(FleetSnapshot { connected: true, ..Default::default() });
        assert!(rt.fleet_snapshot().sharing_destinations);

        // Off means off now (one daemon, #61: the setting changes on a running
        // daemon). What was queued while it was on is not sent a heartbeat
        // later, and a batch a failed heartbeat had in flight is not put back.
        rt.note_network("192.0.2.0/24");
        let in_flight = vec!["198.51.100.0/24".to_string()];
        let gen = rt.fleet_generation();
        rt.set_sharing_destinations(false);
        assert!(rt.fleet_generation() > gen, "every client hears the change");
        assert!(!rt.fleet_snapshot().sharing_destinations);
        rt.restore_networks(in_flight);
        assert!(rt.drain_networks().is_empty(), "nothing collected before the switch leaves after it");
        rt.note_network("192.0.2.0/24");
        assert!(rt.drain_networks().is_empty());
        // Switched on again, it starts from nothing.
        rt.set_sharing_destinations(true);
        assert!(rt.drain_networks().is_empty());

        // Only while an account is connected: a key noted logged out would go
        // to whichever org logs in next, and a logout drops what was queued.
        rt.note_network("192.0.2.0/24");
        rt.set_connected(false);
        rt.note_network("203.0.113.0/24");
        rt.set_connected(true);
        assert!(rt.drain_networks().is_empty());
    }

    #[test]
    fn prevalence_parses_merges_and_records_server_support() {
        assert_eq!(parse_prevalence(&serde_json::json!({"status":"ok"})), None, "no key: the server does not answer it");
        assert_eq!(parse_prevalence(&serde_json::json!({"prevalence": null})), None);
        assert_eq!(parse_prevalence(&serde_json::json!({"prevalence": []})), Some(Vec::new()));
        let rows = parse_prevalence(&serde_json::json!({"prevalence": [
            {"network_key": "203.0.113.0/24", "nodes": 3, "first_seen": 5},
            {"networkKey": "198.51.100.0/24", "nodes": 0},
            {"network_key": "", "nodes": 1},
            {"network_key": "1.2.3.0/24"},
            {"network_key": "1.2.3.0/24", "nodes": "many"},
            "junk"
        ]})).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], Prevalence { network_key: "203.0.113.0/24".into(), nodes: 3, first_seen: 5 });
        assert_eq!(rows[1].first_seen, 0);
        let mut snap = FleetSnapshot::default();
        assert_eq!(snap.prevalence_supported, None);
        snap.apply_prevalence(Some(rows));
        assert_eq!(snap.prevalence_supported, Some(true));
        snap.apply_prevalence(Some(vec![Prevalence { network_key: "203.0.113.0/24".into(), nodes: 7, first_seen: 5 }]));
        assert_eq!(snap.prevalence.len(), 2, "newest answer replaces the key");
        assert_eq!(snap.prevalence.iter().find(|p| p.network_key == "203.0.113.0/24").unwrap().nodes, 7);
        snap.apply_prevalence(None);
        assert_eq!(snap.prevalence_supported, Some(false));
        assert_eq!(snap.prevalence.len(), 2, "an unsupported answer keeps what was learned");
        let ev = snap.to_event(1);
        let line = ev.to_line();
        assert!(line.contains("\"prevalenceSupported\":false"), "{line}");
        assert!(line.contains("\"sharingDestinations\":false"));
    }

    #[test]
    fn heartbeat_tag_objects_have_exactly_the_documented_fields() {
        let t = HeartbeatTag {
            network_key: "1.2.3.0/24".into(),
            label: "Plex".into(),
            kind: Kind::Service,
            ptr_suffix: "example.com".into(),
        };
        let v = serde_json::to_value(&t).unwrap();
        let obj = v.as_object().unwrap();
        let keys: HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let want: HashSet<&str> = ["network_key", "label", "kind", "ptr_suffix"]
            .into_iter()
            .collect();
        assert_eq!(keys, want, "{v}");
        assert_eq!(obj["network_key"], "1.2.3.0/24");
        assert_eq!(obj["label"], "Plex");
        assert_eq!(obj["kind"], "service");
        assert_eq!(obj["ptr_suffix"], "example.com");
        assert!(
            !obj.contains_key("source") && !obj.contains_key("ts") && !obj.contains_key("node"),
            "upload must not carry local provenance or reporter identity: {v}"
        );
    }

    fn sample_store_tag(key: &str, label: &str, source: tags::Source, ptr: &str) -> tags::Tag {
        tags::Tag {
            network_key: key.into(),
            label: label.into(),
            kind: Kind::Service,
            ptr_suffix: ptr.into(),
            ts: 1,
            source,
        }
    }

    #[test]
    fn only_user_tags_are_uploaded() {
        let dir = tmpdir("hb-tags");
        let mut store = TagStore::load(&dir);
        store.set(sample_store_tag(
            "1.2.3.0/24",
            "Plex",
            tags::Source::User,
            "plex.example",
        ));
        store.set(sample_store_tag(
            "9.9.9.0/24",
            "Jellyfin",
            tags::Source::Fleet,
            "jelly.example",
        ));
        let tags = user_heartbeat_tags(&store);
        assert_eq!(tags.len(), 1, "fleet tag must not be re-uploaded: {tags:?}");
        assert_eq!(tags[0].network_key, "1.2.3.0/24");
        assert_eq!(tags[0].label, "Plex");
        assert_eq!(tags[0].ptr_suffix, "plex.example");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disconnected_account_sends_no_tags() {
        let dir = tmpdir("hb-disc");
        let mut store = TagStore::load(&dir);
        store.set(sample_store_tag(
            "1.2.3.0/24",
            "Plex",
            tags::Source::User,
            "",
        ));
        assert!(
            tags_for_heartbeat(false, &store).is_empty(),
            "disconnected must not offer tags to anyone"
        );
        assert_eq!(tags_for_heartbeat(true, &store).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_store_sends_empty_tags_not_an_error() {
        let missing = tmpdir("hb-missing");
        assert!(tags_for_heartbeat_dir(true, &missing).is_empty());
        let corrupt = tmpdir("hb-corrupt");
        std::fs::write(corrupt.join("tags.json"), "{this is not json").unwrap();
        assert!(tags_for_heartbeat_dir(true, &corrupt).is_empty());
        let _ = std::fs::remove_dir_all(&missing);
        let _ = std::fs::remove_dir_all(&corrupt);
    }

    #[test]
    fn fleet_tags_absent_from_response_is_empty_not_an_error() {
        assert!(parse_fleet_tags(&serde_json::json!({"status": "ok"})).is_empty());
        assert!(
            parse_fleet_tags(&serde_json::json!({"status": "ok", "fleet_tags": null})).is_empty()
        );
        assert!(parse_fleet_tags(&serde_json::json!({"fleet_tags": "nope"})).is_empty());
        assert!(parse_fleet_tags_body("").is_empty());
        assert!(parse_fleet_tags_body("not json").is_empty());
        assert!(parse_fleet_tags_body("{\"status\":\"ok\"}").is_empty());
    }

    #[test]
    fn fleet_tags_parse_reports_and_skip_incomplete() {
        let v = serde_json::json!({
            "status": "ok",
            "fleet_tags": [
                {
                    "network_key": "1.2.3.0/24",
                    "label": "Plex",
                    "kind": "service",
                    "ptr_suffix": "plex.example",
                    "node": "node-a"
                },
                {
                    "network_key": "1.2.3.0/24",
                    "label": "Plex",
                    "node_name": "node-b",
                    "kind": "relay",
                    "ptr_suffix": "derp.tailscale.com"
                },
                {
                    "network_key": "4.4.4.0/24",
                    "label": "orphan-no-node"
                },
                {
                    "network_key": "",
                    "label": "empty-key",
                    "node": "node-c"
                }
            ]
        });
        let reports = parse_fleet_tags(&v);
        assert_eq!(reports.len(), 2, "{reports:?}");
        assert_eq!(reports[0].network_key, "1.2.3.0/24");
        assert_eq!(reports[0].label, "Plex");
        assert_eq!(reports[0].node, "node-a");
        assert_eq!(reports[0].kind, Kind::Service);
        assert_eq!(reports[0].ptr_suffix, "plex.example");
        assert_eq!(reports[1].node, "node-b");
        assert_eq!(reports[1].kind, Kind::Relay);
        assert_eq!(reports[1].ptr_suffix, "derp.tailscale.com");
    }

    #[test]
    fn blocks_active_counts_apps_not_ips() {
        // Two apps, five IPs between them: the customer-facing number is 2 apps blocked.
        let text = r#"{"apps":{"slack":["1.2.3.4","5.6.7.8"],"zoom":["9.9.9.9","8.8.8.8","7.7.7.7"]}}"#;
        assert_eq!(blocks_active_from(text), 2);
    }

    #[test]
    fn blocks_active_ignores_emptied_entries() {
        // An app whose IPs were all released is not blocking anything.
        let text = r#"{"apps":{"slack":[],"zoom":["9.9.9.9"]}}"#;
        assert_eq!(blocks_active_from(text), 1);
    }

    #[test]
    fn blocks_active_is_zero_not_an_error_when_unreadable() {
        // User mode may never have run the helper. A heartbeat must not fail over it.
        assert_eq!(blocks_active_from(""), 0);
        assert_eq!(blocks_active_from("not json at all"), 0);
        assert_eq!(blocks_active_from("{}"), 0);
        assert_eq!(read_blocks_active(Path::new("/nonexistent/vallum/owners.json")), 0);
    }

    #[test]
    fn agent_name_matches_the_api_closed_set() {
        // The kub0 API normalises anything but exactly "vallum" to "vigiles", which would
        // put this endpoint back in the cluster-node section wearing eBPF wording.
        assert_eq!(AGENT, "vallum");
    }

    #[test]
    fn lsm_capable_parser_bpf_token() {
        assert!(lsm_capable_from("capability,landlock,lockdown,yama,bpf"));
        assert!(!lsm_capable_from("capability,yama"));
        assert!(!lsm_capable_from("capability,bpfilter,yama"));
        assert!(lsm_capable_from("bpf"));
        assert!(lsm_capable_from(" bpf "));
        assert!(!lsm_capable_from(""));
    }

    #[test]
    fn account_file_written_0600() {
        let dir = tmpdir("acct");
        let path = dir.join("account.json");
        let acct = AccountFile {
            schema: 0,
            token: "secret-token".into(),
            github_username: "alice".into(),
            connected_at: 1,
            server_url: DEFAULT_SERVER_URL.into(),
        };
        write_account(&path, &acct).expect("write");
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let read = read_account(&path).expect("read");
        assert_eq!(read.github_username, "alice");
        assert_eq!(read.schema, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_missing_account_file_reads_as_no_account() {
        let dir = tmpdir("acct-load");
        let path = dir.join("account.json");
        assert_eq!(load_account(&path), Ok(None));
        let acct = AccountFile {
            schema: 1,
            token: "secret-token".into(),
            github_username: "alice".into(),
            connected_at: 1,
            server_url: DEFAULT_SERVER_URL.into(),
        };
        write_account(&path, &acct).unwrap();
        assert_eq!(load_account(&path), Ok(Some(acct)));
        // A write caught between truncate and write, a half-written one, and a schema
        // mismatch that puts the token where a number belongs: errors, never "absent".
        for torn in ["", r#"{"schema":1,"token":"secret-tok"#, r#"{"schema":"secret-token"}"#] {
            std::fs::write(&path, torn).unwrap();
            let err = load_account(&path).unwrap_err();
            assert!(err.contains("cannot parse") && !err.contains("secret"), "{torn:?}: {err}");
            assert_eq!(read_account(&path), None);
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(load_account(&path).unwrap_err().contains("cannot read"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_secret_strips_token() {
        assert_eq!(
            redact_secret("Authorization: Bearer abcdef", "abcdef"),
            "Authorization: Bearer [redacted]"
        );
    }

    #[test]
    fn account_path_system_is_not_under_daemon_state() {
        // The system account is in the state directory in use, never under
        // the daemon's own state: /var/lib/kub0, or /var/lib/vallum on a host
        // that has not moved it yet.
        let system = account_path_for(true, Path::new("/tmp/ignored"));
        assert_eq!(system, crate::rename::state_path("account.json"));
        assert!(
            [crate::rename::STATE_ROOT, crate::rename::OLD_STATE_ROOT].iter().any(|r| system == Path::new(r).join("account.json")),
            "{}",
            system.display()
        );
        assert_eq!(
            account_path_for(false, Path::new("/tmp/state/kub0")),
            PathBuf::from("/tmp/state/kub0/account.json")
        );
    }

    #[test]
    fn connect_json_serializers() {
        let code = connect_event_code("ABCD-EFGH", "https://kub0.ai/connect", 900, 5);
        let v: serde_json::Value = serde_json::from_str(&code).unwrap();
        assert_eq!(v["event"], "code");
        assert_eq!(v["user_code"], "ABCD-EFGH");
        assert_eq!(v["connect_url"], "https://kub0.ai/connect");
        assert_eq!(v["expires_in"], 900);
        assert_eq!(v["interval"], 5);
        let connected = connect_event_connected("alice");
        let v: serde_json::Value = serde_json::from_str(&connected).unwrap();
        assert_eq!(v["event"], "connected");
        assert_eq!(v["github_username"], "alice");
        assert!(connected.find("token").is_none());
        let err = connect_event_error("Authorization: Bearer abcdef failed", "abcdef");
        let v: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["event"], "error");
        assert_eq!(v["message"], "Authorization: Bearer [redacted] failed");
        assert!(!err.contains("abcdef"));
    }

    #[test]
    fn adopt_from_temp_home_present_absent_system() {
        let home = tmpdir("adopt-home");
        let cfg_dir = home.join(".kub0");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(cfg_dir.join("config"), "token=adopt-me-not-on-wire\n").unwrap();
        let state = tmpdir("adopt-state");
        let account = state.join("account.json");

        assert!(try_adopt_account(false, &account, &home));
        let meta = std::fs::metadata(&account).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let read = read_account(&account).expect("adopted");
        assert_eq!(read.github_username, "");
        assert_eq!(read.server_url, DEFAULT_SERVER_URL);
        assert_eq!(read.schema, 0);
        assert!(!try_adopt_account(false, &account, &home), "do not overwrite");

        let home2 = tmpdir("adopt-absent");
        let state2 = tmpdir("adopt-absent-state");
        let account2 = state2.join("account.json");
        assert!(!try_adopt_account(false, &account2, &home2));
        assert!(!account2.exists());

        // A disconnect sticks: adoption stays off until an explicit connect.
        assert!(disconnect_account(&account).unwrap());
        assert!(!try_adopt_account(false, &account, &home), "disconnect was undone by adoption");
        assert!(!account.exists());
        let explicit = AccountFile {
            schema: 0,
            token: "explicit".into(),
            github_username: String::new(),
            connected_at: 1,
            server_url: DEFAULT_SERVER_URL.to_string(),
        };
        write_account(&account, &explicit).unwrap();
        assert!(!disconnect_marker(&account).exists(), "a connect lifts the disconnect");

        let sys_state = tmpdir("adopt-sys");
        let sys_account = sys_state.join("account.json");
        assert!(!try_adopt_account(true, &sys_account, &home));
        assert!(!sys_account.exists());

        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&state);
        let _ = std::fs::remove_dir_all(&home2);
        let _ = std::fs::remove_dir_all(&state2);
        let _ = std::fs::remove_dir_all(&sys_state);
    }

    #[test]
    fn disconnect_after_adoption_check_wins_the_serialized_transition() {
        let state = tmpdir("adopt-disconnect-race");
        let account = state.join("account.json");
        let adopted = AccountFile {
            schema: 0,
            token: "adopted".into(),
            github_username: String::new(),
            connected_at: 1,
            server_url: DEFAULT_SERVER_URL.to_string(),
        };
        let (checked_tx, checked_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let adoption_path = account.clone();
        let adoption = std::thread::spawn(move || {
            with_account_lock(&adoption_path, || {
                assert!(!disconnect_marker(&adoption_path).exists());
                checked_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                write_account_raw(&adoption_path, &adopted)
            })
            .unwrap();
        });
        checked_rx.recv().unwrap();
        let disconnect_path = account.clone();
        let disconnect = std::thread::spawn(move || disconnect_account(&disconnect_path).unwrap());
        resume_tx.send(()).unwrap();
        adoption.join().unwrap();
        assert!(disconnect.join().unwrap());
        assert!(!account.exists());
        assert!(disconnect_marker(&account).exists());
        let _ = std::fs::remove_dir_all(state);
    }

    #[test]
    fn fleet_builder_from_fixture_json() {
        let nodes: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kub0-nodes.json"
        ))
        .unwrap();
        let denylist: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kub0-denylist.json"
        ))
        .unwrap();
        let snap = build_fleet_snapshot(&nodes, &denylist, "host-a", true, Some(true), 42);
        assert!(
            snap.fleet_tags.is_empty(),
            "nodes+denylist builder does not invent fleet tags"
        );
        assert_eq!(snap.org_endpoints, 3);
        assert_eq!(snap.node_limit, 10);
        assert_eq!(snap.self_state, "enforced");
        assert_eq!(snap.denylist_version, 7);
        assert_eq!(snap.denylist.len(), 2);
        assert_eq!(snap.denylist[0].comm, "curl");
        assert_eq!(snap.denylist[0].path, "/usr/bin/curl");
        assert_eq!(snap.denylist[0].action, "block");
        assert_eq!(snap.denylist[0].reason, "org policy");

        let missing = build_fleet_snapshot(&nodes, &denylist, "no-such-node", true, Some(false), 1);
        assert_eq!(missing.self_state, "unknown");
        assert_eq!(missing.org_endpoints, 3);

        let many = serde_json::json!({
            "version": 1,
            "entries": (0..501).map(|i| serde_json::json!({
                "comm": format!("c{i}"),
                "path": "",
                "action": "deny",
                "reason": "",
                "namespace_scope": "",
                "promoted_by": "",
                "created_at": ""
            })).collect::<Vec<_>>()
        });
        let (_, entries) = parse_denylist(&many);
        assert_eq!(denylist_reported_len(&many), 501);
        assert_eq!(entries.len(), DENYLIST_CAP);
    }

    #[test]
    fn endpoints_keep_offline_vallum_and_ignore_other_agents_and_credentials() {
        let nodes = serde_json::json!({"nodes": [
            {"node_name":"cluster", "agent":"vigiles", "state":"enforced"},
            {"node_name":"legacy", "state":"monitored"},
            {"node_name":"online", "agent":"vallum", "state":"enforcing", "blocks_active":2,
             "last_seen":"2026-10-04T06:00:00Z", "agent_ver":"0.2.0", "token":"private-extra-field"},
            {"node_name":"offline", "agent":"vallum", "state":"down", "blocks_active":null}
        ]});
        let endpoints = parse_endpoints(&nodes).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].blocks_active, Some(2));
        assert_eq!(endpoints[1].state, "down");
        assert_eq!(endpoints[1].blocks_active, None);
        let frame = FleetSnapshot {
            connected: true,
            endpoints,
            ..Default::default()
        }
        .to_event(1)
        .to_line();
        assert!(frame.contains("\"nodeName\":\"offline\""));
        assert!(!frame.contains("private-extra-field"));
        assert!(!frame.contains("\"token\""));
    }

    #[test]
    fn fleet_frame_carries_whether_the_policy_refresh_worked() {
        for ok in [true, false] {
            let snap = FleetSnapshot { connected: true, netpolicy_refresh_ok: Some(ok), ..Default::default() };
            let line = snap.to_event(1).to_line();
            assert!(line.contains(&format!("\"netpolicyRefreshOk\":{ok}")), "{line}");
        }
    }

    #[test]
    fn endpoint_counts_distinguish_zero_from_unreported() {
        for (value, expected) in [
            (serde_json::json!(0), Some(0)),
            (serde_json::json!(null), None),
            (serde_json::json!(-1), None),
            (serde_json::json!(1.5), None),
            (serde_json::json!("0"), None),
        ] {
            let rows = parse_endpoints(&serde_json::json!({"nodes":[{
                "agent":"vallum", "node_name":"fixture", "state":"online",
                "last_seen":null, "blocks_active":value
            }]})).unwrap();
            assert_eq!(rows[0].blocks_active, expected);
            assert_eq!(rows[0].state, "unknown");
            assert_eq!(rows[0].last_seen, "");
        }
    }

    #[test]
    fn endpoint_inventory_rejects_missing_malformed_and_duplicate_rows() {
        for nodes in [
            serde_json::json!({}),
            serde_json::json!({"nodes":null}),
            serde_json::json!({"nodes":[null]}),
            serde_json::json!({"nodes":[{"agent":"vallum"}]}),
            serde_json::json!({"nodes":[{"agent":"vallum","node_name":" "}]}),
            serde_json::json!({"nodes":[{"agent":"vallum","node_name":"same"},{"agent":"vallum","node_name":"same"}]}),
        ] {
            assert!(parse_endpoints(&nodes).is_err());
        }
        assert_eq!(
            parse_endpoints(&serde_json::json!({"nodes":[]})).unwrap(),
            vec![]
        );
        let row = parse_endpoints(&serde_json::json!({"items":[{"agent":"vallum","node_name":"host","state":"enforced","blocks_active":-1}]})).unwrap();
        assert_eq!(row[0].state, "unknown");
        assert_eq!(row[0].blocks_active, None);
        assert_eq!(
            parse_nodes(
                &serde_json::json!({"nodes":[{"node_name":"self","state":"monitoring"}]}),
                "self"
            )
            .2,
            "monitoring"
        );
    }

    #[test]
    fn fleet_snapshot_holds_reports_next_to_denylist() {
        let mut snap = FleetSnapshot::default();
        snap.denylist = vec![DenylistEntry {
            comm: "curl".into(),
            ..Default::default()
        }];
        snap.fleet_tags = parse_fleet_tags(&serde_json::json!({
            "fleet_tags": [{
                "network_key": "1.2.3.0/24",
                "label": "Plex",
                "node": "node-a",
                "kind": "service",
                "ptr_suffix": ""
            }]
        }));
        assert_eq!(snap.denylist.len(), 1);
        assert_eq!(snap.fleet_tags.len(), 1);
        assert_eq!(snap.fleet_tags[0].label, "Plex");
        let rt = Kub0Runtime::new();
        rt.publish_fleet(snap);
        let held = rt.fleet_snapshot();
        assert_eq!(held.fleet_tags[0].node, "node-a");
        assert_eq!(held.denylist[0].comm, "curl");
    }

    #[test]
    fn hello_and_fleet_frames_omit_account_token() {
        let raw = include_str!("../../tests/fixtures/kub0-account.json");
        let acct: AccountFile = serde_json::from_str(raw).unwrap();
        assert!(!acct.token.is_empty(), "fixture must define a token");
        let rt = Kub0Runtime::new();
        rt.set_connected(true);
        rt.set_github_username(&acct.github_username);
        rt.set_last_ok(true);
        let hello = Event::Hello {
            requests: true,
            as_uid: true,
            version: "0.1.0".into(),
            pid: 1,
            coverage: "tcp+connected-udp".into(),
            rdns: false,
            mode: crate::event::DaemonMode::User,
            account: rt.hello_account(),
        };
        let denylist: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kub0-denylist.json"
        ))
        .unwrap();
        let nodes: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kub0-nodes.json"
        ))
        .unwrap();
        let fleet = build_fleet_snapshot(&nodes, &denylist, "host-a", true, Some(true), 9)
            .to_event(9);
        let hello_line = hello.to_line();
        let fleet_line = fleet.to_line();
        assert!(
            !hello_line.contains(&acct.token),
            "hello leaked token: {hello_line}"
        );
        assert!(
            !fleet_line.contains(&acct.token),
            "fleet leaked token: {fleet_line}"
        );
        assert!(hello_line.contains(r#""github_username":"alice""#), "{hello_line}");
        assert!(!hello_line.contains("token"));
        assert!(!fleet_line.contains("token"));
    }

    #[test]
    fn netpolicy_url_is_detonate_prefixed_and_encodes_the_node() {
        assert_eq!(
            netpolicy_url("https://api.example.com/", "k8s-node_01.lan"),
            "https://api.example.com/detonate/api/enforce/netpolicy?node=k8s-node_01.lan"
        );
        assert_eq!(
            netpolicy_url("https://api.example.com", "a b&c=d"),
            "https://api.example.com/detonate/api/enforce/netpolicy?node=a%20b%26c%3Dd"
        );
    }

    #[test]
    fn runtime_records_policy_matches_and_hands_back_undelivered_ones() {
        let rt = Kub0Runtime::new();
        assert!(rt.evaluate_connection("198.51.100.7", "", "", 1).is_empty(), "no policies yet");
        rt.set_policies(netpolicy::parse(
            &serde_json::json!({"policies":[{"id":"p","name":"Watch","mode":"monitor","version":1,"rules":[
                {"id":"r","kind":"ip","action":"monitor","match":{"cidr":"198.51.100.0/24"}}]}]}),
            "",
        )
        .unwrap());
        let mut floor = Floor::default();
        floor.extra.insert("198.51.100.1".parse().unwrap()); // the kub0 server
        rt.set_policy_floor(floor);

        let shown = rt.evaluate_connection("198.51.100.7", "US", "/usr/bin/curl", 10);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].label, "Watch: traffic to 198.51.100.0/24");
        assert!(rt.evaluate_connection("198.51.100.1", "US", "", 11).is_empty(), "floor is never shown");
        assert!(rt.evaluate_connection("203.0.113.1", "US", "", 12).is_empty());

        let sent = rt.drain_policy_matches();
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0].hits, sent[0].suppressed), (1, 1));
        assert_eq!(sent[0].dests, vec!["198.51.100.7".to_string()]);
        assert!(rt.drain_policy_matches().is_empty(), "drained");

        rt.restore_policy_matches(sent);
        assert_eq!(rt.drain_policy_matches()[0].hits, 1, "a failed heartbeat loses nothing");

        let view = rt.policy_view();
        assert_eq!(view[0].rules[0].hits, 1);
        assert_eq!(view[0].rules[0].suppressed, 1);
    }

    #[test]
    fn floor_reads_systemd_resolved_upstreams_not_just_the_stub() {
        assert_eq!(RESOLV_FILES, &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]);
        let stub = "nameserver 127.0.0.53\noptions edns0 trust-ad\n".to_string();
        let upstream = "nameserver 10.20.0.1\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n".to_string();
        let floor = host_policy_floor_from("http://127.0.0.1:9", &[stub, upstream]);
        for ip in ["1.1.1.1", "2606:4700:4700::1111", "127.0.0.1"] {
            assert!(floor.contains(ip.parse().unwrap()), "{ip} must be floor");
        }
        assert!(!floor.contains("9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn the_daemon_floor_reads_the_same_files_as_the_helper() {
        let helper = include_str!("../../helper/src/main.rs");
        let body = helper.split("fn host_critical(").nth(1).unwrap();
        for f in RESOLV_FILES {
            assert!(body.contains(f), "kub0-block host_critical no longer reads {f}");
        }
    }
}
