//! Local indicators: what about this connection is worth a second look.
//!
//! Everything here is computed on the machine from evidence the daemon already
//! holds -- the row itself, the per-app baseline it has learned, the cadence of
//! earlier connections to the same place, and the executable on disk. Nothing
//! is sent anywhere and nothing is fetched to produce an indicator.
//!
//! An indicator is a *claim with its basis*, never a verdict. The vocabulary
//! is deliberately plain: "first time this app reaches AS16509", not
//! "suspicious". Where a MITRE ATT&CK technique describes the shape of what
//! was observed it is attached as a reference, because that is the vocabulary
//! an analyst already uses; it is never a statement that the technique is in
//! use. Update checkers beacon, backup clients upload, and dev builds run from
//! `/tmp`. The basis text says so wherever that is true.
//!
//! Severity is about *how much the basis narrows things down*, not about
//! danger:
//!
//! * `warning`: a fact about this machine that is rarely benign -- the
//!   executable has been deleted from disk while still running, or lives in a
//!   world-writable temp directory -- or a watch rule the user wrote.
//! * `notice`: a departure from this app's own learned behaviour, or a shape
//!   (regular cadence, upload-heavy) worth naming.
//! * `info`: context that helps read the row (a hosting provider, a bare IP
//!   with no name) and asks for nothing.
//!
//! 🔑 The baseline rungs only fire once an app is *established*: at least
//! [`MIN_OBSERVATIONS`] connections over at least [`LEARN_MS`]. Before that,
//! everything is new, and a feature that calls every first-day connection an
//! anomaly trains the user to ignore it by day two.

use crate::event::Connection;
use crate::history::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Connections an app must have made before its baseline is trusted.
pub const MIN_OBSERVATIONS: u64 = 20;
/// Age an app's baseline must reach before novelty is reported.
pub const LEARN_MS: u64 = 24 * 60 * 60 * 1000;
/// Reconnections to one destination before a cadence is called regular.
pub const CADENCE_MIN: usize = 6;
/// Inter-arrival times kept per (app, destination).
pub const CADENCE_KEEP: usize = 32;
/// Coefficient of variation at or below which arrivals count as regular.
pub const CADENCE_MAX_CV: f64 = 0.25;
/// Shortest median interval reported as a cadence. Below this, it is a
/// retry loop or a request stream, not a schedule.
pub const CADENCE_MIN_MS: u64 = 5_000;
/// Upload-heavy: at least this many bytes sent...
pub const UPLOAD_MIN_TX: u64 = 1024 * 1024;
/// ...and at least this many times what was received.
pub const UPLOAD_RATIO: u64 = 5;
/// Distinct networks one app may reach inside [`FANOUT_WINDOW_MS`] before
/// the spread itself is reported.
pub const FANOUT_MIN: usize = 25;
pub const FANOUT_WINDOW_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Notice,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
        }
    }
}

/// A MITRE ATT&CK technique reference. Descriptive, never accusatory: it
/// names the shape of what was observed in the vocabulary analysts share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attack {
    pub id: String,
    pub name: String,
}

fn attack(id: &str, name: &str) -> Option<Attack> {
    Some(Attack {
        id: id.into(),
        name: name.into(),
    })
}

/// One claim about one connection, with the evidence that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    /// Stable kebab-case id: `new-asn`, `beacon-cadence`, `exe-deleted`, ...
    pub id: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack: Option<Attack>,
    /// In the user's words, so the claim can be checked rather than trusted.
    pub basis: String,
}

// ---------------------------------------------------------------------------
// Baseline: what this app has done before, on this machine.
// ---------------------------------------------------------------------------

/// Everything learned about one app, persisted across daemon runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBaseline {
    pub first_seen: u64,
    pub observations: u64,
    /// ASN -> first time this app reached it.
    #[serde(default)]
    pub asns: BTreeMap<u32, u64>,
    #[serde(default)]
    pub countries: BTreeMap<String, u64>,
    #[serde(default)]
    pub ports: BTreeMap<u16, u64>,
}

impl AppBaseline {
    pub fn established(&self, now: u64) -> bool {
        self.observations >= MIN_OBSERVATIONS && now.saturating_sub(self.first_seen) >= LEARN_MS
    }
}

/// What a single observation added to an app's baseline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Novelty {
    /// The baseline was established *before* this observation, so the `new_*`
    /// flags are departures from learned behaviour rather than first lessons.
    pub established: bool,
    pub new_asn: bool,
    pub new_country: bool,
    pub new_port: bool,
    /// Observations before this one, for the basis text.
    pub observations: u64,
    pub age_ms: u64,
}

/// JSON document at `<state_dir>/baseline.json`. A missing or corrupt file
/// loads as empty: a daemon with no memory is better than one that will not
/// start.
pub struct BaselineStore {
    path: PathBuf,
    apps: HashMap<String, AppBaseline>,
    dirty: bool,
}

impl BaselineStore {
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("baseline.json");
        let apps = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path,
            apps,
            dirty: false,
        }
    }

    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            apps: HashMap::new(),
            dirty: false,
        }
    }

    pub fn get(&self, app: &str) -> Option<&AppBaseline> {
        self.apps.get(app)
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Record one connection and say what was new about it.
    ///
    /// Private destinations teach nothing about where an app goes on the
    /// internet, so the caller passes `asn`/`country` as `None` for them; the
    /// observation still counts toward the app being established.
    pub fn observe(
        &mut self,
        app: &str,
        asn: Option<u32>,
        country: Option<&str>,
        port: Option<u16>,
        now: u64,
    ) -> Novelty {
        let b = self.apps.entry(app.to_string()).or_insert_with(|| AppBaseline {
            first_seen: now,
            ..Default::default()
        });
        let established = b.established(now);
        let mut n = Novelty {
            established,
            observations: b.observations,
            age_ms: now.saturating_sub(b.first_seen),
            ..Default::default()
        };
        if let Some(a) = asn {
            if let std::collections::btree_map::Entry::Vacant(e) = b.asns.entry(a) {
                e.insert(now);
                n.new_asn = true;
            }
        }
        if let Some(c) = country.filter(|c| !c.is_empty()) {
            if let std::collections::btree_map::Entry::Vacant(e) = b.countries.entry(c.to_string()) {
                e.insert(now);
                n.new_country = true;
            }
        }
        if let Some(p) = port {
            if let std::collections::btree_map::Entry::Vacant(e) = b.ports.entry(p) {
                e.insert(now);
                n.new_port = true;
            }
        }
        b.observations += 1;
        self.dirty = true;
        n
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        if !self.dirty || self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string(&self.apps)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cadence: how regularly this app comes back to this destination.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CadenceStats {
    /// Connections observed, including this one.
    pub count: usize,
    pub median_ms: u64,
    /// Coefficient of variation of the inter-arrival times.
    pub cv: f64,
}

impl CadenceStats {
    pub fn regular(&self) -> bool {
        self.count >= CADENCE_MIN && self.cv <= CADENCE_MAX_CV && self.median_ms >= CADENCE_MIN_MS
    }
}

/// Arrival times of new connections per (app, remote ip, remote port).
#[derive(Default)]
pub struct Cadence {
    arrivals: HashMap<(String, String, u16), VecDeque<u64>>,
}

impl Cadence {
    /// Record an arrival and describe the series so far.
    pub fn record(&mut self, app: &str, ip: &str, port: u16, now: u64) -> Option<CadenceStats> {
        let q = self
            .arrivals
            .entry((app.to_string(), ip.to_string(), port))
            .or_default();
        q.push_back(now);
        while q.len() > CADENCE_KEEP {
            q.pop_front();
        }
        cadence_stats(q.make_contiguous())
    }

    /// Forget series not touched since `before`, so a long-running daemon
    /// does not remember every destination it ever saw.
    pub fn prune(&mut self, before: u64) {
        self.arrivals
            .retain(|_, q| q.back().is_some_and(|t| *t >= before));
    }

    pub fn len(&self) -> usize {
        self.arrivals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arrivals.is_empty()
    }
}

/// Statistics of a sorted arrival series. `None` below two intervals.
pub fn cadence_stats(arrivals: &[u64]) -> Option<CadenceStats> {
    if arrivals.len() < 3 {
        return None;
    }
    let mut gaps: Vec<u64> = arrivals.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
    gaps.sort_unstable();
    let median = gaps[gaps.len() / 2];
    let mean = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let var = gaps
        .iter()
        .map(|g| {
            let d = *g as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / gaps.len() as f64;
    Some(CadenceStats {
        count: arrivals.len(),
        median_ms: median,
        cv: var.sqrt() / mean,
    })
}

// ---------------------------------------------------------------------------
// Fan-out: how many distinct networks one app reached recently.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FanOutWindow {
    arrivals: VecDeque<(u64, String)>,
    /// network key -> arrivals of it still inside the window.
    counts: HashMap<String, u32>,
}

#[derive(Default)]
pub struct FanOut {
    recent: HashMap<String, FanOutWindow>,
}

impl FanOut {
    /// Record a connection and say how many distinct networks the app reached
    /// inside the window, this one included, or 0 when this network was
    /// already in the window: the spread is a property of the connections
    /// that widened it, not of every connection that followed.
    pub fn record(&mut self, app: &str, network_key: &str, now: u64) -> usize {
        let w = self.recent.entry(app.to_string()).or_default();
        let cutoff = now.saturating_sub(FANOUT_WINDOW_MS);
        while w.arrivals.front().is_some_and(|(t, _)| *t < cutoff) || w.arrivals.len() >= 4096 {
            let Some((_, k)) = w.arrivals.pop_front() else { break };
            if let Some(n) = w.counts.get_mut(&k) {
                *n -= 1;
                if *n == 0 {
                    w.counts.remove(&k);
                }
            }
        }
        let widened = !w.counts.contains_key(network_key);
        w.arrivals.push_back((now, network_key.to_string()));
        *w.counts.entry(network_key.to_string()).or_default() += 1;
        if widened { w.counts.len() } else { 0 }
    }
}

// ---------------------------------------------------------------------------
// Executable provenance flags, as the indicator engine consumes them.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExeFlag {
    /// `/proc/<pid>/exe` ends in ` (deleted)`: the file is gone while the
    /// process still runs.
    Deleted,
    /// Under `/tmp`, `/var/tmp` or `/dev/shm`.
    TempDir,
    /// Under a Go build directory (`/tmp/go-build<digits>/`) with the `go`
    /// tool as a near ancestor: what `go test` and `go run` produce. Raised
    /// instead of [`ExeFlag::TempDir`], never alongside it.
    BuildDir,
    /// The file is writable by every user.
    WorldWritable,
    /// Under a hidden directory in the user's home (`~/.cache`, `~/.local/share/...`).
    HiddenHome,
    /// The executable file changed after the process started.
    ChangedSinceStart,
}

// ---------------------------------------------------------------------------
// The engine.
// ---------------------------------------------------------------------------

/// Everything known about one connection at indicator time. Plain data: the
/// callers do the I/O, this stays a pure function pinned by tests.
pub struct Subject<'a> {
    pub app_id: &'a str,
    pub app_name: &'a str,
    /// The account the process runs as, when it is not the daemon's own
    /// (the system daemon naming a logged-in user's app). Names the row in
    /// every basis: `brave (alice)`.
    pub owner: Option<&'a str>,
    pub system: bool,
    pub remote: Option<IpAddr>,
    pub port: u16,
    /// PTR name, if looked up and found. Empty otherwise.
    pub hostname: &'a str,
    /// True when a lookup was attempted and finished (with or without a name).
    pub hostname_settled: bool,
    pub asn: Option<u32>,
    pub org: Option<&'a str>,
    pub country: &'a str,
    pub novelty: Option<Novelty>,
    pub cadence: Option<CadenceStats>,
    pub bytes: Option<(u64, u64)>,
    pub exe_flags: &'a [ExeFlag],
    /// Watch rules this connection matched, as (rule id, human description).
    pub watch_hits: &'a [(String, String)],
    pub fan_out: usize,
}

/// Ports where an outbound connection names a protocol everyone uses. A port
/// outside this set is not wrong; it is just worth a line when it is also new
/// for the app.
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 53, 853, 123, 22, 25, 465, 587, 993, 995, 143, 110, 8080, 8443, 3478, 5222, 5223,
    1194, 51820, 5228, 4070, 32400,
];

pub fn is_common_port(port: u16) -> bool {
    COMMON_PORTS.contains(&port)
}

/// Substrings of an ASN organisation name that mark a hosting provider.
/// Lower-case; matched case-insensitively.
const HOSTING_ORGS: &[&str] = &[
    "hetzner", "ovh", "digitalocean", "linode", "akamai connected cloud", "vultr", "choopa",
    "contabo", "leaseweb", "scaleway", "online s.a.s", "hostinger", "ionos", "godaddy", "namecheap",
    "psychz", "m247", "datacamp", "servers.com", "hostwinds", "hivelocity", "colocrossing",
    "quadranet", "zenlayer", "alibaba", "tencent", "oracle corporation", "the constant company",
    "hostpapa", "hostgator", "bluehost", "dreamhost", "liquid web", "rackspace", "upcloud",
    "kamatera", "netcup", "strato", "aruba", "serverius", "worldstream", "i3d", "g-core",
    "clouvider", "latitude.sh", "packet host", "equinix",
];

fn hosting_org(org: &str) -> bool {
    let lower = org.to_lowercase();
    HOSTING_ORGS.iter().any(|h| lower.contains(h))
}

/// A peer on the internet: not loopback, unspecified, private, link-local,
/// multicast, or carrier-grade NAT (a tailnet). The one predicate behind
/// "public destination" everywhere: the behaviour rungs, the hosting and PTR
/// rungs, and what may leave the machine for org prevalence.
pub fn is_public_peer(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || crate::geo::is_private(ip))
        && !matches!(ip, IpAddr::V4(v) if v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))
}

fn public(ip: IpAddr) -> bool {
    is_public_peer(ip)
}

fn fmt_duration(ms: u64) -> String {
    let s = ms / 1000;
    if s < 90 {
        format!("{s}s")
    } else if s < 90 * 60 {
        format!("{}m", (s + 30) / 60)
    } else if s < 48 * 3600 {
        format!("{}h", (s + 1800) / 3600)
    } else {
        format!("{}d", (s + 43200) / 86400)
    }
}

fn fmt_bytes(n: u64) -> String {
    const K: u64 = 1024;
    if n >= K * K * K {
        format!("{:.1} GiB", n as f64 / (K * K * K) as f64)
    } else if n >= K * K {
        format!("{:.1} MiB", n as f64 / (K * K) as f64)
    } else if n >= K {
        format!("{} KiB", n / K)
    } else {
        format!("{n} B")
    }
}

fn upload_heavy(bytes: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let (tx, rx) = bytes?;
    (tx >= UPLOAD_MIN_TX && tx >= UPLOAD_RATIO * rx.max(1)).then_some((tx, rx))
}

/// Does the upload-heavy rung fire for these counters? Exposed so the sample
/// loop can re-evaluate an existing row cheaply as its counters move.
pub fn is_upload_heavy(bytes: Option<(u64, u64)>) -> bool {
    upload_heavy(bytes).is_some()
}

fn asn_label(asn: Option<u32>, org: Option<&str>) -> String {
    match (asn, org) {
        (Some(a), Some(o)) if !o.is_empty() => format!("AS{a} ({o})"),
        (Some(a), _) => format!("AS{a}"),
        (None, Some(o)) if !o.is_empty() => o.to_string(),
        _ => String::new(),
    }
}

/// Compute every indicator for one connection. Order is by severity, then
/// by the order the rungs are listed here, so the panel can show the first
/// one as the summary without sorting.
/// How an indicator names its app: the display name (the id when there is
/// none), and the owning account when the row carries one, as `brave (alice)`.
pub fn who_label(app_id: &str, app_name: &str, owner: Option<&str>) -> String {
    let name = if app_name.is_empty() { app_id } else { app_name };
    match owner {
        Some(o) if !o.is_empty() => format!("{name} ({o})"),
        _ => name.to_string(),
    }
}

pub fn indicators(s: &Subject) -> Vec<Indicator> {
    let mut out = Vec::new();
    let who = who_label(s.app_id, s.app_name, s.owner);
    let who = who.as_str();

    // -- warning ----------------------------------------------------------
    for (id, what) in s.watch_hits {
        out.push(Indicator {
            id: "watchlist".into(),
            severity: Severity::Warning,
            attack: None,
            basis: format!("Matches your watch rule {id}: {what}"),
        });
    }
    for f in s.exe_flags {
        out.push(exe_flag_indicator(*f, who));
    }

    // -- notice -----------------------------------------------------------
    // Behaviour rungs describe an app the user chose to run. A `system` row
    // is another uid's daemon (resolved, timesyncd, NetworkManager): on a
    // schedule by design, and not something the user can read a schedule of
    // as a decision. Only the file and the watch rules speak for it.
    if s.system {
        out.sort_by_key(|i| std::cmp::Reverse(i.severity));
        return out;
    }
    if let Some(n) = s.novelty.filter(|n| n.established) {
        let history = format!(
            "{} earlier connections over {}",
            n.observations,
            fmt_duration(n.age_ms)
        );
        let net = asn_label(s.asn, s.org);
        if n.new_asn && !net.is_empty() {
            out.push(Indicator {
                id: "new-asn".into(),
                severity: Severity::Notice,
                attack: None,
                basis: format!("First time {who} reaches {net}; its {history} never did."),
            });
        }
        if n.new_country && !s.country.is_empty() {
            out.push(Indicator {
                id: "new-country".into(),
                severity: Severity::Notice,
                attack: None,
                basis: format!("First time {who} reaches {}; its {history} never did.", s.country),
            });
        }
        if n.new_port && !is_common_port(s.port) {
            out.push(Indicator {
                id: "uncommon-port".into(),
                severity: Severity::Notice,
                attack: attack("T1571", "Non-Standard Port"),
                basis: format!("First time {who} uses port {}, which is not a port most clients use; its {history} never did.", s.port),
            });
        }
    }
    if let Some(c) = s.cadence.filter(CadenceStats::regular) {
        out.push(Indicator {
            id: "beacon-cadence".into(),
            severity: Severity::Notice,
            attack: attack("T1071", "Application Layer Protocol"),
            basis: format!(
                "{who} reconnects here about every {} ({} times, {:.0}% jitter). Update checkers, telemetry and command channels all keep a schedule; the schedule alone does not say which.",
                fmt_duration(c.median_ms),
                c.count,
                c.cv * 100.0
            ),
        });
    }
    if let Some((tx, rx)) = upload_heavy(s.bytes) {
        out.push(Indicator {
            id: "upload-heavy".into(),
            severity: Severity::Notice,
            attack: attack("T1048", "Exfiltration Over Alternative Protocol"),
            basis: format!(
                "{who} has sent {} and received {} on this connection. Backups, sync clients and uploads look like this; so does data leaving.",
                fmt_bytes(tx),
                fmt_bytes(rx)
            ),
        });
    }
    if s.fan_out >= FANOUT_MIN {
        out.push(Indicator {
            id: "fan-out".into(),
            severity: Severity::Notice,
            attack: attack("T1046", "Network Service Discovery"),
            basis: format!(
                "{who} reached {} distinct networks in the last minute. Peer-to-peer clients, CDN fan-out and scanners all do this.",
                s.fan_out
            ),
        });
    }

    // -- info -------------------------------------------------------------
    let is_public = s.remote.is_some_and(public);
    let hosting_ptr = crate::suggest::hosting_ptr(s.hostname);
    let hosting_asn = s.org.filter(|o| hosting_org(o));
    if is_public {
        if let Some(label) = hosting_ptr.map(str::to_string).or_else(|| hosting_asn.map(str::to_string)) {
            out.push(Indicator {
                id: "hosting".into(),
                severity: Severity::Info,
                attack: None,
                basis: format!("{label} is a hosting provider: the address says where the server lives, not whose it is."),
            });
        }
        if s.hostname_settled && s.hostname.is_empty() && s.port != 53 {
            out.push(Indicator {
                id: "no-ptr".into(),
                severity: Severity::Info,
                attack: None,
                basis: "The address has no reverse-DNS name. Many CDN and cloud addresses have none; a bare IP is simply harder to read.".into(),
            });
        }
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.severity));
    out
}

/// A name landed on an open row. A PTR answer retires `no-ptr` (the address
/// has a reverse name after all); a DNS answer does not, since the address
/// still has none. Either kind adds `hosting` when the name is a hosting
/// provider's, under the gates `indicators()` applies at first sight: a
/// public peer, not a `system` row. Returns true when the set changed.
pub fn reconcile_hostname(list: &mut Vec<Indicator>, hostname: &str, from_ptr: bool, public: bool, system: bool) -> bool {
    if hostname.is_empty() {
        return false;
    }
    let mut changed = false;
    if from_ptr {
        if let Some(idx) = list.iter().position(|i| i.id == "no-ptr") {
            list.remove(idx);
            changed = true;
        }
    }
    if let (Some(label), true, false) = (crate::suggest::hosting_ptr(hostname), public, system) {
        if !list.iter().any(|i| i.id == "hosting") {
            list.push(Indicator {
                id: "hosting".into(),
                severity: Severity::Info,
                attack: None,
                basis: format!("{label} is a hosting provider: the address says where the server lives, not whose it is."),
            });
            changed = true;
        }
    }
    if changed {
        list.sort_by_key(|i| std::cmp::Reverse(i.severity));
    }
    changed
}

/// Watch rules matched after the row existed (a host rule whose PTR arrived
/// late). Returns true when anything was added.
pub fn add_watch_hits(list: &mut Vec<Indicator>, hits: &[(String, String)]) -> bool {
    let mut changed = false;
    for (id, what) in hits {
        let basis = format!("Matches your watch rule {id}: {what}");
        if list.iter().any(|i| i.id == "watchlist" && i.basis == basis) {
            continue;
        }
        list.push(Indicator {
            id: "watchlist".into(),
            severity: Severity::Warning,
            attack: None,
            basis,
        });
        changed = true;
    }
    if changed {
        list.sort_by_key(|i| std::cmp::Reverse(i.severity));
    }
    changed
}

/// The highest severity in a set, for summaries.
pub fn top_severity(list: &[Indicator]) -> Option<Severity> {
    list.iter().map(|i| i.severity).max()
}

// ---------------------------------------------------------------------------
// Pivot: everything about one subject, from retained history and live rows.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    Ip,
    App,
    Asn,
    Network,
    Country,
    Port,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivotSubject {
    pub kind: SubjectKind,
    pub value: String,
}

impl PivotSubject {
    /// Parse `kind:value`, or guess the kind from a bare value: an address
    /// is an ip, `AS123`/`123` an asn, a two-letter upper-case code a
    /// country, `1.2.3.0/24` a network, a number ≤ 65535 a port, something
    /// with a dot a host, and anything else an app id.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty subject".into());
        }
        if let Some((k, v)) = text.split_once(':') {
            let kind = match k {
                "ip" => Some(SubjectKind::Ip),
                "app" => Some(SubjectKind::App),
                "asn" => Some(SubjectKind::Asn),
                "network" | "net" => Some(SubjectKind::Network),
                "country" => Some(SubjectKind::Country),
                "port" => Some(SubjectKind::Port),
                "host" => Some(SubjectKind::Host),
                _ => None,
            };
            if let Some(kind) = kind {
                return Self::new(kind, v);
            }
        }
        if text.parse::<IpAddr>().is_ok() {
            return Self::new(SubjectKind::Ip, text);
        }
        if let Some(n) = text.strip_prefix("AS").or_else(|| text.strip_prefix("as")) {
            if n.parse::<u32>().is_ok() {
                return Self::new(SubjectKind::Asn, n);
            }
        }
        if text.contains('/') && text.split('/').next().is_some_and(|a| a.parse::<IpAddr>().is_ok()) {
            return Self::new(SubjectKind::Network, text);
        }
        if text.len() == 2 && text.chars().all(|c| c.is_ascii_uppercase()) {
            return Self::new(SubjectKind::Country, text);
        }
        if let Ok(p) = text.parse::<u32>() {
            if p <= 65535 {
                return Self::new(SubjectKind::Port, text);
            }
            return Self::new(SubjectKind::Asn, text);
        }
        if text.contains('.') && !text.contains('/') {
            return Self::new(SubjectKind::Host, text);
        }
        Self::new(SubjectKind::App, text)
    }

    pub fn new(kind: SubjectKind, value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err("subject value must be 1..256 characters".into());
        }
        let value = match kind {
            SubjectKind::Ip => value
                .parse::<IpAddr>()
                .map(|ip| ip.to_string())
                .map_err(|_| format!("{value} is not an IP address"))?,
            SubjectKind::Asn => value
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .map(|n| n.to_string())
                .map_err(|_| format!("{value} is not an ASN"))?,
            SubjectKind::Port => value
                .parse::<u16>()
                .map(|n| n.to_string())
                .map_err(|_| format!("{value} is not a port"))?,
            SubjectKind::Country => value.to_ascii_uppercase(),
            SubjectKind::Host => value.to_ascii_lowercase(),
            SubjectKind::Network | SubjectKind::App => value.to_string(),
        };
        Ok(Self { kind, value })
    }

    pub fn matches(&self, c: &Connection) -> bool {
        match self.kind {
            SubjectKind::Ip => c.remote.ip == self.value,
            SubjectKind::App => c.app.id == self.value || c.exe == self.value,
            SubjectKind::Asn => c.asn.is_some_and(|a| a.to_string() == self.value),
            SubjectKind::Network => c.network_key == self.value,
            SubjectKind::Country => c.country == self.value,
            SubjectKind::Port => c.remote.port.to_string() == self.value,
            SubjectKind::Host => {
                let h = c.hostname.to_ascii_lowercase();
                h == self.value || h.ends_with(&format!(".{}", self.value))
            }
        }
    }

    pub fn label(&self) -> String {
        match self.kind {
            SubjectKind::Asn => format!("AS{}", self.value),
            _ => self.value.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotApp {
    pub id: String,
    pub name: String,
    pub connections: usize,
    pub first: u64,
    pub last: u64,
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotDestination {
    pub ip: String,
    pub port: u16,
    pub hostname: String,
    pub country: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    pub connections: usize,
    pub first: u64,
    pub last: u64,
    pub apps: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotFacet {
    pub key: String,
    pub label: String,
    pub connections: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndicatorCount {
    pub id: String,
    pub severity: Severity,
    pub connections: usize,
    /// One representative basis, so the summary can quote evidence.
    pub example: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pivot {
    pub subject: Option<PivotSubject>,
    pub since: u64,
    pub until: u64,
    pub connections: usize,
    pub live: usize,
    pub tx: u64,
    pub rx: u64,
    pub first: u64,
    pub last: u64,
    pub apps: Vec<PivotApp>,
    pub destinations: Vec<PivotDestination>,
    pub countries: Vec<PivotFacet>,
    pub asns: Vec<PivotFacet>,
    pub ports: Vec<PivotFacet>,
    pub indicators: Vec<IndicatorCount>,
    /// Connections per hour, oldest first, covering `since..until`.
    pub timeline: Vec<usize>,
    pub timeline_bucket_ms: u64,
    /// Regular reconnection cadence to this subject, when the arrivals show one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cadence_ms: Option<u64>,
    pub truncated: bool,
}

/// Cap on list lengths in a pivot, so one noisy subject cannot make the
/// reply unbounded.
pub const PIVOT_LIST_CAP: usize = 50;

/// One observation of a connection, from history or the live table.
pub struct Observed<'a> {
    pub conn: &'a Connection,
    pub first: u64,
    pub last: u64,
    pub live: bool,
    pub bytes: Option<(u64, u64)>,
}

impl<'a> Observed<'a> {
    pub fn from_entry(e: &'a Entry) -> Self {
        Observed {
            conn: &e.connection,
            first: e.first_observed,
            last: e.last_observed,
            live: e.active,
            bytes: e.bytes.map(|b| (b.tx, b.rx)),
        }
    }

    pub fn from_live(c: &'a Connection, now: u64) -> Self {
        Observed {
            conn: c,
            first: c.evidence.as_ref().map(|e| e.recorded_at).unwrap_or(now),
            last: now,
            live: true,
            bytes: c.bytes.map(|b| (b.tx, b.rx)),
        }
    }
}

/// Aggregate everything matching `subject` (or everything, when `None`).
pub fn pivot(
    subject: Option<&PivotSubject>,
    rows: &[Observed<'_>],
    since: u64,
    until: u64,
    truncated: bool,
) -> Pivot {
    let bucket = 3_600_000u64;
    let span = until.saturating_sub(since).max(1);
    let buckets = span.div_ceil(bucket).clamp(1, 24 * 8) as usize;
    let mut p = Pivot {
        subject: subject.cloned(),
        since,
        until,
        timeline: vec![0; buckets],
        timeline_bucket_ms: bucket,
        truncated,
        first: u64::MAX,
        ..Default::default()
    };
    let mut apps: BTreeMap<String, PivotApp> = BTreeMap::new();
    let mut dests: BTreeMap<(String, u16), PivotDestination> = BTreeMap::new();
    let mut countries: BTreeMap<String, usize> = BTreeMap::new();
    let mut asns: BTreeMap<u32, (String, usize)> = BTreeMap::new();
    let mut ports: BTreeMap<u16, usize> = BTreeMap::new();
    let mut inds: BTreeMap<String, IndicatorCount> = BTreeMap::new();
    let mut arrivals: Vec<u64> = Vec::new();
    for o in rows {
        let c = o.conn;
        if subject.is_some_and(|s| !s.matches(c)) {
            continue;
        }
        if c.unresolved {
            continue;
        }
        p.connections += 1;
        if o.live {
            p.live += 1;
        }
        if let Some((tx, rx)) = o.bytes {
            p.tx += tx;
            p.rx += rx;
        }
        p.first = p.first.min(o.first);
        p.last = p.last.max(o.last);
        arrivals.push(o.first);
        if o.first >= since {
            let idx = ((o.first - since) / bucket) as usize;
            if let Some(slot) = p.timeline.get_mut(idx.min(buckets - 1)) {
                *slot += 1;
            }
        }
        let a = apps.entry(c.app.id.clone()).or_insert_with(|| PivotApp {
            id: c.app.id.clone(),
            name: c.app.name.clone(),
            first: o.first,
            ..Default::default()
        });
        a.connections += 1;
        a.first = a.first.min(o.first);
        a.last = a.last.max(o.last);
        if let Some((tx, rx)) = o.bytes {
            a.tx += tx;
            a.rx += rx;
        }
        let d = dests
            .entry((c.remote.ip.clone(), c.remote.port))
            .or_insert_with(|| PivotDestination {
                ip: c.remote.ip.clone(),
                port: c.remote.port,
                hostname: c.hostname.clone(),
                country: c.country.clone(),
                asn: c.asn,
                org: c.org.clone(),
                first: o.first,
                ..Default::default()
            });
        d.connections += 1;
        d.first = d.first.min(o.first);
        d.last = d.last.max(o.last);
        if d.hostname.is_empty() {
            d.hostname = c.hostname.clone();
        }
        if !d.apps.contains(&c.app.id) && d.apps.len() < 16 {
            d.apps.push(c.app.id.clone());
        }
        if !c.country.is_empty() {
            *countries.entry(c.country.clone()).or_default() += 1;
        }
        if let Some(asn) = c.asn {
            let e = asns.entry(asn).or_insert_with(|| (c.org.clone().unwrap_or_default(), 0));
            e.1 += 1;
        }
        *ports.entry(c.remote.port).or_default() += 1;
        for i in &c.indicators {
            let e = inds.entry(i.id.clone()).or_insert_with(|| IndicatorCount {
                id: i.id.clone(),
                severity: i.severity,
                connections: 0,
                example: i.basis.clone(),
            });
            e.connections += 1;
        }
    }
    if p.connections == 0 {
        p.first = 0;
    }
    let mut app_list: Vec<PivotApp> = apps.into_values().collect();
    app_list.sort_by(|a, b| b.connections.cmp(&a.connections).then(a.id.cmp(&b.id)));
    app_list.truncate(PIVOT_LIST_CAP);
    p.apps = app_list;
    let mut dest_list: Vec<PivotDestination> = dests.into_values().collect();
    dest_list.sort_by(|a, b| b.connections.cmp(&a.connections).then(b.last.cmp(&a.last)));
    dest_list.truncate(PIVOT_LIST_CAP);
    p.destinations = dest_list;
    p.countries = facets(countries.into_iter().map(|(k, n)| (k.clone(), k, n)));
    p.asns = facets(asns.into_iter().map(|(k, (org, n))| {
        let label = if org.is_empty() { format!("AS{k}") } else { format!("AS{k} {org}") };
        (k.to_string(), label, n)
    }));
    p.ports = facets(ports.into_iter().map(|(k, n)| (k.to_string(), k.to_string(), n)));
    let mut ind_list: Vec<IndicatorCount> = inds.into_values().collect();
    ind_list.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.connections.cmp(&a.connections)));
    p.indicators = ind_list;
    arrivals.sort_unstable();
    arrivals.dedup();
    p.cadence_ms = cadence_stats(&arrivals)
        .filter(CadenceStats::regular)
        .map(|c| c.median_ms);
    p
}

fn facets(it: impl Iterator<Item = (String, String, usize)>) -> Vec<PivotFacet> {
    let mut v: Vec<PivotFacet> = it
        .map(|(key, label, connections)| PivotFacet {
            key,
            label,
            connections,
        })
        .collect();
    v.sort_by(|a, b| b.connections.cmp(&a.connections).then(a.key.cmp(&b.key)));
    v.truncate(PIVOT_LIST_CAP);
    v
}

// ---------------------------------------------------------------------------
// Brief: a periodic digest, rendered for a terminal or a file.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brief {
    pub generated_at: u64,
    pub hours: u64,
    pub host: String,
    pub pivot: Pivot,
    /// Apps first seen in the window (from the activity log).
    pub new_apps: Vec<String>,
    /// Networks first seen in the window (from the activity log).
    pub new_networks: usize,
    pub blocks: usize,
    pub unblocks: usize,
    pub block_failures: usize,
    pub watch_hits: usize,
    /// Destinations that reconnected on a regular cadence, with the period.
    pub cadences: Vec<(String, u64)>,
    pub listeners: Vec<ListenerSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerSummary {
    pub proto: String,
    pub ip: String,
    pub port: u16,
    pub app: String,
    pub scope: String,
}

pub fn brief(
    host: &str,
    hours: u64,
    now: u64,
    rows: &[Observed<'_>],
    activity: &[crate::activity::ActivityEntry],
    listeners: &[ListenerSummary],
    truncated: bool,
) -> Brief {
    let since = now.saturating_sub(hours * 3_600_000);
    let pivot = pivot(None, rows, since, now, truncated);
    let mut b = Brief {
        generated_at: now,
        hours,
        host: host.to_string(),
        pivot,
        listeners: listeners.to_vec(),
        ..Default::default()
    };
    for e in activity.iter().filter(|e| e.ts >= since) {
        match e.kind {
            crate::activity::ActivityKind::AppFirstSeen => {
                if let Some(app) = &e.app {
                    let name = if app.name.is_empty() { app.id.clone() } else { app.name.clone() };
                    if !b.new_apps.contains(&name) {
                        b.new_apps.push(name);
                    }
                }
            }
            crate::activity::ActivityKind::NewNetwork => b.new_networks += 1,
            crate::activity::ActivityKind::Block => b.blocks += 1,
            crate::activity::ActivityKind::Unblock => b.unblocks += 1,
            crate::activity::ActivityKind::BlockFailed => b.block_failures += 1,
            crate::activity::ActivityKind::WatchHit => b.watch_hits += 1,
            _ => {}
        }
    }
    // Cadences per (app, destination), from the same rows.
    let mut series: BTreeMap<(String, String, u16), Vec<u64>> = BTreeMap::new();
    for o in rows {
        if o.conn.unresolved || o.first < since {
            continue;
        }
        series
            .entry((o.conn.app.id.clone(), o.conn.remote.ip.clone(), o.conn.remote.port))
            .or_default()
            .push(o.first);
    }
    for ((app, ip, port), mut arrivals) in series {
        arrivals.sort_unstable();
        arrivals.dedup();
        if let Some(c) = cadence_stats(&arrivals).filter(CadenceStats::regular) {
            b.cadences.push((format!("{app} -> {ip}:{port}"), c.median_ms));
        }
    }
    b.cadences.sort();
    b.cadences.truncate(PIVOT_LIST_CAP);
    b
}

fn fmt_ts(ms: u64) -> String {
    // UTC, RFC 3339 to the second, without pulling in a time crate.
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Render a brief as Markdown for a terminal, a note, or a ticket.
pub fn render_brief_markdown(b: &Brief) -> String {
    let p = &b.pivot;
    let mut s = String::new();
    s.push_str(&format!(
        "# kub0 brief: {} (last {}h, generated {})\n\n",
        b.host,
        b.hours,
        fmt_ts(b.generated_at)
    ));
    s.push_str("Everything below was computed on this machine from retained local observations. Counts are sampled connections, not packets; see docs/INTEL.md for what each line can and cannot claim.\n\n");
    s.push_str("## Totals\n\n");
    s.push_str(&format!(
        "- {} connections ({} live now) from {} apps to {} destinations\n",
        p.connections,
        p.live,
        p.apps.len(),
        p.destinations.len()
    ));
    s.push_str(&format!(
        "- sampled transfer: {} sent, {} received\n",
        fmt_bytes(p.tx),
        fmt_bytes(p.rx)
    ));
    s.push_str(&format!(
        "- {} new networks, {} new apps{}\n",
        b.new_networks,
        b.new_apps.len(),
        if b.new_apps.is_empty() {
            String::new()
        } else {
            format!(" ({})", b.new_apps.join(", "))
        }
    ));
    s.push_str(&format!(
        "- blocks: {} applied, {} lifted, {} failed; {} watch-rule hits\n",
        b.blocks, b.unblocks, b.block_failures, b.watch_hits
    ));
    if p.truncated {
        s.push_str("- retained history was capped for this window; totals are a floor\n");
    }
    s.push('\n');

    s.push_str("## Indicators\n\n");
    if p.indicators.is_empty() {
        s.push_str("None raised in this window.\n\n");
    } else {
        for i in &p.indicators {
            s.push_str(&format!(
                "- **{}** `{}` on {} connections. {}\n",
                i.severity.as_str(),
                i.id,
                i.connections,
                i.example
            ));
        }
        s.push('\n');
    }

    if !b.cadences.is_empty() {
        s.push_str("## Regular cadences\n\n");
        for (what, period) in &b.cadences {
            s.push_str(&format!("- {what} about every {}\n", fmt_duration(*period)));
        }
        s.push('\n');
    }

    s.push_str("## Top destinations\n\n");
    for d in p.destinations.iter().take(15) {
        let name = if d.hostname.is_empty() { d.ip.clone() } else { format!("{} ({})", d.hostname, d.ip) };
        let net = asn_label(d.asn, d.org.as_deref());
        s.push_str(&format!(
            "- {name}:{} {} {} x{} via {}\n",
            d.port,
            d.country,
            net,
            d.connections,
            d.apps.join(", ")
        ));
    }
    s.push('\n');

    s.push_str("## Apps\n\n");
    for a in p.apps.iter().take(20) {
        s.push_str(&format!(
            "- {} x{} ({} sent, {} received)\n",
            if a.name.is_empty() { &a.id } else { &a.name },
            a.connections,
            fmt_bytes(a.tx),
            fmt_bytes(a.rx)
        ));
    }
    s.push('\n');

    if !p.countries.is_empty() {
        s.push_str("## Countries\n\n");
        s.push_str(
            &p.countries
                .iter()
                .take(12)
                .map(|f| format!("{} x{}", f.label, f.connections))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str("\n\n");
    }

    s.push_str("## Exposure\n\n");
    if b.listeners.is_empty() {
        s.push_str("No listening sockets reported.\n");
    } else {
        for l in &b.listeners {
            s.push_str(&format!("- {} {}:{} {} ({})\n", l.proto, l.ip, l.port, l.app, l.scope));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AppIdentity, Endpoint};

    fn conn(app: &str, ip: &str, port: u16) -> Connection {
        Connection {
            id: format!("tcp:1:{ip}:{port}"),
            proto: "tcp".into(),
            inode: 1,
            app: AppIdentity {
                id: app.into(),
                name: app.to_uppercase(),
                icon: String::new(),
                desktop: String::new(),
                pid: 42,
                system: false,
                exe: format!("/usr/bin/{app}"),
                owner: None,
            },
            local: Endpoint {
                ip: "10.0.0.2".into(),
                port: 40000,
            },
            remote: Endpoint {
                ip: ip.into(),
                port,
            },
            state: "ESTABLISHED".into(),
            country: "DE".into(),
            lat: 0.0,
            lon: 0.0,
            unresolved: false,
            new_network: false,
            network_key: format!("{}/24", ip),
            hostname: String::new(),
            hostname_source: String::new(),
            uid: Some(1000),
            reason: String::new(),
            clue: None,
            tag: None,
            bytes: None,
            exe: format!("/usr/bin/{app}"),
            evidence: None,
            policy: Vec::new(),
            asn: Some(24940),
            org: Some("Hetzner Online GmbH".into()),
            indicators: Vec::new(),
        }
    }

    fn subject<'a>(flags: &'a [ExeFlag], hits: &'a [(String, String)]) -> Subject<'a> {
        Subject {
            app_id: "firefox",
            app_name: "Firefox",
            owner: None,
            system: false,
            remote: Some("203.0.113.7".parse().unwrap()),
            port: 443,
            hostname: "",
            hostname_settled: false,
            asn: Some(16509),
            org: Some("Amazon.com, Inc."),
            country: "US",
            novelty: None,
            cadence: None,
            bytes: None,
            exe_flags: flags,
            watch_hits: hits,
            fan_out: 0,
        }
    }

    #[test]
    fn baseline_is_quiet_until_established() {
        let mut b = BaselineStore::in_memory();
        let t0 = 1_000_000;
        for i in 0..MIN_OBSERVATIONS {
            let n = b.observe("firefox", Some(15169), Some("US"), Some(443), t0 + i);
            assert!(!n.established, "observation {i} came before the baseline existed");
        }
        // Enough observations but not enough age: still learning.
        let n = b.observe("firefox", Some(24940), Some("DE"), Some(443), t0 + 1000);
        assert!(!n.established);
        assert!(n.new_asn && n.new_country);
        // Enough age too: a departure is now reportable.
        let later = t0 + LEARN_MS + 1;
        let n = b.observe("firefox", Some(13335), Some("NL"), Some(8443), later);
        assert!(n.established);
        assert!(n.new_asn && n.new_country && n.new_port);
        assert_eq!(n.observations, MIN_OBSERVATIONS + 1);
        // Seen once, never new again.
        let n = b.observe("firefox", Some(13335), Some("NL"), Some(8443), later + 1);
        assert!(!n.new_asn && !n.new_country && !n.new_port);
    }

    #[test]
    fn baseline_private_destinations_teach_nothing_but_still_count() {
        let mut b = BaselineStore::in_memory();
        let n = b.observe("ssh", None, None, Some(22), 5);
        assert!(!n.new_asn && !n.new_country && n.new_port);
        assert_eq!(b.get("ssh").unwrap().observations, 1);
        assert!(b.get("ssh").unwrap().asns.is_empty());
    }

    #[test]
    fn baseline_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!(
            "vallum-baseline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut b = BaselineStore::load(&dir);
        b.observe("curl", Some(1), Some("FR"), Some(80), 7);
        assert!(b.dirty());
        b.save().unwrap();
        assert!(!b.dirty());
        let again = BaselineStore::load(&dir);
        assert_eq!(again.get("curl").unwrap().asns.get(&1), Some(&7));
        std::fs::write(dir.join("baseline.json"), "{not json").unwrap();
        assert!(BaselineStore::load(&dir).is_empty(), "corrupt file loads as empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cadence_calls_a_regular_series_regular_and_a_burst_not() {
        let mut c = Cadence::default();
        let mut last = None;
        for i in 0..CADENCE_MIN {
            last = c.record("agent", "1.2.3.4", 443, 1_000 + i as u64 * 60_000);
        }
        let s = last.expect("stats after enough arrivals");
        assert!(s.regular(), "{s:?}");
        assert_eq!(s.median_ms, 60_000);
        assert!(s.cv < 0.01);

        // Same count, random gaps: not regular.
        let mut c = Cadence::default();
        let gaps = [1_000u64, 90_000, 4_000, 300_000, 12_000, 70_000];
        let mut t = 0;
        let mut last = None;
        for g in gaps {
            t += g;
            last = c.record("agent", "1.2.3.4", 443, t);
        }
        assert!(!last.unwrap().regular());

        // A tight retry loop is regular but too fast to be a schedule.
        let mut c = Cadence::default();
        let mut last = None;
        for i in 0..CADENCE_MIN {
            last = c.record("agent", "1.2.3.4", 443, 1_000 + i as u64 * 200);
        }
        assert!(!last.unwrap().regular());
    }

    #[test]
    fn cadence_prunes_stale_series_and_caps_memory() {
        let mut c = Cadence::default();
        for i in 0..100 {
            c.record("a", "1.1.1.1", 443, i * 1000);
        }
        c.record("b", "2.2.2.2", 443, 5);
        assert_eq!(c.len(), 2);
        c.prune(50_000);
        assert_eq!(c.len(), 1, "the series last touched at t=5 is gone");
        let s = c.record("a", "1.1.1.1", 443, 100_000).unwrap();
        assert_eq!(s.count, CADENCE_KEEP, "kept arrivals are capped");
    }

    #[test]
    fn fan_out_counts_distinct_networks_in_the_window() {
        let mut f = FanOut::default();
        for i in 0..30 {
            assert_eq!(f.record("p2p", &format!("10.{i}.0.0/24"), 1_000 + i), (i + 1) as usize);
        }
        // Same network again did not widen the spread: nothing to report.
        assert_eq!(f.record("p2p", "10.0.0.0/24", 2_000), 0);
        assert_eq!(f.record("p2p", "10.5.0.0/24", 2_001), 0);
        // A new one does, at the full width.
        assert_eq!(f.record("p2p", "10.77.0.0/24", 2_002), 31);
        // A minute later the old ones fall out.
        assert_eq!(f.record("p2p", "10.99.0.0/24", 2_002 + FANOUT_WINDOW_MS + 1), 1);
    }

    #[test]
    fn indicators_are_quiet_for_an_ordinary_row() {
        let s = subject(&[], &[]);
        assert!(indicators(&s).is_empty(), "nothing to say about https to a non-hosting ASN");
    }

    #[test]
    fn novelty_only_speaks_once_established() {
        let mut s = subject(&[], &[]);
        s.novelty = Some(Novelty {
            established: false,
            new_asn: true,
            new_country: true,
            new_port: true,
            observations: 3,
            age_ms: 1000,
        });
        assert!(indicators(&s).is_empty());
        s.novelty.as_mut().unwrap().established = true;
        s.novelty.as_mut().unwrap().observations = 400;
        s.novelty.as_mut().unwrap().age_ms = 3 * 24 * 3_600_000;
        let out = indicators(&s);
        let ids: Vec<&str> = out.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["new-asn", "new-country"], "443 is a common port: no uncommon-port");
        assert!(out[0].basis.contains("AS16509 (Amazon.com, Inc.)"));
        assert!(out[0].basis.contains("400 earlier connections over 3d"));
        assert!(out.iter().all(|i| i.severity == Severity::Notice));
        s.port = 4444;
        let out = indicators(&s);
        let last = out.last().unwrap();
        assert_eq!(last.id, "uncommon-port");
        assert_eq!(last.attack.as_ref().unwrap().id, "T1571");
    }

    #[test]
    fn exe_flags_and_watch_hits_outrank_everything() {
        let hits = vec![("w-1".to_string(), "ASN 16509".to_string())];
        let mut s = subject(&[ExeFlag::Deleted, ExeFlag::HiddenHome], &hits);
        s.cadence = Some(CadenceStats {
            count: 10,
            median_ms: 30_000,
            cv: 0.05,
        });
        s.bytes = Some((10 * 1024 * 1024, 1024));
        s.fan_out = FANOUT_MIN;
        s.hostname = "ec2-1-2-3-4.compute.amazonaws.com";
        let out = indicators(&s);
        let ids: Vec<&str> = out.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "watchlist",
                "exe-deleted",
                "exe-hidden-home",
                "beacon-cadence",
                "upload-heavy",
                "fan-out",
                "hosting"
            ]
        );
        assert_eq!(out[0].severity, Severity::Warning);
        assert_eq!(out[1].attack.as_ref().unwrap().id, "T1070.004");
        assert!(out[3].basis.contains("every 30s (10 times, 5% jitter)"));
        assert!(out[4].basis.contains("10.0 MiB"));
        assert!(out[6].basis.contains("Amazon Web Services"));
        assert_eq!(top_severity(&out), Some(Severity::Warning));
    }

    #[test]
    fn an_owned_row_is_named_with_its_account() {
        // The system daemon's row for a user's app: the owner rides every
        // basis, and the behaviour rungs apply as they would on the user's own
        // daemon, since `system` is false for a person's process.
        assert_eq!(who_label("brave", "Brave", Some("alice")), "Brave (alice)");
        assert_eq!(who_label("brave", "", Some("alice")), "brave (alice)");
        assert_eq!(who_label("brave", "Brave", Some("")), "Brave");
        assert_eq!(who_label("brave", "Brave", None), "Brave");
        let mut s = subject(&[ExeFlag::HiddenHome], &[]);
        s.app_id = "brave";
        s.app_name = "Brave";
        s.owner = Some("alice");
        s.cadence = Some(CadenceStats { count: 10, median_ms: 64_000, cv: 0.01 });
        let out = indicators(&s);
        let ids: Vec<&str> = out.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["exe-hidden-home", "beacon-cadence"]);
        assert!(out[0].basis.starts_with("Brave (alice) runs from a hidden directory"), "{}", out[0].basis);
        assert!(out[1].basis.contains("Brave (alice)"), "{}", out[1].basis);
    }

    #[test]
    fn system_rows_get_file_and_watch_rungs_only() {
        let hits = vec![("w-1".to_string(), "port 123".to_string())];
        let mut s = subject(&[ExeFlag::TempDir], &hits);
        s.system = true;
        s.cadence = Some(CadenceStats { count: 10, median_ms: 64_000, cv: 0.01 });
        s.bytes = Some((UPLOAD_MIN_TX * 4, 0));
        s.fan_out = FANOUT_MIN;
        s.novelty = Some(Novelty { established: true, new_asn: true, new_country: false, new_port: false, observations: 50, age_ms: LEARN_MS * 2 });
        let ids: Vec<String> = indicators(&s).into_iter().map(|i| i.id).collect();
        assert_eq!(ids, vec!["watchlist", "exe-temp-dir"], "timesyncd on a schedule is not a beacon");
    }

    #[test]
    fn a_go_build_binary_is_a_notice_where_a_temp_binary_warns() {
        let out = indicators(&subject(&[ExeFlag::BuildDir], &[]));
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].id.as_str(), out[0].severity), ("exe-build-dir", Severity::Notice));
        assert!(out[0].attack.is_none(), "a dev build is not a technique");
        assert!(out[0].basis.contains("`go test`") && out[0].basis.contains("still warns"), "{}", out[0].basis);
        let temp = exe_flag_indicator(ExeFlag::TempDir, "X");
        assert_eq!((temp.id.as_str(), temp.severity), ("exe-temp-dir", Severity::Warning), "the warning is untouched");
        // A system row (another uid's daemon) still gets the notice: file flags speak for every row.
        let mut s = subject(&[ExeFlag::BuildDir], &[]);
        s.system = true;
        assert_eq!(indicators(&s).iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["exe-build-dir"]);
    }

    #[test]
    fn a_late_name_retires_no_ptr_and_adds_hosting_and_watch_hits() {
        let mut list = vec![Indicator { id: "no-ptr".into(), severity: Severity::Info, attack: None, basis: "x".into() }];
        assert!(!reconcile_hostname(&mut list, "", true, true, false), "no name, nothing to do");
        // A DNS answer names the row but the address still has no PTR.
        assert!(reconcile_hostname(&mut list, "ec2-1-2-3-4.compute.amazonaws.com", false, true, false));
        assert_eq!(list.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["no-ptr", "hosting"]);
        assert!(reconcile_hostname(&mut list, "ec2-1-2-3-4.compute.amazonaws.com", true, true, false), "a PTR retires no-ptr");
        assert_eq!(list.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["hosting"]);
        assert!(!reconcile_hostname(&mut list, "ec2-1-2-3-4.compute.amazonaws.com", true, true, false), "idempotent");
        let mut sys = Vec::new();
        assert!(!reconcile_hostname(&mut sys, "x.amazonaws.com", true, true, true), "a system row gains no hosting rung");
        assert!(!reconcile_hostname(&mut sys, "x.amazonaws.com", true, false, false), "nor a private peer");
        let hits = vec![("w-9".to_string(), "host *.evil.example".to_string())];
        assert!(add_watch_hits(&mut list, &hits));
        assert_eq!(list[0].id, "watchlist");
        assert_eq!(list[0].severity, Severity::Warning);
        assert!(!add_watch_hits(&mut list, &hits), "the same hit is not added twice");
        assert!(!add_watch_hits(&mut list, &[]));
    }

    #[test]
    fn hosting_from_asn_org_and_no_ptr_are_info_and_only_for_public_peers() {
        let mut s = subject(&[], &[]);
        s.org = Some("Hetzner Online GmbH");
        s.hostname_settled = true;
        let out = indicators(&s);
        let ids: Vec<&str> = out.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["hosting", "no-ptr"]);
        assert!(out.iter().all(|i| i.severity == Severity::Info));
        s.remote = Some("192.168.1.9".parse().unwrap());
        assert!(indicators(&s).is_empty(), "a LAN peer has no hosting or PTR story");
        s.remote = Some("100.100.1.1".parse().unwrap());
        assert!(indicators(&s).is_empty(), "CGNAT (tailnet) is not public either");
    }

    #[test]
    fn upload_heavy_needs_both_volume_and_ratio() {
        assert!(!is_upload_heavy(None));
        assert!(!is_upload_heavy(Some((UPLOAD_MIN_TX - 1, 0))));
        assert!(!is_upload_heavy(Some((UPLOAD_MIN_TX * 4, UPLOAD_MIN_TX))));
        assert!(is_upload_heavy(Some((UPLOAD_MIN_TX, 0))));
        assert!(is_upload_heavy(Some((UPLOAD_MIN_TX * 10, UPLOAD_MIN_TX * 2))));
    }

    #[test]
    fn subject_parse_guesses_kinds_honestly() {
        assert_eq!(PivotSubject::parse("1.2.3.4").unwrap().kind, SubjectKind::Ip);
        assert_eq!(PivotSubject::parse("2606:4700::1111").unwrap().kind, SubjectKind::Ip);
        assert_eq!(PivotSubject::parse("AS13335").unwrap(), PivotSubject { kind: SubjectKind::Asn, value: "13335".into() });
        assert_eq!(PivotSubject::parse("13335").unwrap().kind, SubjectKind::Port, "a small number is a port");
        assert_eq!(PivotSubject::parse("70000").unwrap().kind, SubjectKind::Asn);
        assert_eq!(PivotSubject::parse("DE").unwrap().kind, SubjectKind::Country);
        assert_eq!(PivotSubject::parse("1.2.3.0/24").unwrap().kind, SubjectKind::Network);
        assert_eq!(PivotSubject::parse("firefox").unwrap().kind, SubjectKind::App);
        assert_eq!(PivotSubject::parse("example.com").unwrap().kind, SubjectKind::Host);
        assert_eq!(PivotSubject::parse("app:curl").unwrap(), PivotSubject { kind: SubjectKind::App, value: "curl".into() });
        assert_eq!(PivotSubject::parse("country:de").unwrap().value, "DE");
        assert!(PivotSubject::parse("").is_err());
        assert!(PivotSubject::parse("ip:not-an-ip").is_err());
        assert!(PivotSubject::parse("port:70000").is_err());
    }

    #[test]
    fn subject_matching_covers_every_kind() {
        let mut c = conn("firefox", "203.0.113.7", 443);
        c.hostname = "cdn.example.net".into();
        c.country = "DE".into();
        let yes = [
            "ip:203.0.113.7",
            "app:firefox",
            "app:/usr/bin/firefox",
            "asn:24940",
            "network:203.0.113.7/24",
            "country:DE",
            "port:443",
            "host:example.net",
            "host:cdn.example.net",
        ];
        for s in yes {
            assert!(PivotSubject::parse(s).unwrap().matches(&c), "{s}");
        }
        for s in ["ip:203.0.113.8", "app:curl", "asn:1", "port:80", "host:ample.net"] {
            assert!(!PivotSubject::parse(s).unwrap().matches(&c), "{s}");
        }
    }

    #[test]
    fn pivot_aggregates_and_caps() {
        let mut rows = Vec::new();
        let mut conns = Vec::new();
        for i in 0..60u16 {
            let mut c = conn(if i % 2 == 0 { "firefox" } else { "curl" }, &format!("203.0.113.{}", i % 7), 443 + (i % 3));
            c.indicators.push(Indicator {
                id: if i % 5 == 0 { "beacon-cadence".into() } else { "hosting".into() },
                severity: if i % 5 == 0 { Severity::Notice } else { Severity::Info },
                attack: None,
                basis: format!("row {i}"),
            });
            conns.push(c);
        }
        for (i, c) in conns.iter().enumerate() {
            rows.push(Observed {
                conn: c,
                first: 1_000_000 + i as u64 * 60_000,
                last: 1_000_000 + i as u64 * 60_000 + 500,
                live: i % 10 == 0,
                bytes: Some((100, 10)),
            });
        }
        let p = pivot(None, &rows, 1_000_000, 1_000_000 + 2 * 3_600_000, false);
        assert_eq!(p.connections, 60);
        assert_eq!(p.live, 6);
        assert_eq!(p.tx, 6000);
        assert_eq!(p.apps.len(), 2);
        assert_eq!(p.apps[0].connections, 30);
        assert_eq!(p.destinations.len(), 21, "distinct (ip,port) pairs");
        assert_eq!(p.timeline.len(), 2);
        assert_eq!(p.timeline.iter().sum::<usize>(), 60);
        assert_eq!(p.indicators[0].id, "beacon-cadence", "notice sorts above info");
        assert_eq!(p.indicators[0].connections, 12);
        assert_eq!(p.cadence_ms, Some(60_000), "rows arrive every minute");

        let only_curl = PivotSubject::parse("app:curl").unwrap();
        let p = pivot(Some(&only_curl), &rows, 1_000_000, 1_000_000 + 2 * 3_600_000, true);
        assert_eq!(p.connections, 30);
        assert!(p.truncated);
        assert_eq!(p.subject, Some(only_curl));
        assert_eq!(p.asns[0].label, "AS24940 Hetzner Online GmbH");
    }

    #[test]
    fn brief_renders_markdown_with_every_section() {
        let c = conn("firefox", "203.0.113.7", 443);
        let rows = vec![Observed {
            conn: &c,
            first: 5_000,
            last: 6_000,
            live: true,
            bytes: Some((2048, 4096)),
        }];
        let now = 8_000 + 3_600_000;
        let acts = vec![
            crate::activity::ActivityEntry::new(
                9_000,
                crate::activity::ActivityKind::AppFirstSeen,
                Some(crate::activity::ActivityApp {
                    id: "firefox".into(),
                    name: "Firefox".into(),
                }),
                serde_json::json!({}),
            ),
            crate::activity::ActivityEntry::new(9_001, crate::activity::ActivityKind::NewNetwork, None, serde_json::json!({})),
            crate::activity::ActivityEntry::new(9_002, crate::activity::ActivityKind::Block, None, serde_json::json!({})),
            crate::activity::ActivityEntry::new(9_003, crate::activity::ActivityKind::WatchHit, None, serde_json::json!({})),
            // Outside the window: ignored.
            crate::activity::ActivityEntry::new(1, crate::activity::ActivityKind::Block, None, serde_json::json!({})),
        ];
        let listeners = vec![ListenerSummary {
            proto: "tcp".into(),
            ip: "0.0.0.0".into(),
            port: 22,
            app: "sshd".into(),
            scope: "all interfaces".into(),
        }];
        let b = brief("box", 1, now, &rows, &acts, &listeners, false);
        assert_eq!(b.new_apps, vec!["Firefox"]);
        assert_eq!((b.new_networks, b.blocks, b.watch_hits), (1, 1, 1));
        let md = render_brief_markdown(&b);
        for want in [
            "# kub0 brief: box (last 1h",
            "## Totals",
            "1 connections (1 live now) from 1 apps to 1 destinations",
            "2 KiB sent, 4 KiB received",
            "1 new networks, 1 new apps (Firefox)",
            "## Indicators",
            "None raised",
            "## Top destinations",
            "203.0.113.7:443 DE AS24940 (Hetzner Online GmbH) x1 via firefox",
            "## Exposure",
            "tcp 0.0.0.0:22 sshd (all interfaces)",
        ] {
            assert!(md.contains(want), "missing {want:?} in:\n{md}");
        }
    }

    #[test]
    fn timestamps_render_as_utc_rfc3339() {
        assert_eq!(fmt_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_ts(1_757_600_000_000), "2025-09-11T14:13:20Z");
        assert_eq!(fmt_duration(45_000), "45s");
        assert_eq!(fmt_duration(300_000), "5m");
        assert_eq!(fmt_duration(7_200_000), "2h");
        assert_eq!(fmt_duration(3 * 86_400_000), "3d");
    }
}

/// Add or remove the upload-heavy indicator on an open row as its counters
/// move. Returns true when the set changed and the row should be re-sent.
pub fn reconcile_upload(list: &mut Vec<Indicator>, who: &str, bytes: Option<(u64, u64)>) -> bool {
    let has = list.iter().position(|i| i.id == "upload-heavy");
    match (upload_heavy(bytes), has) {
        (Some((tx, rx)), None) => {
            list.push(Indicator {
                id: "upload-heavy".into(),
                severity: Severity::Notice,
                attack: attack("T1048", "Exfiltration Over Alternative Protocol"),
                basis: format!(
                    "{who} has sent {} and received {} on this connection. Backups, sync clients and uploads look like this; so does data leaving.",
                    fmt_bytes(tx),
                    fmt_bytes(rx)
                ),
            });
            list.sort_by_key(|i| std::cmp::Reverse(i.severity));
            true
        }
        (None, Some(idx)) => {
            list.remove(idx);
            true
        }
        _ => false,
    }
}

/// Render a pivot for a terminal.
pub fn render_pivot_text(p: &Pivot) -> String {
    let mut s = String::new();
    let subject = p.subject.as_ref().map(|s| format!("{:?} {}", s.kind, s.value).to_lowercase()).unwrap_or_else(|| "everything".into());
    s.push_str(&format!("subject: {subject}\nwindow:  {} .. {}\n", fmt_ts(p.since), fmt_ts(p.until)));
    if p.connections == 0 {
        s.push_str("no matching observations in retained history\n");
        return s;
    }
    s.push_str(&format!(
        "matched: {} connections ({} live), first {} last {}, {} sent / {} received{}\n",
        p.connections,
        p.live,
        fmt_ts(p.first),
        fmt_ts(p.last),
        fmt_bytes(p.tx),
        fmt_bytes(p.rx),
        if p.truncated { " (history capped: a floor)" } else { "" }
    ));
    if let Some(c) = p.cadence_ms {
        s.push_str(&format!("cadence: about every {}\n", fmt_duration(c)));
    }
    s.push_str("\napps:\n");
    for a in &p.apps {
        s.push_str(&format!("  {:<28} x{:<5} {} sent / {} received\n", if a.name.is_empty() { &a.id } else { &a.name }, a.connections, fmt_bytes(a.tx), fmt_bytes(a.rx)));
    }
    s.push_str("\ndestinations:\n");
    for d in &p.destinations {
        let name = if d.hostname.is_empty() { d.ip.clone() } else { format!("{} ({})", d.hostname, d.ip) };
        s.push_str(&format!("  {name}:{} {} {} x{} via {}\n", d.port, d.country, asn_label(d.asn, d.org.as_deref()), d.connections, d.apps.join(", ")));
    }
    if !p.asns.is_empty() {
        s.push_str("\nnetworks:\n");
        for f in &p.asns {
            s.push_str(&format!("  {} x{}\n", f.label, f.connections));
        }
    }
    if !p.countries.is_empty() {
        s.push_str("\ncountries: ");
        s.push_str(&p.countries.iter().map(|f| format!("{} x{}", f.label, f.connections)).collect::<Vec<_>>().join(", "));
        s.push('\n');
    }
    if !p.indicators.is_empty() {
        s.push_str("\nindicators:\n");
        for i in &p.indicators {
            s.push_str(&format!("  {:<8} {:<18} x{:<4} {}\n", i.severity.as_str(), i.id, i.connections, i.example));
        }
    }
    s.push_str("\ntimeline (per hour, oldest first): ");
    s.push_str(&p.timeline.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" "));
    s.push('\n');
    s
}

/// The indicator one executable-provenance flag raises. Shared by the engine
/// and by [`reconcile_replaced`], which settles the two an upgrade decides
/// after the package manager answers.
pub fn exe_flag_indicator(f: ExeFlag, who: &str) -> Indicator {
    let (id, sev, attack, basis) = match f {
        ExeFlag::Deleted => (
            "exe-deleted",
            Severity::Warning,
            attack("T1070.004", "Indicator Removal: File Deletion"),
            format!("{who}'s executable has been deleted from disk while the process is still running, and no installed package owns what is at that path now. A process that unlinked itself does this on purpose; so do app self-updaters and software removed or swapped by hand."),
        ),
        ExeFlag::TempDir => (
            "exe-temp-dir",
            Severity::Warning,
            attack("T1036.005", "Masquerading: Match Legitimate Name or Location"),
            format!("{who} runs from a temporary directory. Installers and dev builds live there briefly; a long-lived network client there is unusual."),
        ),
        ExeFlag::WorldWritable => (
            "exe-world-writable",
            Severity::Warning,
            attack("T1574", "Hijack Execution Flow"),
            format!("{who}'s executable is writable by every user on this machine, so any local process could have replaced it."),
        ),
        ExeFlag::BuildDir => (
            "exe-build-dir",
            Severity::Notice,
            None,
            format!("{who} runs from a Go build directory under /tmp; the go tool is its parent, which is what `go test` and `go run` do. A binary placed in /tmp by anything else still warns."),
        ),
        ExeFlag::HiddenHome => (
            "exe-hidden-home",
            Severity::Notice,
            attack("T1036.005", "Masquerading: Match Legitimate Name or Location"),
            format!("{who} runs from a hidden directory under your home. Language toolchains and app updaters install there; so does anything that wants to stay out of sight."),
        ),
        ExeFlag::ChangedSinceStart => (
            "exe-changed",
            Severity::Notice,
            None,
            format!("{who}'s executable on disk changed after this process started; the running code is not the file."),
        ),
    };
    Indicator {
        id: id.into(),
        severity: sev,
        attack,
        basis,
    }
}

/// Settle `exe-deleted` and `exe-changed` on a row once the package manager
/// has answered for a binary replaced under a running process: present iff
/// `flags` carries them now. Returns whether the row changed and the ids it
/// gained, so the caller can log what arrived after the row did.
pub fn reconcile_replaced(list: &mut Vec<Indicator>, who: &str, flags: &[ExeFlag]) -> (bool, Vec<&'static str>) {
    let mut moved = false;
    let mut added = Vec::new();
    for (flag, id) in [(ExeFlag::Deleted, "exe-deleted"), (ExeFlag::ChangedSinceStart, "exe-changed")] {
        let want = flags.contains(&flag);
        match (want, list.iter().position(|i| i.id == id)) {
            (true, None) => {
                list.push(exe_flag_indicator(flag, who));
                moved = true;
                added.push(id);
            }
            (false, Some(idx)) => {
                list.remove(idx);
                moved = true;
            }
            _ => {}
        }
    }
    if moved {
        list.sort_by_key(|i| std::cmp::Reverse(i.severity));
    }
    (moved, added)
}

/// Add or remove the unpackaged-executable indicator once the package manager
/// has answered for an executable in a system directory. Returns true when
/// the set changed. The flag arrives after the row exists, which is why this
/// is a reconcile rather than a rung in [`indicators`].
pub fn reconcile_unpackaged(list: &mut Vec<Indicator>, who: &str, exe: &str, unpackaged: bool) -> bool {
    let has = list.iter().position(|i| i.id == "exe-unpackaged");
    match (unpackaged, has) {
        (true, None) => {
            list.push(Indicator {
                id: "exe-unpackaged".into(),
                severity: Severity::Notice,
                attack: attack("T1036.005", "Masquerading: Match Legitimate Name or Location"),
                basis: format!(
                    "{who} runs {exe}, which sits in a system directory but belongs to no installed package. Software installed by hand or by a vendor script looks like this; so does a planted binary."
                ),
            });
            list.sort_by_key(|i| std::cmp::Reverse(i.severity));
            true
        }
        (false, Some(idx)) => {
            list.remove(idx);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    #[test]
    fn a_replaced_binary_settles_to_exactly_the_flags_it_has() {
        let mut list = vec![exe_flag_indicator(ExeFlag::HiddenHome, "X")];
        // Owned replacement: exe-changed arrives, nothing else moves.
        let (moved, added) = reconcile_replaced(&mut list, "X", &[ExeFlag::HiddenHome, ExeFlag::ChangedSinceStart]);
        assert!(moved);
        assert_eq!(added, vec!["exe-changed"]);
        // Unowned: exe-deleted arrives, ranked first as a warning; exe-changed goes.
        let (moved, added) = reconcile_replaced(&mut list, "X", &[ExeFlag::Deleted, ExeFlag::HiddenHome]);
        assert!(moved);
        assert_eq!(added, vec!["exe-deleted"]);
        let ids: Vec<&str> = list.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["exe-deleted", "exe-hidden-home"]);
        assert_eq!(list[0].severity, Severity::Warning);
        // Settled already: nothing to do.
        assert_eq!(reconcile_replaced(&mut list, "X", &[ExeFlag::Deleted, ExeFlag::HiddenHome]), (false, vec![]));
    }

    #[test]
    fn upload_and_unpackaged_reconcile_in_place() {
        let mut list = vec![Indicator {
            id: "hosting".into(),
            severity: Severity::Info,
            attack: None,
            basis: "x".into(),
        }];
        assert!(reconcile_upload(&mut list, "App", Some((UPLOAD_MIN_TX, 0))));
        assert_eq!(list[0].id, "upload-heavy", "a notice sorts above the info");
        assert!(!reconcile_upload(&mut list, "App", Some((UPLOAD_MIN_TX * 2, 0))), "still heavy: no change");
        assert!(reconcile_upload(&mut list, "App", Some((UPLOAD_MIN_TX, UPLOAD_MIN_TX))), "ratio gone: removed");
        assert_eq!(list.len(), 1);
        assert!(reconcile_unpackaged(&mut list, "App", "/usr/bin/app", true));
        assert_eq!(list[0].id, "exe-unpackaged");
        assert!(list[0].basis.contains("/usr/bin/app"));
        assert!(!reconcile_unpackaged(&mut list, "App", "/usr/bin/app", true));
        assert!(reconcile_unpackaged(&mut list, "App", "/usr/bin/app", false));
        assert!(!reconcile_unpackaged(&mut list, "App", "/usr/bin/app", false));
        assert_eq!(list.len(), 1);
    }
}

// ---------------------------------------------------------------------------
// Timeline: when this machine talks, by app and by hour.
// ---------------------------------------------------------------------------

/// Apps shown as their own row; the rest fold into `other`. Nine rows is
/// about what a panel-height heatmap can label without shrinking the text.
pub const TIMELINE_MAX_APPS: usize = 9;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineApp {
    pub id: String,
    pub name: String,
    /// Connections observed in each bucket, oldest first.
    pub counts: Vec<u64>,
    pub total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub since: u64,
    pub until: u64,
    pub bucket_ms: u64,
    pub buckets: usize,
    /// Busiest apps first, at most [`TIMELINE_MAX_APPS`].
    pub apps: Vec<TimelineApp>,
    /// Every app not in `apps`, folded; empty when none were folded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<u64>,
    pub other_apps: usize,
    /// All apps together.
    pub total: Vec<u64>,
    pub max: u64,
    pub truncated: bool,
}

/// `ts` rounded down to a multiple of `bucket_ms` (UTC epoch alignment).
pub fn align_down(ts: u64, bucket_ms: u64) -> u64 {
    if bucket_ms == 0 { ts } else { ts - ts % bucket_ms }
}

/// Count each observation in every bucket it was observed in, from its first
/// sampling time to its last (a live row's last is `until`). This is presence,
/// not arrivals: an hour in which a connection stayed open is an hour the app
/// was talking, which is the question a timeline answers.
pub fn timeline(rows: &[Observed<'_>], since: u64, until: u64, bucket_ms: u64, max_apps: usize, truncated: bool) -> Timeline {
    let bucket_ms = bucket_ms.max(60_000);
    let span = until.saturating_sub(since).max(1);
    let buckets = span.div_ceil(bucket_ms).clamp(1, 24 * 8) as usize;
    let mut per_app: BTreeMap<String, (String, Vec<u64>)> = BTreeMap::new();
    for o in rows {
        let c = o.conn;
        if c.unresolved {
            continue;
        }
        let first = o.first.max(since);
        let last = if o.live { until } else { o.last }.min(until);
        if last < first {
            continue;
        }
        let a = ((first - since) / bucket_ms) as usize;
        let b = ((last - since) / bucket_ms) as usize;
        let entry = per_app
            .entry(c.app.id.clone())
            .or_insert_with(|| (c.app.name.clone(), vec![0; buckets]));
        for i in a.min(buckets - 1)..=b.min(buckets - 1) {
            entry.1[i] += 1;
        }
    }
    let mut apps: Vec<TimelineApp> = per_app
        .into_iter()
        .map(|(id, (name, counts))| TimelineApp {
            total: counts.iter().sum(),
            id,
            name,
            counts,
        })
        .collect();
    apps.sort_by(|x, y| y.total.cmp(&x.total).then(x.id.cmp(&y.id)));
    let mut total = vec![0u64; buckets];
    for a in &apps {
        for (i, n) in a.counts.iter().enumerate() {
            total[i] += n;
        }
    }
    let mut other = Vec::new();
    let other_apps = apps.len().saturating_sub(max_apps);
    if other_apps > 0 {
        other = vec![0u64; buckets];
        for a in apps.iter().skip(max_apps) {
            for (i, n) in a.counts.iter().enumerate() {
                other[i] += n;
            }
        }
        apps.truncate(max_apps);
    }
    let max = apps
        .iter()
        .flat_map(|a| a.counts.iter().copied())
        .chain(other.iter().copied())
        .max()
        .unwrap_or(0);
    Timeline {
        since,
        until,
        bucket_ms,
        buckets,
        apps,
        other,
        other_apps,
        total,
        max,
        truncated,
    }
}

/// Terminal heatmap: one line per app, one block per bucket, darker for more.
pub fn render_timeline_text(t: &Timeline) -> String {
    const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let mut s = String::new();
    s.push_str(&format!(
        "window: {} .. {} ({} buckets of {})\n",
        fmt_ts(t.since),
        fmt_ts(t.until),
        t.buckets,
        fmt_duration(t.bucket_ms)
    ));
    if t.apps.is_empty() {
        s.push_str("no observations in retained history for this window\n");
        return s;
    }
    s.push_str("presence: a connection counts in every bucket it was observed in; shade is sqrt-scaled to the busiest cell\n");
    if t.truncated {
        s.push_str("retained history was capped for this window; counts are a floor\n");
    }
    let other_label = format!("+{} other apps", t.other_apps);
    let width = t
        .apps
        .iter()
        .map(|a| if a.name.is_empty() { a.id.chars().count() } else { a.name.chars().count() })
        .chain(if t.other.is_empty() { None } else { Some(other_label.chars().count()) })
        .max()
        .unwrap_or(4)
        .clamp(4, 24);
    let shade = |n: u64| -> char {
        if n == 0 || t.max == 0 {
            return BLOCKS[0];
        }
        let f = (n as f64 / t.max as f64).sqrt();
        BLOCKS[((f * 7.0).round() as usize + 1).min(8)]
    };
    let mut line = |name: &str, counts: &[u64], total: u64| {
        let shown: String = name.chars().take(width).collect();
        s.push_str(&format!("{shown:<width$} │"));
        for n in counts {
            s.push(shade(*n));
        }
        s.push_str(&format!("│ {total}\n"));
    };
    for a in &t.apps {
        line(if a.name.is_empty() { &a.id } else { &a.name }, &a.counts, a.total);
    }
    if !t.other.is_empty() {
        line(&other_label, &t.other, t.other.iter().sum());
    }
    // Axis: a tick every 6 buckets for a day, every 24 for a week.
    let step = if t.buckets > 48 { 24 } else { 6 };
    let mut axis = format!("{:<width$}  ", "");
    for i in 0..t.buckets {
        axis.push(if i % step == 0 { '|' } else { ' ' });
    }
    s.push_str(&axis);
    s.push('\n');
    let mut labels = format!("{:<width$}  ", "");
    let mut i = 0;
    while i < t.buckets {
        let ts = t.since + i as u64 * t.bucket_ms;
        let label = if step == 24 { fmt_ts(ts)[5..10].to_string() } else { fmt_ts(ts)[11..16].to_string() };
        labels.push_str(&format!("{label:<step$}"));
        i += step;
    }
    s.push_str(labels.trim_end());
    s.push_str("  (UTC)\n");
    s
}

#[cfg(test)]
mod timeline_tests {
    use super::*;
    use crate::event::{AppIdentity, Endpoint};

    fn conn(app: &str) -> Connection {
        Connection {
            id: format!("tcp:1:1.2.3.4:443:{app}"),
            proto: "tcp".into(),
            inode: 1,
            app: AppIdentity { id: app.into(), name: app.to_uppercase(), icon: String::new(), desktop: String::new(), pid: 1, system: false, exe: String::new(), owner: None },
            local: Endpoint { ip: String::new(), port: 0 },
            remote: Endpoint { ip: "1.2.3.4".into(), port: 443 },
            state: "ESTABLISHED".into(),
            country: String::new(), lat: 0.0, lon: 0.0, unresolved: false, new_network: false,
            network_key: String::new(), hostname: String::new(), hostname_source: String::new(), uid: None, reason: String::new(),
            clue: None, tag: None, bytes: None, exe: String::new(), evidence: None, policy: Vec::new(),
            asn: None, org: None, indicators: Vec::new(),
        }
    }

    #[test]
    fn presence_counts_every_bucket_a_row_was_open_and_folds_the_long_tail() {
        let h = 3_600_000u64;
        let since = 1_000 * h;
        let until = since + 24 * h;
        let a = conn("firefox");
        let b = conn("curl");
        let others: Vec<Connection> = (0..3).map(|i| conn(&format!("app{i}"))).collect();
        let mut rows = vec![
            // Open from hour 2 to hour 5: four buckets.
            Observed { conn: &a, first: since + 2 * h + 1, last: since + 5 * h + 1, live: false, bytes: None },
            // Live since hour 22: counts to the end.
            Observed { conn: &a, first: since + 22 * h, last: since + 22 * h, live: true, bytes: None },
            // Began before the window: clamped to bucket 0.
            Observed { conn: &b, first: since - h, last: since + 30_000, live: false, bytes: None },
            // Ended before the window: ignored.
            Observed { conn: &b, first: since - 3 * h, last: since - 2 * h, live: false, bytes: None },
        ];
        for o in &others {
            rows.push(Observed { conn: o, first: since + h, last: since + h, live: false, bytes: None });
        }
        let t = timeline(&rows, since, until, h, TIMELINE_MAX_APPS, false);
        assert_eq!(t.buckets, 24);
        assert_eq!(t.apps.len(), 5);
        assert_eq!(t.other_apps, 0);
        assert!(t.other.is_empty());
        assert_eq!(t.apps[0].id, "firefox", "busiest first");
        let f = &t.apps[0].counts;
        assert_eq!(&f[2..6], &[1, 1, 1, 1]);
        assert_eq!(f[1], 0);
        assert_eq!(&f[22..24], &[1, 1], "live rows run to the end of the window");
        assert_eq!(t.apps[0].total, 6);
        let c = t.apps.iter().find(|x| x.id == "curl").unwrap();
        assert_eq!(c.counts[0], 1);
        assert_eq!(c.total, 1, "the row that ended before the window is not counted");
        assert_eq!(t.total[1], 3, "the three one-shot apps, all in hour 1");
        assert_eq!(t.total[3], 1);
        assert_eq!(t.max, 1);
        let text = render_timeline_text(&t);
        assert!(text.contains("FIREFOX"), "{text}");
        assert!(text.contains("(UTC)"));
        assert!(!text.contains("other apps"));

        // Two rows shown: firefox, then the first by id among the ties; three fold.
        let t2 = timeline(&rows, since, until, h, 2, true);
        assert_eq!(t2.apps.len(), 2);
        assert_eq!(t2.apps[1].id, "app0");
        assert_eq!(t2.other_apps, 3);
        assert_eq!(t2.other[1], 2, "app1 and app2 in hour 1");
        assert_eq!(t2.other[0], 1, "curl in hour 0");
        assert_eq!(t2.total, t.total, "folding changes rows, not the total");
        let text = render_timeline_text(&t2);
        assert!(text.contains("+3 other apps"), "{text}");
        assert!(text.contains("counts are a floor"));
        let empty = timeline(&[], since, until, h, 9, true);
        assert!(render_timeline_text(&empty).contains("no observations"));
        assert!(empty.apps.is_empty() && empty.max == 0);
        assert_eq!(align_down(1_757_600_000_000 + 1234, h), 1_757_600_000_000 + 1234 - (1_757_600_000_000 + 1234) % h);
        assert_eq!(align_down(h * 5 + 1, h), h * 5);
        assert_eq!(align_down(7, 0), 7);
    }
}
