//! Exec content gate for the system kub0d.
//!
//! When a file is about to be executed, refuse it if the sha256 of its bytes is
//! on the org deny list. The list already arrives through `refresh_fleet` and
//! the deny-list stream; this module only consumes that in-memory snapshot,
//! plus an optional local file for a root self-test. It is the desktop shape
//! of the fanotify gate kub0's cluster node agent runs: the kernel holds the exec on
//! `FAN_OPEN_EXEC_PERM` until we answer.
//!
//! Fail-open on purpose. A late, failed, or missing answer must not freeze
//! every exec on the machine. The gate is loaded at start but marks no
//! filesystem and hashes nothing until the first NON-EMPTY key set arrives
//! (a fleet publish of at most 500 rows, a deny-list stream frame, or a local
//! deny file). When the key set empties again (a local disconnect, an org
//! list that went to zero) the marks are flushed and the gate goes idle. A
//! fleet list longer than 500 rows keeps the keys already installed and does
//! not change the gate. Closing the group fd (read error, or the process
//! exiting) makes the kernel allow everything still pending.
//!
//! A fresh process does not start with no keys. Every list the API returns
//! is also written to `org-list.json` beside the trust store, and the next
//! start loads that copy for the same account, so the gate is armed before
//! the first sync instead of after it: at boot the network is not up yet,
//! and the API can be unreachable for hours. The copy is as old as the last
//! sync and the frame says so (`listReceivedAt`, `listRestored`) until a
//! list from the API replaces it. Only a list the API returned replaces the
//! keys; a failed fetch hands the gate nothing. The list belongs to the
//! account it arrived under: a logout removes the copy with the keys, and
//! naming another account takes the keys out at once. A list that fails to
//! save removes the older copy rather than leave it for a restart to load.
//!
//! The decision path never writes to disk; the only writes are the owner's
//! trust stores, that copy of the org list, and a state file for the panel.
//! An allow-set inode skips the content check only while the size, mtime, and
//! ctime recorded at start still match.
//! The watchdog can answer an event while a worker is still hashing.
//!
//! The effective key set is `(fleet ∪ file) − trusted`: a digest the owner
//! trusted on this machine (`trust.rs`) is never denied, and a one-shot allow
//! lets the next exec of a denied digest through once. Every match produces
//! an [`ExecGateDeny`] with its decision, kept in a ring for the fleet frame
//! and handed to the daemon loop for the activity feed.
//!
//! The decision path hashes the event fd with `pread`. It does not open a path
//! and it does not spawn a process. Fanotify itself is Linux-only; everywhere
//! else the module is an inert stub so `cargo test -p vallumd --lib` still runs.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::{now_ms, DenylistEntry};
use crate::trust::{self, decode_hex, encode_hex, OnceStore, TrustedDigest, DIGEST_LEN};

/// `fanotify_response.response` values. Local so the decision tests compile on
/// macOS, where libc has no fanotify constants. They match the kernel.
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const FANOTIFY_METADATA_VERSION: u8 = 3;
const METADATA_LEN: usize = 24;
/// Numeric value of `libc::FAN_OPEN_EXEC_PERM`. The mark call names the libc
/// constant; the walker compares against this so the parser stays portable.
/// Unused on a non-Linux build that is not running tests.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
const OPEN_EXEC_PERM: u64 = 0x0004_0000;

const ROW_LIMIT: usize = 500;
const CACHE_MAX: usize = 8192;
const DEFAULT_CAP_KIB: u64 = 65536;
const READ_CHUNK: usize = 256 * 1024;
const WORKERS: usize = 4;
const QUEUE_CAP: usize = 1024;
/// Recent denies kept for the fleet frame.
const RECENT_CAP: usize = 50;
const SAVED_SCHEMA: u32 = 1;
/// An unchanged org list is written to disk again this often, so the age a
/// restart reports is the time of the last sync, not of the last change.
const SAVE_REFRESH_MS: u64 = 10 * 60 * 1000;
/// Events waiting for the daemon loop; past this the oldest are dropped
/// (they are still in the ring and the stderr log).
const PENDING_CAP: usize = 256;

const MARK_FS: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "f2fs", "tmpfs", "overlay", "squashfs", "vfat",
];

const BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Directories outside [`BIN_DIRS`] where critical binaries actually live
/// (`systemd-logind`, `systemd-udevd`, `kub0-block`).
const EXTRA_ALLOW_DIRS: &[&str] = &["/usr/lib/systemd", "/usr/lib/kub0", "/usr/libexec"];

/// `comm` values that never contribute a key, and the basenames resolved into
/// the inode allow-set. A row naming one of these is skipped whole. An exec of
/// the binary itself skips hashing only while its size, mtime, and ctime still
/// match the signature recorded at start.
const CRITICAL_COMMS: &[&str] = &[
    "init",
    "systemd",
    "systemd-journal",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolve",
    "sshd",
    "login",
    "agetty",
    "mount",
    "umount",
    "fsck",
    "iptables",
    "ip6tables",
    "nft",
    "bash",
    "sh",
    "dash",
    "zsh",
    "cat",
    "rm",
    "mv",
    "cp",
    "mkdir",
    "chmod",
    "chown",
    "ip",
    "python3",
    "python",
    "perl",
    "grep",
    "awk",
    "sed",
    "find",
    "ls",
    "ps",
    "kill",
    "wget",
    "curl",
    "ssh",
    "scp",
    "rsync",
    "tar",
    "gzip",
    "xz",
    "bzip2",
    "zstd",
    "pacman",
    "pacman-key",
    "makepkg",
    "sudo",
    "pkexec",
    "polkitd",
    "dbus-daemon",
    "dbus-broker",
    "Xorg",
    "Hyprland",
    "sway",
    "gdm",
    "sddm",
    "seq",
    "readlink",
    "dirname",
    "basename",
    "head",
    "tail",
    "sort",
    "uniq",
    "wc",
    "tee",
    "mktemp",
    "sleep",
    "timeout",
    "nohup",
    "env",
    "date",
    "echo",
    "cut",
    "tr",
    "xargs",
    "ln",
    "touch",
    "sync",
    "id",
    "printf",
    "test",
    "true",
    "false",
    "base64",
    "stat",
    "which",
    "kub0d",
    "kub0-block",
];

/// What the gate did with a file whose sha256 matched a deny-list row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecGateDecision {
    /// Refused: the exec failed with EPERM.
    #[default]
    Blocked,
    /// Allowed: the owner trusts this digest on this machine.
    AllowedLocalTrust,
    /// Allowed: a one-shot allow was pending for this digest and is now spent.
    AllowedOnce,
    /// Allowed although it matched: the deny could not be delivered (the
    /// watchdog had already answered, or the response write failed).
    AllowedFailopen,
}

impl ExecGateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::AllowedLocalTrust => "allowed_local_trust",
            Self::AllowedOnce => "allowed_once",
            Self::AllowedFailopen => "allowed_failopen",
        }
    }
}

/// One exec whose digest matched. Local only: it names a path on this
/// machine and is never sent to kub0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecGateDeny {
    pub ts: u64,
    pub pid: i32,
    pub ppid: i32,
    /// Basename of the file that was executed.
    pub comm: String,
    pub exe: String,
    pub sha256: String,
    /// From the matching deny-list row.
    pub reason: String,
    pub promoted_by: String,
    pub created_at: String,
    pub decision: ExecGateDecision,
}

/// Counters on the local fleet frame. CamelCase on the wire; absent on an
/// older daemon (`#[serde(default)]` at the field). Not part of the kub0
/// heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecGateCounters {
    /// Denies delivered to the kernel.
    pub blocked: u64,
    pub allowed_once: u64,
    /// Matches allowed because the digest is trusted here.
    pub trusted: u64,
    /// Matches the gate wanted to deny and could not.
    pub failopen: u64,
    pub hashed: u64,
    pub cache_hit: u64,
    pub allowlisted: u64,
    pub over_cap: u64,
    pub error: u64,
    pub deadline: u64,
    /// Events the reader allowed because the worker queue was full.
    pub overflow: u64,
    pub marks: u64,
    pub uncovered: u64,
}

/// The exec gate as the panel sees it. In the system daemon this is live; the
/// user daemon mirrors the system daemon's state file into it (`source`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecGateFrame {
    /// The fanotify group is open (the gate loaded).
    pub enabled: bool,
    /// Filesystems are marked and execs are hashed: a non-empty key set arrived.
    pub armed: bool,
    pub keys: u64,
    /// `live` (this daemon runs the gate), `mirror` (read from the system
    /// daemon's state file), `stale` (that file is old), `none` (no state).
    pub source: String,
    /// When the frame was produced, ms since the epoch.
    pub observed_at: u64,
    pub counters: ExecGateCounters,
    /// Newest first.
    pub denies: Vec<ExecGateDeny>,
    pub trusted: Vec<TrustedDigest>,
    /// One-shot allows not yet spent or expired.
    pub once_pending: u64,
    /// When the kub0 API last returned the org list behind the keys, ms since
    /// the epoch. 0 while this process holds no org list at all.
    pub list_received_at: u64,
    /// The org list was read back from disk at start and no sync has replaced
    /// it yet: the keys are as old as `list_received_at`.
    pub list_restored: bool,
}

/// What the daemon loop collects on each tick.
#[derive(Debug, Default)]
pub struct Poll {
    /// Matches since the last poll, oldest first.
    pub events: Vec<ExecGateDeny>,
    /// The frame changed since the last poll: re-broadcast it.
    pub changed: bool,
}

/// What a cached digest was computed from. Any change means the bytes may have
/// changed, so the cache miss recomputes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Signature {
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

fn signature_of(meta: &std::fs::Metadata) -> Signature {
    Signature {
        size: meta.size(),
        mtime_sec: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime_sec: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    }
}

#[derive(Default)]
struct Stats {
    hashed: AtomicU64,
    cache_hit: AtomicU64,
    allowlisted: AtomicU64,
    over_cap: AtomicU64,
    error: AtomicU64,
    deadline: AtomicU64,
    overflow: AtomicU64,
    hit_block: AtomicU64,
    allowed_once: AtomicU64,
    trusted: AtomicU64,
    failopen: AtomicU64,
    marks: AtomicU64,
    uncovered: AtomicU64,
}

/// The deny-list row behind a key, for the event it produces.
#[derive(Clone, Debug, Default)]
struct RowMeta {
    reason: String,
    promoted_by: String,
    created_at: String,
}

impl RowMeta {
    fn from_row(row: &DenylistEntry) -> Self {
        Self {
            reason: row.reason.clone(),
            promoted_by: row.promoted_by.clone(),
            created_at: row.created_at.clone(),
        }
    }
}

/// Shared decision state. `keys` is what the workers consult: the union of
/// every source minus the trusted digests.
struct Shared {
    on: AtomicBool,
    /// Byte cap. `0` disables it.
    cap: u64,
    keys: RwLock<BTreeSet<[u8; DIGEST_LEN]>>,
    /// `fleet ∪ file` before the trusted digests are subtracted, so a trusted
    /// match can still be recorded as one.
    union: RwLock<BTreeSet<[u8; DIGEST_LEN]>>,
    trusted: RwLock<BTreeSet<[u8; DIGEST_LEN]>>,
    trusted_rows: RwLock<Vec<TrustedDigest>>,
    once: Mutex<OnceStore>,
    meta: RwLock<HashMap<[u8; DIGEST_LEN], RowMeta>>,
    /// `(dev, ino)` → signature observed when the allow-set was built.
    allow: RwLock<HashMap<(u64, u64), Signature>>,
    cache: Mutex<HashMap<(u64, u64), (Signature, [u8; DIGEST_LEN])>>,
    /// `(dev, ino)` of every over-cap file already named on stderr, so a
    /// toolchain binary that runs many times a second is logged once.
    over_cap_logged: Mutex<HashSet<(u64, u64)>>,
    stats: Stats,
    /// Last `(hit_block, error, deadline, overflow)` written to the telemetry line.
    last_logged: Mutex<Option<(u64, u64, u64, u64)>>,
    /// Newest last; the frame reverses it.
    denies: Mutex<VecDeque<ExecGateDeny>>,
    pending: Mutex<Vec<ExecGateDeny>>,
    /// Bumped on every match, key change and trust change.
    generation: AtomicU64,
    /// See [`ExecGateFrame::list_received_at`] and `list_restored`.
    list_received_at: AtomicU64,
    list_restored: AtomicBool,
}

impl Shared {
    fn new(cap: u64, allow: HashMap<(u64, u64), Signature>) -> Self {
        Self {
            on: AtomicBool::new(false),
            cap,
            keys: RwLock::new(BTreeSet::new()),
            union: RwLock::new(BTreeSet::new()),
            trusted: RwLock::new(BTreeSet::new()),
            trusted_rows: RwLock::new(Vec::new()),
            once: Mutex::new(OnceStore::in_memory()),
            meta: RwLock::new(HashMap::new()),
            allow: RwLock::new(allow),
            cache: Mutex::new(HashMap::new()),
            over_cap_logged: Mutex::new(HashSet::new()),
            stats: Stats::default(),
            // Zero so the first sample is not itself a change.
            last_logged: Mutex::new(Some((0, 0, 0, 0))),
            denies: Mutex::new(VecDeque::new()),
            pending: Mutex::new(Vec::new()),
            generation: AtomicU64::new(0),
            list_received_at: AtomicU64::new(0),
            list_restored: AtomicBool::new(false),
        }
    }

    fn counters(&self) -> ExecGateCounters {
        ExecGateCounters {
            blocked: self.stats.hit_block.load(Ordering::Relaxed),
            allowed_once: self.stats.allowed_once.load(Ordering::Relaxed),
            trusted: self.stats.trusted.load(Ordering::Relaxed),
            failopen: self.stats.failopen.load(Ordering::Relaxed),
            hashed: self.stats.hashed.load(Ordering::Relaxed),
            cache_hit: self.stats.cache_hit.load(Ordering::Relaxed),
            allowlisted: self.stats.allowlisted.load(Ordering::Relaxed),
            over_cap: self.stats.over_cap.load(Ordering::Relaxed),
            error: self.stats.error.load(Ordering::Relaxed),
            deadline: self.stats.deadline.load(Ordering::Relaxed),
            overflow: self.stats.overflow.load(Ordering::Relaxed),
            marks: self.stats.marks.load(Ordering::Relaxed),
            uncovered: self.stats.uncovered.load(Ordering::Relaxed),
        }
    }

    fn frame(&self, enabled: bool) -> ExecGateFrame {
        let now = now_ms();
        let denies: Vec<ExecGateDeny> = self
            .denies
            .lock()
            .map(|d| d.iter().rev().cloned().collect())
            .unwrap_or_default();
        ExecGateFrame {
            enabled,
            armed: self.on.load(Ordering::Relaxed),
            keys: self.keys.read().map(|k| k.len() as u64).unwrap_or(0),
            source: "live".into(),
            observed_at: now,
            counters: self.counters(),
            denies,
            trusted: self.trusted_rows.read().map(|t| t.clone()).unwrap_or_default(),
            once_pending: self
                .once
                .lock()
                .map(|o| o.live(now).len() as u64)
                .unwrap_or(0),
            list_received_at: self.list_received_at.load(Ordering::Relaxed),
            list_restored: self.list_restored.load(Ordering::Relaxed),
        }
    }

    /// Replace the trusted set from a store and recompute nothing else; the
    /// caller re-commits the key set.
    fn set_trusted(&self, store: &trust::TrustStore) {
        *self.trusted.write().unwrap() = store.digests();
        *self.trusted_rows.write().unwrap() = store.entries().to_vec();
    }
}

/// Keys contributed by deny-list rows.
///
/// A row contributes a key only when its path basename is exactly 64 hex
/// characters and `action` is `block`. A critical `comm` contributes nothing.
/// More than 500 rows leaves `previous` unchanged: a list that large is not
/// applied over the set the gate already has. The fleet path does not use
/// this alone: [`publish_fleet`] sees the org's uncapped row count, because
/// the panel slice is already capped at 500.
fn keys_from_denylist(
    rows: &[DenylistEntry],
    previous: &BTreeSet<[u8; DIGEST_LEN]>,
) -> BTreeSet<[u8; DIGEST_LEN]> {
    if rows.len() > ROW_LIMIT {
        return previous.clone();
    }
    rows.iter().filter_map(row_key).collect()
}

/// Install one fleet list.
///
/// `reported_len` is the org row count before the panel cap. Over
/// [`ROW_LIMIT`] this returns `None` and leaves `fleet`, `keys` and `union`
/// untouched; the caller must not log a key change. `Some(changed)` means the
/// new effective set `(fleet ∪ file) − trusted` is installed.
fn publish_fleet(
    fleet: &mut BTreeSet<[u8; DIGEST_LEN]>,
    file: &BTreeSet<[u8; DIGEST_LEN]>,
    trusted: &BTreeSet<[u8; DIGEST_LEN]>,
    keys: &mut BTreeSet<[u8; DIGEST_LEN]>,
    union: &mut BTreeSet<[u8; DIGEST_LEN]>,
    rows: &[DenylistEntry],
    reported_len: usize,
) -> Option<bool> {
    if reported_len > ROW_LIMIT || rows.len() > ROW_LIMIT {
        return None;
    }
    *fleet = keys_from_denylist(rows, fleet);
    let mut u = fleet.clone();
    u.extend(file.iter().copied());
    let next = trust::subtract(&u, trusted);
    let changed = *keys != next;
    *keys = next;
    *union = u;
    Some(changed)
}

fn row_key(row: &DenylistEntry) -> Option<[u8; DIGEST_LEN]> {
    if CRITICAL_COMMS.iter().any(|c| *c == row.comm) {
        return None;
    }
    if row.action != "block" {
        return None;
    }
    let base = Path::new(&row.path).file_name()?.to_str()?;
    decode_hex(base)
}

/// The org list as it is kept on disk between runs. Only rows that give the
/// gate a key are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct SavedList {
    schema: u32,
    /// The account the list arrived under (`kub0::account_id`). The copy is
    /// loaded only for that account.
    account: String,
    /// When the API last returned this list, ms since the epoch.
    received_at: u64,
    rows: Vec<DenylistEntry>,
}

/// The rows of an org list that give the gate a key.
fn keyed_rows(rows: &[DenylistEntry]) -> Vec<DenylistEntry> {
    rows.iter().filter(|r| row_key(r).is_some()).cloned().collect()
}

/// Why a copy on disk was not loaded.
#[derive(Debug, PartialEq, Eq)]
enum NotLoaded {
    /// The file could not be read this time. It may be a good copy: it stays.
    Unreadable(String),
    /// The file is not a list this gate may load: not this build's shape,
    /// saved under another account, or longer than the gate accepts from the
    /// API. It is removed.
    Refused(String),
}

/// The copy saved under `account`. `Ok(None)` is no file.
fn read_saved(dir: &Path, account: &str) -> Result<Option<SavedList>, NotLoaded> {
    let text = match std::fs::read_to_string(dir.join(trust::ORG_LIST_FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(NotLoaded::Unreadable(e.to_string())),
    };
    let refused = |why: String| Err(NotLoaded::Refused(why));
    let saved: SavedList = match serde_json::from_str(&text) {
        Ok(saved) => saved,
        Err(e) => return refused(format!("not a saved list: {e}")),
    };
    if saved.schema != SAVED_SCHEMA || saved.received_at == 0 {
        return refused(format!("schema {} is not one this build reads", saved.schema));
    }
    if saved.account != account {
        return refused("it was saved under another account".into());
    }
    if saved.rows.len() > ROW_LIMIT {
        return refused(format!("{} rows, over the {ROW_LIMIT} the gate accepts", saved.rows.len()));
    }
    Ok(Some(saved))
}

/// Root-only: the file names the account.
fn write_saved(dir: &Path, saved: &SavedList) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(saved).map_err(std::io::Error::other)?;
    trust::write_atomic(&dir.join(trust::ORG_LIST_FILE), &bytes, 0o600)
}

/// True when no copy is on disk afterwards.
fn remove_saved(dir: &Path) -> bool {
    match std::fs::remove_file(dir.join(trust::ORG_LIST_FILE)) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// What the gate knows about the copy of the org list on disk.
#[derive(Default)]
struct ListBook {
    /// Whose lists the gate is being handed. `None` before the first
    /// `set_account` and after a logout: nothing is saved then.
    account: Option<String>,
    /// The copy on disk: its rows, their keys, and the `received_at` written
    /// with them. `None` when there is no copy this process knows of.
    saved: Option<(Vec<DenylistEntry>, BTreeSet<[u8; DIGEST_LEN]>, u64)>,
}

impl ListBook {
    /// The copy to write after the API returned `rows` at `now`. `None` when
    /// the one on disk has the same keys and is newer than [`SAVE_REFRESH_MS`],
    /// or when no account is known to save it under.
    fn due(&self, rows: &[DenylistEntry], now: u64) -> Option<SavedList> {
        let account = self.account.clone()?;
        let rows = keyed_rows(rows);
        if let Some((_, keys, at)) = &self.saved {
            let same: BTreeSet<[u8; DIGEST_LEN]> = rows.iter().filter_map(row_key).collect();
            if same == *keys && now.saturating_sub(*at) < SAVE_REFRESH_MS {
                return None;
            }
        }
        Some(SavedList {
            schema: SAVED_SCHEMA,
            account,
            received_at: now,
            rows,
        })
    }

    fn wrote(&mut self, saved: SavedList) {
        let keys = saved.rows.iter().filter_map(row_key).collect();
        self.saved = Some((saved.rows, keys, saved.received_at));
    }
}

/// How long ago, for one log line: `45s`, `12m`, `3h 12m`, `2d 5h`.
fn age_text(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h", s / 86_400, s % 86_400 / 3600),
    }
}

thread_local! {
    static HANDED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn note_handed() {
    HANDED.with(|n| n.set(n.get() + 1));
}

/// How many lists the calling thread has handed to [`publish`], counted
/// whether or not a gate is loaded. For the tests of `publish`'s callers:
/// without root no gate loads, so nothing else shows whether a refresh
/// handed the gate a list.
pub fn handed_on_this_thread() -> u64 {
    HANDED.with(|n| n.get())
}

fn parse_deny_file(text: &str) -> BTreeSet<[u8; DIGEST_LEN]> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(key) = decode_hex(line) {
            out.insert(key);
        }
    }
    out
}

/// A `#` comment is either the whole line or a trailing ` # ...`. A digest is
/// only hex, so this does not cut one in half.
fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return "";
    }
    match line.find(" #") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// `(mask, fd, pid)` of each complete version-3 record. A short record stops
/// the walk; a different version is skipped and the walk continues.
fn parse_events(buf: &[u8]) -> Vec<(u64, RawFd, i32)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + METADATA_LEN <= buf.len() {
        let rec = &buf[off..];
        let event_len = u32::from_ne_bytes(rec[0..4].try_into().unwrap()) as usize;
        if event_len < METADATA_LEN || off + event_len > buf.len() {
            break;
        }
        if rec[4] == FANOTIFY_METADATA_VERSION {
            let mask = u64::from_ne_bytes(rec[8..16].try_into().unwrap());
            let fd = i32::from_ne_bytes(rec[16..20].try_into().unwrap());
            let pid = i32::from_ne_bytes(rec[20..24].try_into().unwrap());
            out.push((mask, fd, pid));
        }
        off += event_len;
    }
    out
}

/// A digest that matched a deny-list row, and what was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Matched {
    digest: [u8; DIGEST_LEN],
    decision: ExecGateDecision,
}

/// The answer for one event, plus the match it came from (if any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decision {
    response: u32,
    matched: Option<Matched>,
}

impl Decision {
    const fn allow() -> Self {
        Self {
            response: FAN_ALLOW,
            matched: None,
        }
    }
}

/// Decide one permission event. The fd stays open: the caller writes the
/// response and closes it. Before the first non-empty key set `on` is false
/// and this returns `FAN_ALLOW` without touching a counter. An allow-set hit
/// short-circuits only when the inode's signature still matches the one
/// recorded at start; otherwise the bytes are hashed.
///
/// A digest in the effective set is denied unless a one-shot allow is pending
/// for it. A digest that is on the org list but trusted here is allowed and
/// recorded as such. Every fail-open branch answers `FAN_ALLOW` exactly as
/// before: metadata error, non-file, over cap, read error.
fn decide(shared: &Shared, fd: RawFd) -> Decision {
    if !shared.on.load(Ordering::Relaxed) {
        return Decision::allow();
    }
    // Borrow the kernel's fd. The caller closes it; dropping this File must not.
    let file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => {
            note_error(shared);
            return Decision::allow();
        }
    };
    if !meta.is_file() {
        return Decision::allow();
    }
    let id = (meta.dev(), meta.ino());
    let sig = signature_of(&meta);
    if shared.allow.read().unwrap().get(&id).copied() == Some(sig) {
        shared.stats.allowlisted.fetch_add(1, Ordering::Relaxed);
        return Decision::allow();
    }
    if shared.cap != 0 && meta.size() > shared.cap {
        shared.stats.over_cap.fetch_add(1, Ordering::Relaxed);
        // One line per file, not per exec. The counter moves every time; the
        // stderr line named the path on every exec before, and four toolchain
        // binaries (claude, mise, kubectl, rclone) wrote twenty lines in thirty
        // seconds to one desktop's journal the moment the gate armed.
        let first = {
            let mut logged = shared.over_cap_logged.lock().unwrap();
            if logged.len() >= CACHE_MAX {
                logged.clear();
            }
            logged.insert(id)
        };
        if first {
            let path = fd_path(fd);
            eprintln!(
                "exec gate: over cap: path={path} size={} (allowed unhashed; later execs of this file are counted, not logged)",
                meta.size()
            );
        }
        return Decision::allow();
    }
    let cached = shared
        .cache
        .lock()
        .unwrap()
        .get(&id)
        .and_then(|(s, d)| (*s == sig).then_some(*d));
    let digest = if let Some(d) = cached {
        shared.stats.cache_hit.fetch_add(1, Ordering::Relaxed);
        d
    } else {
        match hash_fd(fd) {
            Ok(d) => {
                shared.stats.hashed.fetch_add(1, Ordering::Relaxed);
                let mut cache = shared.cache.lock().unwrap();
                if cache.len() >= CACHE_MAX {
                    cache.clear();
                }
                cache.insert(id, (sig, d));
                d
            }
            Err(_) => {
                note_error(shared);
                return Decision::allow();
            }
        }
    };
    // The read guard ends with this statement, before any other lock.
    let hit = shared.keys.read().unwrap().contains(&digest);
    if hit {
        let spent = shared.once.lock().unwrap().take(&digest, now_ms());
        if spent {
            shared.stats.allowed_once.fetch_add(1, Ordering::Relaxed);
            return Decision {
                response: FAN_ALLOW,
                matched: Some(Matched {
                    digest,
                    decision: ExecGateDecision::AllowedOnce,
                }),
            };
        }
        shared.stats.hit_block.fetch_add(1, Ordering::Relaxed);
        log_telemetry(shared, false);
        return Decision {
            response: FAN_DENY,
            matched: Some(Matched {
                digest,
                decision: ExecGateDecision::Blocked,
            }),
        };
    }
    // Not in the effective set. If it is on the org list, it is here because
    // the owner trusts it: say so rather than passing silently.
    let trusted = shared.trusted.read().unwrap().contains(&digest);
    if trusted && shared.union.read().unwrap().contains(&digest) {
        shared.stats.trusted.fetch_add(1, Ordering::Relaxed);
        return Decision {
            response: FAN_ALLOW,
            matched: Some(Matched {
                digest,
                decision: ExecGateDecision::AllowedLocalTrust,
            }),
        };
    }
    Decision::allow()
}

fn note_error(shared: &Shared) {
    shared.stats.error.fetch_add(1, Ordering::Relaxed);
    log_telemetry(shared, false);
}

fn fd_path(fd: RawFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Parent pid from `/proc/<pid>/stat`, or 0 when it cannot be read (the
/// process may already be gone, or this is not Linux).
fn ppid_of(pid: i32) -> i32 {
    if pid <= 0 {
        return 0;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    let Some(rparen) = stat.rfind(')') else {
        return 0;
    };
    // After `comm`: state, ppid, ...
    stat[rparen + 1..]
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Record one match: into the ring for the frame, into `pending` for the
/// daemon loop, and one stderr line that names the path (the owner's own
/// machine; nothing here leaves it).
fn record(shared: &Shared, m: Matched, pid: i32, exe: &str) -> ExecGateDeny {
    let meta = shared
        .meta
        .read()
        .ok()
        .and_then(|g| g.get(&m.digest).cloned())
        .unwrap_or_default();
    let deny = ExecGateDeny {
        ts: now_ms(),
        pid,
        ppid: ppid_of(pid),
        comm: basename(exe),
        exe: exe.to_string(),
        sha256: encode_hex(&m.digest),
        reason: meta.reason,
        promoted_by: meta.promoted_by,
        created_at: meta.created_at,
        decision: m.decision,
    };
    {
        let mut ring = shared.denies.lock().unwrap();
        ring.push_back(deny.clone());
        while ring.len() > RECENT_CAP {
            ring.pop_front();
        }
    }
    {
        let mut pending = shared.pending.lock().unwrap();
        if pending.len() >= PENDING_CAP {
            pending.remove(0);
        }
        pending.push(deny.clone());
    }
    shared.generation.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "exec gate: {} {} sha256={} pid={} ppid={}{}",
        match m.decision {
            ExecGateDecision::Blocked => "BLOCKED",
            ExecGateDecision::AllowedLocalTrust => "allowed (trusted here)",
            ExecGateDecision::AllowedOnce => "allowed once",
            ExecGateDecision::AllowedFailopen => "NOT blocked (fail-open)",
        },
        deny.exe,
        deny.sha256,
        deny.pid,
        deny.ppid,
        if deny.reason.is_empty() {
            String::new()
        } else {
            format!(" reason={:?}", deny.reason)
        }
    );
    deny
}

/// sha256 of the whole file from offset 0. `pread` leaves the fd offset alone;
/// the exec'ing process does not share it, and we still don't move it.
fn hash_fd(fd: RawFd) -> std::io::Result<[u8; DIGEST_LEN]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut off: libc::off_t = 0;
    loop {
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), off) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n as usize]);
        off += n as libc::off_t;
    }
    Ok(hasher.finalize().into())
}

fn log_telemetry(shared: &Shared, force: bool) {
    let hit = shared.stats.hit_block.load(Ordering::Relaxed);
    let err = shared.stats.error.load(Ordering::Relaxed);
    let deadline = shared.stats.deadline.load(Ordering::Relaxed);
    let overflow = shared.stats.overflow.load(Ordering::Relaxed);
    {
        let mut last = shared.last_logged.lock().unwrap();
        let cur = (hit, err, deadline, overflow);
        if !force && *last == Some(cur) {
            return;
        }
        *last = Some(cur);
    }
    let keys = shared.keys.read().map(|k| k.len()).unwrap_or(0);
    eprintln!(
        "exec gate: on={} marks={} uncovered={} hashed={} cache_hit={} allowlisted={} over_cap={} error={} deadline={} overflow={} hit_block={} once={} trusted={} failopen={} keys={}",
        shared.on.load(Ordering::Relaxed),
        shared.stats.marks.load(Ordering::Relaxed),
        shared.stats.uncovered.load(Ordering::Relaxed),
        shared.stats.hashed.load(Ordering::Relaxed),
        shared.stats.cache_hit.load(Ordering::Relaxed),
        shared.stats.allowlisted.load(Ordering::Relaxed),
        shared.stats.over_cap.load(Ordering::Relaxed),
        err,
        deadline,
        overflow,
        hit,
        shared.stats.allowed_once.load(Ordering::Relaxed),
        shared.stats.trusted.load(Ordering::Relaxed),
        shared.stats.failopen.load(Ordering::Relaxed),
        keys,
    );
}

/// Debug goes to syslog, not stderr. stderr is the daemon's info stream.
fn log_debug(msg: &str) {
    #[cfg(target_os = "linux")]
    {
        let Ok(c) = std::ffi::CString::new(msg) else {
            return;
        };
        unsafe {
            libc::syslog(
                libc::LOG_DEBUG,
                b"%s\0".as_ptr().cast::<libc::c_char>(),
                c.as_ptr(),
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = msg;
    }
}

fn cap_bytes() -> u64 {
    crate::rename::env("KUB0_EXEC_GATE_CAP_KIB")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CAP_KIB)
        .saturating_mul(1024)
}

fn allow_dirs() -> impl Iterator<Item = &'static str> {
    BIN_DIRS
        .iter()
        .copied()
        .chain(EXTRA_ALLOW_DIRS.iter().copied())
}

fn remember_inode(out: &mut HashMap<(u64, u64), Signature>, path: &str) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.is_file() {
        out.insert((meta.dev(), meta.ino()), signature_of(&meta));
    }
}

/// Critical binaries under `dirs`, plus the same paths seen through pid 1's
/// root so a `ProtectSystem=strict` bind mount still matches the inode the
/// event fd will report. The signature is the one observed here, at start.
fn collect_allow_set<'a>(
    dirs: impl IntoIterator<Item = &'a str>,
) -> HashMap<(u64, u64), Signature> {
    let mut out = HashMap::new();
    for dir in dirs {
        for name in CRITICAL_COMMS {
            remember_inode(&mut out, &format!("{dir}/{name}"));
            remember_inode(&mut out, &format!("/proc/1/root{dir}/{name}"));
        }
    }
    out
}

fn platform_inodes() -> HashMap<(u64, u64), Signature> {
    collect_allow_set(allow_dirs())
}

/// Events the reader has handed off and nobody has answered yet.
///
/// An entry stays until it is answered, so the watchdog can answer while a worker is still hashing.
struct InFlight {
    next: u64,
    events: HashMap<u64, (RawFd, Instant)>,
}

impl InFlight {
    fn new() -> Self {
        Self {
            next: 0,
            events: HashMap::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn enqueue(&mut self, fd: RawFd, at: Instant) -> u64 {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.events.insert(id, (fd, at));
        id
    }

    /// Ids old enough that the watchdog must answer them.
    fn deadline_ids(&self, deadline: Duration) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .events
            .iter()
            .filter(|(_, (_, at))| at.elapsed() > deadline)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Every id still unanswered, oldest-id order.
    fn pending_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.events.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Duplicate the event fd and leave the entry in the map.
    ///
    /// `None` when `id` is already gone or `dup` fails. A failed dup does not
    /// remove the entry, so the watchdog can still answer it.
    fn dup_event(&self, id: u64) -> Option<RawFd> {
        let fd = self.events.get(&id)?.0;
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return None;
        }
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFD) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(dup, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
        Some(dup)
    }

    /// Take `id` if it is still unanswered. A second claim is `None`.
    fn claim(&mut self, id: u64) -> Option<RawFd> {
        self.events.remove(&id).map(|(fd, _)| fd)
    }

    /// Answer `id` if it is still unanswered: run `respond`, then close the fd.
    ///
    /// The first caller wins. The watchdog and the worker both use this. A
    /// later call returns false and does not write or close again.
    fn answer_id(&mut self, id: u64, respond: impl FnOnce(RawFd)) -> bool {
        let Some(fd) = self.claim(id) else {
            return false;
        };
        respond(fd);
        unsafe { libc::close(fd) };
        true
    }
}

/// Claim `id` if it is still unanswered, write `verdict` for the original fd,
/// and close that fd. Always closes `dup_fd`. Returns `(won, written)`: whether
/// this caller claimed the event, and whether the kernel took the response.
/// A deny that was not both won and written did not deny anything.
fn finish_verdict(
    flight: &mut InFlight,
    group: &Mutex<RawFd>,
    shared: &Shared,
    id: u64,
    dup_fd: RawFd,
    verdict: u32,
) -> (bool, bool) {
    let mut written = false;
    let won = flight.answer_id(id, |event_fd| {
        written = write_response(group, event_fd, verdict, shared);
    });
    unsafe { libc::close(dup_fd) };
    (won, written)
}

/// Write one permission response. The group fd lives in this mutex, and
/// [`close_group`] swaps it to `-1` under the same lock, so a close that has
/// already run cannot be followed by a write of the old number.
///
/// `EINTR` is retried. Any other failure or a short write counts `error` once
/// and logs one debug line. After [`close_group`] this writes nothing and
/// counts nothing. The caller still closes the event fd.
fn write_response(group: &Mutex<RawFd>, event_fd: RawFd, response: u32, shared: &Shared) -> bool {
    let g = group.lock().unwrap();
    if *g < 0 {
        return false;
    }
    let mut rec = [0u8; 8];
    rec[0..4].copy_from_slice(&event_fd.to_ne_bytes());
    rec[4..8].copy_from_slice(&response.to_ne_bytes());
    let result = loop {
        let n = unsafe { libc::write(*g, rec.as_ptr().cast(), rec.len()) };
        if n == rec.len() as isize {
            break Ok(());
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break Err(err);
        }
        break Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short response write",
        ));
    };
    drop(g);
    if let Err(err) = result {
        shared.stats.error.fetch_add(1, Ordering::Relaxed);
        log_debug(&format!("exec gate: response write failed: {err}"));
        log_telemetry(shared, false);
        return false;
    }
    true
}

fn close_group(group: &Mutex<RawFd>) {
    let mut g = group.lock().unwrap();
    if *g >= 0 {
        unsafe { libc::close(*g) };
        *g = -1;
    }
}

enum PushResult {
    Queued,
    Full,
    Closed,
}

struct QueueState {
    items: VecDeque<(u64, i32)>,
    closed: bool,
}

/// Bounded handoff from the reader to the workers. The lock is not held
/// while a worker hashes, so the four workers actually run together.
/// Each item is `(event id, pid)`. The fd lives in the in-flight map.
struct Queue {
    inner: Mutex<QueueState>,
    cv: Condvar,
    cap: usize,
}

impl Queue {
    fn new() -> Self {
        Self::with_capacity(QUEUE_CAP)
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Mutex::new(QueueState {
                items: VecDeque::new(),
                closed: false,
            }),
            cv: Condvar::new(),
            cap,
        }
    }

    /// [`PushResult::Full`] when the queue is at its cap. The caller
    /// fail-opens that event instead of blocking the reader. [`PushResult::Closed`]
    /// is shutdown, and is not an overflow.
    fn push(&self, item: (u64, i32)) -> PushResult {
        let mut q = self.inner.lock().unwrap();
        if q.closed {
            return PushResult::Closed;
        }
        if q.items.len() >= self.cap {
            return PushResult::Full;
        }
        q.items.push_back(item);
        self.cv.notify_one();
        PushResult::Queued
    }

    fn pop(&self) -> Option<(u64, i32)> {
        let mut q = self.inner.lock().unwrap();
        loop {
            if let Some(item) = q.items.pop_front() {
                return Some(item);
            }
            if q.closed {
                return None;
            }
            q = self.cv.wait(q).unwrap();
        }
    }

    /// Set `closed` and wake waiters while holding the queue mutex. A worker
    /// that has seen an empty queue but not yet reached `wait` still holds
    /// this mutex, so it cannot sleep through the shutdown.
    fn close(&self) {
        let mut q = self.inner.lock().unwrap();
        q.closed = true;
        self.cv.notify_all();
    }
}

/// Hand an event to a worker, or allow it at once when the queue cannot take it.
fn deliver(
    queue: &Queue,
    flight: &Mutex<InFlight>,
    group: &Mutex<RawFd>,
    shared: &Shared,
    id: u64,
    pid: i32,
) {
    match queue.push((id, pid)) {
        PushResult::Queued => {}
        PushResult::Closed => {
            let mut flight = flight.lock().unwrap();
            flight.answer_id(id, |event_fd| {
                let _ = write_response(group, event_fd, FAN_ALLOW, shared);
            });
        }
        PushResult::Full => {
            shared.stats.overflow.fetch_add(1, Ordering::Relaxed);
            {
                let mut flight = flight.lock().unwrap();
                flight.answer_id(id, |event_fd| {
                    let _ = write_response(group, event_fd, FAN_ALLOW, shared);
                });
            }
            log_telemetry(shared, false);
        }
    }
}

/// Set by the Linux `SIGTERM` handler after the gate has started. The daemon
/// returns from its main loop so shutdown can join the gate threads.
static STOP: AtomicBool = AtomicBool::new(false);

pub fn stop_requested() -> bool {
    STOP.load(Ordering::Acquire)
}

/// `(major:minor, mount point, fstype)` from a mountinfo table. Octal escapes
/// in the mount point are decoded; lines without the ` - ` separator are not
/// mount records.
fn parse_mountinfo(table: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for line in table.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre: Vec<&str> = pre.split(' ').collect();
        let Some(fstype) = post.split_whitespace().next() else {
            continue;
        };
        if pre.len() < 5 {
            continue;
        }
        out.push((pre[2].to_owned(), unescape_octal(pre[4]), fstype.to_owned()));
    }
    out
}

fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The user daemon's view of the system daemon's gate: the state file the
/// system daemon writes under `trust::dir()`, re-read when its mtime moves.
/// Pure over a directory so the tests can point it at a temp dir.
pub mod mirror {
    use super::*;
    use std::time::SystemTime;

    /// Re-read the state file at most this often.
    const CHECK_EVERY: Duration = Duration::from_secs(2);
    /// A frame older than this is `stale`: the system daemon stopped writing.
    const STALE_AFTER_MS: u64 = 90_000;

    pub struct State {
        frame: ExecGateFrame,
        stamp: Option<(SystemTime, u64)>,
        seen: HashSet<(u64, i32, String)>,
        primed: bool,
        last_check: Option<Instant>,
    }

    impl State {
        pub fn new() -> Self {
            Self {
                frame: ExecGateFrame {
                    source: "none".into(),
                    ..Default::default()
                },
                stamp: None,
                seen: HashSet::new(),
                primed: false,
                last_check: None,
            }
        }

        pub fn frame(&self) -> ExecGateFrame {
            self.frame.clone()
        }

        /// Read `dir/state.json` if it changed. Returns the denies not seen
        /// before (oldest first) and whether the frame changed. The first load
        /// primes `seen` without reporting: a user daemon that restarts must
        /// not re-announce denies the owner has already been told about.
        pub fn poll_dir(&mut self, dir: &Path, now: u64) -> Poll {
            let mut out = Poll::default();
            let path = dir.join(trust::STATE_FILE);
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => {
                    if self.frame.source != "none" {
                        self.frame = ExecGateFrame {
                            source: "none".into(),
                            ..Default::default()
                        };
                        self.stamp = None;
                        out.changed = true;
                    }
                    return out;
                }
            };
            let stamp = (meta.modified().unwrap_or(SystemTime::UNIX_EPOCH), meta.len());
            if self.stamp == Some(stamp) {
                // Unchanged bytes can still go stale.
                let stale = now.saturating_sub(self.frame.observed_at) > STALE_AFTER_MS;
                let want = if stale { "stale" } else { "mirror" };
                if self.frame.source != want {
                    self.frame.source = want.into();
                    out.changed = true;
                }
                return out;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                return out;
            };
            let Ok(mut frame) = serde_json::from_str::<ExecGateFrame>(&text) else {
                return out;
            };
            self.stamp = Some(stamp);
            let stale = now.saturating_sub(frame.observed_at) > STALE_AFTER_MS;
            frame.source = if stale { "stale" } else { "mirror" }.into();
            // Oldest first for the activity feed.
            for d in frame.denies.iter().rev() {
                let key = (d.ts, d.pid, d.sha256.clone());
                if self.seen.insert(key) && self.primed {
                    out.events.push(d.clone());
                }
            }
            if self.seen.len() > 4 * RECENT_CAP {
                let keep: HashSet<_> = frame
                    .denies
                    .iter()
                    .map(|d| (d.ts, d.pid, d.sha256.clone()))
                    .collect();
                self.seen = keep;
            }
            self.primed = true;
            out.changed = frame != self.frame;
            self.frame = frame;
            out
        }

        /// `poll_dir` on `trust::dir()`, rate-limited.
        pub fn poll(&mut self) -> Poll {
            let now = Instant::now();
            if let Some(last) = self.last_check {
                if now.duration_since(last) < CHECK_EVERY {
                    return Poll::default();
                }
            }
            self.last_check = Some(now);
            self.poll_dir(&trust::dir(), now_ms())
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new()
        }
    }

    static MIRROR: Mutex<Option<State>> = Mutex::new(None);

    pub fn frame() -> ExecGateFrame {
        MIRROR
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.frame()))
            .unwrap_or_else(|| State::new().frame())
    }

    pub fn poll() -> Poll {
        let mut g = MIRROR.lock().unwrap();
        g.get_or_insert_with(State::new).poll()
    }
}

#[cfg(not(target_os = "linux"))]
pub fn start(_account: Option<&str>) {}

#[cfg(not(target_os = "linux"))]
pub fn set_account(_account: &str) {}

#[cfg(not(target_os = "linux"))]
pub fn publish(_rows: &[DenylistEntry], _reported_len: usize) {
    note_handed();
}

#[cfg(not(target_os = "linux"))]
pub fn clear_fleet() {}

#[cfg(not(target_os = "linux"))]
pub fn shutdown() {}

#[cfg(not(target_os = "linux"))]
pub fn frame() -> ExecGateFrame {
    mirror::frame()
}

#[cfg(not(target_os = "linux"))]
pub fn poll() -> Poll {
    mirror::poll()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::sync::{Arc, OnceLock};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const ANSWER_DEADLINE: Duration = Duration::from_secs(3);
    /// The state file is rewritten at least this often while nothing changes,
    /// so the mirror's staleness check has something to read.
    const STATE_REFRESH: Duration = Duration::from_secs(30);

    struct Sources {
        fleet: BTreeSet<[u8; DIGEST_LEN]>,
        file: BTreeSet<[u8; DIGEST_LEN]>,
    }

    struct MountBook {
        marked: HashSet<String>,
        uncovered: HashSet<String>,
    }

    struct Live {
        shared: Arc<Shared>,
        group: Mutex<RawFd>,
        in_flight: Mutex<InFlight>,
        sources: Mutex<Sources>,
        mounts: Mutex<MountBook>,
        queue: Queue,
        closing: AtomicBool,
        shutdown_started: AtomicBool,
        reader: Mutex<Option<JoinHandle<()>>>,
        rescan: Mutex<Option<JoinHandle<()>>>,
        watchdog: Mutex<Option<JoinHandle<()>>>,
        store: Mutex<Option<JoinHandle<()>>>,
        republish: AtomicU64,
        over_limit_logged: AtomicBool,
        file_err_logged: AtomicBool,
        mountinfo_logged: AtomicBool,
        save_err_logged: AtomicBool,
        /// The copy of the org list on disk. Held across a restore and across
        /// a publish's key install, so one cannot overwrite the other's keys.
        list: Mutex<ListBook>,
        dir: std::path::PathBuf,
        trust: Mutex<trust::TrustStore>,
        /// Generation the daemon loop last saw, and when the state file was
        /// last written.
        polled_gen: AtomicU64,
        state_written: Mutex<Option<(u64, Instant)>>,
    }

    static GATE: OnceLock<Arc<Live>> = OnceLock::new();

    /// `account` is the account on disk when the daemon starts, if one reads
    /// (`kub0::account_id`). With one, the org list saved under it arms the
    /// gate now; without one the gate waits for its first list.
    pub fn start(account: Option<&str>) {
        if GATE.get().is_some() {
            return;
        }
        match load() {
            Err(reason) => eprintln!("exec gate NOT loaded: {reason}"),
            Ok(()) => {
                if let Some(account) = account {
                    set_account(account);
                }
                let armed = GATE
                    .get()
                    .map(|l| l.shared.on.load(Ordering::Relaxed))
                    .unwrap_or(false);
                if !armed {
                    eprintln!("exec gate loaded, idle until the first deny-list sync");
                }
            }
        }
    }

    /// Say whose org lists the gate is being handed from here on. Calling it
    /// again with the same account does nothing. For a new account:
    ///
    /// - An org list the gate holds arrived under another account (or under
    ///   none it was told of). Its keys come out now, not when the new
    ///   account's first list arrives: that list may never come.
    /// - The copy saved under the new account, if there is one, is loaded, so
    ///   a restarted daemon is armed before its first sync.
    /// - A copy this gate may not load (another account's, another build's)
    ///   is removed. One that only failed to read stays for the next start.
    pub fn set_account(account: &str) {
        if let Some(live) = GATE.get() {
            set_account_on(live, account);
        }
    }

    fn set_account_on(live: &Live, account: &str) {
        let mut book = live.list.lock().unwrap();
        if book.account.as_deref() == Some(account) {
            return;
        }
        book.account = Some(account.to_string());
        book.saved = None;
        let held = live.shared.list_received_at.swap(0, Ordering::Relaxed) != 0;
        live.shared.list_restored.store(false, Ordering::Relaxed);
        let saved = match read_saved(&live.dir, account) {
            Ok(saved) => saved,
            Err(NotLoaded::Unreadable(why)) => {
                eprintln!("exec gate: the saved org list could not be read ({why}); starting without it");
                None
            }
            Err(NotLoaded::Refused(why)) => {
                eprintln!("exec gate: the saved org list is not used: {why}");
                remove_saved(&live.dir);
                None
            }
        };
        let mut fleet = BTreeSet::new();
        if let Some(saved) = saved {
            fleet = keys_from_denylist(&saved.rows, &BTreeSet::new());
            {
                let mut meta = live.shared.meta.write().unwrap();
                for row in &saved.rows {
                    if let Some(key) = row_key(row) {
                        meta.insert(key, RowMeta::from_row(row));
                    }
                }
            }
            eprintln!(
                "exec gate: {} key(s) from the org list saved {} ago; the first sync replaces it",
                fleet.len(),
                age_text(now_ms().saturating_sub(saved.received_at))
            );
            live.shared.list_received_at.store(saved.received_at, Ordering::Relaxed);
            live.shared.list_restored.store(true, Ordering::Relaxed);
            book.wrote(saved);
        } else if held {
            eprintln!("exec gate: the org list held was another account's; its keys are out");
        }
        let changed = commit(live, |src| src.fleet = fleet);
        drop(book);
        after_commit(live, changed);
        live.shared.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn shutdown() {
        let Some(live) = GATE.get() else {
            return;
        };
        if live.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        live.closing.store(true, Ordering::Release);
        // Reader and rescan wake within 500ms. The watchdog then allows what
        // is still in the map. One shared bound, in that order, so a stuck
        // thread cannot add three waits together.
        let deadline = Instant::now() + Duration::from_secs(2);
        join_by(live.reader.lock().unwrap().take(), deadline);
        join_by(live.rescan.lock().unwrap().take(), deadline);
        join_by(live.store.lock().unwrap().take(), deadline);
        join_by(live.watchdog.lock().unwrap().take(), deadline);
        close_group(&live.group);
        live.queue.close();
        live.shared.on.store(false, Ordering::Relaxed);
        save_last_sync(live);
        // The panel's mirror reads this: off, not stale.
        write_state(live, false);
        eprintln!("exec gate: stopped");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }

    /// Join `handle` if it finishes before `deadline`. Past the deadline the
    /// handle is detached so shutdown can close the group fd anyway.
    fn join_by(handle: Option<JoinHandle<()>>, deadline: Instant) {
        let Some(handle) = handle else {
            return;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        if std::thread::Builder::new()
            .name("execgate-join".into())
            .spawn(move || {
                let _ = handle.join();
                let _ = tx.send(());
            })
            .is_err()
        {
            return;
        }
        let _ = rx.recv_timeout(left);
    }

    /// `reported_len` is the org list before the panel cap. Over [`ROW_LIMIT`]
    /// the previous key set stays, and this does not log a key change.
    ///
    /// The caller hands over only what the kub0 API returned: this list
    /// replaces the gate's keys, including the ones a start loaded from disk.
    pub fn publish(rows: &[DenylistEntry], reported_len: usize) {
        note_handed();
        if let Some(live) = GATE.get() {
            publish_on(live, rows, reported_len);
        }
    }

    fn publish_on(live: &Live, rows: &[DenylistEntry], reported_len: usize) {
        let mut book = live.list.lock().unwrap();
        let changed = {
            let mut src = live.sources.lock().unwrap();
            let file = src.file.clone();
            let trusted = live.shared.trusted.read().unwrap().clone();
            let mut keys = live.shared.keys.write().unwrap();
            let mut union = live.shared.union.write().unwrap();
            publish_fleet(
                &mut src.fleet,
                &file,
                &trusted,
                &mut keys,
                &mut union,
                rows,
                reported_len,
            )
        };
        let Some(changed) = changed else {
            if !live.over_limit_logged.swap(true, Ordering::Relaxed) {
                eprintln!("exec gate: deny list over 500 rows, keeping current keys");
            }
            return;
        };
        let now = now_ms();
        live.shared.list_received_at.store(now, Ordering::Relaxed);
        if live.shared.list_restored.swap(false, Ordering::Relaxed) {
            eprintln!("exec gate: first sync since the start; the saved org list is replaced");
            live.shared.generation.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(saved) = book.due(rows, now) {
            save(live, &mut book, saved);
        }
        drop(book);
        {
            let mut meta = live.shared.meta.write().unwrap();
            for row in rows {
                if let Some(key) = row_key(row) {
                    meta.insert(key, RowMeta::from_row(row));
                }
            }
        }
        after_commit(live, changed);
        let nrep = live.republish.fetch_add(1, Ordering::Relaxed) + 1;
        log_telemetry(&live.shared, nrep % 10 == 0);
    }

    /// A local disconnect: the org's keys come out, and so does the copy of
    /// its list on disk (no account, no org list: a later start must not arm
    /// from it). A deny file keeps its own.
    pub fn clear_fleet() {
        if let Some(live) = GATE.get() {
            clear_fleet_on(live);
        }
    }

    fn clear_fleet_on(live: &Live) {
        let mut book = live.list.lock().unwrap();
        *book = ListBook::default();
        let _ = remove_saved(&live.dir);
        let held = live.shared.list_received_at.swap(0, Ordering::Relaxed) != 0;
        live.shared.list_restored.store(false, Ordering::Relaxed);
        let had = !live.sources.lock().unwrap().fleet.is_empty();
        let changed = commit(live, |src| src.fleet.clear());
        drop(book);
        if had {
            eprintln!("exec gate: fleet keys cleared (disconnected)");
        }
        after_commit(live, changed);
        if held && !changed {
            live.shared.generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Write `saved` and note it in the book. A failure is logged once until
    /// a write works again, and the next list from the API tries again; the
    /// gate keeps running on the keys it has.
    fn save(live: &Live, book: &mut ListBook, saved: SavedList) {
        match write_saved(&live.dir, &saved) {
            Ok(()) => {
                live.save_err_logged.store(false, Ordering::Relaxed);
                book.wrote(saved);
            }
            Err(e) => {
                // Whatever is on disk is an older list. A start must not load
                // it in place of this one, and the last-sync time written on
                // the way out must not be stamped on it.
                book.saved = None;
                let gone = remove_saved(&live.dir);
                if !live.save_err_logged.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "exec gate: the org list was not saved ({e}); {}",
                        if gone {
                            "a restart starts without it"
                        } else {
                            "an older copy is still on disk and a restart loads that one"
                        }
                    );
                }
            }
        }
    }

    /// On the way out: the copy on disk can be up to [`SAVE_REFRESH_MS`]
    /// behind the last sync. Write that time, so the age the next start
    /// reports is the real one.
    fn save_last_sync(live: &Live) {
        let mut book = live.list.lock().unwrap();
        let at = live.shared.list_received_at.load(Ordering::Relaxed);
        if live.shared.list_restored.load(Ordering::Relaxed) {
            return;
        }
        let (Some(account), Some((rows, _, saved_at))) = (book.account.clone(), book.saved.clone())
        else {
            return;
        };
        if at <= saved_at {
            return;
        }
        let saved = SavedList {
            schema: SAVED_SCHEMA,
            account,
            received_at: at,
            rows,
        };
        save(live, &mut book, saved);
    }

    pub fn frame() -> ExecGateFrame {
        match GATE.get() {
            Some(live) => live.shared.frame(group_fd(&live.group) >= 0),
            None => mirror::frame(),
        }
    }

    /// The daemon loop's hook: new matches for the activity feed, whether the
    /// frame changed, and the state file for the panel's mirror.
    pub fn poll() -> Poll {
        let Some(live) = GATE.get() else {
            return mirror::poll();
        };
        let gen = live.shared.generation.load(Ordering::Relaxed);
        let changed = live.polled_gen.swap(gen, Ordering::Relaxed) != gen;
        let events = std::mem::take(&mut *live.shared.pending.lock().unwrap());
        let due = {
            let written = live.state_written.lock().unwrap();
            match *written {
                None => true,
                Some((g, at)) => g != gen || at.elapsed() >= STATE_REFRESH,
            }
        };
        if due {
            write_state(live, group_fd(&live.group) >= 0);
        }
        Poll { events, changed }
    }

    fn write_state(live: &Live, enabled: bool) {
        let frame = live.shared.frame(enabled);
        let gen = live.shared.generation.load(Ordering::Relaxed);
        match serde_json::to_vec(&frame) {
            Ok(bytes) => {
                if let Err(e) = trust::write_atomic(&live.dir.join(trust::STATE_FILE), &bytes, trust::STATE_FILE_MODE) {
                    log_debug(&format!("exec gate: state file not written: {e}"));
                }
            }
            Err(e) => log_debug(&format!("exec gate: state frame not encoded: {e}")),
        }
        *live.state_written.lock().unwrap() = Some((gen, Instant::now()));
    }

    /// Hold the source sets and the key-set write together so a file reload
    /// and a publish cannot each install a union that dropped the other's update.
    fn commit(live: &Live, mutate: impl FnOnce(&mut Sources)) -> bool {
        let mut src = live.sources.lock().unwrap();
        mutate(&mut src);
        let mut u = src.fleet.clone();
        u.extend(src.file.iter().copied());
        let trusted = live.shared.trusted.read().unwrap().clone();
        let next = trust::subtract(&u, &trusted);
        let mut keys = live.shared.keys.write().unwrap();
        let mut union = live.shared.union.write().unwrap();
        let changed = *keys != next;
        *keys = next;
        *union = u;
        changed
    }

    /// Arm or disarm on the key count, log a change, and bump the generation.
    /// The gate hashes only while the effective set is non-empty.
    fn after_commit(live: &Live, changed: bool) {
        let n = live.shared.keys.read().map(|k| k.len()).unwrap_or(0);
        let on = live.shared.on.load(Ordering::Relaxed);
        if n > 0 && !on {
            if arm(live) {
                eprintln!("exec gate ON: {n} keys");
            }
        } else if n == 0 && on {
            disarm(live);
            eprintln!("exec gate idle: no keys, filesystems unmarked");
        } else if changed && on {
            eprintln!("exec gate: {n} keys");
        }
        if changed {
            live.shared.generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Mark the filesystems and start hashing. False, and still off, when no
    /// filesystem could be marked: the gate then denies nothing.
    fn arm(live: &Live) -> bool {
        if let Err(e) = rescan(live, true) {
            eprintln!("exec gate NOT armed (fail-open): {e}");
            return false;
        }
        if live.shared.stats.marks.load(Ordering::Relaxed) == 0 {
            eprintln!("exec gate NOT armed (fail-open): no filesystem could be marked");
            return false;
        }
        live.shared.on.store(true, Ordering::Relaxed);
        true
    }

    /// Flush every filesystem mark and stop hashing. Events already queued are
    /// answered allow by the workers (`on` is false).
    fn disarm(live: &Live) {
        live.shared.on.store(false, Ordering::Relaxed);
        let group = group_fd(&live.group);
        if group >= 0 {
            let rc = unsafe {
                libc::fanotify_mark(
                    group,
                    libc::FAN_MARK_FLUSH | libc::FAN_MARK_FILESYSTEM,
                    0,
                    libc::AT_FDCWD,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                log_debug(&format!(
                    "exec gate: mark flush failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let mut book = live.mounts.lock().unwrap();
        book.marked.clear();
        book.uncovered.clear();
        live.shared.stats.marks.store(0, Ordering::Relaxed);
        live.shared.stats.uncovered.store(0, Ordering::Relaxed);
    }

    /// The gate's state for one fanotify group, with the owner's trust store
    /// and one-shot allows read from `dir`. No thread is started and nothing
    /// is marked here.
    fn new_live(group: RawFd, dir: std::path::PathBuf) -> Arc<Live> {
        let now = now_ms();
        let trust_store = trust::TrustStore::load(&dir);
        let once = OnceStore::load(&dir, now);
        let shared = Arc::new(Shared::new(cap_bytes(), platform_inodes()));
        shared.set_trusted(&trust_store);
        *shared.once.lock().unwrap() = once;
        if !trust_store.is_empty() {
            eprintln!(
                "exec gate: {} trusted digest(s) from {}",
                trust_store.len(),
                dir.join(trust::TRUSTED_FILE).display()
            );
        }
        Arc::new(Live {
            shared,
            group: Mutex::new(group),
            in_flight: Mutex::new(InFlight::new()),
            sources: Mutex::new(Sources {
                fleet: BTreeSet::new(),
                file: BTreeSet::new(),
            }),
            mounts: Mutex::new(MountBook {
                marked: HashSet::new(),
                uncovered: HashSet::new(),
            }),
            queue: Queue::new(),
            closing: AtomicBool::new(false),
            shutdown_started: AtomicBool::new(false),
            reader: Mutex::new(None),
            rescan: Mutex::new(None),
            watchdog: Mutex::new(None),
            store: Mutex::new(None),
            republish: AtomicU64::new(0),
            over_limit_logged: AtomicBool::new(false),
            file_err_logged: AtomicBool::new(false),
            mountinfo_logged: AtomicBool::new(false),
            save_err_logged: AtomicBool::new(false),
            list: Mutex::new(ListBook::default()),
            dir,
            trust: Mutex::new(trust_store),
            polled_gen: AtomicU64::new(0),
            state_written: Mutex::new(None),
        })
    }

    fn load() -> Result<(), String> {
        let group = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_UNLIMITED_QUEUE,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if group < 0 {
            return Err(format!(
                "fanotify_init: {}",
                std::io::Error::last_os_error()
            ));
        }
        let live = new_live(group, trust::dir());
        // Mountinfo must be readable for the gate to ever arm. Checked here so
        // a confined unit fails loudly at start instead of at the first key.
        if let Err(e) = std::fs::read_to_string("/proc/1/mountinfo") {
            close_group(&live.group);
            return Err(format!("no filesystem could be marked: {e}"));
        }
        let mut workers_ok = true;
        for _ in 0..WORKERS {
            let live2 = Arc::clone(&live);
            if std::thread::Builder::new()
                .name("execgate-worker".into())
                .spawn(move || worker(live2))
                .is_err()
            {
                workers_ok = false;
                break;
            }
        }
        let reader = workers_ok.then(|| {
            let live2 = Arc::clone(&live);
            std::thread::Builder::new()
                .name("execgate-read".into())
                .spawn(move || reader(live2))
                .ok()
        });
        let reader = reader.flatten();
        let watchdog = reader.is_some().then(|| {
            let live2 = Arc::clone(&live);
            std::thread::Builder::new()
                .name("execgate-watchdog".into())
                .spawn(move || watchdog(live2))
                .ok()
        });
        let watchdog = watchdog.flatten();
        let rescan = watchdog.is_some().then(|| {
            let live2 = Arc::clone(&live);
            std::thread::Builder::new()
                .name("execgate-mounts".into())
                .spawn(move || mount_loop(live2))
                .ok()
        });
        let rescan = rescan.flatten();
        let store = rescan.is_some().then(|| {
            let live2 = Arc::clone(&live);
            std::thread::Builder::new()
                .name("execgate-store".into())
                .spawn(move || store_loop(live2))
                .ok()
        });
        let store = store.flatten();
        if reader.is_none() || watchdog.is_none() || rescan.is_none() || store.is_none() {
            close_group(&live.group);
            live.queue.close();
            return Err("exec gate thread did not start".into());
        }
        *live.reader.lock().unwrap() = reader;
        *live.watchdog.lock().unwrap() = watchdog;
        *live.rescan.lock().unwrap() = rescan;
        *live.store.lock().unwrap() = store;
        if let Some(path) = deny_file_path() {
            if let Some(set) = read_deny_file(&live, &path) {
                // Root self-test: the file is a list. A non-empty one arms the
                // gate without waiting for a fleet publish the machine may
                // never make.
                let changed = commit(&live, |src| src.file = set);
                after_commit(&live, changed);
            }
            let live2 = Arc::clone(&live);
            if std::thread::Builder::new()
                .name("execgate-denyfile".into())
                .spawn(move || file_loop(live2, path))
                .is_err()
            {
                close_group(&live.group);
                live.queue.close();
                return Err("deny-file thread did not start".into());
            }
        }
        let _ = GATE.set(live);
        arm_stop_on_sigterm();
        Ok(())
    }

    fn arm_stop_on_sigterm() {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_sigterm as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) != 0 {
                eprintln!(
                    "exec gate: SIGTERM handler was not installed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    extern "C" fn on_sigterm(_sig: libc::c_int) {
        STOP.store(true, Ordering::Release);
    }

    fn deny_file_path() -> Option<String> {
        crate::rename::env("KUB0_EXEC_GATE_DENY_FILE")
            .filter(|s| !s.is_empty())
    }

    fn group_fd(group: &Mutex<RawFd>) -> RawFd {
        *group.lock().unwrap()
    }

    fn file_loop(live: Arc<Live>, path: String) {
        loop {
            std::thread::sleep(Duration::from_secs(60));
            if live.closing.load(Ordering::Acquire) || group_fd(&live.group) < 0 {
                return;
            }
            let Some(set) = read_deny_file(&live, &path) else {
                continue;
            };
            let changed = commit(&live, |src| src.file = set);
            after_commit(&live, changed);
        }
    }

    fn read_deny_file(live: &Live, path: &str) -> Option<BTreeSet<[u8; DIGEST_LEN]>> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                live.file_err_logged.store(false, Ordering::Relaxed);
                Some(parse_deny_file(&text))
            }
            Err(e) => {
                if !live.file_err_logged.swap(true, Ordering::Relaxed) {
                    eprintln!("exec gate: deny file unreadable: {path}: {e}");
                }
                None
            }
        }
    }

    /// Consume the helper's requests and apply them to the owner's stores.
    /// Every 500 ms: an "Allow once" click must beat the owner's re-run.
    fn store_loop(live: Arc<Live>) {
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if live.closing.load(Ordering::Acquire) || group_fd(&live.group) < 0 {
                return;
            }
            let requests = match trust::take_requests(&live.dir) {
                Ok(r) => r,
                Err(e) => {
                    log_debug(&format!("exec gate: requests unreadable: {e}"));
                    continue;
                }
            };
            if requests.is_empty() {
                let now = now_ms();
                let mut once = live.shared.once.lock().unwrap();
                let before = once.live(now).len();
                once.prune(now);
                let after = once.live(now).len();
                drop(once);
                if before != after {
                    live.shared.generation.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            let now = now_ms();
            let mut trust_changed = false;
            for req in requests {
                let outcome: Result<String, String> = match req.op.as_str() {
                    "trust" => {
                        let (comm, exe) = last_match_for(&live.shared, &req.sha256);
                        let mut store = live.trust.lock().unwrap();
                        store
                            .add(&req.sha256, &comm, &exe, &req.note, now)
                            .map(|added| {
                                trust_changed |= added;
                                if added { "trusted" } else { "already trusted" }.to_string()
                            })
                    }
                    "untrust" => {
                        let mut store = live.trust.lock().unwrap();
                        store.remove(&req.sha256).map(|removed| {
                            trust_changed |= removed;
                            if removed { "untrusted" } else { "was not trusted" }.to_string()
                        })
                    }
                    "allow_once" => live
                        .shared
                        .once
                        .lock()
                        .unwrap()
                        .grant(&req.sha256, now)
                        .map(|exp| format!("allowed once until {exp}")),
                    other => Err(format!("unknown op {other}")),
                };
                match outcome {
                    Ok(what) => {
                        eprintln!("exec gate: {} {} (uid {})", req.sha256, what, req.uid);
                        live.shared.generation.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => eprintln!("exec gate: request {} {} refused: {e}", req.op, req.sha256),
                }
            }
            if trust_changed {
                {
                    let store = live.trust.lock().unwrap();
                    live.shared.set_trusted(&store);
                }
                let changed = commit(&live, |_| {});
                after_commit(&live, changed);
                live.shared.generation.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// `(comm, exe)` of the newest recorded match for `sha256`, so a trust
    /// granted from a notification names the file it was granted for.
    fn last_match_for(shared: &Shared, sha256: &str) -> (String, String) {
        shared
            .denies
            .lock()
            .ok()
            .and_then(|ring| {
                ring.iter()
                    .rev()
                    .find(|d| d.sha256 == sha256)
                    .map(|d| (d.comm.clone(), d.exe.clone()))
            })
            .unwrap_or_default()
    }

    fn mount_loop(live: Arc<Live>) {
        // The rescan itself stays on a 5s cadence. The flag is checked at
        // least every 500ms so shutdown can join this thread.
        loop {
            for _ in 0..10 {
                if live.closing.load(Ordering::Acquire) || group_fd(&live.group) < 0 {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if live.closing.load(Ordering::Acquire) || group_fd(&live.group) < 0 {
                return;
            }
            // Idle means unmarked: a mount that appears now is marked when
            // the gate next arms.
            if live.shared.on.load(Ordering::Relaxed) {
                let _ = rescan(&live, false);
            }
        }
    }

    fn rescan(live: &Live, initial: bool) -> Result<(), String> {
        let table = match std::fs::read_to_string("/proc/1/mountinfo") {
            Ok(t) => {
                live.mountinfo_logged.store(false, Ordering::Relaxed);
                t
            }
            Err(e) if initial => {
                return Err(format!("no filesystem could be marked: {e}"));
            }
            Err(e) => {
                if !live.mountinfo_logged.swap(true, Ordering::Relaxed) {
                    eprintln!("exec gate: mountinfo unreadable: {e}");
                }
                return Ok(());
            }
        };
        let group = group_fd(&live.group);
        if group < 0 {
            return Ok(());
        }
        let mut book = live.mounts.lock().unwrap();
        for (dev, mountpoint, fstype) in parse_mountinfo(&table) {
            if !MARK_FS.iter().any(|fs| *fs == fstype) {
                continue;
            }
            if book.marked.contains(&dev) || book.uncovered.contains(&dev) {
                continue;
            }
            let path = format!("/proc/1/root{mountpoint}");
            match mark_one(group, &path) {
                Ok(()) => {
                    book.marked.insert(dev);
                    live.shared.stats.marks.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    // Once per superblock. A later rescan does not try again and
                    // does not log again. EXDEV, ENODEV, and anything else are
                    // the same: uncovered, and the gate keeps going.
                    book.uncovered.insert(dev.clone());
                    live.shared.stats.uncovered.fetch_add(1, Ordering::Relaxed);
                    log_debug(&format!(
                        "exec gate: superblock {dev} ({fstype}) not marked: {err}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn mark_one(group: RawFd, path: &str) -> std::io::Result<()> {
        let cpath = CString::new(path).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mount path contains a nul",
            )
        })?;
        let rc = unsafe {
            libc::fanotify_mark(
                group,
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                cpath.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn reader(live: Arc<Live>) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if live.closing.load(Ordering::Acquire) {
                return;
            }
            let group = group_fd(&live.group);
            if group < 0 {
                live.queue.close();
                return;
            }
            let mut pfd = libc::pollfd {
                fd: group,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 500) };
            if live.closing.load(Ordering::Acquire) {
                return;
            }
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                eprintln!("exec gate: read failed, the gate stops (fail-open): {err}");
                close_group(&live.group);
                live.queue.close();
                return;
            }
            if rc == 0 {
                continue;
            }
            if pfd.revents & libc::POLLNVAL != 0 {
                if !live.closing.load(Ordering::Acquire) {
                    eprintln!("exec gate: read failed, the gate stops (fail-open): bad group fd");
                    close_group(&live.group);
                    live.queue.close();
                }
                return;
            }
            if pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
                continue;
            }
            let n = unsafe { libc::read(group, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                eprintln!("exec gate: read failed, the gate stops (fail-open): {err}");
                close_group(&live.group);
                live.queue.close();
                return;
            }
            if n == 0 {
                continue;
            }
            for (mask, fd, pid) in parse_events(&buf[..n as usize]) {
                if fd < 0 {
                    continue;
                }
                if (mask & OPEN_EXEC_PERM) == 0 {
                    unsafe { libc::close(fd) };
                    continue;
                }
                let id = live.in_flight.lock().unwrap().enqueue(fd, Instant::now());
                deliver(
                    &live.queue,
                    &live.in_flight,
                    &live.group,
                    &live.shared,
                    id,
                    pid,
                );
            }
        }
    }

    fn worker(live: Arc<Live>) {
        let me = std::process::id() as i32;
        while let Some((id, pid)) = live.queue.pop() {
            // The original stays in the map. A deadline can allow it while
            // this read is still running; the late verdict then loses the claim.
            let dup_fd = {
                let flight = live.in_flight.lock().unwrap();
                flight.dup_event(id)
            };
            let Some(dup_fd) = dup_fd else {
                continue;
            };
            let decision = if pid == me || !live.shared.on.load(Ordering::Relaxed) {
                Decision::allow()
            } else {
                decide(&live.shared, dup_fd)
            };
            // The path is read while the dup is still open; finish_verdict closes it.
            let exe = if decision.matched.is_some() {
                fd_path(dup_fd)
            } else {
                String::new()
            };
            let (won, written) = {
                let mut flight = live.in_flight.lock().unwrap();
                finish_verdict(
                    &mut flight,
                    &live.group,
                    &live.shared,
                    id,
                    dup_fd,
                    decision.response,
                )
            };
            if let Some(mut m) = decision.matched {
                if decision.response == FAN_DENY && !(won && written) {
                    // The watchdog allowed it first, or the kernel did not
                    // take the deny: the file ran. Say so.
                    live.shared.stats.failopen.fetch_add(1, Ordering::Relaxed);
                    m.decision = ExecGateDecision::AllowedFailopen;
                }
                record(&live.shared, m, pid, &exe);
            }
        }
    }

    fn allow_ids(live: &Live, ids: Vec<u64>, count_deadline: bool) -> u32 {
        let mut answered = 0u32;
        for id in ids {
            let mut did = false;
            {
                let mut flight = live.in_flight.lock().unwrap();
                flight.answer_id(id, |fd| {
                    if write_response(&live.group, fd, FAN_ALLOW, &live.shared) && count_deadline {
                        live.shared.stats.deadline.fetch_add(1, Ordering::Relaxed);
                        did = true;
                    }
                });
            }
            if did {
                answered += 1;
            }
        }
        if answered > 0 {
            log_telemetry(&live.shared, false);
        }
        answered
    }

    fn watchdog(live: Arc<Live>) {
        loop {
            if live.closing.load(Ordering::Acquire) {
                let late = live.in_flight.lock().unwrap().deadline_ids(ANSWER_DEADLINE);
                allow_ids(&live, late, true);
                let rest = live.in_flight.lock().unwrap().pending_ids();
                allow_ids(&live, rest, false);
                if live.in_flight.lock().unwrap().is_empty() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            std::thread::sleep(Duration::from_millis(250));
            if live.closing.load(Ordering::Acquire) {
                continue;
            }
            if group_fd(&live.group) < 0 && live.in_flight.lock().unwrap().is_empty() {
                return;
            }
            let late = live.in_flight.lock().unwrap().deadline_ids(ANSWER_DEADLINE);
            allow_ids(&live, late, true);
        }
    }

    /// The saved org list across a "restart": two `Live`s over one directory.
    /// The group fd is -1, so nothing is marked and `on` stays false; what is
    /// under test is which keys the gate holds and what it tells the frame.
    #[cfg(test)]
    mod tests {
        use super::super::tests::{keyed, row, Tmp, ACCOUNT, HEX, HEX_B};
        use super::*;

        fn keys(live: &Live) -> usize {
            live.shared.keys.read().unwrap().len()
        }

        fn saved_file(tmp: &Tmp) -> std::path::PathBuf {
            tmp.path(trust::ORG_LIST_FILE)
        }

        /// One run that received `rows` from the API under `ACCOUNT`.
        fn a_run_that_synced(tmp: &Tmp, rows: &[DenylistEntry]) -> Arc<Live> {
            let live = new_live(-1, tmp.dir.clone());
            set_account_on(&live, ACCOUNT);
            publish_on(&live, rows, rows.len());
            live
        }

        /// #86. A daemon that restarted while the kub0 API was unreachable came
        /// up with no org keys and stayed that way until the API answered: on
        /// 2026-11-17 a host ran 0 keys for the length of an outage, and every
        /// boot ran 0 keys until the network was up.
        #[test]
        fn a_restarted_gate_holds_the_saved_keys_before_any_sync() {
            let tmp = Tmp::new();
            let monitor = row("x", &format!("/workspace/{HEX_B}"), "monitor");
            let first = a_run_that_synced(
                &tmp,
                &[keyed(HEX, "vigiles-auto"), keyed(HEX_B, "api"), monitor],
            );
            assert_eq!(keys(&first), 2);
            let synced = first.shared.frame(true);
            assert!(synced.list_received_at > 0);
            assert!(!synced.list_restored);

            // The same directory, a new process, and no list from the API yet.
            let second = new_live(-1, tmp.dir.clone());
            assert_eq!(keys(&second), 0);
            set_account_on(&second, ACCOUNT);
            assert_eq!(keys(&second), 2, "the org's keys must not wait for a sync");
            let frame = second.shared.frame(true);
            assert_eq!(frame.keys, 2);
            assert!(frame.list_restored);
            assert_eq!(frame.list_received_at, synced.list_received_at);
            // A match on a restored key still says who listed it.
            let listed_by = second.shared.meta.read().unwrap()[&decode_hex(HEX).unwrap()]
                .promoted_by
                .clone();
            assert_eq!(listed_by, "vigiles-auto");

            // Naming the account again changes nothing.
            set_account_on(&second, ACCOUNT);
            assert_eq!(keys(&second), 2);

            // The first list the API returns replaces the saved one, on disk too.
            publish_on(&second, &[keyed(HEX_B, "api")], 1);
            assert_eq!(keys(&second), 1);
            let frame = second.shared.frame(true);
            assert!(!frame.list_restored);
            assert!(frame.list_received_at >= synced.list_received_at);
            let on_disk = read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap();
            assert_eq!(on_disk.rows, vec![keyed(HEX_B, "api")]);
        }

        #[test]
        fn a_list_over_the_row_limit_leaves_the_restored_keys_in_place() {
            let tmp = Tmp::new();
            drop(a_run_that_synced(&tmp, &[keyed(HEX, "api")]));
            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, ACCOUNT);
            let too_long = vec![keyed(HEX_B, "api"); ROW_LIMIT + 1];
            publish_on(&second, &too_long, too_long.len());
            assert_eq!(keys(&second), 1);
            assert!(second.shared.frame(true).list_restored, "that list was not applied");
            assert_eq!(read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap().rows, vec![keyed(HEX, "api")]);
        }

        #[test]
        fn a_logout_removes_the_saved_list_and_the_next_start_is_idle() {
            let tmp = Tmp::new();
            let first = a_run_that_synced(&tmp, &[keyed(HEX, "api")]);
            assert!(saved_file(&tmp).exists());
            clear_fleet_on(&first);
            assert_eq!(keys(&first), 0);
            assert!(!saved_file(&tmp).exists(), "no account, no org list on disk");
            assert_eq!(first.shared.frame(true).list_received_at, 0);

            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, ACCOUNT);
            assert_eq!(keys(&second), 0);
            assert!(!second.shared.frame(true).list_restored);
        }

        #[test]
        fn a_list_saved_under_another_account_is_removed_and_not_loaded() {
            let tmp = Tmp::new();
            drop(a_run_that_synced(&tmp, &[keyed(HEX, "api")]));
            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, "someone-else@https://api.example");
            assert_eq!(keys(&second), 0);
            assert!(!second.shared.frame(true).list_restored);
            assert!(!saved_file(&tmp).exists());
        }

        /// The keys of the account before must not wait for the new account's
        /// first list: its server may be down, or answer 401 for good.
        #[test]
        fn naming_another_account_takes_out_the_keys_of_the_one_before() {
            let other = "someone-else@https://api.example";
            let tmp = Tmp::new();
            // Keys that came from the API under ACCOUNT.
            let live = a_run_that_synced(&tmp, &[keyed(HEX, "api")]);
            assert_eq!(keys(&live), 1);
            set_account_on(&live, other);
            assert_eq!(keys(&live), 0);
            let frame = live.shared.frame(true);
            assert_eq!((frame.list_received_at, frame.list_restored), (0, false));
            assert!(!saved_file(&tmp).exists());

            // Keys a start loaded from disk, when the first tick then reads another account.
            drop(a_run_that_synced(&tmp, &[keyed(HEX, "api")]));
            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, ACCOUNT);
            assert_eq!(keys(&second), 1);
            set_account_on(&second, other);
            assert_eq!(keys(&second), 0);
            let frame = second.shared.frame(true);
            assert_eq!((frame.list_received_at, frame.list_restored), (0, false));
            assert!(!saved_file(&tmp).exists());
        }

        /// An older copy must not be what a restart loads once a newer list
        /// failed to save: the org may have taken a digest off since.
        #[test]
        fn a_save_that_fails_takes_the_older_copy_with_it() {
            let tmp = Tmp::new();
            let live = a_run_that_synced(&tmp, &[keyed(HEX, "api"), keyed(HEX_B, "api")]);
            // write_atomic's temp file cannot be created over a directory.
            let in_the_way = tmp.path(&format!("org-list.tmp.{}", std::process::id()));
            std::fs::create_dir(&in_the_way).unwrap();
            publish_on(&live, &[keyed(HEX_B, "api")], 1);
            assert_eq!(keys(&live), 1, "the gate itself is on the new list");
            assert!(!saved_file(&tmp).exists());
            // Nothing is stamped on the way out either.
            save_last_sync(&live);
            assert!(!saved_file(&tmp).exists());
            let restarted = new_live(-1, tmp.dir.clone());
            set_account_on(&restarted, ACCOUNT);
            assert_eq!(keys(&restarted), 0);

            // The next list from the API is saved once a write works again.
            std::fs::remove_dir(&in_the_way).unwrap();
            publish_on(&live, &[keyed(HEX_B, "api")], 1);
            assert_eq!(read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap().rows, vec![keyed(HEX_B, "api")]);
        }

        #[test]
        fn a_copy_that_only_failed_to_read_is_left_on_disk() {
            let tmp = Tmp::new();
            std::fs::create_dir(saved_file(&tmp)).unwrap();
            let live = new_live(-1, tmp.dir.clone());
            set_account_on(&live, ACCOUNT);
            assert_eq!(keys(&live), 0);
            assert!(saved_file(&tmp).exists());
        }

        #[test]
        fn a_digest_trusted_on_this_machine_stays_out_of_the_restored_keys() {
            let tmp = Tmp::new();
            drop(a_run_that_synced(&tmp, &[keyed(HEX, "api"), keyed(HEX_B, "api")]));
            trust::TrustStore::load(&tmp.dir)
                .add(HEX, "sample", "/opt/sample", "", 1)
                .unwrap();
            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, ACCOUNT);
            assert_eq!(keys(&second), 1);
            assert!(second.shared.keys.read().unwrap().contains(&decode_hex(HEX_B).unwrap()));
            assert_eq!(second.shared.union.read().unwrap().len(), 2);
        }

        #[test]
        fn the_time_of_the_last_sync_is_written_on_the_way_out() {
            let tmp = Tmp::new();
            let first = a_run_that_synced(&tmp, &[keyed(HEX, "api")]);
            let written = read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap().received_at;
            // A later sync inside the refresh interval moves the time in memory only.
            first.shared.list_received_at.store(written + 5_000, Ordering::Relaxed);
            save_last_sync(&first);
            let on_disk = read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap();
            assert_eq!(on_disk.received_at, written + 5_000);
            assert_eq!(on_disk.rows, vec![keyed(HEX, "api")]);

            // A gate still on its restored list has nothing newer to write.
            let second = new_live(-1, tmp.dir.clone());
            set_account_on(&second, ACCOUNT);
            second.shared.list_received_at.store(written + 99_000, Ordering::Relaxed);
            save_last_sync(&second);
            assert_eq!(read_saved(&tmp.dir, ACCOUNT).unwrap().unwrap().received_at, written + 5_000);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{clear_fleet, frame, poll, publish, set_account, shutdown, start};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
    use std::sync::atomic::Ordering;

    pub(super) const HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    pub(super) const HEX_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    pub(super) const ACCOUNT: &str = "fixture@https://api.example";

    /// A block row whose path names a digest, with the fields the poll carries.
    pub(super) fn keyed(hex: &str, promoted_by: &str) -> DenylistEntry {
        DenylistEntry {
            comm: "sample".into(),
            path: format!("/workspace/{hex}"),
            action: "block".into(),
            reason: "fixture reason".into(),
            promoted_by: promoted_by.into(),
            created_at: "2026-10-20T01:02:03Z".into(),
            ..Default::default()
        }
    }

    pub(super) fn row(comm: &str, path: &str, action: &str) -> DenylistEntry {
        DenylistEntry {
            name: String::new(),
            comm: comm.into(),
            path: path.into(),
            action: action.into(),
            reason: String::new(),
            promoted_by: String::new(),
            created_at: String::new(),
        }
    }

    fn shared_with(cap: u64, keys: BTreeSet<[u8; 32]>) -> Shared {
        let shared = Shared::new(cap, HashMap::new());
        *shared.union.write().unwrap() = keys.clone();
        *shared.keys.write().unwrap() = keys;
        shared.on.store(true, Ordering::Relaxed);
        shared
    }

    pub(super) struct Tmp {
        pub(super) dir: std::path::PathBuf,
    }

    impl Tmp {
        pub(super) fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vallum-execgate-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        pub(super) fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn the_saved_copy_keeps_only_rows_with_a_key_and_reads_back_for_its_account() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = Tmp::new();
        let book = ListBook {
            account: Some(ACCOUNT.into()),
            saved: None,
        };
        let rows = vec![
            keyed(HEX, "vigiles-auto"),
            row("miner", "/usr/bin/miner", "block"),
            row("x", &format!("/workspace/{HEX_B}"), "monitor"),
            row("bash", &format!("/workspace/{HEX_B}"), "block"),
        ];
        let saved = book.due(&rows, 1_000).expect("nothing is on disk yet");
        assert_eq!(saved.rows, vec![keyed(HEX, "vigiles-auto")]);
        write_saved(&tmp.dir, &saved).unwrap();
        let mode = std::fs::metadata(tmp.path(trust::ORG_LIST_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the copy names the account: root only");

        let back = read_saved(&tmp.dir, ACCOUNT).unwrap().expect("a copy was written");
        assert_eq!(back, saved);
        assert_eq!(back.received_at, 1_000);
        let keys = keys_from_denylist(&back.rows, &BTreeSet::new());
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), vec![decode_hex(HEX).unwrap()]);
    }

    #[test]
    fn a_saved_copy_is_refused_for_another_account_another_shape_or_too_many_rows() {
        let tmp = Tmp::new();
        assert_eq!(read_saved(&tmp.dir, ACCOUNT), Ok(None));
        let good = SavedList {
            schema: SAVED_SCHEMA,
            account: ACCOUNT.into(),
            received_at: 5,
            rows: vec![keyed(HEX, "api")],
        };
        write_saved(&tmp.dir, &good).unwrap();
        assert_eq!(read_saved(&tmp.dir, ACCOUNT), Ok(Some(good.clone())));
        let other = read_saved(&tmp.dir, "someone-else@https://api.example").unwrap_err();
        assert!(
            matches!(&other, NotLoaded::Refused(why) if why.contains("another account")),
            "{other:?}"
        );

        let refused = [
            ("a later schema", SavedList { schema: SAVED_SCHEMA + 1, ..good.clone() }),
            ("no sync time", SavedList { received_at: 0, ..good.clone() }),
            (
                "over the row limit",
                SavedList { rows: vec![keyed(HEX, "api"); ROW_LIMIT + 1], ..good.clone() },
            ),
        ];
        for (what, bad) in refused {
            write_saved(&tmp.dir, &bad).unwrap();
            assert!(
                matches!(read_saved(&tmp.dir, ACCOUNT), Err(NotLoaded::Refused(_))),
                "{what} must be refused"
            );
        }
        std::fs::write(tmp.path(trust::ORG_LIST_FILE), "{not json").unwrap();
        let garbage = read_saved(&tmp.dir, ACCOUNT).unwrap_err();
        assert!(
            matches!(&garbage, NotLoaded::Refused(why) if why.contains("not a saved list")),
            "{garbage:?}"
        );
        // A copy that only failed to read is not a bad copy (here: a directory
        // in its place). The caller leaves that one on disk.
        std::fs::remove_file(tmp.path(trust::ORG_LIST_FILE)).unwrap();
        std::fs::create_dir(tmp.path(trust::ORG_LIST_FILE)).unwrap();
        assert!(matches!(read_saved(&tmp.dir, ACCOUNT), Err(NotLoaded::Unreadable(_))));
    }

    #[test]
    fn an_unchanged_list_is_written_again_only_after_the_refresh_interval() {
        let mut book = ListBook {
            account: Some(ACCOUNT.into()),
            saved: None,
        };
        let rows = vec![keyed(HEX, "api")];
        let first = book.due(&rows, 1_000).unwrap();
        book.wrote(first);
        // The stream's rows carry no promoted_by or created_at. Same keys, same list.
        let from_stream = vec![row("sample", &format!("/workspace/{HEX}"), "block")];
        assert!(book.due(&from_stream, 1_000 + SAVE_REFRESH_MS - 1).is_none());
        let again = book.due(&rows, 1_000 + SAVE_REFRESH_MS).unwrap();
        assert_eq!(again.received_at, 1_000 + SAVE_REFRESH_MS);

        // A key change is written at once, a list that went to zero included.
        let grown = book.due(&[keyed(HEX, "api"), keyed(HEX_B, "api")], 1_001).unwrap();
        assert_eq!(grown.rows.len(), 2);
        assert!(book.due(&[], 1_001).unwrap().rows.is_empty());

        // No account, nothing to save it under.
        assert!(ListBook::default().due(&rows, 1_000).is_none());
    }

    #[test]
    fn an_age_reads_in_the_two_largest_units() {
        assert_eq!(
            [45_000, 12 * 60_000, 3 * 3_600_000 + 12 * 60_000, 53 * 3_600_000].map(age_text),
            ["45s", "12m", "3h 12m", "2d 5h"]
        );
    }

    #[test]
    fn a_workspace_digest_path_yields_its_key_and_a_normal_path_yields_none() {
        let digest_row = row("", &format!("/workspace/{HEX}"), "block");
        let keys = keys_from_denylist(&[digest_row], &BTreeSet::new());
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys.iter().next().copied().unwrap(),
            decode_hex(HEX).unwrap()
        );

        let normal = row("", "/usr/bin/curl", "block");
        assert!(keys_from_denylist(&[normal], &BTreeSet::new()).is_empty());
    }

    #[test]
    fn upper_case_hex_decodes() {
        let path = format!("/workspace/{}", HEX.to_ascii_uppercase());
        let keys = keys_from_denylist(&[row("", &path, "block")], &BTreeSet::new());
        assert_eq!(
            keys.iter().next().copied().unwrap(),
            decode_hex(HEX).unwrap()
        );
    }

    #[test]
    fn monitor_and_any_action_other_than_block_yield_no_key() {
        let path = format!("/workspace/{HEX}");
        for action in ["monitor", "deny", "warn", "audit", "kill", ""] {
            let keys = keys_from_denylist(&[row("xmrig", &path, action)], &BTreeSet::new());
            assert!(keys.is_empty(), "{action}");
        }
        assert_eq!(
            keys_from_denylist(&[row("xmrig", &path, "block")], &BTreeSet::new()).len(),
            1
        );
    }

    #[test]
    fn a_critical_comm_yields_no_key() {
        let path = format!("/workspace/{HEX}");
        assert!(keys_from_denylist(&[row("bash", &path, "block")], &BTreeSet::new()).is_empty());
        assert!(
            keys_from_denylist(&[row("kub0-block", &path, "block")], &BTreeSet::new()).is_empty()
        );
        // The helper's 0.4.x name was critical while 0.4.5 and 0.4.6 kept a
        // link at its old path. Nothing runs under that name now, so a row
        // that names it is a row like any other.
        assert_eq!(keys_from_denylist(&[row("vallum-block", &path, "block")], &BTreeSet::new()).len(), 1);
        assert_eq!(
            keys_from_denylist(&[row("xmrig", &path, "block")], &BTreeSet::new()).len(),
            1
        );
    }

    #[test]
    fn a_deny_file_keeps_hex_lines_and_drops_comments() {
        let text = format!("# full line\n{HEX}\n{HEX_B} # trailing\nnot-a-digest\n\n  {HEX}  \n");
        let set = parse_deny_file(&text);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&decode_hex(HEX).unwrap()));
        assert!(set.contains(&decode_hex(HEX_B).unwrap()));
        let upper = format!("{}\n", HEX.to_ascii_uppercase());
        assert_eq!(
            parse_deny_file(&upper).iter().next().copied().unwrap(),
            decode_hex(HEX).unwrap()
        );
    }

    #[test]
    fn five_hundred_and_one_rows_leave_the_previous_set_unchanged() {
        let previous: BTreeSet<[u8; 32]> = [decode_hex(HEX).unwrap()].into_iter().collect();
        let path = format!("/workspace/{HEX_B}");
        let rows: Vec<DenylistEntry> = (0..501).map(|_| row("", &path, "block")).collect();
        assert_eq!(keys_from_denylist(&rows, &previous), previous);

        let exactly_500: Vec<DenylistEntry> = rows.into_iter().take(500).collect();
        let updated = keys_from_denylist(&exactly_500, &previous);
        assert_eq!(updated.len(), 1);
        assert!(updated.contains(&decode_hex(HEX_B).unwrap()));
        assert!(!updated.contains(&decode_hex(HEX).unwrap()));
    }

    #[test]
    fn decide_denies_a_digest_in_the_set_and_allows_one_byte_different() {
        let tmp = Tmp::new();
        let bytes = b"vallum-exec-gate-sample";
        let digest = hash_bytes(bytes);
        let mut keys = BTreeSet::new();
        keys.insert(digest);
        let shared = shared_with(DEFAULT_CAP_KIB * 1024, keys);

        let blocked = tmp.path("blocked");
        std::fs::write(&blocked, bytes).unwrap();
        let blocked_fd = File::open(&blocked).unwrap();
        let d = decide(&shared, blocked_fd.as_raw_fd());
        assert_eq!(d.response, FAN_DENY);
        assert_eq!(
            d.matched,
            Some(Matched {
                digest,
                decision: ExecGateDecision::Blocked
            })
        );
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 1);

        let mut other = bytes.to_vec();
        other[0] ^= 0xff;
        let allowed = tmp.path("allowed");
        std::fs::write(&allowed, &other).unwrap();
        let allowed_fd = File::open(&allowed).unwrap();
        assert_eq!(decide(&shared, allowed_fd.as_raw_fd()), Decision::allow());
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 1);
        // The seam does not own the fd.
        drop(blocked_fd);
        drop(allowed_fd);
    }

    #[test]
    fn a_once_grant_allows_exactly_one_exec_of_a_denied_digest() {
        let tmp = Tmp::new();
        let bytes = b"allow-me-once";
        let digest = hash_bytes(bytes);
        let shared = shared_with(DEFAULT_CAP_KIB * 1024, [digest].into_iter().collect());
        shared
            .once
            .lock()
            .unwrap()
            .grant(&encode_hex(&digest), now_ms())
            .unwrap();
        let path = tmp.path("once");
        std::fs::write(&path, bytes).unwrap();
        let fd = File::open(&path).unwrap();

        let first = decide(&shared, fd.as_raw_fd());
        assert_eq!(first.response, FAN_ALLOW);
        assert_eq!(first.matched.unwrap().decision, ExecGateDecision::AllowedOnce);
        assert_eq!(shared.stats.allowed_once.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 0);

        let second = decide(&shared, fd.as_raw_fd());
        assert_eq!(second.response, FAN_DENY, "once means once");
        assert_eq!(second.matched.unwrap().decision, ExecGateDecision::Blocked);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_trusted_digest_is_allowed_and_recorded_as_local_trust() {
        let tmp = Tmp::new();
        let bytes = b"trusted-here";
        let digest = hash_bytes(bytes);
        let union: BTreeSet<_> = [digest].into_iter().collect();
        let mut store = trust::TrustStore::in_memory();
        store.add(&encode_hex(&digest), "t", "/x/t", "", 1).unwrap();
        let shared = Shared::new(DEFAULT_CAP_KIB * 1024, HashMap::new());
        shared.set_trusted(&store);
        *shared.union.write().unwrap() = union.clone();
        *shared.keys.write().unwrap() = trust::subtract(&union, &store.digests());
        shared.on.store(true, Ordering::Relaxed);
        let path = tmp.path("trusted");
        std::fs::write(&path, bytes).unwrap();
        let fd = File::open(&path).unwrap();

        let d = decide(&shared, fd.as_raw_fd());
        assert_eq!(d.response, FAN_ALLOW);
        assert_eq!(d.matched.unwrap().decision, ExecGateDecision::AllowedLocalTrust);
        assert_eq!(shared.stats.trusted.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 0);
        let rec = record(&shared, d.matched.unwrap(), 4242, "/home/u/trusted");
        assert_eq!(rec.comm, "trusted");
        assert_eq!(rec.sha256, encode_hex(&digest));
        assert_eq!(rec.decision, ExecGateDecision::AllowedLocalTrust);
        let frame = shared.frame(true);
        assert_eq!(frame.trusted.len(), 1);
        assert_eq!(frame.keys, 0, "a trusted key is subtracted");
        assert_eq!(frame.denies.len(), 1);
        assert_eq!(frame.source, "live");
        assert_eq!(frame.counters.trusted, 1);
    }

    #[test]
    fn records_keep_a_ring_drain_once_and_carry_the_rows_metadata() {
        let shared = shared_with(0, BTreeSet::new());
        let digest = decode_hex(HEX).unwrap();
        shared.meta.write().unwrap().insert(
            digest,
            RowMeta {
                reason: "detonated".into(),
                promoted_by: "vigiles-auto".into(),
                created_at: "2026-10-20T01:02:03Z".into(),
            },
        );
        let m = Matched {
            digest,
            decision: ExecGateDecision::Blocked,
        };
        for i in 0..(RECENT_CAP + 5) {
            record(&shared, m, i as i32, &format!("/tmp/sample{i}"));
        }
        let ring = shared.denies.lock().unwrap();
        assert_eq!(ring.len(), RECENT_CAP);
        assert_eq!(ring.back().unwrap().exe, format!("/tmp/sample{}", RECENT_CAP + 4));
        assert_eq!(ring.back().unwrap().reason, "detonated");
        assert_eq!(ring.back().unwrap().promoted_by, "vigiles-auto");
        assert_eq!(ring.back().unwrap().created_at, "2026-10-20T01:02:03Z");
        assert_eq!(ring.back().unwrap().comm, format!("sample{}", RECENT_CAP + 4));
        drop(ring);
        let pending = std::mem::take(&mut *shared.pending.lock().unwrap());
        assert_eq!(pending.len(), RECENT_CAP + 5, "pending holds everything under its cap");
        assert!(shared.pending.lock().unwrap().is_empty(), "drained once");
        assert_eq!(shared.generation.load(Ordering::Relaxed), (RECENT_CAP + 5) as u64);
        let frame = shared.frame(true);
        assert_eq!(frame.denies[0].exe, format!("/tmp/sample{}", RECENT_CAP + 4), "newest first");
    }

    #[test]
    fn the_frame_round_trips_through_serde_in_camel_case() {
        let frame = ExecGateFrame {
            enabled: true,
            armed: true,
            keys: 3,
            source: "live".into(),
            observed_at: 99,
            counters: ExecGateCounters {
                blocked: 1,
                failopen: 2,
                ..Default::default()
            },
            denies: vec![ExecGateDeny {
                ts: 5,
                pid: 1,
                ppid: 2,
                comm: "s".into(),
                exe: "/s".into(),
                sha256: HEX.into(),
                reason: "r".into(),
                promoted_by: "p".into(),
                created_at: "c".into(),
                decision: ExecGateDecision::AllowedFailopen,
            }],
            trusted: vec![TrustedDigest {
                sha256: HEX_B.into(),
                comm: "t".into(),
                exe: "/t".into(),
                added_at: 7,
                note: String::new(),
            }],
            once_pending: 1,
            list_received_at: 11,
            list_restored: true,
        };
        let text = serde_json::to_string(&frame).unwrap();
        assert!(text.contains(r#""oncePending":1"#), "{text}");
        assert!(text.contains(r#""listReceivedAt":11"#), "{text}");
        assert!(text.contains(r#""listRestored":true"#), "{text}");
        assert!(text.contains(r#""decision":"allowed_failopen""#), "{text}");
        assert!(text.contains(r#""promotedBy":"p""#), "{text}");
        assert!(text.contains(r#""addedAt":7"#), "{text}");
        let back: ExecGateFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn the_mirror_primes_silently_then_reports_only_new_denies_and_goes_stale() {
        let tmp = Tmp::new();
        let mut state = mirror::State::new();
        let now = 1_000_000u64;
        let none = state.poll_dir(&tmp.dir, now);
        assert!(!none.changed && none.events.is_empty());
        assert_eq!(state.frame().source, "none");

        let deny = |ts: u64, pid: i32| ExecGateDeny {
            ts,
            pid,
            sha256: HEX.into(),
            comm: "s".into(),
            exe: "/tmp/s".into(),
            ..Default::default()
        };
        let mut frame = ExecGateFrame {
            enabled: true,
            armed: true,
            keys: 1,
            source: "live".into(),
            observed_at: now,
            denies: vec![deny(900, 1)],
            ..Default::default()
        };
        let path = tmp.path(trust::STATE_FILE);
        trust::write_atomic(&path, &serde_json::to_vec(&frame).unwrap(), 0o644).unwrap();
        let first = state.poll_dir(&tmp.dir, now);
        assert!(first.changed);
        assert!(first.events.is_empty(), "the first read is history, not news");
        assert_eq!(state.frame().source, "mirror");
        assert_eq!(state.frame().denies.len(), 1);

        frame.denies.insert(0, deny(950, 2));
        frame.observed_at = now + 1;
        std::thread::sleep(Duration::from_millis(20));
        trust::write_atomic(&path, &serde_json::to_vec(&frame).unwrap(), 0o644).unwrap();
        let second = state.poll_dir(&tmp.dir, now + 1);
        assert!(second.changed);
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].pid, 2);

        let same = state.poll_dir(&tmp.dir, now + 2);
        assert!(!same.changed && same.events.is_empty(), "unchanged file is silent");

        let late = state.poll_dir(&tmp.dir, now + 200_000);
        assert!(late.changed);
        assert_eq!(state.frame().source, "stale");

        std::fs::remove_file(&path).unwrap();
        let gone = state.poll_dir(&tmp.dir, now + 200_001);
        assert!(gone.changed);
        assert_eq!(state.frame().source, "none");
        assert!(!state.frame().enabled);
    }

    #[test]
    fn the_cache_reuses_a_digest_when_the_signature_matches_and_recomputes_when_it_changes() {
        let tmp = Tmp::new();
        let first = b"one";
        let second = b"two!";
        let mut keys = BTreeSet::new();
        keys.insert(hash_bytes(second));
        let shared = shared_with(DEFAULT_CAP_KIB * 1024, keys);

        let path = tmp.path("cached");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(first).unwrap();
        file.sync_all().unwrap();
        let fd = file.as_raw_fd();

        assert_eq!(decide(&shared, fd).response, FAN_ALLOW);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.cache_hit.load(Ordering::Relaxed), 0);

        assert_eq!(decide(&shared, fd).response, FAN_ALLOW);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.cache_hit.load(Ordering::Relaxed), 1);

        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(second).unwrap();
        file.sync_all().unwrap();
        assert_eq!(decide(&shared, fd).response, FAN_DENY);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 2);
        assert_eq!(shared.stats.cache_hit.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_file_over_the_cap_is_allowed_without_hashing() {
        let tmp = Tmp::new();
        let bytes = b"abcdef";
        let mut keys = BTreeSet::new();
        keys.insert(hash_bytes(bytes));
        // Smaller than the file, so the digest being present must not matter.
        let shared = shared_with(4, keys);
        let path = tmp.path("big");
        std::fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(decide(&shared, file.as_raw_fd()), Decision::allow());
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 0);
        assert_eq!(shared.stats.over_cap.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_over_cap_file_is_counted_every_exec_but_named_once() {
        let tmp = Tmp::new();
        let shared = shared_with(4, BTreeSet::new());
        let big = tmp.path("big");
        std::fs::write(&big, b"abcdef").unwrap();
        let file = File::open(&big).unwrap();
        for _ in 0..3 {
            assert_eq!(decide(&shared, file.as_raw_fd()), Decision::allow());
        }
        assert_eq!(shared.stats.over_cap.load(Ordering::Relaxed), 3);
        assert_eq!(shared.over_cap_logged.lock().unwrap().len(), 1);

        // A second over-cap file is its own line; a file under the cap never enters the set.
        let other = tmp.path("other");
        std::fs::write(&other, b"ghijkl").unwrap();
        let small = tmp.path("small");
        std::fs::write(&small, b"abc").unwrap();
        let other_file = File::open(&other).unwrap();
        let small_file = File::open(&small).unwrap();
        assert_eq!(decide(&shared, other_file.as_raw_fd()), Decision::allow());
        assert_eq!(decide(&shared, small_file.as_raw_fd()), Decision::allow());
        assert_eq!(shared.stats.over_cap.load(Ordering::Relaxed), 4);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 1);
        assert_eq!(shared.over_cap_logged.lock().unwrap().len(), 2);
    }

    #[test]
    fn an_unarmed_gate_answers_allow_without_counting() {
        let tmp = Tmp::new();
        let bytes = b"idle";
        let shared = shared_with(0, [hash_bytes(bytes)].into_iter().collect());
        shared.on.store(false, Ordering::Relaxed);
        let path = tmp.path("idle");
        std::fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(decide(&shared, file.as_raw_fd()), Decision::allow());
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 0);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn events_parse_and_a_short_or_foreign_record_stops_the_walk() {
        let rec = |mask: u64, fd: i32, pid: i32, vers: u8| {
            let mut r = Vec::new();
            r.extend_from_slice(&(METADATA_LEN as u32).to_ne_bytes());
            r.push(vers);
            r.push(0);
            r.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
            r.extend_from_slice(&mask.to_ne_bytes());
            r.extend_from_slice(&fd.to_ne_bytes());
            r.extend_from_slice(&pid.to_ne_bytes());
            r
        };
        let mut buf = rec(OPEN_EXEC_PERM, 7, 100, FANOTIFY_METADATA_VERSION);
        buf.extend(rec(OPEN_EXEC_PERM, 8, 101, 99)); // other version: skipped
        buf.extend(rec(OPEN_EXEC_PERM, 9, 102, FANOTIFY_METADATA_VERSION));
        buf.extend_from_slice(&[1, 2, 3]); // a truncated tail
        assert_eq!(
            parse_events(&buf),
            vec![(OPEN_EXEC_PERM, 7, 100), (OPEN_EXEC_PERM, 9, 102)]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_exec_perm_matches_the_libc_constant() {
        assert_eq!(OPEN_EXEC_PERM, libc::FAN_OPEN_EXEC_PERM);
    }

    #[test]
    fn an_allow_set_entry_whose_signature_changed_is_hashed_and_denied() {
        let tmp = Tmp::new();
        let stable_path = tmp.path("stable");
        std::fs::write(&stable_path, b"stable-critical").unwrap();
        let stable_meta = std::fs::metadata(&stable_path).unwrap();

        let changed_path = tmp.path("changed");
        std::fs::write(&changed_path, b"before").unwrap();
        let before = std::fs::metadata(&changed_path).unwrap();
        let id = (before.dev(), before.ino());
        let recorded = signature_of(&before);
        let bytes = b"before-and-now-different";
        std::fs::write(&changed_path, bytes).unwrap();
        let after = std::fs::metadata(&changed_path).unwrap();
        assert_eq!((after.dev(), after.ino()), id);
        assert_ne!(signature_of(&after), recorded);

        let mut allow = HashMap::new();
        allow.insert(
            (stable_meta.dev(), stable_meta.ino()),
            signature_of(&stable_meta),
        );
        allow.insert(id, recorded);
        let mut keys = BTreeSet::new();
        keys.insert(hash_bytes(bytes));
        let shared = Shared::new(DEFAULT_CAP_KIB * 1024, allow);
        *shared.union.write().unwrap() = keys.clone();
        *shared.keys.write().unwrap() = keys;
        shared.on.store(true, Ordering::Relaxed);

        let stable = File::open(&stable_path).unwrap();
        assert_eq!(decide(&shared, stable.as_raw_fd()), Decision::allow());
        assert_eq!(shared.stats.allowlisted.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 0);

        let changed = File::open(&changed_path).unwrap();
        assert_eq!(decide(&shared, changed.as_raw_fd()).response, FAN_DENY);
        assert_eq!(shared.stats.allowlisted.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hashed.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.hit_block.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn five_hundred_one_fleet_rows_leave_the_previous_set_unchanged_and_trust_is_subtracted() {
        let previous = decode_hex(HEX).unwrap();
        let mut keys: BTreeSet<[u8; DIGEST_LEN]> = [previous].into_iter().collect();
        let mut union = keys.clone();
        let mut fleet = keys.clone();
        let file = BTreeSet::new();
        let mut trusted = BTreeSet::new();
        let capped: Vec<DenylistEntry> = (0..ROW_LIMIT)
            .map(|_| row("", &format!("/workspace/{HEX_B}"), "block"))
            .collect();
        assert!(publish_fleet(
            &mut fleet,
            &file,
            &trusted,
            &mut keys,
            &mut union,
            &capped,
            ROW_LIMIT + 1
        )
        .is_none());
        assert_eq!(keys, BTreeSet::from([previous]));
        assert_eq!(fleet, BTreeSet::from([previous]));

        let changed = publish_fleet(
            &mut fleet,
            &file,
            &trusted,
            &mut keys,
            &mut union,
            &capped,
            capped.len(),
        )
        .unwrap();
        assert!(changed);
        assert_eq!(keys, BTreeSet::from([decode_hex(HEX_B).unwrap()]));
        assert_eq!(union, keys);

        // The owner trusts the only key: the same publish now installs none,
        // and the union still remembers it was on the list.
        trusted.insert(decode_hex(HEX_B).unwrap());
        let changed = publish_fleet(
            &mut fleet,
            &file,
            &trusted,
            &mut keys,
            &mut union,
            &capped,
            capped.len(),
        )
        .unwrap();
        assert!(changed);
        assert!(keys.is_empty());
        assert_eq!(union, BTreeSet::from([decode_hex(HEX_B).unwrap()]));
        // An empty list within the cap is a change too: the gate goes idle.
        let changed = publish_fleet(&mut fleet, &file, &trusted, &mut keys, &mut union, &[], 0).unwrap();
        assert!(!changed, "nothing effective changed: it was already empty");
        assert!(union.is_empty());
    }

    #[test]
    fn a_deadline_expired_entry_is_closed_by_the_watchdog_and_a_later_pop_is_a_noop() {
        let tmp = Tmp::new();
        let path = tmp.path("event");
        std::fs::write(&path, b"event").unwrap();
        let fd = File::open(&path).unwrap().into_raw_fd();
        let fd_id = FdId::of(fd);
        let mut flight = InFlight::new();
        let at = Instant::now()
            .checked_sub(Duration::from_secs(4))
            .expect("clock");
        let id = flight.enqueue(fd, at);
        assert_eq!(flight.deadline_ids(Duration::from_secs(3)), vec![id]);
        let mut wrote = false;
        assert!(flight.answer_id(id, |_| wrote = true));
        assert!(wrote);
        assert!(flight.claim(id).is_none());
        assert!(fd_id.is_closed(fd));
    }

    #[test]
    fn a_name_resolved_from_an_extra_directory_lands_in_the_allow_set() {
        for dir in ["/usr/lib/systemd", "/usr/lib/kub0", "/usr/libexec"] {
            assert!(allow_dirs().any(|d| d == dir), "{dir}");
        }
        assert!(!allow_dirs().any(|d| d == "/usr/lib/vallum"), "the 0.4.x directory holds nothing critical any more");
        let tmp = Tmp::new();
        let dir = tmp.path("extra");
        std::fs::create_dir(&dir).unwrap();
        let bin = dir.join("systemd-logind");
        let bytes = b"logind-stand-in";
        std::fs::write(&bin, bytes).unwrap();
        let set = collect_allow_set([dir.to_str().unwrap()]);
        let meta = std::fs::metadata(&bin).unwrap();
        let sig = set
            .get(&(meta.dev(), meta.ino()))
            .copied()
            .expect("resolved from the extra directory");
        assert_eq!(sig, signature_of(&meta));
        assert_eq!(sig.size, bytes.len() as u64);
    }

    #[test]
    fn a_close_followed_by_a_response_attempt_writes_nothing() {
        // Close-on-exec: a process another test starts must not carry the write
        // end for its whole life, or the pipe never reads as closed below.
        let mut fds = [0i32; 2];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // macOS has no pipe2, so the flag goes on in a second step there. A
        // process started in the gap between the two keeps the write end for
        // as long as it runs: a narrower window than no flag, not a closed one.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            for fd in fds {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
            }
        }
        let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let group = Mutex::new(fds[1]);
        let shared = Shared::new(0, HashMap::new());
        assert!(write_response(&group, 7, FAN_ALLOW, &shared));
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(n, 8);

        close_group(&group);
        assert!(!write_response(&group, 7, FAN_DENY, &shared));
        assert_eq!(shared.stats.error.load(Ordering::Relaxed), 0);
        // Nothing was written, and the write end is closed: end of file. A
        // process being started elsewhere holds a copy of the write end from
        // its clone until its exec, and until then the read says "nothing
        // yet", so wait for the end of file instead of taking the first answer.
        let deadline = Instant::now() + Duration::from_secs(3);
        let n = loop {
            let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n >= 0 || Instant::now() >= deadline {
                break n;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(n, 0, "end of file and no bytes: the response was not written");
        unsafe { libc::close(fds[0]) };
    }

    #[test]
    fn the_watchdog_answers_an_event_a_worker_is_still_hashing() {
        let tmp = Tmp::new();
        let path = tmp.path("event");
        let bytes = b"still-hashing";
        std::fs::write(&path, bytes).unwrap();
        let fd = File::open(&path).unwrap().into_raw_fd();
        let fd_id = FdId::of(fd);
        let mut flight = InFlight::new();
        let id = flight.enqueue(fd, Instant::now());
        let dup = flight.dup_event(id).expect("worker holds a dup");
        assert!(unsafe { libc::fcntl(dup, libc::F_GETFD) } >= 0);

        assert!(flight.answer_id(id, |_| {}));
        assert!(fd_id.is_closed(fd));
        assert!(unsafe { libc::fcntl(dup, libc::F_GETFD) } >= 0);
        let mut buf = [0u8; 4];
        let n = unsafe { libc::pread(dup, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert_eq!(n, 4);
        assert_eq!(&buf, &bytes[..4]);

        let mut wrote = false;
        assert!(!flight.answer_id(id, |_| wrote = true));
        assert!(!wrote);
        unsafe { libc::close(dup) };
    }

    #[test]
    fn the_worker_claims_the_original_when_the_watchdog_has_not_answered() {
        let tmp = Tmp::new();
        let path = tmp.path("event");
        std::fs::write(&path, b"worker-wins").unwrap();
        let fd = File::open(&path).unwrap().into_raw_fd();
        let fd_id = FdId::of(fd);
        let mut flight = InFlight::new();
        let id = flight.enqueue(fd, Instant::now());
        let dup = flight.dup_event(id).expect("dup");
        let dup_id = FdId::of(dup);
        let mut pipes = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
        let group = Mutex::new(pipes[1]);
        let shared = Shared::new(0, HashMap::new());
        assert_eq!(
            finish_verdict(&mut flight, &group, &shared, id, dup, FAN_ALLOW),
            (true, true)
        );
        assert!(fd_id.is_closed(fd));
        assert!(dup_id.is_closed(dup));
        assert!(!flight.answer_id(id, |_| {}));
        assert_eq!(shared.stats.error.load(Ordering::Relaxed), 0);
        unsafe { libc::close(pipes[0]) };
        close_group(&group);
    }

    #[test]
    fn a_late_deny_that_lost_the_claim_reports_not_won() {
        let tmp = Tmp::new();
        let path = tmp.path("event");
        std::fs::write(&path, b"late").unwrap();
        let fd = File::open(&path).unwrap().into_raw_fd();
        let mut flight = InFlight::new();
        let id = flight.enqueue(fd, Instant::now());
        let dup = flight.dup_event(id).expect("dup");
        let dup_id = FdId::of(dup);
        // The watchdog answers first.
        assert!(flight.answer_id(id, |_| {}));
        let mut pipes = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
        let group = Mutex::new(pipes[1]);
        let shared = Shared::new(0, HashMap::new());
        assert_eq!(
            finish_verdict(&mut flight, &group, &shared, id, dup, FAN_DENY),
            (false, false),
            "the deny was never written: the worker must record fail-open"
        );
        assert!(dup_id.is_closed(dup), "the dup is closed either way");
        unsafe { libc::close(pipes[0]) };
        close_group(&group);
    }

    #[test]
    fn a_response_write_on_an_invalid_group_fd_counts_an_error() {
        let tmp = Tmp::new();
        let path = tmp.path("ro");
        std::fs::write(&path, b"x").unwrap();
        let ro = File::open(&path).unwrap();
        let group_fd = ro.as_raw_fd();
        assert_ne!(group_fd, -1);
        let group = Mutex::new(group_fd);
        let shared = Shared::new(0, HashMap::new());
        let event_path = tmp.path("event");
        std::fs::write(&event_path, b"e").unwrap();
        let event = File::open(&event_path).unwrap().into_raw_fd();
        let event_id = FdId::of(event);
        let mut flight = InFlight::new();
        let id = flight.enqueue(event, Instant::now());
        assert!(flight.answer_id(id, |event_fd| {
            assert!(!write_response(&group, event_fd, FAN_DENY, &shared));
        }));
        assert_eq!(shared.stats.error.load(Ordering::Relaxed), 1);
        assert!(event_id.is_closed(event));
        assert_ne!(*group.lock().unwrap(), -1);
        assert!(unsafe { libc::fcntl(group_fd, libc::F_GETFD) } >= 0);
    }

    #[test]
    fn a_queue_of_capacity_one_counts_overflow_when_the_second_push_fails() {
        let probe = Queue::with_capacity(1);
        assert!(matches!(probe.push((1, 0)), PushResult::Queued));
        assert!(matches!(probe.push((2, 0)), PushResult::Full));

        let queue = Queue::with_capacity(1);
        let shared = Shared::new(0, HashMap::new());
        let flight = Mutex::new(InFlight::new());
        let mut pipes = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
        let group = Mutex::new(pipes[1]);
        let tmp = Tmp::new();
        let first = tmp.path("first");
        let second = tmp.path("second");
        std::fs::write(&first, b"a").unwrap();
        std::fs::write(&second, b"b").unwrap();
        let fd1 = File::open(&first).unwrap().into_raw_fd();
        let fd2 = File::open(&second).unwrap().into_raw_fd();
        let fd2_id = FdId::of(fd2);
        let id1 = flight.lock().unwrap().enqueue(fd1, Instant::now());
        let id2 = flight.lock().unwrap().enqueue(fd2, Instant::now());

        deliver(&queue, &flight, &group, &shared, id1, 1);
        assert_eq!(shared.stats.overflow.load(Ordering::Relaxed), 0);
        assert_eq!(shared.counters().overflow, 0);
        deliver(&queue, &flight, &group, &shared, id2, 2);
        assert_eq!(shared.stats.overflow.load(Ordering::Relaxed), 1);
        assert_eq!(shared.counters().overflow, 1);
        assert_eq!(shared.stats.error.load(Ordering::Relaxed), 0);

        assert!(fd2_id.is_closed(fd2));
        let held = flight
            .lock()
            .unwrap()
            .claim(id1)
            .expect("first event stays queued");
        unsafe { libc::close(held) };
        unsafe { libc::close(pipes[0]) };
        close_group(&group);
    }

    // (st_dev, st_ino) taken before close. A reused fd number is closed when
    // fstat fails with EBADF or the number now names a different file.
    struct FdId {
        dev: libc::dev_t,
        ino: libc::ino_t,
    }

    impl FdId {
        fn of(fd: RawFd) -> Self {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
            assert_eq!(
                rc,
                0,
                "fstat before close: {}",
                std::io::Error::last_os_error()
            );
            let stat = unsafe { stat.assume_init() };
            Self {
                dev: stat.st_dev,
                ino: stat.st_ino,
            }
        }

        fn is_closed(&self, fd: RawFd) -> bool {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
            if rc != 0 {
                return std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
            }
            let stat = unsafe { stat.assume_init() };
            stat.st_dev != self.dev || stat.st_ino != self.ino
        }
    }

    fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }
}
