//! Local trust for the exec gate: digests this machine's owner has chosen to
//! run anyway, and one-shot allows with a short TTL.
//!
//! Everything here stays on the machine. The system kub0d is the only
//! reader and the only writer of `trusted.json` and `allow-once.json`; the
//! privileged helper (`kub0-block execgate-*`, behind polkit) does not edit
//! them. It appends one line to `requests.ndjson`, and the daemon consumes
//! that file under a lock, applies each request to its stores, and truncates
//! it. One owner for each file, so two writers can never interleave.
//!
//! The gate's effective key set is `(fleet ∪ file) − trusted`, recomputed on
//! every refresh. A one-shot allow is consumed by the first matching exec and
//! expires after [`ONCE_TTL_MS`] whether or not it was used.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the system daemon keeps the gate's local state, under the state
/// directory in use. `KUB0_EXEC_GATE_DIR` overrides it (the root self-test
/// uses a private directory).
pub const DIR_NAME: &str = "execgate";
pub const TRUSTED_FILE: &str = "trusted.json";
pub const ONCE_FILE: &str = "allow-once.json";
pub const REQUESTS_FILE: &str = "requests.ndjson";
pub const REQUESTS_LOCK: &str = "requests.lock";
/// The frame the user daemon mirrors into its fleet event.
pub const STATE_FILE: &str = "state.json";
/// `state.json` and the trusted list: root's, and the group's that the gate's
/// directory is in (`statedir::share_with_group`), which is how a per-user
/// daemon in the `kub0` group reads the frame. Not other accounts': the frame
/// carries the path, pid and digest of every exec the gate stopped.
pub const STATE_FILE_MODE: u32 = 0o640;
/// The org deny list as the API last returned it, so a restarted daemon arms
/// before its first sync (`execgate.rs`). Mode 0600: it names the account.
pub const ORG_LIST_FILE: &str = "org-list.json";
/// A one-shot allow lives this long.
pub const ONCE_TTL_MS: u64 = 5 * 60 * 1000;
const TRUSTED_CAP: usize = 1024;
const ONCE_CAP: usize = 64;
/// The requests file is never large; anything past this is not a helper's.
const REQUESTS_MAX: u64 = 256 * 1024;

pub const DIGEST_LEN: usize = 32;

pub fn dir() -> PathBuf {
    crate::rename::env("KUB0_EXEC_GATE_DIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::rename::state_path(DIR_NAME))
}

pub fn decode_hex(s: &str) -> Option<[u8; DIGEST_LEN]> {
    if s.len() != DIGEST_LEN * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; DIGEST_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn encode_hex(d: &[u8; DIGEST_LEN]) -> String {
    let mut s = String::with_capacity(DIGEST_LEN * 2);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Lower-case the digest the way every store keys it, or refuse it.
pub fn canonical_sha256(s: &str) -> Option<String> {
    let s = s.trim();
    decode_hex(s).map(|_| s.to_ascii_lowercase())
}

/// Keys minus the trusted digests. Pure, so the refresh test can pin it.
pub fn subtract(
    union: &BTreeSet<[u8; DIGEST_LEN]>,
    trusted: &BTreeSet<[u8; DIGEST_LEN]>,
) -> BTreeSet<[u8; DIGEST_LEN]> {
    union.difference(trusted).copied().collect()
}

/// One digest the owner trusts on this machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TrustedDigest {
    pub sha256: String,
    /// Basename of the file that was blocked when the trust was granted; empty
    /// when the trust came from a request that named only a digest.
    pub comm: String,
    pub exe: String,
    pub added_at: u64,
    pub note: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct TrustedFile {
    version: u32,
    trusted: Vec<TrustedDigest>,
}

/// Persistent allow list. `None` path means in-memory only (tests).
pub struct TrustStore {
    path: Option<PathBuf>,
    entries: Vec<TrustedDigest>,
}

impl TrustStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            entries: Vec::new(),
        }
    }

    pub fn load(dir: &Path) -> Self {
        let path = dir.join(TRUSTED_FILE);
        let entries = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<TrustedFile>(&text)
                .map(|f| f.trusted)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let mut store = Self {
            path: Some(path),
            entries: Vec::new(),
        };
        // Re-validate every row: a hand-edited file must not smuggle a key the
        // decode would refuse, and duplicates collapse to the first.
        for e in entries {
            if let Some(sha) = canonical_sha256(&e.sha256) {
                if !store.contains_hex(&sha) {
                    store.entries.push(TrustedDigest { sha256: sha, ..e });
                }
            }
        }
        store
    }

    pub fn entries(&self) -> &[TrustedDigest] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn digests(&self) -> BTreeSet<[u8; DIGEST_LEN]> {
        self.entries
            .iter()
            .filter_map(|e| decode_hex(&e.sha256))
            .collect()
    }

    pub fn contains(&self, digest: &[u8; DIGEST_LEN]) -> bool {
        self.contains_hex(&encode_hex(digest))
    }

    fn contains_hex(&self, sha: &str) -> bool {
        self.entries.iter().any(|e| e.sha256 == sha)
    }

    /// `Ok(true)` when the digest was added, `Ok(false)` when it was already
    /// trusted. Saves on change.
    pub fn add(
        &mut self,
        sha256: &str,
        comm: &str,
        exe: &str,
        note: &str,
        now: u64,
    ) -> Result<bool, String> {
        let sha = canonical_sha256(sha256).ok_or("sha256 must be 64 hex characters")?;
        if self.contains_hex(&sha) {
            return Ok(false);
        }
        if self.entries.len() >= TRUSTED_CAP {
            return Err(format!("trust store holds {TRUSTED_CAP} digests already"));
        }
        self.entries.push(TrustedDigest {
            sha256: sha,
            comm: comm.chars().take(64).collect(),
            exe: exe.chars().take(512).collect(),
            added_at: now,
            note: note.chars().take(200).collect(),
        });
        self.save().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// True when a row was removed. Saves on change.
    pub fn remove(&mut self, sha256: &str) -> Result<bool, String> {
        let sha = canonical_sha256(sha256).ok_or("sha256 must be 64 hex characters")?;
        let before = self.entries.len();
        self.entries.retain(|e| e.sha256 != sha);
        if self.entries.len() == before {
            return Ok(false);
        }
        self.save().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let doc = TrustedFile {
            version: 1,
            trusted: self.entries.clone(),
        };
        let text = serde_json::to_string_pretty(&doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic(path, text.as_bytes(), STATE_FILE_MODE)
    }
}

/// One allow-once grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OnceGrant {
    pub sha256: String,
    pub granted_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct OnceFile {
    version: u32,
    grants: Vec<OnceGrant>,
}

/// One-shot allows. A grant is spent by the first exec of its digest or by
/// its TTL, whichever comes first.
pub struct OnceStore {
    path: Option<PathBuf>,
    grants: Vec<OnceGrant>,
}

impl OnceStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            grants: Vec::new(),
        }
    }

    pub fn load(dir: &Path, now: u64) -> Self {
        let path = dir.join(ONCE_FILE);
        let grants = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<OnceFile>(&text)
                .map(|f| f.grants)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let mut store = Self {
            path: Some(path),
            grants: grants
                .into_iter()
                .filter(|g| canonical_sha256(&g.sha256).as_deref() == Some(g.sha256.as_str()))
                .collect(),
        };
        store.prune(now);
        store
    }

    /// Grants that are still live at `now`.
    pub fn live(&self, now: u64) -> Vec<OnceGrant> {
        self.grants
            .iter()
            .filter(|g| g.expires_at > now)
            .cloned()
            .collect()
    }

    /// Add a grant for `sha256` that expires at `now + ONCE_TTL_MS`. A second
    /// grant for the same digest replaces the first (one exec, not two).
    pub fn grant(&mut self, sha256: &str, now: u64) -> Result<u64, String> {
        let sha = canonical_sha256(sha256).ok_or("sha256 must be 64 hex characters")?;
        self.prune(now);
        self.grants.retain(|g| g.sha256 != sha);
        if self.grants.len() >= ONCE_CAP {
            return Err(format!("{ONCE_CAP} one-shot allows are already pending"));
        }
        let expires_at = now.saturating_add(ONCE_TTL_MS);
        self.grants.push(OnceGrant {
            sha256: sha,
            granted_at: now,
            expires_at,
        });
        self.save().map_err(|e| e.to_string())?;
        Ok(expires_at)
    }

    /// Consume a live grant for `digest`. True exactly once per grant.
    pub fn take(&mut self, digest: &[u8; DIGEST_LEN], now: u64) -> bool {
        self.prune(now);
        let sha = encode_hex(digest);
        let before = self.grants.len();
        self.grants.retain(|g| g.sha256 != sha);
        if self.grants.len() == before {
            return false;
        }
        let _ = self.save();
        true
    }

    /// Drop expired grants. Saves only when something was dropped.
    pub fn prune(&mut self, now: u64) {
        let before = self.grants.len();
        self.grants.retain(|g| g.expires_at > now);
        if self.grants.len() != before {
            let _ = self.save();
        }
    }

    pub fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let doc = OnceFile {
            version: 1,
            grants: self.grants.clone(),
        };
        let text = serde_json::to_string(&doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic(path, text.as_bytes(), 0o600)
    }
}

/// What the helper asks for. `op` is one of `trust`, `untrust`, `allow_once`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Request {
    pub op: String,
    pub sha256: String,
    #[serde(default)]
    pub ts: u64,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub note: String,
}

impl Request {
    pub fn parse_line(line: &str) -> Option<Self> {
        let r: Request = serde_json::from_str(line.trim()).ok()?;
        let sha = canonical_sha256(&r.sha256)?;
        match r.op.as_str() {
            "trust" | "untrust" | "allow_once" => Some(Request { sha256: sha, ..r }),
            _ => None,
        }
    }
}

fn lock_file(dir: &Path) -> io::Result<File> {
    fs::create_dir_all(dir)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(REQUESTS_LOCK))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
}

/// Append one request. The helper's half of the protocol; the daemon's unit
/// tests use it too.
pub fn append_request(dir: &Path, req: &Request) -> io::Result<()> {
    let lock = lock_file(dir)?;
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(REQUESTS_FILE))?;
    let mut line = serde_json::to_string(req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    drop(lock);
    Ok(())
}

/// Take every pending request and empty the file. Unparseable lines are
/// dropped: the helper wrote them, and a line it did not write is not a
/// request. An absent file is no requests, not an error.
pub fn take_requests(dir: &Path) -> io::Result<Vec<Request>> {
    let path = dir.join(REQUESTS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let lock = lock_file(dir)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = f.metadata()?;
    let mut text = String::new();
    if meta.len() <= REQUESTS_MAX {
        f.read_to_string(&mut text)?;
    }
    f.set_len(0)?;
    drop(lock);
    Ok(text.lines().filter_map(Request::parse_line).collect())
}

/// Write `bytes` to `path` through a sibling temp file and a rename, so a
/// reader never sees a half-written file.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_data()?;
        // create() leaves an existing temp file's mode alone; set it anyway.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vallum-trust-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn add_remove_and_contains() {
        let mut store = TrustStore::in_memory();
        assert!(store.add(A, "sample", "/tmp/sample", "", 5).unwrap());
        assert!(!store.add(A, "sample", "/tmp/sample", "", 6).unwrap(), "a second add is a no-op");
        assert!(store.add(&A.to_ascii_uppercase(), "", "", "", 7).is_ok());
        assert_eq!(store.len(), 1, "case does not make a second digest");
        assert!(store.contains(&decode_hex(A).unwrap()));
        assert!(!store.contains(&decode_hex(B).unwrap()));
        assert!(store.add("not hex", "", "", "", 1).is_err());
        assert!(store.remove(A).unwrap());
        assert!(!store.remove(A).unwrap());
        assert!(store.is_empty());
    }

    #[test]
    fn persistence_round_trip_keeps_rows_and_drops_bad_ones() {
        let tmp = Tmp::new("roundtrip");
        {
            let mut store = TrustStore::load(&tmp.0);
            store.add(A, "sample", "/home/u/sample", "false positive", 1000).unwrap();
            store.add(B, "", "", "", 2000).unwrap();
        }
        // A hand edit adds junk and a duplicate.
        let path = tmp.0.join(TRUSTED_FILE);
        let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = doc["trusted"].as_array_mut().unwrap();
        arr.push(serde_json::json!({"sha256": "zzz", "comm": "junk"}));
        arr.push(serde_json::json!({"sha256": A, "comm": "dupe"}));
        fs::write(&path, doc.to_string()).unwrap();
        let store = TrustStore::load(&tmp.0);
        assert_eq!(store.len(), 2);
        assert_eq!(store.entries()[0].sha256, A);
        assert_eq!(store.entries()[0].comm, "sample");
        assert_eq!(store.entries()[0].exe, "/home/u/sample");
        assert_eq!(store.entries()[0].note, "false positive");
        assert_eq!(store.entries()[0].added_at, 1000);
        assert_eq!(store.entries()[1].sha256, B);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "the trusted list is root's and the gate directory's group's, like state.json");
    }

    #[test]
    fn refresh_subtraction_removes_trusted_keys_and_nothing_else() {
        let a = decode_hex(A).unwrap();
        let b = decode_hex(B).unwrap();
        let union: BTreeSet<_> = [a, b].into_iter().collect();
        let mut store = TrustStore::in_memory();
        store.add(A, "", "", "", 1).unwrap();
        let keys = subtract(&union, &store.digests());
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&b));
        assert!(!keys.contains(&a));
        store.remove(A).unwrap();
        assert_eq!(subtract(&union, &store.digests()), union, "untrust puts the key back");
    }

    #[test]
    fn a_once_grant_is_spent_by_one_take_or_by_its_ttl() {
        let a = decode_hex(A).unwrap();
        let mut once = OnceStore::in_memory();
        let exp = once.grant(A, 10_000).unwrap();
        assert_eq!(exp, 10_000 + ONCE_TTL_MS);
        assert!(once.take(&a, 10_001), "first exec passes");
        assert!(!once.take(&a, 10_002), "second exec does not");
        once.grant(A, 20_000).unwrap();
        assert!(!once.take(&a, 20_000 + ONCE_TTL_MS), "expired at the boundary");
        assert!(once.live(20_000 + ONCE_TTL_MS).is_empty());
        once.grant(A, 30_000).unwrap();
        once.grant(A, 30_001).unwrap();
        assert_eq!(once.live(30_002).len(), 1, "a re-grant replaces, never stacks");
        assert!(once.grant("nope", 1).is_err());
    }

    #[test]
    fn once_grants_persist_and_expired_ones_are_pruned_on_load() {
        let tmp = Tmp::new("once");
        let t0 = 10 * ONCE_TTL_MS;
        {
            let mut once = OnceStore::load(&tmp.0, t0);
            once.grant(A, t0).unwrap();
            // Granted a full TTL ago: expired by the time of the reload.
            once.grant(B, t0 - ONCE_TTL_MS).unwrap();
        }
        let once = OnceStore::load(&tmp.0, t0 + 1);
        let live = once.live(t0 + 1);
        assert_eq!(live.len(), 1, "B expired before the reload");
        assert_eq!(live[0].sha256, A);
        let mode = fs::metadata(tmp.0.join(ONCE_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn requests_are_appended_taken_once_and_junk_is_dropped() {
        let tmp = Tmp::new("requests");
        assert!(take_requests(&tmp.0).unwrap().is_empty(), "no file is no requests");
        append_request(&tmp.0, &Request { op: "trust".into(), sha256: A.into(), ts: 5, uid: 1000, note: String::new() }).unwrap();
        append_request(&tmp.0, &Request { op: "allow_once".into(), sha256: B.to_ascii_uppercase(), ts: 6, uid: 1000, note: String::new() }).unwrap();
        {
            let mut f = OpenOptions::new().append(true).open(tmp.0.join(REQUESTS_FILE)).unwrap();
            f.write_all(b"{\"op\":\"format\",\"sha256\":\"zz\"}\nnot json\n").unwrap();
        }
        let got = take_requests(&tmp.0).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].op, "trust");
        assert_eq!(got[0].sha256, A);
        assert_eq!(got[1].op, "allow_once");
        assert_eq!(got[1].sha256, B, "digest is canonical lower-case");
        assert!(take_requests(&tmp.0).unwrap().is_empty(), "taken means gone");
        assert_eq!(fs::metadata(tmp.0.join(REQUESTS_FILE)).unwrap().len(), 0);
    }

    #[test]
    fn hex_round_trips() {
        let a = decode_hex(A).unwrap();
        assert_eq!(encode_hex(&a), A);
        assert_eq!(canonical_sha256(&format!(" {} ", A.to_ascii_uppercase())).as_deref(), Some(A));
        assert!(decode_hex("abc").is_none());
    }
}
