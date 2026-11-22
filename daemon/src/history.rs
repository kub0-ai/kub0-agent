//! Bounded, private local observations. A vanished sampled socket is not proof
//! of its exact close time; first/last times are always observation timestamps.
//!
//! Write cost. Every row present in a sample was observed at that sample's
//! time, so an active row whose content did not change needs no write of its
//! own: one `checkpoint` record holds the latest sample time, and an active
//! row's last observation is read from it. Transfer counters, the one thing
//! that moves on a busy connection, live in `live_transfer`, a narrow table of
//! the active rows only, so a checkpoint that updates twenty of them dirties
//! one or two small pages instead of twenty record pages. A row's own record
//! is written only when it is new, changes otherwise, or is no longer
//! observed. Before this, every checkpoint rewrote every active row's whole
//! JSON record through a rollback journal; with `hosts.json` that came to
//! 174 KB/s (15 GB a day) over an hour on a laptop holding 41 to 100
//! connections.
use crate::{event::Connection, traffic::Bytes};
use rusqlite::{params, Connection as Db, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    hash::{Hash, Hasher},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub const RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const ROW_CAP: usize = 10_000;
/// Rows past the cap are trimmed once this many have accumulated, not one or
/// two per checkpoint. Deleting the oldest rows a few at a time rewrote the
/// same head pages, index pages and freelist on nearly every checkpoint; a
/// batch frees whole pages at once. Queries and exports never return more
/// than the newest [`ROW_CAP`], so only the file briefly holds the extra.
pub const TRIM_SLACK: usize = 256;
pub const QUERY_CAP: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub key: String,
    pub first_observed: u64,
    pub last_observed: u64,
    pub active: bool,
    pub connection: Connection,
    /// Measured differences since the first available TCP counter.
    pub bytes: Option<Bytes>,
    #[serde(default, skip_serializing)]
    baseline: Option<Bytes>,
    /// Fingerprint of the content last committed for this row, with the
    /// per-sample timestamps and transfer counters masked. In memory only.
    #[serde(skip)]
    written: Option<u64>,
    /// The counters last committed to `live_transfer` for this row.
    #[serde(skip)]
    counters_written: Option<Counters>,
}

/// `(bytes, connection.bytes)`: the sampled difference and the raw counters.
type Counters = (Option<Bytes>, Option<Bytes>);

fn counters(e: &Entry) -> Counters {
    (e.bytes, e.connection.bytes)
}

/// An active row's last observation when its own `last_seen` is older: the
/// newest committed sample time. Rows are only active while present in the
/// latest sample, so that time is exact, not an estimate.
const EFFECTIVE_LAST_SEEN: &str = "CASE WHEN active THEN MAX(last_seen, COALESCE((SELECT last_sample FROM checkpoint WHERE id = 1), last_seen)) ELSE last_seen END";

/// Hash of what would be written for `e`, ignoring what moves every sample:
/// `last_observed`, the evidence timestamp when it is in lockstep with it
/// (procfs stamps `recorded_at` with the sample time), and the transfer
/// counters, which `live_transfer` carries. A source whose timestamp is not in
/// lockstep keeps it in the hash, so a change still writes.
fn fingerprint(e: &Entry) -> Option<u64> {
    let mut masked = e.clone();
    masked.last_observed = 0;
    masked.bytes = None;
    masked.connection.bytes = None;
    if let Some(ev) = masked.connection.evidence.as_mut() {
        if ev.recorded_at == e.last_observed {
            ev.recorded_at = 0;
        }
    }
    let text = serde_json::to_string(&masked).ok()?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    Some(h.finish())
}

pub struct History {
    db: Db,
    active: HashMap<String, Entry>,
    pending: Vec<Entry>,
    session: String,
    serial: u64,
    /// Time of the latest `observe`, and the value last committed for it.
    last_sample: Option<u64>,
    checkpointed: Option<u64>,
    _lease: fs::File,
}

/// Open the store with SQLite's temporary space kept in memory.
///
/// The system unit runs under `ProtectSystem=strict` without a private /tmp,
/// so /tmp, /var/tmp and its working directory (/) are all read-only to it.
/// A statement that outgrows SQLite's in-memory limits then has nowhere to
/// spill and fails with SQLITE_IOERR_GETTEMPPATH, printed as "disk I/O
/// error": the restart fold's multi-row UPDATE inside one transaction spills
/// its statement journal past 64 KiB, and a large ORDER BY spills its sorter.
/// The daemon then runs with no history at all. The store is capped at
/// 64 MiB (`max_page_count`), which bounds what memory temp space can hold.
fn open_db(path: &Path, flags: OpenFlags) -> Result<Db, String> {
    let db = Db::open_with_flags(path, flags).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_millis(100))
        .map_err(|e| e.to_string())?;
    db.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|e| e.to_string())?;
    Ok(db)
}

fn private_path(state_dir: &Path, create: bool) -> Result<std::path::PathBuf, String> {
    let uid = unsafe { libc::geteuid() };
    let real = fs::canonicalize(state_dir).map_err(|e| e.to_string())?;
    let dir = fs::symlink_metadata(state_dir).map_err(|e| e.to_string())?;
    if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o022 != 0 {
        return Err("history needs an owner-controlled state directory".into());
    }
    // Root must not open SQLite beneath a user-writable ancestor. User mode
    // may use its own directories, and a sticky /tmp for isolated previews.
    for ancestor in real.ancestors() {
        let meta = fs::metadata(ancestor).map_err(|e| e.to_string())?;
        let sticky_tmp = uid != 0 && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if (meta.uid() != uid && meta.uid() != 0) || (meta.mode() & 0o022 != 0 && !sticky_tmp) {
            return Err("history state has an unsafe ancestor".into());
        }
    }
    let path = real.join("history.sqlite");
    if create && !path.exists() {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| e.to_string())?;
    }
    let file = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !file.is_file() || file.uid() != uid || file.mode() & 0o077 != 0 {
        return Err("history database must be a private regular file owned by this user".into());
    }
    Ok(path)
}

impl History {
    pub fn open(state_dir: &Path, now: u64) -> Result<Self, String> {
        let path = private_path(state_dir, true)?;
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(state_dir.join("history.lock"))
            .map_err(|e| e.to_string())?;
        let meta = lease.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("unsafe history lease".into());
        }
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another daemon owns this history store".into());
        }
        let mut db = open_db(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        // WAL appends the pages a commit changes instead of journalling every
        // page it is about to overwrite, and NORMAL syncs at WAL checkpoints
        // rather than on every commit. NORMAL can lose the last commits on
        // power loss, never corrupt the database; the documented loss window
        // is already "since the last checkpoint". A failure here (another
        // process holding a lock) keeps the previous journal mode.
        let _ = db.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0));
        let _ = db.pragma_update(None, "synchronous", "NORMAL");
        let _ = db.pragma_update_and_check(None, "journal_size_limit", 4 * 1024 * 1024, |r| r.get::<_, i64>(0));
        db.execute_batch(
            "PRAGMA max_page_count=16384;
            CREATE TABLE IF NOT EXISTS observations (
                key TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                active INTEGER NOT NULL, search TEXT NOT NULL, record TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS observed_time ON observations(last_seen DESC, key DESC);
            CREATE TABLE IF NOT EXISTS checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1), last_sample INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS live_transfer (
                key TEXT PRIMARY KEY, bytes TEXT NOT NULL, connection_bytes TEXT NOT NULL)
                WITHOUT ROWID;",
        )
        .map_err(|e| e.to_string())?;
        fold_previous_session(&mut db)?;
        let mut h = Self {
            db,
            active: HashMap::new(),
            pending: Vec::new(),
            _lease: lease,
            session: format!(
                "{}-{now}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            serial: 0,
            last_sample: None,
            checkpointed: None,
        };
        h.flush(now)?;
        Ok(h)
    }

    pub fn observe(&mut self, rows: &[Connection], now: u64) {
        let present: std::collections::HashSet<_> = rows.iter().map(|r| r.id.as_str()).collect();
        let gone: Vec<_> = self
            .active
            .keys()
            .filter(|id| !present.contains(id.as_str()))
            .cloned()
            .collect();
        for id in gone {
            if let Some(mut e) = self.active.remove(&id) {
                e.active = false;
                self.pending.push(e);
            }
        }
        for c in rows {
            // A recycled inode with a different endpoint or process is a new
            // observation, even if the old sampler id happens to be identical.
            if self.active.get(&c.id).is_some_and(|e| e.connection.local != c.local || e.connection.app != c.app || e.connection.exe != c.exe
                || matches!((e.connection.bytes, c.bytes), (Some(old), Some(new)) if new.tx < old.tx || new.rx < old.rx)) {
                if let Some(mut e) = self.active.remove(&c.id) { e.active = false; self.pending.push(e); }
            }
            if !self.active.contains_key(&c.id) {
                self.serial += 1;
                self.active.insert(
                    c.id.clone(),
                    Entry {
                        key: format!("{}-{:012}", self.session, self.serial),
                        first_observed: now,
                        last_observed: now,
                        active: true,
                        connection: c.clone(),
                        bytes: c.bytes.map(|_| Bytes { tx: 0, rx: 0 }),
                        baseline: c.bytes,
                        written: None,
                        counters_written: None,
                    },
                );
            }
            let e = self.active.get_mut(&c.id).unwrap();
            e.last_observed = now;
            if let Some(bytes) = c.bytes {
                let base = e.baseline.get_or_insert(bytes);
                // Counter resets are a new measurement baseline, never a
                // wraparound producing an enormous fictitious transfer.
                if bytes.tx < base.tx || bytes.rx < base.rx {
                    *base = bytes;
                }
                e.bytes = Some(Bytes {
                    tx: bytes.tx - base.tx,
                    rx: bytes.rx - base.rx,
                });
            }
            e.connection = c.clone();
        }
        if self.pending.len() > ROW_CAP {
            self.pending.drain(..self.pending.len() - ROW_CAP);
        }
        self.last_sample = Some(now);
    }

    pub fn record_attempt(&mut self, connection: Connection) {
        self.serial += 1;
        let ts = connection
            .evidence
            .as_ref()
            .map(|e| e.recorded_at)
            .unwrap_or(0);
        self.pending.push(Entry {
            key: format!("{}-{:012}", self.session, self.serial),
            first_observed: ts,
            last_observed: ts,
            active: false,
            connection,
            bytes: None,
            baseline: None,
            written: None,
            counters_written: None,
        });
        if self.pending.len() > ROW_CAP {
            self.pending.drain(..self.pending.len() - ROW_CAP);
        }
    }

    pub fn flush(&mut self, now: u64) -> Result<(), String> {
        let mut committed: Vec<(String, Option<u64>, Counters)> = Vec::new();
        let tx = self.db.transaction().map_err(|e| e.to_string())?;
        {
            let mut write = tx.prepare_cached("INSERT INTO observations(key, first_seen, last_seen, active, search, record)
                VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,
                active=excluded.active, search=excluded.search, record=excluded.record").map_err(|e| e.to_string())?;
            let mut transfer = tx
                .prepare_cached(
                    "INSERT INTO live_transfer(key, bytes, connection_bytes) VALUES (?1,?2,?3)
                    ON CONFLICT(key) DO UPDATE SET bytes=excluded.bytes,
                    connection_bytes=excluded.connection_bytes",
                )
                .map_err(|e| e.to_string())?;
            let mut forget = tx
                .prepare_cached("DELETE FROM live_transfer WHERE key = ?1")
                .map_err(|e| e.to_string())?;
            // Rows no longer observed, and capture attempts, are always new
            // content and carry their final counters in the record. An active
            // row's record is written only when something other than its
            // per-sample timestamps and counters changed; the checkpoint below
            // carries the timestamps for every active row at once, and
            // `live_transfer` the counters.
            for e in &self.pending {
                write_record(&mut write, e)?;
                forget.execute([&e.key]).map_err(|e| e.to_string())?;
            }
            for (id, e) in &self.active {
                let fp = fingerprint(e);
                if fp.is_none() || e.written != fp {
                    write_record(&mut write, e)?;
                }
                let now_counters = counters(e);
                if e.counters_written != Some(now_counters) {
                    let json = |b: Option<Bytes>| serde_json::to_string(&b).map_err(|e| e.to_string());
                    transfer
                        .execute(params![e.key, json(now_counters.0)?, json(now_counters.1)?])
                        .map_err(|e| e.to_string())?;
                }
                committed.push((id.clone(), fp, now_counters));
            }
            if self.last_sample != self.checkpointed {
                if let Some(ts) = self.last_sample {
                    tx.execute(
                        "INSERT INTO checkpoint(id, last_sample) VALUES (1, ?1)
                        ON CONFLICT(id) DO UPDATE SET last_sample=excluded.last_sample",
                        [ts.min(i64::MAX as u64) as i64],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        // Both trims stay on the `observed_time` index: a full scan of the
        // table here would read all of it every checkpoint. The effective
        // time is never older than the stored one, so the stored-time range
        // is a safe prefilter.
        tx.execute(
            &format!(
                "DELETE FROM observations WHERE last_seen < ?1 AND {EFFECTIVE_LAST_SEEN} < ?1"
            ),
            [now.saturating_sub(RETENTION_MS).min(i64::MAX as u64) as i64],
        )
        .map_err(|e| e.to_string())?;
        let rows: i64 = tx
            .query_row("SELECT count(*) FROM observations", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let mut over = if rows > (ROW_CAP + TRIM_SLACK) as i64 {
            rows - ROW_CAP as i64
        } else {
            0
        };
        if over > 0 {
            // Oldest first. Rows no longer observed go first, in stored-time
            // order (for them that is the effective time); rows still present
            // carry the newest sample time, so only a table of nearly nothing
            // but live rows reaches them.
            over -= tx
                .execute(
                    "DELETE FROM observations WHERE key IN (SELECT key FROM observations
                    WHERE active = 0 ORDER BY last_seen ASC, key ASC LIMIT ?1)",
                    [over],
                )
                .map_err(|e| e.to_string())? as i64;
        }
        if over > 0 {
            tx.execute(
                &format!(
                    "DELETE FROM observations WHERE key IN (SELECT key FROM observations
                    ORDER BY {EFFECTIVE_LAST_SEEN} ASC, key ASC LIMIT ?1)"
                ),
                [over],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.execute(
            "DELETE FROM live_transfer WHERE key NOT IN (SELECT key FROM observations)",
            [],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        // Only content that actually committed counts as written.
        for (id, fp, c) in committed {
            if let Some(e) = self.active.get_mut(&id) {
                e.written = fp;
                e.counters_written = Some(c);
            }
        }
        self.checkpointed = self.last_sample;
        self.pending.clear();
        Ok(())
    }

    pub fn query(&self, query: &str, since: u64, limit: usize) -> Result<Vec<Entry>, String> {
        query_db(&self.db, query, since, limit)
    }

    pub fn read(state_dir: &Path, query: &str, since: u64) -> Result<Vec<Entry>, String> {
        let path = private_path(state_dir, false)?;
        let db = open_db(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        query_db(&db, query, since, ROW_CAP)
    }
}

fn write_record(write: &mut rusqlite::CachedStatement<'_>, e: &Entry) -> Result<(), String> {
    let c = &e.connection;
    let search = format!(
        "{} {} {} {} {} {} {} {} {}",
        c.app.name,
        c.app.id,
        c.exe,
        c.remote.ip,
        c.remote.port,
        c.hostname,
        c.country,
        c.proto,
        c.app.pid
    )
    .to_lowercase();
    let record = serde_json::to_string(e).map_err(|e| e.to_string())?;
    if record.len() > 64 * 1024 {
        return Ok(());
    }
    write
        .execute(params![
            e.key,
            e.first_observed.min(i64::MAX as u64) as i64,
            e.last_observed.min(i64::MAX as u64) as i64,
            e.active,
            search,
            record
        ])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Close out the previous daemon session: its active rows become no longer
/// observed, at the last committed sample time and with the last committed
/// counters folded into their records, exactly what a full rewrite at that
/// checkpoint would have stored.
fn fold_previous_session(db: &mut Db) -> Result<(), String> {
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let carried: Vec<(String, String, String, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT o.key, o.record, t.bytes, t.connection_bytes
                FROM observations o JOIN live_transfer t ON t.key = o.key",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    };
    for (key, record, bytes, connection_bytes) in carried {
        // A record this cannot parse keeps what it had: one bad row must not
        // take the whole store offline at startup.
        let (Ok(mut v), Ok(b), Ok(cb)) = (
            serde_json::from_str::<serde_json::Value>(&record),
            serde_json::from_str::<serde_json::Value>(&bytes),
            serde_json::from_str::<serde_json::Value>(&connection_bytes),
        ) else {
            continue;
        };
        if !v.is_object() {
            continue;
        }
        v["bytes"] = b;
        if v.get("connection").is_some_and(|c| c.is_object()) {
            v["connection"]["bytes"] = cb;
        }
        tx.execute(
            "UPDATE observations SET record = ?1 WHERE key = ?2",
            params![v.to_string(), key],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute_batch(&format!(
        "UPDATE observations SET last_seen = {EFFECTIVE_LAST_SEEN}, active = 0 WHERE active = 1;
        DELETE FROM live_transfer;
        DELETE FROM checkpoint;"
    ))
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn has_table(db: &Db, name: &str) -> Result<bool, String> {
    db.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |r| r.get(0),
    )
    .map_err(|e| e.to_string())
}

fn query_db(db: &Db, query: &str, since: u64, limit: usize) -> Result<Vec<Entry>, String> {
    // A store last written by an older daemon has neither table, and a
    // read-only export cannot create them; its rows carry their own values.
    let seen = if has_table(db, "checkpoint")? { EFFECTIVE_LAST_SEEN } else { "last_seen" };
    let (counters, join) = if has_table(db, "live_transfer")? {
        ("t.bytes, t.connection_bytes", "LEFT JOIN live_transfer t ON t.key = o.key")
    } else {
        ("NULL, NULL", "")
    };
    let mut stmt = db.prepare(&format!("SELECT o.record, o.active, {seen} AS seen, {counters} FROM observations o {join} WHERE seen >= ?1 AND instr(o.search, ?2) > 0 ORDER BY seen DESC, o.key DESC LIMIT ?3")).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            params![
                since.min(i64::MAX as u64) as i64,
                query.to_lowercase(),
                limit.min(ROW_CAP) as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let (json, active, seen, bytes, connection_bytes) = r.map_err(|e| e.to_string())?;
        let mut e: Entry = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        e.active = active;
        // The columns and `live_transfer` are authoritative. A record skipped
        // because only its timestamps or counters moved still holds the values
        // of its last write; restore what a full rewrite would have stored,
        // the lockstep evidence timestamp included (see `fingerprint`).
        let written_at = e.last_observed;
        e.last_observed = seen.max(0) as u64;
        if let Some(ev) = e.connection.evidence.as_mut() {
            if ev.recorded_at == written_at {
                ev.recorded_at = e.last_observed;
            }
        }
        if let (Some(b), Some(cb)) = (bytes, connection_bytes) {
            e.bytes = serde_json::from_str(&b).map_err(|e| e.to_string())?;
            e.connection.bytes = serde_json::from_str(&cb).map_err(|e| e.to_string())?;
        }
        out.push(e);
    }
    Ok(out)
}

pub fn csv(entries: &[Entry]) -> String {
    fn cell(s: &str) -> String {
        // Prevent spreadsheet formulas in process names and destination names.
        let prefix = if s.trim_start().starts_with(['=', '+', '-', '@', '\t', '\r']) {
            "'"
        } else {
            ""
        };
        format!("\"{prefix}{}\"", s.replace('"', "\"\""))
    }
    let mut out = String::from("first_observed_ms,last_observed_ms,app,executable,protocol,destination,port,hostname,country,sampled_tx_bytes,sampled_rx_bytes,present_at_last_sample\n");
    for e in entries {
        let c = &e.connection;
        let fields = [
            e.first_observed.to_string(),
            e.last_observed.to_string(),
            c.app.name.clone(),
            c.exe.clone(),
            c.proto.clone(),
            c.remote.ip.clone(),
            c.remote.port.to_string(),
            c.hostname.clone(),
            c.country.clone(),
            e.bytes.map(|b| b.tx.to_string()).unwrap_or_default(),
            e.bytes.map(|b| b.rx.to_string()).unwrap_or_default(),
            e.active.to_string(),
        ];
        out.push_str(&fields.iter().map(|s| cell(s)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_store(db: &Db) -> i64 {
        db.query_row("PRAGMA temp_store", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn both_opens_keep_temp_space_in_memory() {
        let d = std::env::temp_dir().join(format!("vallum-history-temp-store-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        let h = History::open(&d, 1_000_000).unwrap();
        // 2 = MEMORY. The system unit has no writable temp directory, so a
        // file-backed temp store fails the restart fold (see open_db).
        assert_eq!(temp_store(&h.db), 2);
        drop(h);
        let ro = open_db(
            &private_path(&d, false).unwrap(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(temp_store(&ro), 2);
        drop(ro);
        fs::remove_dir_all(&d).unwrap();
    }
}
