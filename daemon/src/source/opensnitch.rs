//! OpenSnitch source driver.
//!
//! Reads the event database that `opensnitch-ui` maintains when its storage is
//! configured to a file, and normalises rows into [`Flow`].
//!
//! # Clean-room boundary
//!
//! OpenSnitch is GPL-3.0 and vallum is not. See `THIRD-PARTY.md` section 3 —
//! the rule is binding, not advisory. Everything this module knows about
//! OpenSnitch is *interface*: the name of a table, the names of some columns,
//! two keys in an INI file. None of it was taken from their implementation, and
//! none of it may be. Interoperating with GPL software creates no derivative
//! work; adapting its source does.
//!
//! The column names come from omasnatch's `collector.py`, an MIT-licensed third
//! party that reads the same database (`THIRD-PARTY.md` section 2).
//!
//! # This driver never writes
//!
//! The database belongs to another program, which is actively writing it. The
//! connection is opened through a percent-encoded `mode=ro` URI so a crafted
//! path cannot talk us out of read-only, and nothing here issues a statement
//! that is not a `SELECT` or a `PRAGMA`.

use crate::fileguard::{read_capped, ro_uri};
use crate::flow::{
    Action, App, Bytes, Flow, FlowState, Peer, Provenance, SourceKind, Verdict, SCHEMA_VERSION,
};
use crate::source::{Backfill, Source, SourceError};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// `settings.conf` is a few kilobytes of INI and is re-read to pick up a
/// database path the user changed. A file orders of magnitude larger is not a
/// config, so it is read to a ceiling and refused above it.
const MAX_SETTINGS_BYTES: usize = 1024 * 1024;

/// Rows per poll. The poll interval is sub-second, so this is a ceiling on
/// burst catch-up, not a throughput limit.
const BATCH: usize = 512;

/// Columns worth having if the installed schema has them. Only `time` is
/// required; every other absence degrades one field rather than the driver.
const WANTED: &[&str] = &[
    "time", "action", "process", "dst_host", "dst_ip", "dst_port", "protocol", "src_ip",
    "src_port", "uid", "pid",
];

/// Which of [`WANTED`] this install actually has, in the order they are
/// selected.
struct Columns(Vec<String>);

impl Columns {
    fn index_of(&self, name: &str) -> Option<usize> {
        self.0.iter().position(|c| c == name)
    }

    fn select_list(&self) -> String {
        self.0
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Incremental position in a table that has no column we can trust to be
/// monotonic except the timestamp.
///
/// A timestamp is not unique, so a bare `time > watermark` drops every row that
/// shares its second with the last one read, and `time >= watermark` re-reads
/// them forever. The cursor therefore keeps the ids already emitted *at* the
/// watermark second and filters them out, which is bounded by one second of
/// traffic rather than by the size of the database.
///
/// A row inserted later but stamped earlier than the watermark is not seen.
/// That is a real hole and an acceptable one: it needs another program to write
/// history out of order into a database it is appending to live.
#[derive(Default)]
struct Cursor {
    watermark: Option<String>,
    emitted_at_watermark: HashSet<String>,
}

pub struct OpenSnitchSource {
    db_path: PathBuf,
    conn: Connection,
    columns: Columns,
    cursor: Cursor,
    /// How OpenSnitch's `time` text is interpreted. See [`parse_ts_ms`].
    assume_utc: bool,
}

impl OpenSnitchSource {
    /// Open the configured database, or explain why there isn't one.
    ///
    /// Every "not set up" case is [`SourceError::Unavailable`], because a
    /// desktop that simply does not run OpenSnitch is the common case and not
    /// an error anyone needs to see.
    pub fn open(
        settings: Option<&Path>,
        backfill: Backfill,
        assume_utc: bool,
    ) -> Result<Self, SourceError> {
        let settings = settings
            .map(PathBuf::from)
            .unwrap_or_else(default_settings_path);
        let text = read_capped(&settings, MAX_SETTINGS_BYTES).ok_or_else(|| {
            SourceError::Unavailable(format!("no readable settings at {}", settings.display()))
        })?;
        let db_path = db_path_from_settings(&text).ok_or_else(|| {
            SourceError::Unavailable(
                "OpenSnitch is not storing events in a file (Preferences -> Database type: File)"
                    .into(),
            )
        })?;
        if !db_path.exists() {
            return Err(SourceError::Unavailable(format!(
                "configured database {} does not exist yet",
                db_path.display()
            )));
        }
        Self::open_db(&db_path, backfill, assume_utc)
    }

    /// Open a database directly, bypassing settings discovery. The test path,
    /// and what `--os-db` uses.
    pub fn open_db(
        db_path: &Path,
        backfill: Backfill,
        assume_utc: bool,
    ) -> Result<Self, SourceError> {
        // Belt and braces: the URI says `mode=ro` and the flags say read-only.
        // Either alone would do; both together mean a mistake in one of them
        // cannot hand us a writable handle on someone else's live database.
        let conn = Connection::open_with_flags(
            ro_uri(db_path),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| SourceError::Failed(format!("open {}: {e}", db_path.display())))?;

        let columns = probe_columns(&conn)?;
        let mut me = Self {
            db_path: db_path.to_path_buf(),
            conn,
            columns,
            cursor: Cursor::default(),
            assume_utc,
        };
        me.cursor.watermark = me.initial_watermark(backfill)?;
        Ok(me)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Where to start reading on the first poll.
    ///
    /// `None` means "from the beginning of the table".
    fn initial_watermark(&self, backfill: Backfill) -> Result<Option<String>, SourceError> {
        match backfill {
            Backfill::All => Ok(None),
            Backfill::Today => Ok(Some(local_midnight_text())),
            Backfill::None => {
                // Start at the newest row rather than at "now": a clock that
                // disagrees with the database's own stamps would otherwise skip
                // or replay, and the database's idea of the present is the only
                // one that matters for a cursor compared against it.
                let max: Option<String> = self
                    .conn
                    .query_row("SELECT MAX(\"time\") FROM connections", [], |r| r.get(0))
                    .map_err(|e| SourceError::Failed(format!("watermark: {e}")))?;
                Ok(max)
            }
        }
    }

    fn read_batch(&mut self) -> Result<Vec<Flow>, SourceError> {
        let sql = format!(
            "SELECT {} FROM connections {} ORDER BY \"time\" ASC LIMIT {}",
            self.columns.select_list(),
            if self.cursor.watermark.is_some() {
                "WHERE \"time\" >= ?1"
            } else {
                ""
            },
            BATCH
        );
        let mut stmt = self
            .conn
            .prepare_cached(&sql)
            .map_err(|e| SourceError::Failed(format!("prepare: {e}")))?;

        let time_idx = self.columns.index_of("time").unwrap_or(0);
        let mut out = Vec::new();
        let mut max_time: Option<String> = None;
        let mut at_max: HashSet<String> = HashSet::new();

        let mut rows = match &self.cursor.watermark {
            Some(w) => stmt.query([w.as_str()]),
            None => stmt.query([]),
        }
        .map_err(|e| SourceError::Failed(format!("query: {e}")))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| SourceError::Failed(format!("row: {e}")))?
        {
            let Some(time_text) = cell_text(row, time_idx) else {
                continue;
            };
            let flow = self.row_to_flow(row, &time_text);

            // Track the newest second in this batch and everything emitted in
            // it, so the next poll can re-ask for that second without
            // re-emitting what it already produced.
            match &max_time {
                Some(m) if *m == time_text => {
                    at_max.insert(flow.id.clone());
                }
                Some(m) if *m > time_text => {}
                _ => {
                    max_time = Some(time_text.clone());
                    at_max.clear();
                    at_max.insert(flow.id.clone());
                }
            }

            let already = self.cursor.watermark.as_deref() == Some(time_text.as_str())
                && self.cursor.emitted_at_watermark.contains(&flow.id);
            if !already {
                out.push(flow);
            }
        }

        if let Some(m) = max_time {
            if self.cursor.watermark.as_deref() == Some(m.as_str()) {
                // Same second as before: accumulate, do not forget what an
                // earlier poll already emitted within it.
                self.cursor.emitted_at_watermark.extend(at_max);
            } else {
                self.cursor.watermark = Some(m);
                self.cursor.emitted_at_watermark = at_max;
            }
        }
        Ok(out)
    }

    fn row_to_flow(&self, row: &rusqlite::Row<'_>, time_text: &str) -> Flow {
        let get = |name: &str| self.columns.index_of(name).and_then(|i| cell_text(row, i));

        let process = get("process").unwrap_or_default();
        let dst_ip = get("dst_ip").unwrap_or_default();
        let dst_port = get("dst_port")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let proto = get("protocol").unwrap_or_default().to_lowercase();
        let host = get("dst_host").filter(|h| !h.is_empty());
        let action = get("action").unwrap_or_default();

        let local = match (
            get("src_ip"),
            get("src_port").and_then(|s| s.parse::<u16>().ok()),
        ) {
            (Some(ip), Some(port)) if !ip.is_empty() => Some(Peer {
                ip,
                port,
                host: None,
            }),
            // A destination we know and a source port we do not is normal for a
            // store of past decisions. Null says so; a zero port would claim we
            // measured one.
            _ => None,
        };

        let id = flow_id(time_text, &process, &proto, &dst_ip, dst_port);

        Flow {
            schema: SCHEMA_VERSION,
            kind: "flow".into(),
            ts: parse_ts_ms(time_text, self.assume_utc).unwrap_or_else(crate::event::now_ms),
            id,
            source: SourceKind::Opensnitch,
            // Every row is a decision already taken about a connection that is
            // no longer in flight. `live` would claim a socket we cannot see.
            state: FlowState::Closed,
            app: App {
                key: process.clone(),
                name: None,
                desktop: None,
                icon: None,
                pid: get("pid").and_then(|s| s.parse().ok()),
                hash: None,
                container: None,
                system: false,
            },
            proto,
            local,
            remote: Peer {
                ip: dst_ip,
                port: dst_port,
                host,
            },
            verdict: Verdict {
                action: map_action(&action),
                // OpenSnitch does record which rule fired, but under a column
                // this driver has not verified. Claiming a rule id we did not
                // read would make the fleet console audit a fiction.
                rule_id: None,
                // Not `default`: vallum did not decide this, and saying it did
                // would be a lie the audit trail cannot detect later.
                provenance: Provenance::External,
            },
            geo: None,
            // OpenSnitch's connections table is a decision log, not an
            // accounting record. Unmeasured, so null.
            bytes: None::<Bytes>,
            new_network: false,
            network_key: String::new(),
        }
    }
}

impl Source for OpenSnitchSource {
    fn name(&self) -> &'static str {
        "opensnitch"
    }

    fn poll(&mut self) -> Result<Vec<Flow>, SourceError> {
        self.read_batch()
    }
}

/// Map OpenSnitch's action text onto the schema's verdict actions.
///
/// Unknown text becomes `observed` rather than `allow`: an action we do not
/// understand is not evidence that traffic was permitted, and defaulting a
/// security field to the permissive value is how a parser change becomes a
/// silent policy change.
fn map_action(s: &str) -> Action {
    match s.trim().to_lowercase().as_str() {
        "allow" => Action::Allow,
        "deny" | "drop" => Action::Deny,
        "reject" => Action::Reject,
        _ => Action::Observed,
    }
}

/// Read a cell as text whatever SQLite chose to store in it.
///
/// `dst_port` is an integer in some installs and text in others, and a strict
/// typed getter turns that into a hard failure on a database vallum does not
/// control. Widening here is cheaper than being wrong about a foreign schema.
fn cell_text(row: &rusqlite::Row<'_>, idx: usize) -> Option<String> {
    match row.get_ref(idx).ok()? {
        ValueRef::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Null | ValueRef::Blob(_) => None,
    }
}

fn probe_columns(conn: &Connection) -> Result<Columns, SourceError> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(connections)")
        .map_err(|e| SourceError::Failed(format!("table_info: {e}")))?;
    let found: HashSet<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| SourceError::Failed(format!("table_info: {e}")))?
        .filter_map(Result::ok)
        .collect();

    if found.is_empty() {
        return Err(SourceError::Unavailable(
            "no `connections` table — this is not an OpenSnitch event database".into(),
        ));
    }
    if !found.contains("time") {
        return Err(SourceError::Failed(
            "`connections` has no `time` column, so there is nothing to page on".into(),
        ));
    }
    Ok(Columns(
        WANTED
            .iter()
            .filter(|w| found.contains(**w))
            .map(|w| w.to_string())
            .collect(),
    ))
}

fn default_settings_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".config/opensnitch/settings.conf")
}

/// Pull the event database path out of OpenSnitch's INI settings.
///
/// Two keys, so a config-file crate would be a dependency bought for nothing.
/// `type = 1` is "store to a file"; anything else means there is no database to
/// read and the source is simply unavailable.
fn db_path_from_settings(text: &str) -> Option<PathBuf> {
    let mut section = String::new();
    let mut db_type = None;
    let mut file = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }
        if section != "database" {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim().to_lowercase().as_str() {
            "type" => db_type = Some(v.trim().to_string()),
            "file" => file = Some(v.trim().to_string()),
            _ => {}
        }
    }
    if db_type.as_deref() != Some("1") {
        return None;
    }
    let raw = file?;
    if raw.is_empty() {
        return None;
    }
    Some(PathBuf::from(expand_tilde(&raw)))
}

fn expand_tilde(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(h) if !h.is_empty() => format!("{h}/{rest}"),
            _ => p.to_string(),
        },
        None => p.to_string(),
    }
}

/// FNV-1a over the row's identifying tuple.
///
/// The table has no id column this driver is willing to depend on, so identity
/// is derived from content. Two byte-identical rows collapse to one flow, which
/// is the behaviour we want for a store that records one row per unique
/// connection.
fn flow_id(time: &str, process: &str, proto: &str, ip: &str, port: u16) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [time, process, proto, ip, &port.to_string()] {
        for b in part.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("os:{h:016x}")
}

/// Parse OpenSnitch's `time` text into epoch milliseconds.
///
/// Accepts `YYYY-MM-DD HH:MM:SS` and the same with a `T` separator and/or a
/// fractional part, which are the shapes SQLite's own datetime functions
/// produce.
///
/// **Timezone is an assumption, not a fact.** The stamp carries no offset, and
/// this driver has not read OpenSnitch's source to find out which one it means
/// (`THIRD-PARTY.md` section 3). Local time is the default because that is what
/// desktop software writing a human-readable stamp almost always means, and
/// `--os-time-utc` exists so the assumption can be falsified by whoever has a
/// real database in front of them rather than argued about here.
///
/// Ordering never depends on this. The cursor compares the raw text, which is
/// lexically ordered by construction in this format, so a wrong guess misdates
/// a display timestamp and cannot corrupt the incremental read.
pub fn parse_ts_ms(text: &str, assume_utc: bool) -> Option<u64> {
    let t = text.trim();
    if t.len() < 19 {
        return None;
    }
    let b = t.as_bytes();
    if b[10] != b' ' && b[10] != b'T' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }

    let secs = if assume_utc {
        (days_from_civil(y, mo, d) * 86_400) + h * 3600 + mi * 60 + s
    } else {
        // `mktime` with `tm_isdst = -1` is the definition of "interpret this
        // wall clock in the local zone", DST transitions included. Doing it by
        // hand would mean shipping a timezone database.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = (y - 1900) as libc::c_int;
        tm.tm_mon = (mo - 1) as libc::c_int;
        tm.tm_mday = d as libc::c_int;
        tm.tm_hour = h as libc::c_int;
        tm.tm_min = mi as libc::c_int;
        tm.tm_sec = s as libc::c_int;
        tm.tm_isdst = -1;
        // SAFETY: `tm` is fully initialised above and `mktime` only reads it
        // and normalises it in place.
        let e = unsafe { libc::mktime(&mut tm) };
        if e == -1 {
            return None;
        }
        e as i64
    };
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000)
}

/// Days since 1970-01-01 from a proleptic Gregorian date (Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Local midnight in the same text shape the `time` column uses, so it can be
/// compared against it directly.
fn local_midnight_text() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid time_t and `tm` is a valid out-pointer.
    unsafe { libc::localtime_r(&now, &mut tm) };
    format!(
        "{:04}-{:02}-{:02} 00:00:00",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(rows: &[(&str, &str, &str, &str, i64, &str)]) -> (tempdb::Dir, PathBuf) {
        let dir = tempdb::Dir::new("os");
        let path = dir.0.join("events.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE connections (
                time TEXT, action TEXT, process TEXT,
                dst_host TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT);",
        )
        .unwrap();
        for (t, a, p, host, port, proto) in rows {
            c.execute(
                "INSERT INTO connections VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![t, a, p, host, "1.2.3.4", port, proto],
            )
            .unwrap();
        }
        drop(c);
        (dir, path)
    }

    mod tempdb {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new(tag: &str) -> Self {
                let p = std::env::temp_dir().join(format!(
                    "vallum-{tag}-{}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn settings_parse_requires_file_storage() {
        let ini = "[global]\ndefault_action=1\n\n[database]\ntype=1\nfile=/tmp/ev.db\n";
        assert_eq!(
            db_path_from_settings(ini),
            Some(PathBuf::from("/tmp/ev.db"))
        );
        // In-memory storage is the default; there is nothing to read, and that
        // is unavailability rather than breakage.
        assert!(db_path_from_settings("[database]\ntype=0\nfile=/tmp/ev.db\n").is_none());
        assert!(db_path_from_settings("[database]\ntype=1\nfile=\n").is_none());
        // A `file` key outside the [database] section must not be picked up.
        assert!(db_path_from_settings("[global]\ntype=1\nfile=/tmp/ev.db\n").is_none());
    }

    #[test]
    fn settings_parse_tolerates_comments_and_case() {
        let ini = "; a comment\n[DataBase]\n# another\nType = 1\nFile = /tmp/x.db\n";
        assert_eq!(db_path_from_settings(ini), Some(PathBuf::from("/tmp/x.db")));
    }

    #[test]
    fn unknown_action_is_never_allow() {
        // The canary for the permissive-default trap.
        assert_eq!(map_action("allow"), Action::Allow);
        assert_eq!(map_action("DENY"), Action::Deny);
        assert_eq!(map_action("reject"), Action::Reject);
        assert_eq!(map_action("something-new"), Action::Observed);
        assert_eq!(map_action(""), Action::Observed);
    }

    #[test]
    fn timestamps_parse_in_both_shapes() {
        let a = parse_ts_ms("2026-09-11 00:00:00", true).unwrap();
        let b = parse_ts_ms("2026-09-11T00:00:00.123", true).unwrap();
        assert_eq!(a, b);
        assert_eq!(parse_ts_ms("1970-01-01 00:00:01", true), Some(1000));
        assert!(parse_ts_ms("not a time", true).is_none());
        assert!(parse_ts_ms("2026-13-01 00:00:00", true).is_none());
        assert!(parse_ts_ms("2026-09-11 25:00:00", true).is_none());
    }

    #[test]
    fn reads_rows_and_normalises_them() {
        let (_d, db) = fixture(&[(
            "2026-09-11 10:00:00",
            "deny",
            "/usr/bin/curl",
            "example.com",
            443,
            "tcp",
        )]);
        let mut s = OpenSnitchSource::open_db(&db, Backfill::All, true).unwrap();
        let flows = s.poll().unwrap();
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.app.key, "/usr/bin/curl");
        assert_eq!(f.remote.host.as_deref(), Some("example.com"));
        assert_eq!(f.remote.port, 443);
        assert_eq!(f.verdict.action, Action::Deny);
        // A decision another engine made is never reported as ours.
        assert_eq!(f.verdict.provenance, Provenance::External);
        assert!(f.bytes.is_none());
        // No src_port column in this fixture: null, not a fabricated zero.
        assert!(f.local.is_none());
    }

    #[test]
    fn same_second_rows_are_emitted_once_and_only_once() {
        // The cursor's whole reason to exist. Three rows share a second, so
        // `time > watermark` would lose two and `time >= watermark` would
        // replay all three on every poll, forever.
        let (_d, db) = fixture(&[
            (
                "2026-09-11 10:00:00",
                "allow",
                "/bin/a",
                "a.test",
                80,
                "tcp",
            ),
            (
                "2026-09-11 10:00:00",
                "allow",
                "/bin/b",
                "b.test",
                80,
                "tcp",
            ),
            (
                "2026-09-11 10:00:00",
                "allow",
                "/bin/c",
                "c.test",
                80,
                "tcp",
            ),
        ]);
        let mut s = OpenSnitchSource::open_db(&db, Backfill::All, true).unwrap();
        assert_eq!(s.poll().unwrap().len(), 3);
        assert_eq!(s.poll().unwrap().len(), 0, "second poll must be quiet");
        assert_eq!(s.poll().unwrap().len(), 0);
    }

    #[test]
    fn a_new_row_in_the_watermark_second_is_still_delivered() {
        let (_d, db) = fixture(&[(
            "2026-09-11 10:00:00",
            "allow",
            "/bin/a",
            "a.test",
            80,
            "tcp",
        )]);
        let mut s = OpenSnitchSource::open_db(&db, Backfill::All, true).unwrap();
        assert_eq!(s.poll().unwrap().len(), 1);

        let w = Connection::open(&db).unwrap();
        w.execute(
            "INSERT INTO connections VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                "2026-09-11 10:00:00",
                "deny",
                "/bin/late",
                "late.test",
                "1.2.3.4",
                80,
                "tcp"
            ],
        )
        .unwrap();
        drop(w);

        let flows = s.poll().unwrap();
        assert_eq!(flows.len(), 1, "row sharing the watermark second was lost");
        assert_eq!(flows[0].app.key, "/bin/late");
    }

    #[test]
    fn backfill_none_starts_at_the_end() {
        let (_d, db) = fixture(&[
            (
                "2026-09-11 10:00:00",
                "allow",
                "/bin/old",
                "o.test",
                80,
                "tcp",
            ),
            (
                "2026-09-11 10:00:01",
                "allow",
                "/bin/new",
                "n.test",
                80,
                "tcp",
            ),
        ]);
        let mut s = OpenSnitchSource::open_db(&db, Backfill::None, true).unwrap();
        // The newest row is at the watermark and was emitted before we started,
        // conceptually — but nothing has been emitted yet, so it comes through
        // once and history stays out.
        let first = s.poll().unwrap();
        assert!(first.iter().all(|f| f.app.key != "/bin/old"));
        assert_eq!(s.poll().unwrap().len(), 0);
    }

    #[test]
    fn a_foreign_database_is_unavailable_not_a_crash() {
        let dir = tempdb::Dir::new("foreign");
        let path = dir.0.join("other.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE notes (body TEXT);").unwrap();
        drop(c);
        match OpenSnitchSource::open_db(&path, Backfill::All, true) {
            Err(SourceError::Unavailable(_)) => {}
            Err(e) => panic!("expected Unavailable, got {e}"),
            Ok(_) => panic!("expected Unavailable, got a working source"),
        }
    }

    #[test]
    fn missing_optional_columns_degrade_one_field_each() {
        let dir = tempdb::Dir::new("sparse");
        let path = dir.0.join("sparse.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE connections (time TEXT, process TEXT, dst_ip TEXT);
             INSERT INTO connections VALUES ('2026-09-11 10:00:00','/bin/x','9.9.9.9');",
        )
        .unwrap();
        drop(c);
        let mut s = OpenSnitchSource::open_db(&path, Backfill::All, true).unwrap();
        let f = &s.poll().unwrap()[0];
        assert_eq!(f.app.key, "/bin/x");
        assert_eq!(f.remote.ip, "9.9.9.9");
        assert_eq!(f.remote.port, 0);
        // No action column at all is still not permission to say "allow".
        assert_eq!(f.verdict.action, Action::Observed);
    }

    #[test]
    fn integer_or_text_ports_both_read() {
        let dir = tempdb::Dir::new("porttype");
        let path = dir.0.join("p.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE connections (time TEXT, process TEXT, dst_ip TEXT, dst_port TEXT);
             INSERT INTO connections VALUES ('2026-09-11 10:00:00','/bin/x','9.9.9.9','8443');",
        )
        .unwrap();
        drop(c);
        let mut s = OpenSnitchSource::open_db(&path, Backfill::All, true).unwrap();
        assert_eq!(s.poll().unwrap()[0].remote.port, 8443);
    }

    #[test]
    fn the_connection_is_read_only() {
        let (_d, db) = fixture(&[(
            "2026-09-11 10:00:00",
            "allow",
            "/bin/a",
            "a.test",
            80,
            "tcp",
        )]);
        let s = OpenSnitchSource::open_db(&db, Backfill::All, true).unwrap();
        // The single most important property of this driver: OpenSnitch's
        // database is theirs, it is being written live, and vallum holding a
        // writable handle on it is the failure that loses someone's data.
        assert!(s.conn.execute("DELETE FROM connections", []).is_err());
        assert!(s
            .conn
            .execute_batch("CREATE TABLE vallum_was_here (x INT)")
            .is_err());
    }
}
