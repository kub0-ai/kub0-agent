use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
};
use vallumd::{
    event::Connection,
    history::{History, RETENTION_MS, ROW_CAP, TRIM_SLACK},
    traffic::{self, Bytes, SocketTraffic, Tracker},
};

fn row(id: &str, proto: &str) -> Connection {
    serde_json::from_value(serde_json::json!({
        "id": id, "proto": proto, "inode": 42, "exe": "/usr/bin/probe",
        "app": { "id": "probe", "name": "Probe", "icon": "", "desktop": "", "pid": 4321 },
        "local": {"ip":"127.0.0.1", "port": 40000}, "remote":{"ip":"127.0.0.1", "port":443},
        "state":"ESTABLISHED", "hostname":"probe.example", "country":"DE"
    }))
    .unwrap()
}
fn stat(r: &Connection, cookie: u64, tx: u64, rx: u64) -> HashMap<u64, SocketTraffic> {
    HashMap::from([(
        42,
        SocketTraffic {
            cookie,
            bytes: Bytes { tx, rx },
            local: r.local.clone(),
            remote: r.remote.clone(),
        },
    )])
}
fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vallum-traffic-history-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn rates_use_elapsed_time_and_only_measured_deltas() {
    let r = row("one", "tcp");
    let mut t = Tracker::default();
    let first = t.sample(&[r.clone()], &stat(&r, 123, 500000, 300000), 1000);
    assert_eq!(first[0].tx_bytes, 0);
    assert_eq!(first[0].tx_rate, None);
    let next = t.sample(&[r.clone()], &stat(&r, 123, 502000, 304000), 3000);
    assert_eq!(next[0].tx_rate, Some(1000.0));
    assert_eq!(next[0].rx_rate, Some(2000.0));
    assert_eq!(next[0].tx_bytes, 2000);
    assert_eq!(next[0].rx_bytes, 4000);
    let gap = t.sample(&[r.clone()], &HashMap::new(), 4000);
    assert_eq!(gap[0].measured, 0);
    assert_eq!(gap[0].tx_rate, None);
    let recovered = t.sample(&[r.clone()], &stat(&r, 123, 800000, 900000), 5000);
    assert_eq!(recovered[0].tx_rate, None);
    assert_eq!(recovered[0].tx_bytes, 2000);
    let recycled = t.sample(&[r.clone()], &stat(&r, 999, 1000000, 1200000), 6000);
    assert_eq!(recycled[0].tx_rate, None);
    assert_eq!(recycled[0].tx_bytes, 2000);
    let reset = t.sample(&[r.clone()], &stat(&r, 999, 0, 0), 7000);
    assert_eq!(reset[0].tx_rate, None);
    assert_eq!(reset[0].tx_bytes, 2000);
    assert!(t
        .sample(&[row("udp", "udp")], &stat(&r, 123, 10, 20), 8000)
        .is_empty());
}

#[test]
fn capture_attempts_survive_restart_without_live_or_byte_claims() {
    let d = dir("capture");
    let now = 1000000;
    let frame = serde_json::json!({"type":"attempt","uid":1000,"pid":4321,"ts":now,
        "proto":"udp","operation":"sendmsg","ip":"127.0.0.1","port":443,
        "commHex":"70726f62650000000000000000000000"})
    .to_string();
    let vallumd::capture::Message::Attempt(c) =
        vallumd::capture::decode(&frame, 1000, 1, now).unwrap()
    else {
        panic!()
    };
    let mut h = History::open(&d, now).unwrap();
    h.record_attempt(c);
    h.observe(&[], now + 500);
    h.flush(now + 500).unwrap();
    drop(h);
    let h = History::open(&d, now + 1000).unwrap();
    let rows = h.query("probe", 0, 200).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].active);
    assert_eq!(rows[0].last_observed, now);
    assert!(rows[0].bytes.is_none());
    assert_eq!(rows[0].connection.state, "sendmsg-attempt");
    assert!(rows[0]
        .connection
        .evidence
        .as_ref()
        .unwrap()
        .verdict
        .is_none());
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn multiple_sockets_aggregate_without_hiding_missing_measurements() {
    let r = row("one", "tcp");
    let mut other = r.clone();
    other.id = "two".into();
    other.inode = 43;
    let rows = vec![r.clone(), other.clone()];
    let mut t = Tracker::default();
    let mut stats = stat(&r, 1, 50, 100);
    stats.insert(
        43,
        SocketTraffic {
            cookie: 2,
            bytes: Bytes { tx: 20, rx: 30 },
            local: other.local.clone(),
            remote: other.remote.clone(),
        },
    );
    t.sample(&rows, &stats, 1000);
    stats.get_mut(&42).unwrap().bytes = Bytes { tx: 60, rx: 200 };
    stats.get_mut(&43).unwrap().bytes = Bytes { tx: 40, rx: 80 };
    let apps = t.sample(&rows, &stats, 2000);
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].tx_rate, Some(30.0));
    assert_eq!(apps[0].rx_bytes, 150);
    stats.remove(&43);
    let apps = t.sample(&rows, &stats, 3000);
    assert_eq!(apps[0].measured, 1);
    assert_eq!(apps[0].tcp, 2);
    assert_eq!(apps[0].rx_rate, None);
}

#[test]
fn history_survives_restart_searches_and_counts_only_sampled_bytes() {
    let d = dir("persist");
    let now = 1000000;
    let mut h = History::open(&d, now).unwrap();
    let mut r = row("one", "tcp");
    r.bytes = Some(Bytes {
        tx: 10000,
        rx: 20000,
    });
    h.observe(&[r.clone()], now);
    r.bytes = Some(Bytes {
        tx: 11024,
        rx: 22048,
    });
    h.observe(&[r], now + 1000);
    h.observe(&[], now + 2000);
    h.flush(now + 2000).unwrap();
    let rows = h.query("PROBE.EXAMPLE", 0, 200).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].active);
    assert_eq!(rows[0].first_observed, now);
    assert_eq!(rows[0].last_observed, now + 1000);
    assert_eq!(rows[0].bytes, Some(Bytes { tx: 1024, rx: 2048 }));
    assert_eq!(h.query("/usr/bin/probe", 0, 200).unwrap().len(), 1);
    assert!(h.query("no match", 0, 200).unwrap().is_empty());
    assert!(h.query("%", 0, 200).unwrap().is_empty()); // literal, no SQL wildcard interpretation
    assert!(h.query("probe", now + 1001, 200).unwrap().is_empty());
    assert!(History::open(&d, now).is_err()); // a second daemon cannot rewrite active state
    drop(h);
    let mut reopened = History::open(&d, now + 3000).unwrap();
    assert_eq!(reopened.query("443", 0, 200).unwrap().len(), 1);
    reopened.observe(&[row("udp", "udp")], now + 4000);
    reopened.flush(now + 4000).unwrap();
    assert!(reopened.query("udp", 0, 200).unwrap()[0].bytes.is_none());
    drop(reopened);
    let again = History::open(&d, now + 5000).unwrap();
    assert!(!again.query("udp", 0, 200).unwrap()[0].active);
    drop(again);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn history_retention_and_row_cap_are_enforced_on_disk() {
    let d = dir("cap");
    let now = RETENTION_MS * 2;
    let mut h = History::open(&d, now).unwrap();
    h.observe(&[row("old", "tcp")], now - RETENTION_MS - 1);
    h.observe(&[], now);
    let mut rows = Vec::new();
    for i in 0..ROW_CAP + TRIM_SLACK + 2 {
        rows.push(row(&format!("c-{i}"), "tcp"));
    }
    h.observe(&rows, now);
    h.flush(now).unwrap();
    // Past the slack, the file itself is trimmed back to exactly the cap.
    assert_eq!(rows_on_disk(&d), ROW_CAP as i64);
    assert_eq!(h.query("", 0, ROW_CAP + 10).unwrap().len(), ROW_CAP);
    assert!(h.query("", now + 1, 200).unwrap().is_empty());
    assert_eq!(History::read(&d, "", 0).unwrap().len(), ROW_CAP);
    h.flush(now + RETENTION_MS + 1).unwrap();
    assert!(h.query("", 0, 200).unwrap().is_empty());
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn history_refuses_symlinks_and_exports_unknown_as_blank() {
    let d = dir("security");
    let target = d.join("outside");
    std::fs::write(&target, b"canary").unwrap();
    std::os::unix::fs::symlink(&target, d.join("history.sqlite")).unwrap();
    assert!(History::open(&d, 1000).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"canary");
    std::fs::remove_file(d.join("history.sqlite")).unwrap();
    let mut h = History::open(&d, 1000).unwrap();
    let mut r = row("csv", "udp");
    r.app.name = "=1+1,\"name\"".into();
    h.observe(&[r], 1000);
    h.flush(1000).unwrap();
    let csv = vallumd::history::csv(&h.query("", 0, 200).unwrap());
    assert!(csv.contains("\"'=1+1,\"\"name\"\"\""));
    assert!(csv.contains("\"/usr/bin/probe\""));
    assert!(csv.contains(",\"\",\"\",\"true\""));
    assert_eq!(
        std::fs::metadata(d.join("history.sqlite"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_counters_measure_an_actual_local_tcp_transfer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let local = client.local_addr().unwrap();
    let remote = client.peer_addr().unwrap();
    let find = |stats: HashMap<u64, SocketTraffic>| {
        stats
            .into_values()
            .find(|s| s.local.port == local.port() && s.remote.port == remote.port())
            .unwrap()
    };
    let before = find(traffic::read());
    client.write_all(&[42; 8192]).unwrap();
    let mut read = [0; 8192];
    server.read_exact(&mut read).unwrap();
    server.write_all(&[43; 4096]).unwrap();
    client.read_exact(&mut read[..4096]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let after = find(traffic::read());
    assert!(after.bytes.tx >= before.bytes.tx + 8192);
    assert!(after.bytes.rx >= before.bytes.rx + 4096);
}

/// A procfs row as `sample()` builds it: the evidence timestamp is the sample time.
fn sampled(id: &str, ts: u64, tx: u64) -> Connection {
    let mut r = row(id, "tcp");
    r.evidence = Some(vallumd::event::ConnectionEvidence {
        source: vallumd::flow::SourceKind::Procfs,
        recorded_at: ts,
        verdict: None,
        owner_method: "procfs".into(),
        hash: None,
        container: None,
        lineage: None,
        package: None,
    });
    r.bytes = Some(Bytes { tx, rx: 7 });
    r
}

fn stored_record(d: &std::path::Path) -> serde_json::Value {
    let db = rusqlite::Connection::open_with_flags(
        d.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let text: String = db
        .query_row("SELECT record FROM observations", [], |r| r.get(0))
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn an_unchanged_active_row_is_not_rewritten_yet_reads_as_current() {
    let d = dir("unchanged");
    let t0 = 1_000_000;
    let mut h = History::open(&d, t0).unwrap();
    h.observe(&[sampled("one", t0, 100)], t0);
    h.flush(t0).unwrap();
    // Twenty checkpoints in which only the per-sample timestamps move.
    let mut t = t0;
    for _ in 0..20 {
        t += 5000;
        h.observe(&[sampled("one", t, 100)], t);
        h.flush(t).unwrap();
    }
    // The row on disk is the first write: nothing rewrote it.
    assert_eq!(stored_record(&d)["lastObserved"], t0);
    // Yet both readers see the newest observation, evidence time included,
    // exactly as a full rewrite would have stored it.
    for rows in [h.query("probe", 0, 200).unwrap(), History::read(&d, "probe", 0).unwrap()] {
        assert_eq!(rows.len(), 1);
        assert!(rows[0].active);
        assert_eq!(rows[0].first_observed, t0);
        assert_eq!(rows[0].last_observed, t);
        assert_eq!(rows[0].connection.evidence.as_ref().unwrap().recorded_at, t);
    }
    // `since` filters on the current time, not the stale column.
    assert_eq!(h.query("probe", t, 200).unwrap().len(), 1);
    // Positive control: a real content change rewrites the record.
    t += 5000;
    let mut renamed = sampled("one", t, 100);
    renamed.hostname = "renamed.example".into();
    h.observe(&[renamed], t);
    h.flush(t).unwrap();
    assert_eq!(stored_record(&d)["lastObserved"], t);
    assert_eq!(stored_record(&d)["connection"]["hostname"], "renamed.example");
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

fn rows_on_disk(d: &std::path::Path) -> i64 {
    let db = rusqlite::Connection::open_with_flags(
        d.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row("SELECT count(*) FROM observations", [], |r| r.get(0))
        .unwrap()
}

fn live_transfer_rows(d: &std::path::Path) -> i64 {
    let db = rusqlite::Connection::open_with_flags(
        d.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row("SELECT count(*) FROM live_transfer", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn transfer_counters_move_without_rewriting_the_record_and_survive_restart() {
    let d = dir("transfer");
    let t0 = 4_000_000;
    let mut h = History::open(&d, t0).unwrap();
    h.observe(&[sampled("one", t0, 100)], t0);
    h.flush(t0).unwrap();
    let mut t = t0;
    for tx in [600, 1100, 1600] {
        t += 5000;
        h.observe(&[sampled("one", t, tx)], t);
        h.flush(t).unwrap();
    }
    // The record is still its first write; the counters moved elsewhere.
    assert_eq!(stored_record(&d)["lastObserved"], t0);
    assert_eq!(stored_record(&d)["bytes"]["tx"], 0);
    assert_eq!(live_transfer_rows(&d), 1);
    for rows in [h.query("probe", 0, 200).unwrap(), History::read(&d, "probe", 0).unwrap()] {
        assert_eq!(rows[0].bytes, Some(Bytes { tx: 1500, rx: 0 }));
        assert_eq!(rows[0].connection.bytes, Some(Bytes { tx: 1600, rx: 7 }));
    }
    // A sample after the last checkpoint is lost on a crash, as documented.
    h.observe(&[sampled("one", t + 2000, 9999)], t + 2000);
    drop(h);
    let h = History::open(&d, t + 60_000).unwrap();
    // Restart folds the last committed counters into the record and empties
    // the table: the row reads exactly as a full rewrite would have left it.
    assert_eq!(live_transfer_rows(&d), 0);
    assert_eq!(stored_record(&d)["bytes"]["tx"], 1500);
    let rows = h.query("probe", 0, 200).unwrap();
    assert!(!rows[0].active);
    assert_eq!(rows[0].last_observed, t);
    assert_eq!(rows[0].bytes, Some(Bytes { tx: 1500, rx: 0 }));
    assert_eq!(rows[0].connection.bytes, Some(Bytes { tx: 1600, rx: 7 }));
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_row_no_longer_observed_carries_its_final_counters_in_the_record() {
    let d = dir("transfer-gone");
    let t0 = 5_000_000;
    let mut h = History::open(&d, t0).unwrap();
    h.observe(&[sampled("one", t0, 100)], t0);
    h.flush(t0).unwrap();
    h.observe(&[sampled("one", t0 + 5000, 4100)], t0 + 5000);
    h.flush(t0 + 5000).unwrap();
    h.observe(&[], t0 + 10_000);
    h.flush(t0 + 10_000).unwrap();
    assert_eq!(live_transfer_rows(&d), 0);
    assert_eq!(stored_record(&d)["bytes"]["tx"], 4000);
    assert_eq!(stored_record(&d)["active"], false);
    let rows = History::read(&d, "probe", 0).unwrap();
    assert_eq!(rows[0].bytes, Some(Bytes { tx: 4000, rx: 0 }));
    assert_eq!(rows[0].last_observed, t0 + 5000);
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn restart_keeps_the_last_checkpointed_observation_of_an_unwritten_row() {
    let d = dir("restart-checkpoint");
    let t0 = 2_000_000;
    let mut h = History::open(&d, t0).unwrap();
    h.observe(&[sampled("one", t0, 5)], t0);
    h.flush(t0).unwrap();
    h.observe(&[sampled("one", t0 + 5000, 5)], t0 + 5000);
    h.flush(t0 + 5000).unwrap();
    // Observed again but never checkpointed: lost, as documented.
    h.observe(&[sampled("one", t0 + 7000, 5)], t0 + 7000);
    drop(h);
    let h = History::open(&d, t0 + 60_000).unwrap();
    let rows = h.query("probe", 0, 200).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].active);
    assert_eq!(rows[0].first_observed, t0);
    assert_eq!(rows[0].last_observed, t0 + 5000);
    assert_eq!(rows[0].connection.evidence.as_ref().unwrap().recorded_at, t0 + 5000);
    // A further restart does not move it again.
    drop(h);
    let h = History::open(&d, t0 + 120_000).unwrap();
    assert_eq!(h.query("probe", 0, 200).unwrap()[0].last_observed, t0 + 5000);
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn an_evidence_time_that_is_not_the_sample_time_is_never_moved() {
    let d = dir("fixed-evidence");
    let t0 = 3_000_000;
    let mut h = History::open(&d, t0).unwrap();
    // A source that reports when IT recorded the flow, not when we sampled it.
    let fixed = || sampled("one", 1234, 5);
    h.observe(&[fixed()], t0);
    h.flush(t0).unwrap();
    h.observe(&[fixed()], t0 + 5000);
    h.flush(t0 + 5000).unwrap();
    let rows = h.query("probe", 0, 200).unwrap();
    assert_eq!(rows[0].last_observed, t0 + 5000);
    assert_eq!(rows[0].connection.evidence.as_ref().unwrap().recorded_at, 1234);
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn the_store_uses_a_write_ahead_log() {
    let d = dir("wal");
    let h = History::open(&d, 1000).unwrap();
    let db = rusqlite::Connection::open(d.join("history.sqlite")).unwrap();
    let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, "wal");
    // The log and its index stay as private as the database. Checked while
    // the writer is open: SQLite removes both when the last connection closes.
    for f in ["history.sqlite", "history.sqlite-wal", "history.sqlite-shm"] {
        let m = std::fs::metadata(d.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(m.permissions().mode() & 0o077, 0, "{f} is not private");
    }
    drop(db);
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn the_row_cap_never_trims_a_live_row_by_its_stale_stored_time() {
    // A long-lived connection is written once, so its stored last_seen is the
    // oldest in the table. It is still the newest observation and must
    // survive the cap; the oldest row no longer observed goes instead.
    let d = dir("cap-live");
    let t0 = 6_000_000;
    let mut h = History::open(&d, t0).unwrap();
    let mut long = row("long-lived", "tcp");
    long.hostname = "keepalive.example".into();
    h.observe(&[long.clone()], t0);
    h.flush(t0).unwrap();
    // Fill the table to the trim threshold with rows that then stop being
    // observed.
    let mut batch: Vec<Connection> = (0..ROW_CAP + TRIM_SLACK - 1)
        .map(|i| row(&format!("b-{i}"), "udp"))
        .collect();
    batch.push(long.clone());
    h.observe(&batch, t0 + 1000);
    h.flush(t0 + 1000).unwrap();
    // They stop being observed in two waves: one wave of more than ROW_CAP
    // would overflow the in-memory pending queue, a separate (pre-existing)
    // bound this test is not about.
    let half = batch.len() / 2;
    h.observe(&batch[half..], t0 + 1500);
    h.flush(t0 + 1500).unwrap();
    h.observe(&[long.clone()], t0 + 2000);
    h.flush(t0 + 2000).unwrap();
    assert_eq!(rows_on_disk(&d), (ROW_CAP + TRIM_SLACK) as i64, "trimmed inside the slack");
    // One more row takes the table past it.
    h.observe(&[long, row("extra", "udp")], t0 + 3000);
    h.flush(t0 + 3000).unwrap();
    assert_eq!(rows_on_disk(&d), ROW_CAP as i64);
    let all = h.query("", 0, ROW_CAP + 10).unwrap();
    assert_eq!(all.len(), ROW_CAP);
    let live: Vec<_> = all.iter().filter(|e| e.connection.id == "long-lived").collect();
    assert_eq!(live.len(), 1, "the live row was trimmed");
    assert!(live[0].active);
    assert_eq!(live[0].last_observed, t0 + 3000);
    assert!(all.iter().any(|e| e.connection.id == "extra"));
    // One of the oldest rows no longer observed went instead (equal times
    // tie-break on the key, as before).
    let kept = all.iter().filter(|e| e.connection.id.starts_with("b-")).count();
    assert_eq!(kept, ROW_CAP - 2);
    assert!(all.iter().filter(|e| e.connection.id.starts_with("b-")).all(|e| !e.active));
    drop(h);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn an_unparseable_record_does_not_stop_the_store_opening() {
    let d = dir("bad-record");
    let t0 = 7_000_000;
    let mut h = History::open(&d, t0).unwrap();
    h.observe(&[sampled("one", t0, 100), sampled("two", t0, 100)], t0);
    h.flush(t0).unwrap();
    drop(h);
    {
        let db = rusqlite::Connection::open(d.join("history.sqlite")).unwrap();
        db.execute("UPDATE observations SET record = 'not json' WHERE key = (SELECT min(key) FROM observations)", [])
            .unwrap();
    }
    // The fold skips the bad row; the store opens and the good row is folded.
    let h = History::open(&d, t0 + 60_000).unwrap();
    drop(h);
    let db = rusqlite::Connection::open(d.join("history.sqlite")).unwrap();
    let active: i64 = db
        .query_row("SELECT count(*) FROM observations WHERE active = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(active, 0);
    std::fs::remove_dir_all(d).unwrap();
}
