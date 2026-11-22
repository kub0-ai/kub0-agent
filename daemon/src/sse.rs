//! Live deny-list updates over kub0's server-sent events stream.
//!
//! `GET {server}/detonate/api/events/stream` with the account's Bearer token.
//! The server sends `: heartbeat` on connect and every 30 s, one
//! `denylist_snapshot` (`{"entries":[...]}`) on every connect, and a
//! `denylist_update` (one flat row, `action: "remove"` for a deletion) when the
//! org list changes. Everything else on the stream is ignored here.
//!
//! The parser is pure and tested on captured frames. The client loop
//! reconnects with exponential backoff (1 s doubling to 60 s) and rests the
//! backoff once a frame has arrived. ureq's body timeout is a total budget,
//! not a per-read one, so a healthy stream is re-dialled every
//! [`BODY_BUDGET`]; the snapshot that comes with each connect is also the
//! reconciliation. The 60 s `/api/enforce/denylist` poll in `refresh_fleet`
//! stays as it was: it carries `reason`, `promoted_by` and `created_at`, which
//! the stream does not, and it is the fallback while the stream is down.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::event::DenylistEntry;
use crate::kub0::Kub0Runtime;

/// Re-dial a healthy stream this often (ureq's recv-body budget).
pub const BODY_BUDGET: Duration = Duration::from_secs(300);
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A frame larger than this is not a deny-list frame; the connection is dropped.
const FRAME_MAX: usize = 4 * 1024 * 1024;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub event: String,
    pub data: String,
    pub id: String,
}

/// Incremental `text/event-stream` parser. Feed it bytes as they arrive;
/// each blank line dispatches one [`Frame`]. Comments (`: ...`) are dropped,
/// `\r\n` and `\n` both end a line, a `data:` without a value is an empty
/// line of data, and a frame with no `data` is not dispatched (the spec says
/// so, and that is what a bare `event:` line followed by a blank line is).
#[derive(Default)]
pub struct Parser {
    buf: Vec<u8>,
    event: String,
    data: Vec<String>,
    id: String,
    overflow: bool,
}

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    /// True once a line or frame exceeded [`FRAME_MAX`]; the caller drops the stream.
    pub fn overflowed(&self) -> bool {
        self.overflow
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > FRAME_MAX {
            self.overflow = true;
            self.buf.clear();
            return out;
        }
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            let mut text = String::from_utf8_lossy(&line).into_owned();
            if text.ends_with('\n') {
                text.pop();
            }
            if text.ends_with('\r') {
                text.pop();
            }
            self.line(&text, &mut out);
        }
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<Frame>) {
        if line.is_empty() {
            if !self.data.is_empty() {
                out.push(Frame {
                    event: std::mem::take(&mut self.event),
                    data: self.data.join("\n"),
                    id: self.id.clone(),
                });
                self.data.clear();
            } else {
                self.event.clear();
            }
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => self.event = value.to_string(),
            "data" => {
                let total: usize = self.data.iter().map(|d| d.len()).sum();
                if total + value.len() > FRAME_MAX {
                    self.overflow = true;
                    self.data.clear();
                    return;
                }
                self.data.push(value.to_string());
            }
            "id" => self.id = value.to_string(),
            // `retry` and unknown fields are ignored; the backoff is ours.
            _ => {}
        }
    }
}

/// One flat deny-list row as the stream carries it. `action: "remove"` is a
/// deletion of the `(comm, path)` row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DenylistUpdate {
    pub comm: String,
    pub path: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenylistFrame {
    /// Every row the org has, with the uncapped count.
    Snapshot(Vec<DenylistEntry>, usize),
    Update(DenylistUpdate),
    /// Something else on the stream: not ours.
    Other,
}

/// What a frame means for the deny list.
pub fn classify(frame: &Frame) -> DenylistFrame {
    match frame.event.as_str() {
        "denylist_snapshot" => {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) else {
                return DenylistFrame::Other;
            };
            if v.get("entries").and_then(|e| e.as_array()).is_none() {
                return DenylistFrame::Other;
            }
            let reported = crate::kub0::denylist_reported_len(&v);
            let (_, rows) = crate::kub0::parse_denylist(&v);
            DenylistFrame::Snapshot(rows, reported)
        }
        "denylist_update" => {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) else {
                return DenylistFrame::Other;
            };
            let s = |k: &str| {
                v.get(k)
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let u = DenylistUpdate {
                comm: s("comm"),
                path: s("path"),
                action: s("action"),
                reason: s("reason"),
            };
            if u.comm.is_empty() && u.path.is_empty() {
                return DenylistFrame::Other;
            }
            DenylistFrame::Update(u)
        }
        _ => DenylistFrame::Other,
    }
}

pub fn is_removal(action: &str) -> bool {
    matches!(
        action.trim().to_ascii_lowercase().as_str(),
        "remove" | "removed" | "delete" | "deleted"
    )
}

/// Apply one update to the rows. A removal drops the `(comm, path)` row; any
/// other action upserts it, keeping the metadata the REST poll gave the row
/// (`promoted_by`, `created_at`, an org `name`) when the stream has none.
/// Returns true when the rows changed.
pub fn apply_update(rows: &mut Vec<DenylistEntry>, u: &DenylistUpdate) -> bool {
    let same = |e: &DenylistEntry| e.comm == u.comm && e.path == u.path;
    if is_removal(&u.action) {
        let before = rows.len();
        rows.retain(|e| !same(e));
        return rows.len() != before;
    }
    if let Some(e) = rows.iter_mut().find(|e| same(e)) {
        let changed = e.action != u.action || (!u.reason.is_empty() && e.reason != u.reason);
        e.action = u.action.clone();
        if !u.reason.is_empty() {
            e.reason = u.reason.clone();
        }
        // The name was settled from the old action; settle it again.
        let mut fresh = e.clone();
        fresh.name.clear();
        e.name = fresh.label();
        return changed;
    }
    if rows.len() >= crate::kub0::DENYLIST_CAP {
        return false;
    }
    let mut e = DenylistEntry {
        comm: u.comm.clone(),
        path: u.path.clone(),
        action: u.action.clone(),
        reason: u.reason.clone(),
        ..Default::default()
    };
    e.name = e.label();
    rows.push(e);
    true
}

/// A stream snapshot has only `comm`, `path` and `action`. Carry the REST
/// poll's `reason`, `promoted_by`, `created_at` and org `name` over to the
/// matching `(comm, path)` row so a deny raised between polls still names
/// its row's provenance.
pub fn merge_metadata(fresh: &mut [DenylistEntry], previous: &[DenylistEntry]) {
    for row in fresh.iter_mut() {
        let Some(old) = previous
            .iter()
            .find(|p| p.comm == row.comm && p.path == row.path)
        else {
            continue;
        };
        if row.reason.is_empty() {
            row.reason = old.reason.clone();
        }
        if row.promoted_by.is_empty() {
            row.promoted_by = old.promoted_by.clone();
        }
        if row.created_at.is_empty() {
            row.created_at = old.created_at.clone();
        }
        // parse_denylist settled a fallback name; the org's own wins.
        let mut unnamed = row.clone();
        unnamed.name.clear();
        if row.name == unnamed.label() && old.name != unnamed.label() && !old.name.is_empty() {
            row.name = old.name.clone();
        }
    }
}

pub fn stream_url(server_url: &str) -> String {
    format!(
        "{}/detonate/api/events/stream",
        server_url.trim_end_matches('/')
    )
}

/// 1 s, 2 s, 4 s ... capped at 60 s.
pub fn backoff(attempt: u32) -> Duration {
    let secs = 1u64 << attempt.min(6);
    Duration::from_secs(secs).min(BACKOFF_MAX).max(BACKOFF_MIN)
}

/// One stream thread's switches. `stop` is set by the owner (account gone or
/// changed); the thread notices between reads, so at the latest on the next
/// keepalive or the body budget.
pub struct StreamState {
    pub stop: AtomicBool,
}

impl StreamState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
        })
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_recv_response(Some(Duration::from_secs(15)))
            .timeout_recv_body(Some(BODY_BUDGET))
            .http_status_as_error(false)
            .build(),
    )
}

/// Apply a classified frame to the runtime and the gate. Returns true when it
/// was a deny-list frame.
pub fn apply_frame(runtime: &Kub0Runtime, frame: &Frame) -> bool {
    match classify(frame) {
        DenylistFrame::Snapshot(rows, reported) => {
            let rows = runtime.apply_denylist_snapshot(rows, reported);
            crate::execgate::publish(&rows, reported);
            true
        }
        DenylistFrame::Update(u) => {
            let (rows, reported) = runtime.apply_denylist_update(&u);
            crate::execgate::publish(&rows, reported);
            true
        }
        DenylistFrame::Other => false,
    }
}

/// Connect, read, apply, reconnect. Returns when `state.stop` is set.
pub fn run(server_url: String, token: String, runtime: Arc<Kub0Runtime>, state: Arc<StreamState>) {
    let url = stream_url(&server_url);
    let mut attempt: u32 = 0;
    let mut logged_auth = false;
    let mut logged_err = String::new();
    runtime.set_denylist_live(Some(false));
    while !state.stop.load(Ordering::Acquire) {
        let agent = agent();
        let resp = agent
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "text/event-stream")
            .call();
        let mut saw_frame = false;
        match resp {
            Ok(resp) if resp.status().as_u16() == 200 => {
                logged_err.clear();
                let mut parser = Parser::new();
                let mut reader = resp.into_body().into_reader();
                let mut buf = [0u8; 4096];
                loop {
                    if state.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let n = match std::io::Read::read(&mut reader, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    for frame in parser.feed(&buf[..n]) {
                        // Told to stop while the read was blocked: the account
                        // changed or logged out, and the tick has already reset
                        // the rows this frame would be applied to. An update on
                        // top of that is not the org's list; it must not reach
                        // the gate, which would also write it to disk.
                        if state.stop.load(Ordering::Acquire) {
                            break;
                        }
                        if apply_frame(&runtime, &frame) {
                            saw_frame = true;
                            attempt = 0;
                            runtime.set_denylist_live(Some(true));
                            runtime.request_refresh();
                        }
                    }
                    if parser.overflowed() {
                        eprintln!("kub0d: deny-list stream frame too large; reconnecting");
                        break;
                    }
                }
            }
            Ok(resp) => {
                let code = resp.status().as_u16();
                if (code == 401 || code == 403) && !logged_auth {
                    eprintln!("kub0d: deny-list stream HTTP {code}; the 60 s poll stays the source");
                    logged_auth = true;
                } else if code != 401 && code != 403 {
                    let msg = format!("HTTP {code}");
                    if msg != logged_err {
                        eprintln!("kub0d: deny-list stream {msg}; retrying");
                        logged_err = msg;
                    }
                }
            }
            Err(e) => {
                let msg = crate::kub0::redact_secret(&e.to_string(), &token);
                if msg != logged_err {
                    eprintln!("kub0d: deny-list stream failed: {msg}; retrying");
                    logged_err = msg;
                }
            }
        }
        runtime.set_denylist_live(Some(false));
        if state.stop.load(Ordering::Acquire) {
            break;
        }
        // A stream that delivered frames and ended (budget, server restart)
        // re-dials at once; one that never did backs off.
        let wait = if saw_frame { BACKOFF_MIN } else { backoff(attempt) };
        if !saw_frame {
            attempt = attempt.saturating_add(1);
        }
        let until = std::time::Instant::now() + wait;
        while std::time::Instant::now() < until {
            if state.stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    runtime.set_denylist_live(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/sse-denylist.txt"
        ))
        .expect("tests/fixtures/sse-denylist.txt")
    }

    #[test]
    fn the_captured_stream_parses_into_a_snapshot_and_two_updates() {
        let text = fixture();
        let mut p = Parser::new();
        // Feed in awkward chunks so a frame split anywhere still dispatches once.
        let bytes = text.as_bytes();
        let mut frames = Vec::new();
        for chunk in bytes.chunks(7) {
            frames.extend(p.feed(chunk));
        }
        let kinds: Vec<&str> = frames.iter().map(|f| f.event.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["denylist_snapshot", "denylist_update", "", "denylist_update"],
            "comments and the bare heartbeat never dispatch; an un-named data frame does"
        );
        match classify(&frames[0]) {
            DenylistFrame::Snapshot(rows, reported) => {
                assert_eq!(reported, 2);
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].comm, "xmrig");
                assert_eq!(rows[0].action, "block");
                assert_eq!(rows[0].name, "Block xmrig", "the name is settled on arrival");
                assert_eq!(rows[1].path, "/workspace/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            }
            other => panic!("{other:?}"),
        }
        match classify(&frames[1]) {
            DenylistFrame::Update(u) => {
                assert_eq!(u.comm, "nc");
                assert_eq!(u.action, "monitor");
                assert_eq!(u.reason, "ops review");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(classify(&frames[2]), DenylistFrame::Other, "a probe event is not ours");
        match classify(&frames[3]) {
            DenylistFrame::Update(u) => {
                assert!(is_removal(&u.action));
                assert_eq!(u.comm, "xmrig");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn crlf_multi_line_data_and_a_frame_without_data_are_handled() {
        let mut p = Parser::new();
        let frames = p.feed(b"event: denylist_update\r\ndata: {\"comm\":\r\ndata: \"a\"}\r\n\r\nevent: x\n\n: c\n\ndata:\n\n");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].event, "denylist_update");
        assert_eq!(frames[0].data, "{\"comm\":\n\"a\"}");
        assert_eq!(frames[1].event, "", "the `event: x` with no data was dropped, not carried over");
        assert_eq!(frames[1].data, "");
        assert!(!p.overflowed());
    }

    #[test]
    fn updates_upsert_remove_and_keep_rest_metadata() {
        let mut rows = vec![DenylistEntry {
            name: "Miners".into(),
            comm: "xmrig".into(),
            path: String::new(),
            action: "monitor".into(),
            reason: "cpu".into(),
            promoted_by: "loop5-auto".into(),
            created_at: "2026-10-01T00:00:00Z".into(),
        }];
        assert!(apply_update(&mut rows, &DenylistUpdate { comm: "xmrig".into(), action: "block".into(), ..Default::default() }));
        assert_eq!(rows[0].action, "block");
        assert_eq!(rows[0].reason, "cpu", "an empty stream reason keeps the poll's");
        assert_eq!(rows[0].promoted_by, "loop5-auto");
        assert!(!apply_update(&mut rows, &DenylistUpdate { comm: "xmrig".into(), action: "block".into(), ..Default::default() }), "same again is no change");
        assert!(apply_update(&mut rows, &DenylistUpdate { comm: "nc".into(), action: "block".into(), reason: "ops".into(), ..Default::default() }));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].name, "Block nc");
        assert!(apply_update(&mut rows, &DenylistUpdate { comm: "xmrig".into(), action: "remove".into(), ..Default::default() }));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].comm, "nc");
        assert!(!apply_update(&mut rows, &DenylistUpdate { comm: "ghost".into(), action: "remove".into(), ..Default::default() }));
    }

    #[test]
    fn a_snapshot_inherits_metadata_from_the_last_poll() {
        let previous = vec![DenylistEntry {
            name: "Miners".into(),
            comm: "xmrig".into(),
            path: String::new(),
            action: "block".into(),
            reason: "cpu".into(),
            promoted_by: "api".into(),
            created_at: "2026-10-01T00:00:00Z".into(),
        }];
        let (_, mut fresh) = crate::kub0::parse_denylist(&serde_json::json!({
            "entries": [{"comm": "xmrig", "action": "block"}, {"comm": "new", "action": "block"}]
        }));
        merge_metadata(&mut fresh, &previous);
        assert_eq!(fresh[0].name, "Miners");
        assert_eq!(fresh[0].reason, "cpu");
        assert_eq!(fresh[0].promoted_by, "api");
        assert_eq!(fresh[0].created_at, "2026-10-01T00:00:00Z");
        assert_eq!(fresh[1].name, "Block new");
        assert_eq!(fresh[1].promoted_by, "");
    }

    #[test]
    fn backoff_doubles_from_one_second_and_caps_at_sixty() {
        let secs: Vec<u64> = (0..9).map(|a| backoff(a).as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(stream_url("https://api.kub0.io/"), "https://api.kub0.io/detonate/api/events/stream");
    }
}
