//! Local append-only activity timeline (`activity.ndjson`).
//!
//! Closed kind set. Heartbeat kinds are recorded only when the outcome
//! changes (ok→failed, failed→ok, or the first result), never every tick.
//! Nothing in this module is sent off the machine.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE_CAP_TRIGGER: usize = 5000;
pub const FILE_KEEP: usize = 2500;
pub const HELLO_REPLAY: usize = 300;
pub const ERROR_CAP: usize = 200;

/// Closed kind set. Anything else is rejected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    DaemonStart,
    SourceChanged,
    AppFirstSeen,
    NewNetwork,
    UnknownOwner,
    Block,
    Unblock,
    BlockFailed,
    Kub0Connected,
    Kub0Disconnected,
    HeartbeatOk,
    HeartbeatFailed,
    /// A connection matched one of the user's watch rules.
    WatchHit,
    /// A warning- or notice-level local indicator was raised on a new
    /// connection. Info-level indicators are shown on the row, not logged.
    Indicator,
    /// The exec gate matched a file's sha256 against the org deny list. The
    /// detail is an `execgate::ExecGateDeny`: what was executed, which row
    /// matched, and the decision (`blocked`, `allowed_local_trust`,
    /// `allowed_once`, `allowed_failopen`). Local only.
    ExecGateDeny,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonStart => "daemon_start",
            Self::SourceChanged => "source_changed",
            Self::AppFirstSeen => "app_first_seen",
            Self::NewNetwork => "new_network",
            Self::UnknownOwner => "unknown_owner",
            Self::Block => "block",
            Self::Unblock => "unblock",
            Self::BlockFailed => "block_failed",
            Self::Kub0Connected => "kub0_connected",
            Self::Kub0Disconnected => "kub0_disconnected",
            Self::HeartbeatOk => "heartbeat_ok",
            Self::HeartbeatFailed => "heartbeat_failed",
            Self::WatchHit => "watch_hit",
            Self::Indicator => "indicator",
            Self::ExecGateDeny => "exec_gate_deny",
        }
    }

    pub fn parse_closed(s: &str) -> Option<Self> {
        match s {
            "daemon_start" => Some(Self::DaemonStart),
            "source_changed" => Some(Self::SourceChanged),
            "app_first_seen" => Some(Self::AppFirstSeen),
            "new_network" => Some(Self::NewNetwork),
            "unknown_owner" => Some(Self::UnknownOwner),
            "block" => Some(Self::Block),
            "unblock" => Some(Self::Unblock),
            "block_failed" => Some(Self::BlockFailed),
            "kub0_connected" => Some(Self::Kub0Connected),
            "kub0_disconnected" => Some(Self::Kub0Disconnected),
            "heartbeat_ok" => Some(Self::HeartbeatOk),
            "heartbeat_failed" => Some(Self::HeartbeatFailed),
            "watch_hit" => Some(Self::WatchHit),
            "indicator" => Some(Self::Indicator),
            "exec_gate_deny" => Some(Self::ExecGateDeny),
            _ => None,
        }
    }

    /// Kinds a panel may inject with `{"cmd":"note"}`. An exec-gate deny is
    /// not one: only the gate can say it denied something.
    pub fn parse_note(s: &str) -> Option<Self> {
        match s {
            "block" => Some(Self::Block),
            "unblock" => Some(Self::Unblock),
            "block_failed" => Some(Self::BlockFailed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityApp {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActivityEntry {
    pub ts: u64,
    pub kind: ActivityKind,
    pub app: Option<ActivityApp>,
    pub detail: serde_json::Value,
}

impl ActivityEntry {
    pub fn new(
        ts: u64,
        kind: ActivityKind,
        app: Option<ActivityApp>,
        detail: serde_json::Value,
    ) -> Self {
        let detail = if detail.is_object() {
            detail
        } else {
            serde_json::json!({})
        };
        Self {
            ts,
            kind,
            app,
            detail,
        }
    }
}

pub struct ActivityLog {
    path: PathBuf,
    entries: Vec<ActivityEntry>,
    kub0_connected: Option<bool>,
    last_heartbeat: Option<bool>,
}

impl ActivityLog {
    pub fn load(state_dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(state_dir);
        let path = state_dir.join("activity.ndjson");
        let mut entries = Vec::new();
        let mut raw_lines = 0usize;
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                raw_lines += 1;
                if let Ok(e) = serde_json::from_str::<ActivityEntry>(line) {
                    entries.push(e);
                }
            }
        }
        let mut log = Self {
            path,
            entries,
            kub0_connected: None,
            last_heartbeat: None,
        };
        if raw_lines > FILE_CAP_TRIGGER {
            let keep_from = log.entries.len().saturating_sub(FILE_KEEP);
            log.entries = log.entries.split_off(keep_from);
            let _ = log.rewrite();
        }
        log
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[ActivityEntry] {
        &self.entries
    }

    /// Newest last in the file. Client hello replay is ascending ts.
    pub fn replay_newest(&self, n: usize) -> Vec<ActivityEntry> {
        let start = self.entries.len().saturating_sub(n);
        self.entries[start..].to_vec()
    }

    pub fn append(&mut self, entry: ActivityEntry) -> std::io::Result<ActivityEntry> {
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        self.entries.push(entry.clone());
        Ok(entry)
    }

    fn rewrite(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("ndjson.tmp");
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        for e in &self.entries {
            let mut line = serde_json::to_string(e)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            line.push('\n');
            f.write_all(line.as_bytes())?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Connect/disconnect on change; heartbeat kinds only on outcome change.
    pub fn observe_kub0(
        &mut self,
        now: u64,
        connected: bool,
        last_ok: Option<bool>,
    ) -> Vec<ActivityEntry> {
        let mut out = Vec::new();
        if self.kub0_connected != Some(connected) {
            let prev = self.kub0_connected;
            self.kub0_connected = Some(connected);
            if connected {
                if let Ok(e) = self.append(ActivityEntry::new(
                    now,
                    ActivityKind::Kub0Connected,
                    None,
                    serde_json::json!({}),
                )) {
                    out.push(e);
                }
            } else if prev == Some(true) {
                if let Ok(e) = self.append(ActivityEntry::new(
                    now,
                    ActivityKind::Kub0Disconnected,
                    None,
                    serde_json::json!({}),
                )) {
                    out.push(e);
                }
            }
            if !connected {
                self.last_heartbeat = None;
            }
        }
        if connected {
            if let Some(ok) = last_ok {
                if self.last_heartbeat != Some(ok) {
                    self.last_heartbeat = Some(ok);
                    let kind = if ok {
                        ActivityKind::HeartbeatOk
                    } else {
                        ActivityKind::HeartbeatFailed
                    };
                    let detail = serde_json::json!({ "ok": ok });
                    if let Ok(e) = self.append(ActivityEntry::new(now, kind, None, detail)) {
                        out.push(e);
                    }
                }
            }
        }
        out
    }
}

/// Strict validator for `{"cmd":"note",...}`. Unknown kinds and shapes fail.
pub fn parse_note(v: &serde_json::Value, now: u64) -> Result<ActivityEntry, String> {
    let cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
    if cmd != "note" {
        return Err("not a note command".into());
    }
    let kind_s = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
    let Some(kind) = ActivityKind::parse_note(kind_s) else {
        return Err(format!("unknown kind {kind_s:?}"));
    };
    let app_v = v.get("app").ok_or_else(|| "missing app".to_string())?;
    let app_obj = app_v
        .as_object()
        .ok_or_else(|| "app must be an object".to_string())?;
    let id = app_obj
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "app.id must be a string".to_string())?;
    let name = app_obj
        .get("name")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "app.name must be a string".to_string())?;
    if id.is_empty() {
        return Err("app.id empty".into());
    }
    let detail_v = v
        .get("detail")
        .ok_or_else(|| "missing detail".to_string())?;
    let detail_obj = detail_v
        .as_object()
        .ok_or_else(|| "detail must be an object".to_string())?;
    let mut detail = serde_json::Map::new();
    match detail_obj.get("mechanism").and_then(|x| x.as_str()) {
        Some("cgroup") | Some("endpoints") => {
            detail.insert(
                "mechanism".into(),
                serde_json::Value::String(
                    detail_obj
                        .get("mechanism")
                        .and_then(|x| x.as_str())
                        .unwrap()
                        .to_string(),
                ),
            );
        }
        Some(_) => return Err("mechanism must be cgroup or endpoints".into()),
        None => {}
    }
    if let Some(err) = detail_obj.get("error") {
        let s = err
            .as_str()
            .ok_or_else(|| "detail.error must be a string".to_string())?;
        let capped: String = s.chars().take(ERROR_CAP).collect();
        detail.insert("error".into(), serde_json::Value::String(capped));
    }
    Ok(ActivityEntry::new(
        now,
        kind,
        Some(ActivityApp {
            id: id.to_string(),
            name: name.to_string(),
        }),
        serde_json::Value::Object(detail),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum-act-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn entry(ts: u64, kind: ActivityKind) -> ActivityEntry {
        ActivityEntry::new(ts, kind, None, serde_json::json!({}))
    }

    #[test]
    fn unknown_kind_rejected() {
        assert!(ActivityKind::parse_closed("not_a_kind").is_none());
        assert!(ActivityKind::parse_note("daemon_start").is_none());
        assert!(ActivityKind::parse_note("heartbeat_failed").is_none());
        assert!(ActivityKind::parse_note("exec_gate_deny").is_none(), "a panel cannot forge a deny");
        assert_eq!(ActivityKind::parse_closed("exec_gate_deny"), Some(ActivityKind::ExecGateDeny));
        let v = serde_json::json!({
            "cmd": "note",
            "kind": "daemon_start",
            "app": {"id": "a", "name": "A"},
            "detail": {}
        });
        let err = parse_note(&v, 1).unwrap_err();
        assert!(err.contains("unknown kind"), "{err}");
        let v2 = serde_json::json!({
            "cmd": "note",
            "kind": "explode",
            "app": {"id": "a", "name": "A"},
            "detail": {}
        });
        assert!(parse_note(&v2, 1).is_err());
    }

    #[test]
    fn append_and_cap_keeps_newest() {
        let dir = tmpdir("cap");
        let path = dir.join("activity.ndjson");
        let mut body = String::new();
        for i in 0..(FILE_CAP_TRIGGER + 10) {
            body.push_str(&format!(
                "{{\"ts\":{i},\"kind\":\"daemon_start\",\"app\":null,\"detail\":{{}}}}\n"
            ));
        }
        std::fs::write(&path, body).unwrap();
        let log = ActivityLog::load(&dir);
        assert_eq!(log.len(), FILE_KEEP);
        assert_eq!(log.entries().first().unwrap().ts, 2510);
        assert_eq!(log.entries().last().unwrap().ts, 5009);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.lines().filter(|l| !l.is_empty()).count(), FILE_KEEP);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_on_hello_is_ascending_newest_last_in_file() {
        let dir = tmpdir("replay");
        let mut log = ActivityLog::load(&dir);
        for i in 0..5 {
            log.append(entry(1000 + i, ActivityKind::DaemonStart))
                .unwrap();
        }
        let replay = log.replay_newest(3);
        let ts: Vec<u64> = replay.iter().map(|e| e.ts).collect();
        assert_eq!(ts, vec![1002, 1003, 1004]);
        let text = std::fs::read_to_string(dir.join("activity.ndjson")).unwrap();
        let file_ts: Vec<u64> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                serde_json::from_str::<ActivityEntry>(l)
                    .unwrap()
                    .ts
            })
            .collect();
        assert_eq!(file_ts, vec![1000, 1001, 1002, 1003, 1004]);
        assert!(file_ts.last() >= file_ts.first());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_change_only() {
        let dir = tmpdir("hb");
        let mut log = ActivityLog::load(&dir);
        let a = log.observe_kub0(1, true, None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, ActivityKind::Kub0Connected);
        let b = log.observe_kub0(2, true, None);
        assert!(b.is_empty(), "no heartbeat until first result");
        let c = log.observe_kub0(3, true, Some(true));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, ActivityKind::HeartbeatOk);
        let d = log.observe_kub0(4, true, Some(true));
        assert!(d.is_empty(), "repeat ok must not emit");
        let e = log.observe_kub0(5, true, Some(false));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].kind, ActivityKind::HeartbeatFailed);
        let f = log.observe_kub0(6, true, Some(false));
        assert!(f.is_empty());
        let g = log.observe_kub0(7, true, Some(true));
        assert_eq!(g[0].kind, ActivityKind::HeartbeatOk);
        let h = log.observe_kub0(8, false, None);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].kind, ActivityKind::Kub0Disconnected);
        let i = log.observe_kub0(9, true, Some(true));
        assert!(i.iter().any(|e| e.kind == ActivityKind::Kub0Connected));
        assert!(i.iter().any(|e| e.kind == ActivityKind::HeartbeatOk));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn note_command_validation() {
        let ok = serde_json::json!({
            "cmd": "note",
            "kind": "block",
            "app": {"id": "firefox", "name": "Firefox"},
            "detail": {"mechanism": "cgroup"}
        });
        let e = parse_note(&ok, 42).unwrap();
        assert_eq!(e.ts, 42);
        assert_eq!(e.kind, ActivityKind::Block);
        assert_eq!(e.app.as_ref().unwrap().id, "firefox");
        assert_eq!(e.detail["mechanism"], "cgroup");

        let failed = serde_json::json!({
            "cmd": "note",
            "kind": "block_failed",
            "app": {"id": "x", "name": "X"},
            "detail": {"mechanism": "endpoints", "error": "nope"}
        });
        let e = parse_note(&failed, 1).unwrap();
        assert_eq!(e.kind, ActivityKind::BlockFailed);
        assert_eq!(e.detail["error"], "nope");

        let long = "e".repeat(250);
        let cap = serde_json::json!({
            "cmd": "note",
            "kind": "unblock",
            "app": {"id": "x", "name": "X"},
            "detail": {"mechanism": "cgroup", "error": long, "secret": "drop-me"}
        });
        let e = parse_note(&cap, 1).unwrap();
        let err = e.detail["error"].as_str().unwrap();
        assert_eq!(err.len(), ERROR_CAP);
        assert!(e.detail.get("secret").is_none());

        assert!(parse_note(
            &serde_json::json!({
                "cmd": "note",
                "kind": "block",
                "app": "firefox",
                "detail": {}
            }),
            1
        )
        .is_err());
        assert!(parse_note(
            &serde_json::json!({
                "cmd": "note",
                "kind": "block",
                "app": {"id": "x", "name": "X"},
                "detail": {"mechanism": "iptables"}
            }),
            1
        )
        .is_err());
        assert!(parse_note(
            &serde_json::json!({
                "cmd": "note",
                "kind": "block",
                "detail": {}
            }),
            1
        )
        .is_err());
        assert!(parse_note(
            &serde_json::json!({
                "cmd": "note",
                "kind": "block",
                "app": {"id": "x", "name": "X"},
                "detail": "free text"
            }),
            1
        )
        .is_err());
        assert!(parse_note(
            &serde_json::json!({
                "cmd": "note",
                "kind": "block",
                "app": {"id": "x", "name": "X"},
                "detail": {"error": 1}
            }),
            1
        )
        .is_err());
    }

    #[test]
    fn closed_kind_roundtrip() {
        for k in [
            ActivityKind::DaemonStart,
            ActivityKind::SourceChanged,
            ActivityKind::AppFirstSeen,
            ActivityKind::NewNetwork,
            ActivityKind::UnknownOwner,
            ActivityKind::Block,
            ActivityKind::Unblock,
            ActivityKind::BlockFailed,
            ActivityKind::Kub0Connected,
            ActivityKind::Kub0Disconnected,
            ActivityKind::HeartbeatOk,
            ActivityKind::HeartbeatFailed,
            ActivityKind::WatchHit,
            ActivityKind::Indicator,
            ActivityKind::ExecGateDeny,
        ] {
            let e = ActivityEntry::new(1, k, None, serde_json::json!({"x": 1}));
            let s = serde_json::to_string(&e).unwrap();
            assert!(s.contains(k.as_str()), "{s}");
            let back: ActivityEntry = serde_json::from_str(&s).unwrap();
            assert_eq!(back.kind, k);
        }
        let bad = r#"{"ts":1,"kind":"nope","app":null,"detail":{}}"#;
        assert!(serde_json::from_str::<ActivityEntry>(bad).is_err());
    }
}
