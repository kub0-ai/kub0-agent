//! One request, one reply, over the daemon's NDJSON socket.
//!
//! The daemon greets every client with a burst of frames (hello, fleet,
//! activity, snapshot…). The client keeps the `hello` and ignores the rest,
//! sends `{"req": id, "cmd": verb, …}`, then reads until the `reply` frame
//! carrying its id arrives without `partial`. Partial replies go to a
//! callback as they come, which is how a login shows its code before the
//! browser round-trip completes.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct Hello {
    pub version: String,
    pub mode: String,
    pub pid: u64,
    pub connected: bool,
    pub github_username: String,
    pub node_name: String,
    /// The daemon answers requests. False on a daemon older than this
    /// protocol, which would otherwise swallow every request silently.
    pub requests: bool,
    /// The daemon honours `as_uid`. An older one ignores the field and acts
    /// as root, so `kub0` never sends it there.
    pub as_uid: bool,
}

pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    pub hello: Hello,
    next_req: u64,
}

/// Why a connection could not be made, kept apart from a daemon's answer
/// because the fix is different (start a daemon, or run as root).
#[derive(Debug)]
pub enum ConnectError {
    Absent(String),
    Denied(String),
    Other(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Absent(m) | ConnectError::Denied(m) | ConnectError::Other(m) => f.write_str(m),
        }
    }
}

const HELLO_WAIT: Duration = Duration::from_secs(5);

impl Client {
    pub fn connect(path: &Path) -> Result<Self, ConnectError> {
        let stream = UnixStream::connect(path).map_err(|e| {
            let m = format!("{}: {e}", path.display());
            match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => ConnectError::Absent(m),
                std::io::ErrorKind::PermissionDenied => ConnectError::Denied(m),
                _ => ConnectError::Other(m),
            }
        })?;
        let writer = stream.try_clone().map_err(|e| ConnectError::Other(e.to_string()))?;
        let mut client = Client {
            reader: BufReader::new(stream),
            writer,
            hello: Hello::default(),
            next_req: 1,
        };
        client.read_hello()?;
        Ok(client)
    }

    fn read_hello(&mut self) -> Result<(), ConnectError> {
        let deadline = Instant::now() + HELLO_WAIT;
        loop {
            let v = self
                .next_frame(deadline)
                .map_err(|e| ConnectError::Other(format!("waiting for the daemon's greeting: {e}")))?;
            if v.get("type").and_then(|t| t.as_str()) == Some("hello") {
                self.hello = parse_hello(&v);
                return Ok(());
            }
        }
    }

    fn next_frame(&mut self, deadline: Instant) -> Result<serde_json::Value, String> {
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| "timed out".to_string())?;
            self.reader
                .get_ref()
                .set_read_timeout(Some(left.max(Duration::from_millis(50))))
                .map_err(|e| e.to_string())?;
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return Err("the daemon closed the connection".into()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err("timed out".into())
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // A frame this client does not understand is not an error; the
            // daemon adds frame types freely.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                return Ok(v);
            }
        }
    }

    /// Send `cmd` with `args` and wait up to `timeout` for the final reply.
    /// `on_partial` sees each partial reply's `result`.
    pub fn request(
        &mut self,
        cmd: &str,
        args: serde_json::Map<String, serde_json::Value>,
        timeout: Duration,
        on_partial: &mut dyn FnMut(&serde_json::Value),
    ) -> Result<serde_json::Value, String> {
        self.request_split(cmd, args, timeout, on_partial)?
    }

    /// As [`Client::request`], keeping two failures apart: the daemon answered
    /// and refused (`Ok(Err(its reason))`), or the daemon was not reached
    /// (`Err`): the send or a read failed, or no reply came in time. A caller
    /// that sends many requests stops on the second and goes on after the first.
    pub fn request_split(
        &mut self,
        cmd: &str,
        mut args: serde_json::Map<String, serde_json::Value>,
        timeout: Duration,
        on_partial: &mut dyn FnMut(&serde_json::Value),
    ) -> Result<Result<serde_json::Value, String>, String> {
        let id = format!("{}-{}", std::process::id(), self.next_req);
        self.next_req += 1;
        args.insert("req".into(), serde_json::Value::String(id.clone()));
        args.insert("cmd".into(), serde_json::Value::String(cmd.to_string()));
        let mut line = serde_json::Value::Object(args).to_string();
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("sending {cmd}: {e}"))?;
        let deadline = Instant::now() + timeout;
        loop {
            let v = self.next_frame(deadline).map_err(|e| format!("{cmd}: {e}"))?;
            match reply_for(&v, &id) {
                Some(Outcome::Partial(result)) => on_partial(&result),
                Some(Outcome::Final(reply)) => return Ok(reply),
                None => {}
            }
        }
    }
}

impl Client {
    /// Every frame from here on, to `on_frame`, until it returns false or the
    /// daemon closes the connection (an error). No deadline: `conns --follow`
    /// runs until interrupted.
    pub fn follow(&mut self, on_frame: &mut dyn FnMut(&serde_json::Value) -> bool) -> Result<(), String> {
        self.reader.get_ref().set_read_timeout(None).map_err(|e| e.to_string())?;
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return Err("the daemon closed the connection".into()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                if !on_frame(&v) {
                    return Ok(());
                }
            }
        }
    }
}

pub enum Outcome {
    Partial(serde_json::Value),
    Final(Result<serde_json::Value, String>),
}

/// The reply for `id`, if `frame` is one. Anything else is `None`.
pub fn reply_for(frame: &serde_json::Value, id: &str) -> Option<Outcome> {
    if frame.get("type").and_then(|t| t.as_str()) != Some("reply") {
        return None;
    }
    if frame.get("req").and_then(|r| r.as_str()) != Some(id) {
        return None;
    }
    let ok = frame.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
    let partial = frame.get("partial").and_then(|b| b.as_bool()).unwrap_or(false);
    let result = frame.get("result").cloned().unwrap_or(serde_json::Value::Null);
    if partial {
        return Some(Outcome::Partial(result));
    }
    if ok {
        Some(Outcome::Final(Ok(result)))
    } else {
        let error = frame
            .get("error")
            .and_then(|e| e.as_str())
            .filter(|e| !e.is_empty())
            .unwrap_or("the daemon refused without a reason")
            .to_string();
        Some(Outcome::Final(Err(error)))
    }
}

pub fn parse_hello(v: &serde_json::Value) -> Hello {
    let s = |key: &str| v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let account = v.get("account").cloned().unwrap_or(serde_json::Value::Null);
    let a = |key: &str| account.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Hello {
        version: s("version"),
        mode: if s("mode").is_empty() { "user".into() } else { s("mode") },
        pid: v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0),
        connected: account.get("connected").and_then(|x| x.as_bool()).unwrap_or(false),
        github_username: a("github_username"),
        node_name: a("node_name"),
        requests: v.get("requests").and_then(|x| x.as_bool()).unwrap_or(false),
        as_uid: v.get("as_uid").and_then(|x| x.as_bool()).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_reply_with_our_id_counts() {
        assert!(reply_for(&json!({"type":"snapshot"}), "1").is_none());
        assert!(reply_for(&json!({"type":"reply","req":"2","ok":true}), "1").is_none());
        match reply_for(&json!({"type":"reply","req":"1","ok":true,"result":{"a":1}}), "1") {
            Some(Outcome::Final(Ok(r))) => assert_eq!(r["a"], 1),
            _ => panic!("final ok expected"),
        }
        match reply_for(&json!({"type":"reply","req":"1","ok":true,"partial":true,"result":{"code":"X"}}), "1") {
            Some(Outcome::Partial(r)) => assert_eq!(r["code"], "X"),
            _ => panic!("partial expected"),
        }
        match reply_for(&json!({"type":"reply","req":"1","ok":false,"error":"no"}), "1") {
            Some(Outcome::Final(Err(e))) => assert_eq!(e, "no"),
            _ => panic!("final err expected"),
        }
        match reply_for(&json!({"type":"reply","req":"1","ok":false}), "1") {
            Some(Outcome::Final(Err(e))) => assert!(e.contains("without a reason")),
            _ => panic!("final err expected"),
        }
    }

    #[test]
    fn hello_defaults_mode_to_user_and_never_carries_a_token() {
        let h = parse_hello(&json!({"type":"hello","version":"0.3.0","pid":7,
            "account":{"connected":true,"github_username":"octo","node_name":"box"}}));
        assert_eq!(h.mode, "user");
        assert_eq!(h.version, "0.3.0");
        assert!(h.connected);
        assert_eq!(h.github_username, "octo");
        assert_eq!(h.node_name, "box");
        let h = parse_hello(&json!({"type":"hello","mode":"system"}));
        assert_eq!(h.mode, "system");
        assert!(!h.connected);
        assert!(!h.requests, "an older daemon's hello has no requests flag");
        assert!(parse_hello(&json!({"type":"hello","requests":true})).requests);
        assert!(!parse_hello(&json!({"type":"hello","requests":true})).as_uid, "an older daemon");
        assert!(parse_hello(&json!({"type":"hello","requests":true,"as_uid":true})).as_uid);
    }
}
