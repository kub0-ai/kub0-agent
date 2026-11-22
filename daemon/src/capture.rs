//! Optional, root-owned local collector. Attempts never become live socket counts.
use crate::event::Connection;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Instant,
};

pub const COLLECTOR: &str = "/usr/lib/kub0/kub0-capture";

/// The collector `scripts/install-capture.sh` installs. One left at the
/// 0.4.x path by an install before the rename is not used: run the script
/// again.
pub fn collector() -> PathBuf {
    PathBuf::from(COLLECTOR)
}
pub const QUEUE_CAP: usize = 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub state: String,
    pub detail: String,
    pub received: u64,
    pub emitted: u64,
    pub kernel_dropped: u64,
    #[serde(default)]
    pub collector_dropped: u64,
    pub userspace_dropped: u64,
    pub invalid: u64,
    /// The collector attached the DNS-answer program. False on a kernel that
    /// refused it, in which case names still come only from PTR lookups.
    #[serde(default)]
    pub dns: bool,
    #[serde(default)]
    pub dns_received: u64,
    #[serde(default)]
    pub dns_dropped: u64,
    /// Queries the egress program recorded, and responses the ingress program
    /// refused because no query from the same socket matched (id, name and
    /// server). A rising `dns_unmatched` with `dns_received` at zero means
    /// responses arrive that nothing in this slice asked for.
    #[serde(default)]
    pub dns_queries: u64,
    #[serde(default)]
    pub dns_unmatched: u64,
    /// Matched answers the daemon still refused because the server was not a
    /// resolver in `/etc/resolv.conf` (loopback only when it is unreadable).
    #[serde(default)]
    pub dns_foreign: u64,
}
impl Status {
    pub fn unavailable(detail: String) -> Self {
        Self {
            state: "unavailable".into(),
            detail,
            received: 0,
            emitted: 0,
            kernel_dropped: 0,
            collector_dropped: 0,
            userspace_dropped: 0,
            invalid: 0,
            dns: false,
            dns_received: 0,
            dns_dropped: 0,
            dns_queries: 0,
            dns_unmatched: 0,
            dns_foreign: 0,
        }
    }
}

pub enum Message {
    Attempt(Connection),
    Status(Status),
    Dns(crate::dns::Answer),
}
pub fn decode(line: &str, uid: u32, serial: u64, now: u64) -> Result<Message, String> {
    if line.len() > 2048 {
        return Err("oversized capture frame".into());
    }
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let num = |key: &str| {
        v.get(key)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("invalid capture {key}"))
    };
    if v.get("type").and_then(|s| s.as_str()) == Some("capture-status") {
        if v.get("state").and_then(|s| s.as_str()) != Some("current") {
            return Err("invalid capture state".into());
        }
        return Ok(Message::Status(Status {
            state: "current".into(),
                detail: "Attempts in your user slice only; apps moved to Vallum scopes are excluded. Success and bytes are unknown"
                .into(),
            received: num("received")?,
            emitted: num("emitted")?,
            kernel_dropped: num("kernelDropped")?,
            collector_dropped: v
                .get("collectorDropped")
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
            invalid: num("invalid")?,
            userspace_dropped: 0,
            dns: v.get("dns").and_then(|b| b.as_bool()).unwrap_or(false),
            dns_received: v.get("dnsReceived").and_then(|n| n.as_u64()).unwrap_or(0),
            dns_dropped: v.get("dnsDropped").and_then(|n| n.as_u64()).unwrap_or(0),
            dns_queries: v.get("dnsQueries").and_then(|n| n.as_u64()).unwrap_or(0),
            dns_unmatched: v.get("dnsUnmatched").and_then(|n| n.as_u64()).unwrap_or(0),
            dns_foreign: 0,
        }));
    }
    if v.get("type").and_then(|s| s.as_str()) == Some("dns") {
        return crate::dns::parse(&v, uid, now).map(Message::Dns);
    }
    if v.get("type").and_then(|s| s.as_str()) != Some("attempt") || num("uid")? != u64::from(uid) {
        return Err("capture source/owner mismatch".into());
    }
    let pid = num("pid")?;
    let ts = num("ts")?;
    if pid == 0
        || pid > u32::MAX as u64
        || ts == 0
        || ts > now.saturating_add(1000)
        || ts < now.saturating_sub(crate::history::RETENTION_MS)
    {
        return Err("invalid capture pid/time".into());
    }
    let proto = v
        .get("proto")
        .and_then(|s| s.as_str())
        .ok_or("missing protocol")?;
    let op = v
        .get("operation")
        .and_then(|s| s.as_str())
        .ok_or("missing operation")?;
    if !matches!(proto, "tcp" | "udp")
        || !matches!(op, "connect" | "sendmsg")
        || (op == "sendmsg" && proto != "udp")
    {
        return Err("invalid capture operation".into());
    }
    let ip: IpAddr = v
        .get("ip")
        .and_then(|s| s.as_str())
        .ok_or("missing IP")?
        .parse()
        .map_err(|_| "invalid capture IP")?;
    let ip = match ip {
        IpAddr::V6(a) => a
            .to_ipv4_mapped()
            .map(|a| a.to_string())
            .unwrap_or_else(|| a.to_string()),
        a => a.to_string(),
    };
    let port = num("port")?;
    if port == 0 || port > 65535 {
        return Err("invalid capture port".into());
    }
    let hex = v
        .get("commHex")
        .and_then(|s| s.as_str())
        .ok_or("missing command")?;
    if hex.len() != 32 || !hex.is_ascii() {
        return Err("invalid capture command".into());
    }
    let bytes = (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "invalid command encoding"))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())];
    let name = String::from_utf8_lossy(bytes).into_owned();
    let c=serde_json::from_value(serde_json::json!({
        "id":format!("capture-{pid}-{ts}-{serial}"),"proto":proto,"inode":0,"exe":"","uid":uid,
        "app":{"id":format!("capture-pid-{pid}"),"name":if name.is_empty(){format!("PID {pid}")}else{name},"pid":pid,"icon":"","desktop":""},
        "local":{"ip":"","port":0},"remote":{"ip":ip,"port":port},"state":format!("{op}-attempt"),
        "bytes":null,"evidence":{"source":"ebpf","recordedAt":ts,"verdict":null,"ownerMethod":"Kernel calling PID/UID/comm at connect or unconnected UDP sendmsg; executable and socket lifetime unknown","hash":null,"container":null}
    })).map_err(|e|e.to_string())?;
    Ok(Message::Attempt(c))
}

pub fn verify_collector(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o111 == 0 {
        return Err("collector must be a root-owned, non-writable executable".into());
    }
    for p in path.parent().ok_or("invalid collector path")?.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe collector parent".into());
        }
    }
    Ok(())
}
struct Shared {
    status: Mutex<(Status, Instant)>,
    dropped: AtomicU64,
    dns_dropped: AtomicU64,
    invalid: AtomicU64,
    running: AtomicBool,
}
pub struct Capture {
    rx: mpsc::Receiver<Connection>,
    dns_rx: mpsc::Receiver<crate::dns::Answer>,
    shared: Arc<Shared>,
    _child: Child,
    input: Option<ChildStdin>,
}
impl Capture {
    pub fn start() -> Result<Self, String> {
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0 {
            return Err("capture is supported in Linux user mode".into());
        }
        let collector = collector();
        verify_collector(&collector)?;
        let uid = unsafe { libc::geteuid() };
        let mut child = Command::new("/usr/bin/pkexec")
            .arg(&collector)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("collector stdout unavailable")?;
        let input = child.stdin.take();
        let (tx, rx) = mpsc::sync_channel(QUEUE_CAP);
        let (dns_tx, dns_rx) = mpsc::sync_channel(QUEUE_CAP);
        let shared = Arc::new(Shared {
            status: Mutex::new((
                Status {
                    state: "starting".into(),
                    ..Status::unavailable("Awaiting collector authorization".into())
                },
                Instant::now(),
            )),
            dropped: AtomicU64::new(0),
            dns_dropped: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });
        let state = shared.clone();
        std::thread::spawn(move || {
            let mut serial = 0u64;
            let mut reader = BufReader::new(stdout);
            loop {
                // Read a bounded line without allowing an unbounded allocation.
                let mut line = Vec::new();
                let mut oversized = false;
                loop {
                    let buffer = match reader.fill_buf() {
                        Ok(b) => b,
                        Err(_) => break,
                    };
                    if buffer.is_empty() {
                        break;
                    }
                    let n = buffer
                        .iter()
                        .position(|b| *b == b'\n')
                        .map(|p| p + 1)
                        .unwrap_or(buffer.len());
                    if line.len() + n <= 2048 && !oversized {
                        line.extend_from_slice(&buffer[..n]);
                    } else {
                        oversized = true;
                    }
                    let end = buffer[n - 1] == b'\n';
                    reader.consume(n);
                    if end {
                        break;
                    }
                }
                if line.is_empty() && !oversized {
                    break;
                }
                serial = serial.wrapping_add(1);
                let now = crate::event::now_ms();
                let result = if oversized {
                    Err("oversized capture frame".into())
                } else {
                    String::from_utf8(line)
                        .map_err(|_| "invalid capture UTF-8".into())
                        .and_then(|line| decode(&line, uid, serial, now))
                };
                match result {
                    Ok(Message::Attempt(c)) => {
                        if tx.try_send(c).is_err() {
                            state.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(Message::Dns(a)) => {
                        if dns_tx.try_send(a).is_err() {
                            state.dns_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(Message::Status(s)) => *state.status.lock().unwrap() = (s, Instant::now()),
                    Err(_) => {
                        state.invalid.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            state.running.store(false, Ordering::Relaxed);
            let mut s = state.status.lock().unwrap();
            s.0.state = "unavailable".into();
            s.0.detail = "Collector stopped; procfs sampling continues".into();
        });
        Ok(Self {
            rx,
            dns_rx,
            shared,
            _child: child,
            input,
        })
    }
    /// DNS answers decoded since the last call.
    pub fn poll_dns(&mut self) -> Vec<crate::dns::Answer> {
        self.dns_rx.try_iter().take(QUEUE_CAP).collect()
    }
    pub fn poll(&mut self) -> (Vec<Connection>, Status) {
        let _ = self._child.try_wait();
        let rows = self.rx.try_iter().take(QUEUE_CAP).collect();
        let (mut s, when) = self.shared.status.lock().unwrap().clone();
        if self.running() && when.elapsed().as_secs() > 3 {
            s.state = "stale".into();
            s.detail =
                "Collector has not reported current counters; procfs sampling continues".into();
        }
        s.userspace_dropped = self.shared.dropped.load(Ordering::Relaxed);
        // Kernel-side DNS loss from the collector plus this side's queue loss.
        s.dns_dropped = s.dns_dropped.saturating_add(self.shared.dns_dropped.load(Ordering::Relaxed));
        s.invalid = s
            .invalid
            .saturating_add(self.shared.invalid.load(Ordering::Relaxed));
        (rows, s)
    }
    pub fn running(&self) -> bool {
        self.shared.running.load(Ordering::Relaxed)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"stop\n");
        }
        let _ = self._child.try_wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> String {
        serde_json::json!({"type":"attempt","uid":1000,"pid":123,"ts":1000,"proto":"udp","operation":"sendmsg","ip":"::ffff:127.0.0.1","port":443,"commHex":"70726f62650000000000000000000000"}).to_string()
    }
    #[test]
    fn captures_are_attempts_with_unknown_transfer_and_no_invented_verdict() {
        match decode(&frame(), 1000, 1, 1000).unwrap() {
            Message::Attempt(c) => {
                assert_eq!(c.app.name, "probe");
                assert_eq!(c.remote.ip, "127.0.0.1");
                assert_eq!(c.state, "sendmsg-attempt");
                assert!(c.bytes.is_none());
                assert!(c.evidence.unwrap().verdict.is_none());
            }
            _ => panic!(),
        }
    }
    #[test]
    fn ownership_shape_and_size_are_checked() {
        assert!(decode(&frame(), 1001, 1, 1000).is_err());
        assert!(decode(&"x".repeat(2049), 1000, 1, 1000).is_err());
        assert!(decode(&frame().replace("sendmsg", "exec"), 1000, 1, 1000).is_err());
    }
    #[test]
    fn dns_frames_decode_to_answers_for_the_owner_only() {
        let line = r#"{"type":"dns","ts":1000,"uid":1000,"name":"cdn.example.net","ip":"203.0.113.7","ttl":60}"#;
        match decode(line, 1000, 1, 1000).unwrap() {
            Message::Dns(a) => {
                assert_eq!(a.name, "cdn.example.net");
                assert_eq!(a.ip, "203.0.113.7");
                assert_eq!(a.ttl, 60);
            }
            _ => panic!("not a dns answer"),
        }
        assert!(decode(line, 1001, 1, 1000).is_err());
        match decode(r#"{"type":"capture-status","state":"current","received":1,"emitted":1,"kernelDropped":0,"invalid":0,"dns":true,"dnsReceived":4}"#, 1000, 1, 1000).unwrap() {
            Message::Status(s) => {
                assert!(s.dns);
                assert_eq!(s.dns_received, 4);
            }
            _ => panic!(),
        }
    }
    #[test]
    fn loss_counters_are_reported() {
        match decode(r#"{"type":"capture-status","state":"current","received":10,"emitted":12,"kernelDropped":2,"invalid":0}"#,1000,1,1000).unwrap(){Message::Status(s)=>{assert_eq!(s.kernel_dropped,2);assert_eq!(s.emitted,12);},_=>panic!()}
    }
}
