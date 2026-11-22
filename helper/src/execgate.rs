//! Exec-gate trust requests.
//!
//! The system kub0d owns the exec gate's trust stores (`daemon/src/trust.rs`).
//! This helper, behind its own polkit actions, does not edit them: it appends
//! one JSON line to `requests.ndjson` under a lock and the daemon applies it
//! within a second. One writer per file, so a panel click and a daemon save
//! can never interleave. The line names a digest and an op, nothing else: no
//! path, no process, nothing that is not already on the org deny list.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Where the system kub0d reads requests (its `KUB0_EXEC_GATE_DIR` default),
/// under the state directory in use.
pub fn dir() -> std::path::PathBuf {
    crate::rename::state_path("execgate")
}
pub const REQUESTS_FILE: &str = "requests.ndjson";
pub const REQUESTS_LOCK: &str = "requests.lock";
const NOTE_CAP: usize = 200;

/// `trust`, `untrust`, `allow_once`: the daemon's closed op set.
pub fn op_for_verb(verb: &str) -> Option<&'static str> {
    match verb {
        "execgate-trust" => Some("trust"),
        "execgate-untrust" => Some("untrust"),
        "execgate-allow-once" => Some("allow_once"),
        _ => None,
    }
}

/// Lower-case 64 hex characters, or nothing. The digest is the only datum the
/// request carries, and it is the one word a notification action passes on.
pub fn canonical_sha256(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

pub fn request_line(op: &str, sha256: &str, uid: u32, ts: u64, note: &str) -> String {
    let note: String = note.chars().take(NOTE_CAP).collect();
    let mut line = serde_json::json!({
        "op": op,
        "sha256": sha256,
        "ts": ts,
        "uid": uid,
        "note": note,
    })
    .to_string();
    line.push('\n');
    line
}

/// Append one request under the daemon's lock. Root only: the directory is
/// root-owned and the lock file is 0600.
pub fn append_request(dir: &Path, op: &str, sha256: &str, uid: u32, ts: u64, note: &str) -> Result<(), String> {
    crate::rename::create_state_dir(dir, 0o755).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(REQUESTS_LOCK))
        .map_err(|e| format!("open lock: {e}"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("lock: {}", std::io::Error::last_os_error()));
    }
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(REQUESTS_FILE))
        .map_err(|e| format!("open requests: {e}"))?;
    f.write_all(request_line(op, sha256, uid, ts, note).as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    f.sync_data().map_err(|e| format!("sync request: {e}"))?;
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const A: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn verbs_map_to_the_daemons_ops_and_nothing_else() {
        assert_eq!(op_for_verb("execgate-trust"), Some("trust"));
        assert_eq!(op_for_verb("execgate-untrust"), Some("untrust"));
        assert_eq!(op_for_verb("execgate-allow-once"), Some("allow_once"));
        assert_eq!(op_for_verb("execgate-nuke"), None);
    }

    #[test]
    fn only_a_64_hex_digest_is_accepted_and_it_is_lower_cased() {
        assert_eq!(canonical_sha256(&A.to_ascii_uppercase()).as_deref(), Some(A));
        assert_eq!(canonical_sha256(&format!(" {A} ")).as_deref(), Some(A));
        assert!(canonical_sha256("abc").is_none());
        assert!(canonical_sha256(&format!("{A}0")).is_none());
        assert!(canonical_sha256("--action").is_none());
    }

    #[test]
    fn a_request_line_is_one_json_object_the_daemon_parses() {
        let line = request_line("trust", A, 1000, 5, &"n".repeat(300));
        assert!(line.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["op"], "trust");
        assert_eq!(v["sha256"], A);
        assert_eq!(v["uid"], 1000);
        assert_eq!(v["ts"], 5);
        assert_eq!(v["note"].as_str().unwrap().len(), NOTE_CAP);
    }

    #[test]
    fn requests_append_in_order_under_the_lock() {
        let dir = std::env::temp_dir().join(format!(
            "vallum-helper-execgate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        append_request(&dir, "trust", A, 1000, 1, "").unwrap();
        append_request(&dir, "allow_once", A, 1000, 2, "x").unwrap();
        let text = fs::read_to_string(dir.join(REQUESTS_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"op\":\"trust\""));
        assert!(lines[1].contains("\"op\":\"allow_once\""));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join(REQUESTS_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
