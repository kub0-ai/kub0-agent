//! What a daemon start leaves on disk for other accounts to read.
//!
//! The daemon's state says who connected where. It is run here as the
//! per-user daemon, on a replay, with HOME and the XDG directories pointing
//! into a temporary directory, so its default state directory is one this
//! test made. Nothing here is root and no real state is opened. The system
//! daemon closes its own directory through the same call (`statedir`, and
//! `close_default_state` in `main.rs`).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sandbox(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kub0-state-modes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["home", "state", "run"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    std::fs::set_permissions(d.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

/// Start the per-user daemon in `sb` and stop it once it has opened its
/// state (the history database is the last thing a start creates there).
fn start_and_stop(sb: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kub0d"))
        .args(["--socket"])
        .arg(sb.join("run/kub0.sock"))
        .arg("--replay")
        .arg(repo.join("tests/fixtures/replay.ndjson"))
        .arg("--data-dir")
        .arg(repo.join("data"))
        .env("HOME", sb.join("home"))
        .env("XDG_STATE_HOME", sb.join("state"))
        .env("XDG_RUNTIME_DIR", sb.join("run"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run kub0d");
    let opened = sb.join("state/kub0/history.sqlite");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !opened.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    // One more beat, so anything a start writes after the database is there.
    std::thread::sleep(Duration::from_millis(300));
    let _ = child.kill();
    let _ = child.wait();
    assert!(opened.exists(), "the daemon never opened its state in {}", sb.display());
}

/// Every path under `dir` that an account other than its owner can reach:
/// the directory itself if it lets them in, then each entry with a group or
/// other bit. A closed directory closes what is in it.
fn reachable_by_others(dir: &Path) -> Vec<String> {
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    let mut out = Vec::new();
    if mode(dir) & 0o077 == 0 {
        return out;
    }
    out.push(format!("{} {:o}", dir.display(), mode(dir)));
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if mode(&p) & 0o077 != 0 {
            out.push(format!("{} {:o}", p.file_name().unwrap().to_string_lossy(), mode(&p)));
        }
    }
    out
}

#[test]
fn a_first_start_makes_a_state_directory_other_accounts_cannot_enter() {
    let sb = sandbox("fresh");
    start_and_stop(&sb);
    let open = reachable_by_others(&sb.join("state/kub0"));
    assert!(open.is_empty(), "readable by accounts other than the daemon's: {open:?}");
    std::fs::remove_dir_all(&sb).unwrap();
}

#[test]
fn a_start_closes_a_state_directory_an_earlier_version_left_open() {
    let sb = sandbox("upgrade");
    // As 0.5.1 left it: the directory 0755, its records 0644.
    let state = sb.join("state/kub0");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["unknown.ndjson", "activity.ndjson", "hosts.json"] {
        std::fs::write(state.join(name), "").unwrap();
        std::fs::set_permissions(state.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    start_and_stop(&sb);
    let open = reachable_by_others(&state);
    assert!(open.is_empty(), "still readable by accounts other than the daemon's after a start: {open:?}");
    for name in ["unknown.ndjson", "activity.ndjson", "hosts.json"] {
        let mode = std::fs::metadata(state.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "{name} is {mode:o}");
    }
    std::fs::remove_dir_all(&sb).unwrap();
}
