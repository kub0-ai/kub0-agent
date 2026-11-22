//! The vallum → kub0 rename (#61 step 3): the new names, and the one-time
//! move of a 0.4.x state directory. kub0d, kub0-block and kub0 each compile
//! this file (std only, no crate dependency), so all three agree on where
//! state lives. Nothing here answers to a 0.4.x name any more: every `OLD_*`
//! name is something to move, to remove, or to recognise as a 0.4.x daemon
//! still running (whose state must not move under it).

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};

/// The system state directory, and the 0.4.x one the daemon moves to it.
pub const STATE_ROOT: &str = "/var/lib/kub0";
pub const OLD_STATE_ROOT: &str = "/var/lib/vallum";

/// The system daemon's runtime directory and sockets.
pub const RUNTIME_DIR: &str = "/run/kub0";
pub const SYSTEM_SOCKET: &str = "/run/kub0/kub0.sock";
pub const STATUS_SOCKET: &str = "/run/kub0/kub0-status.sock";
/// The 0.4.x command socket path. Nothing links it any more; a socket that
/// answers there is a 0.4.x daemon still running (the state must not move).
pub const OLD_SYSTEM_SOCKET: &str = "/run/vallum/vallum.sock";

/// The group that reads the status socket and reaches the command socket.
/// `kub0 install` renames the 0.4.x group in place, keeping its GID.
pub const STATUS_GROUP: &str = "kub0";
pub const OLD_STATUS_GROUP: &str = "vallum-status";

/// The system GID range from `/etc/login.defs` text: `SYS_GID_MIN` to
/// `SYS_GID_MAX`, else up to `GID_MIN - 1`, else 1 to 999.
pub fn system_gids(login_defs: &str) -> (u32, u32) {
    let get = |key: &str| {
        login_defs.lines().find_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some(key)).then(|| w.next().and_then(|v| v.parse::<u32>().ok())).flatten()
        })
    };
    let min = get("SYS_GID_MIN").unwrap_or(1).max(1);
    let max = get("SYS_GID_MAX").or_else(|| get("GID_MIN").map(|g| g.saturating_sub(1))).unwrap_or(999);
    (min, max)
}

/// The first `/etc/passwd` entry whose primary group is `gid`.
pub fn primary_group_of(passwd: &str, gid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && !f[0].starts_with('#') && f[3].parse::<u32>() == Ok(gid)).then(|| f[0].to_string())
    })
}

/// Why `name` (GID `gid`) cannot be the status group, or `None` when it can:
/// a system group (`system_gids`) that is no account's primary group. A
/// `kub0` group that was there first, a user's private group say, is not
/// one `kub0 install` made, and is never handed the command socket.
pub fn status_group_refusal(name: &str, gid: u32, passwd: &str, login_defs: &str) -> Option<String> {
    let (min, max) = system_gids(login_defs);
    if gid < min || gid > max {
        return Some(format!("the {name} group has GID {gid}, outside this host's system GIDs ({min}-{max}), so it is not one kub0 install made"));
    }
    primary_group_of(passwd, gid).map(|user| format!("the {name} group (GID {gid}) is the primary group of the account {user}, so it is not one kub0 install made"))
}

/// The per-user daemon's names under `$XDG_RUNTIME_DIR` and `$XDG_STATE_HOME`.
pub const USER_SOCKET_NAME: &str = "kub0.sock";
pub const USER_STATE_NAME: &str = "kub0";
pub const OLD_USER_STATE_NAME: &str = "vallum";

/// Something is at `p`: it exists, or it exists and this process may not
/// look at it (EACCES on a parent is still "there").
pub fn present(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

/// The path that holds a thing now: `old` while it still waits to be moved
/// (nothing at `new`, or nothing there but empty directories: a
/// `StateDirectory=` skeleton, or an empty mount point a failed move could
/// not replace), else `new`. A reader, a helper, or a daemon whose move
/// failed must not begin a second state directory beside the one that holds
/// the state.
pub fn current(new: &Path, old: &Path) -> PathBuf {
    if present(old) && (!present(new) || skeleton(new)) {
        old.to_path_buf()
    } else {
        new.to_path_buf()
    }
}

/// `p` is a directory holding nothing but empty directories.
fn skeleton(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) && only_empty_dirs(p, 0).unwrap_or(false)
}

/// Create `dir` and its missing parents, but never the 0.4.x state root
/// itself: a path under `/var/lib/vallum` is made one component at a time
/// below that root, so a helper that resolved the old root just before kub0d
/// moved it gets an error instead of recreating it empty.
pub fn create_state_dir(dir: &Path, mode: u32) -> io::Result<()> {
    create_dir_below(dir, Path::new(OLD_STATE_ROOT), mode)
}

/// `create_state_dir` with the protected root given, for tests.
pub fn create_dir_below(dir: &Path, protected: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let Ok(rest) = dir.strip_prefix(protected) else {
        return std::fs::DirBuilder::new().recursive(true).mode(mode).create(dir);
    };
    let mut at = protected.to_path_buf();
    for part in rest.components() {
        at.push(part);
        match std::fs::DirBuilder::new().mode(mode).create(&at) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && at.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The system state directory in use (`current` of the two roots).
pub fn state_root() -> PathBuf {
    current(Path::new(STATE_ROOT), Path::new(OLD_STATE_ROOT))
}

/// A path under the system state directory in use.
pub fn state_path(rel: &str) -> PathBuf {
    state_root().join(rel)
}

/// What `move_state` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    /// `old` was renamed to `new`.
    Moved,
    /// Nothing at `old`: a fresh install, or one moved already.
    NothingToMove,
    /// Both hold state. `new` is the one in use; `old` is left untouched.
    BothExist,
}

/// Directories nested deeper than this are content, not a skeleton.
const SKELETON_DEPTH: usize = 8;

/// `dir` holds nothing but (possibly nested) empty directories: what
/// systemd's `StateDirectory=` or an earlier `mkdir -p` leaves before
/// anything was written. A file, a symlink, a socket, or an unreadable
/// entry is content.
fn only_empty_dirs(dir: &Path, depth: usize) -> io::Result<bool> {
    if depth > SKELETON_DEPTH {
        return Ok(false);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let m = std::fs::symlink_metadata(&path)?;
        if !m.is_dir() || !only_empty_dirs(&path, depth + 1)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Remove an all-empty-directories tree, children first. `rmdir` refuses a
/// directory that is not empty, so a file written meanwhile is never lost:
/// the move then stops with that error instead.
fn remove_skeleton(dir: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if std::fs::symlink_metadata(&path)?.is_dir() {
            remove_skeleton(&path)?;
        }
    }
    std::fs::remove_dir(dir)
}

/// Move the 0.4.x state directory to its new path, once. One `rename(2)`
/// on the same filesystem: never a copy then a delete, so it is either done
/// or not, and a start interrupted anywhere simply runs it again.
///
/// * nothing at `old`: nothing to do;
/// * nothing at `new` (or only an empty skeleton, which is removed first):
///   `old` is renamed to `new`;
/// * real state at both: `new` is used and `old` is left as it is, for the
///   caller to report.
///
/// A rename the kernel refuses (another filesystem, a mount point, a
/// read-only view) is an error, and nothing has moved.
pub fn move_state(old: &Path, new: &Path) -> io::Result<Moved> {
    match std::fs::symlink_metadata(old) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Moved::NothingToMove),
        Err(e) => return Err(e),
    }
    match std::fs::symlink_metadata(new) {
        Ok(m) => {
            if !m.is_dir() || !only_empty_dirs(new, 0)? {
                return Ok(Moved::BothExist);
            }
            remove_skeleton(new)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::rename(old, new)?;
    Ok(Moved::Moved)
}

/// The system move, `/var/lib/vallum` to `/var/lib/kub0`.
pub fn move_system_state() -> io::Result<Moved> {
    move_state(Path::new(OLD_STATE_ROOT), Path::new(STATE_ROOT))
}

/// The 0.4.x daemon's binary name.
pub const OLD_DAEMON_NAME: &str = "vallumd";

/// Which 0.4.x daemon `old_daemon_running_in` looks for.
#[derive(Clone, Copy)]
pub enum OldDaemon<'a> {
    /// `vallumd --system`, which owns `/var/lib/vallum` whatever its flags.
    System,
    /// A per-user `vallumd` whose state directory is this one.
    User(&'a Path),
}

/// A process `owner` owns, other than this one, whose argv[0] is a 0.4.x
/// `vallumd`: with `--system`, or a per-user one using the given directory
/// (its `--state-dir`, else its own `$XDG_STATE_HOME/vallum`, else
/// `$HOME/.local/state/vallum`, read from its environment).
pub fn old_daemon_running_in(proc_root: &Path, owner: u32, which: OldDaemon) -> bool {
    use std::os::unix::fs::MetadataExt;
    let me = std::process::id().to_string();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return false;
    };
    let same = |a: &Path, b: &Path| a == b || matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y);
    entries.flatten().any(|e| {
        let name = e.file_name();
        let Some(pid) = name.to_str() else { return false };
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) || pid == me {
            return false;
        }
        if !std::fs::metadata(e.path()).is_ok_and(|m| m.uid() == owner) {
            return false;
        }
        let Ok(raw) = std::fs::read(e.path().join("cmdline")) else { return false };
        let args: Vec<&[u8]> = raw.split(|&b| b == 0).filter(|a| !a.is_empty()).collect();
        let Some(argv0) = args.first() else { return false };
        let base = argv0.rsplit(|&b| b == b'/').next().unwrap_or(argv0);
        if base != OLD_DAEMON_NAME.as_bytes() {
            return false;
        }
        let system = args.iter().any(|a| *a == b"--system");
        match which {
            OldDaemon::System => system,
            OldDaemon::User(dir) => !system && old_daemon_dir(&e.path(), &args).is_some_and(|d| same(&d, dir)),
        }
    })
}

/// The state directory a per-user 0.4.x daemon process uses.
fn old_daemon_dir(proc_entry: &Path, args: &[&[u8]]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if let Some(i) = args.iter().position(|a| *a == b"--state-dir") {
        return args.get(i + 1).map(|d| PathBuf::from(std::ffi::OsStr::from_bytes(d)));
    }
    let env = std::fs::read(proc_entry.join("environ")).ok()?;
    let var = |k: &[u8]| {
        env.split(|&b| b == 0)
            .find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix(b"=")))
            .filter(|v| !v.is_empty())
            .map(|v| PathBuf::from(std::ffi::OsStr::from_bytes(v)))
    };
    var(b"XDG_STATE_HOME")
        .map(|d| d.join(OLD_USER_STATE_NAME))
        .or_else(|| var(b"HOME").map(|h| h.join(".local/state").join(OLD_USER_STATE_NAME)))
}

/// The 0.4.x spelling of a `KUB0_*` variable, read through 0.4.6.
pub fn old_env_name(name: &str) -> Option<String> {
    name.strip_prefix("KUB0_").map(|rest| format!("VALLUM_{rest}"))
}

/// `name`, a `KUB0_*` variable. Its 0.4.x spelling is not read any more. One
/// that is still set, with the new name unset, says so once per process: a
/// switch someone set (the exec gate's off switch among them) must not stop
/// working in silence.
pub fn env_os(name: &str) -> Option<std::ffi::OsString> {
    let value = std::env::var_os(name);
    if value.is_none() {
        if let Some(old) = old_env_name(name).filter(|old| std::env::var_os(old).is_some()) {
            warn_once(&old, name);
        }
    }
    value
}

/// `env_os` as a UTF-8 string; a value that is not UTF-8 is unset.
pub fn env(name: &str) -> Option<String> {
    env_os(name).and_then(|v| v.into_string().ok())
}

fn warn_once(old: &str, new: &str) {
    static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut seen = match SEEN.lock() {
        Ok(s) => s,
        Err(p) => p.into_inner(),
    };
    if !seen.iter().any(|s| s == old) {
        seen.push(old.to_string());
        eprintln!("{old} is set but is not read any more; set {new} instead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kub0-rename-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A 0.4.x state directory: account, exec-gate trusts, scoped records,
    /// the expiry timer's records, the daemon's own state.
    fn old_tree(root: &Path) {
        for (rel, body) in [
            ("account.json", "{\"token\":\"fixture\"}"),
            ("execgate/trusts.json", "[\"aa\"]"),
            ("scoped/1000-app-192.0.2.1.json", "{\"until\":1}"),
            ("cgroup-blocks/firefox", ""),
            ("daemon/history.sqlite", "sqlite"),
            ("endpoint-owners.json", "{}"),
        ] {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
    }

    fn tree(root: &Path) -> Vec<(String, String)> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
            for e in fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    let rel = p.strip_prefix(base).unwrap().display().to_string();
                    out.push((rel, fs::read_to_string(&p).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn the_move_brings_every_record_to_the_new_directory() {
        let d = scratch("moves");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        old_tree(&old);
        let before = tree(&old);
        assert_eq!(move_state(&old, &new).unwrap(), Moved::Moved);
        assert!(!present(&old), "the old directory is gone, not copied");
        assert_eq!(tree(&new), before, "account, trusts, scoped and expiry records all moved");
        assert_eq!(move_state(&old, &new).unwrap(), Moved::NothingToMove, "a second start does nothing");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn with_state_at_both_the_old_directory_is_left_untouched() {
        let d = scratch("both");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        old_tree(&old);
        fs::create_dir_all(new.join("execgate")).unwrap();
        fs::write(new.join("account.json"), "{\"token\":\"newer\"}").unwrap();
        let (old_before, new_before) = (tree(&old), tree(&new));
        assert_eq!(move_state(&old, &new).unwrap(), Moved::BothExist);
        assert_eq!(tree(&old), old_before, "vallum untouched");
        assert_eq!(tree(&new), new_before, "kub0 is the one in use, unchanged");
        assert_eq!(current(&new, &old), new);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn an_interrupted_move_resumes_on_the_next_start() {
        let d = scratch("resume");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        old_tree(&old);
        let before = tree(&old);
        // Interrupted before the rename: the new path holds only what
        // StateDirectory= or a mkdir -p left (empty directories), and the
        // old one still holds everything.
        fs::create_dir_all(new.join("daemon")).unwrap();
        fs::create_dir_all(new.join("execgate/pending")).unwrap();
        assert_eq!(move_state(&old, &new).unwrap(), Moved::Moved);
        assert_eq!(tree(&new), before);
        assert!(!present(&old));
        // Interrupted part-way through clearing that skeleton: the same.
        old_tree(&old);
        fs::remove_dir_all(&new).unwrap();
        fs::create_dir_all(&new).unwrap();
        assert_eq!(move_state(&old, &new).unwrap(), Moved::Moved);
        assert_eq!(tree(&new), before);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn with_no_old_directory_nothing_happens() {
        let d = scratch("absent");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        assert_eq!(move_state(&old, &new).unwrap(), Moved::NothingToMove);
        assert!(!present(&new), "nothing is created");
        fs::create_dir_all(new.join("daemon")).unwrap();
        assert_eq!(move_state(&old, &new).unwrap(), Moved::NothingToMove);
        assert!(new.join("daemon").is_dir(), "an existing new directory is not touched");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_reader_before_the_move_uses_the_old_directory() {
        let d = scratch("current");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        assert_eq!(current(&new, &old), new, "a fresh host");
        fs::create_dir_all(&old).unwrap();
        assert_eq!(current(&new, &old), old, "not moved yet: no second directory beside it");
        fs::create_dir_all(&new).unwrap();
        assert_eq!(current(&new, &old), old, "an empty new directory holds nothing yet");
        fs::write(new.join("account.json"), "{}").unwrap();
        assert_eq!(current(&new, &old), new);
        let _ = fs::remove_dir_all(&d);
    }

    /// A move that failed with the new path present (an empty mount point
    /// returns EBUSY, a skeleton can be left) keeps every reader on the old
    /// directory, as the log line says; real state at the new path wins.
    #[test]
    fn an_empty_new_directory_does_not_take_over_from_the_old_one() {
        let d = scratch("pinned");
        let (old, new) = (d.join("vallum"), d.join("kub0"));
        old_tree(&old);
        fs::create_dir_all(new.join("lost+found")).unwrap();
        assert_eq!(current(&new, &old), old, "an empty mount point is not where the state is");
        fs::write(new.join("account.json"), "{}").unwrap();
        assert_eq!(current(&new, &old), new, "state at both: the new one, as move_state reports");
        let _ = fs::remove_dir_all(&d);
    }

    /// The helper never recreates the old root after kub0d moved it.
    #[test]
    fn a_state_directory_below_the_old_root_needs_the_old_root() {
        let d = scratch("create");
        let root = d.join("vallum");
        let err = create_dir_below(&root.join("scoped"), &root, 0o755).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!present(&root), "the old root is never created");
        fs::create_dir(&root).unwrap();
        create_dir_below(&root.join("execgate/pending"), &root, 0o755).unwrap();
        assert!(root.join("execgate/pending").is_dir());
        create_dir_below(&root.join("execgate/pending"), &root, 0o755).unwrap();
        let elsewhere = d.join("kub0/scoped");
        create_dir_below(&elsewhere, &root, 0o755).unwrap();
        assert!(elsewhere.is_dir(), "anything else is created as usual");
        let _ = fs::remove_dir_all(&d);
    }

    /// Only a system group that is nobody's primary group can be the status
    /// group: a `kub0` user's private group never is.
    #[test]
    fn the_status_group_must_be_a_system_group_and_nobodys_primary_group() {
        assert_eq!(system_gids(""), (1, 999));
        assert_eq!(system_gids("GID_MIN 500\n"), (1, 499));
        assert_eq!(system_gids("# comment\nSYS_GID_MIN   201\nSYS_GID_MAX 499\nGID_MIN 1000\n"), (201, 499));
        let passwd = "root:x:0:0::/root:/bin/sh\nkub0:x:1001:1001::/home/kub0:/bin/sh\nsvc:x:960:981::/:/usr/bin/nologin\n";
        assert_eq!(status_group_refusal("kub0", 975, passwd, ""), None, "a system group nobody has as primary");
        let upg = status_group_refusal("kub0", 1001, passwd, "").unwrap();
        assert!(upg.contains("outside this host's system GIDs"), "{upg}");
        let primary = status_group_refusal("kub0", 981, passwd, "").unwrap();
        assert!(primary.contains("primary group of the account svc"), "{primary}");
        assert!(status_group_refusal("kub0", 300, "", "SYS_GID_MIN 101\nSYS_GID_MAX 299\n").is_some());
    }

    /// A 0.4.x daemon is found by its process, wherever its socket is, and a
    /// per-user one counts only for the directory it uses.
    #[test]
    fn an_old_daemon_is_found_by_its_process() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("kub0d-old-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let entry = |pid: &str, cmdline: &[u8], environ: &[u8]| {
            std::fs::create_dir_all(dir.join(pid)).unwrap();
            std::fs::write(dir.join(pid).join("cmdline"), cmdline).unwrap();
            std::fs::write(dir.join(pid).join("environ"), environ).unwrap();
        };
        let mine = Path::new("/home/u/.local/state/vallum");
        let user = OldDaemon::User(mine);
        entry("12", b"/home/u/.config/omarchy/plugins/ai.kub0.vallum/bin/kub0d\0--state-dir\0/home/u/.local/state/vallum\0", b"");
        assert!(!old_daemon_running_in(&dir, me, user), "a kub0d is not a 0.4.x daemon");
        entry("13", b"/opt/panel/bin/vallumd\0--socket\0/custom/where.sock\0--state-dir\0/home/u/.local/state/vallum\0", b"");
        assert!(old_daemon_running_in(&dir, me, user), "found with its socket at no default path");
        assert!(!old_daemon_running_in(&dir, me, OldDaemon::User(Path::new("/tmp/private/vallum"))), "another directory's daemon");
        assert!(!old_daemon_running_in(&dir, me, OldDaemon::System), "not a system daemon");
        assert!(!old_daemon_running_in(&dir, me.wrapping_add(1), user), "another user's");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        entry("15", b"vallumd\0--interval-ms\0500\0", b"PATH=/usr/bin\0HOME=/home/u\0");
        assert!(old_daemon_running_in(&dir, me, user), "no --state-dir: its own HOME default");
        entry("16", b"vallumd\0", b"XDG_STATE_HOME=/srv/st\0HOME=/home/u\0");
        assert!(old_daemon_running_in(&dir, me, OldDaemon::User(Path::new("/srv/st/vallum"))), "its own XDG_STATE_HOME");
        entry("14", b"/usr/lib/vallum/vallumd\0--system\0", b"");
        assert!(old_daemon_running_in(&dir, me, OldDaemon::System));
        let own = std::process::id().to_string();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        entry(&own, b"/usr/lib/vallum/vallumd\0--system\0", b"");
        assert!(!old_daemon_running_in(&dir, me, OldDaemon::System), "this process, run through the old path, is not another daemon");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 0.4.5 and 0.4.6 read the old spelling with a warning. Now only the
    /// new name is read; the old one, still set, changes nothing.
    #[test]
    fn a_vallum_variable_is_no_longer_read() {
        assert_eq!(old_env_name("KUB0_EXEC_GATE").as_deref(), Some("VALLUM_EXEC_GATE"));
        assert_eq!(old_env_name("HOME"), None);
        let new = format!("KUB0_RENAME_TEST_{}", std::process::id());
        let old = old_env_name(&new).unwrap();
        std::env::remove_var(&new);
        std::env::set_var(&old, "0");
        assert_eq!(env(&new), None, "the old name is not read");
        std::env::set_var(&new, "1");
        assert_eq!(env(&new).as_deref(), Some("1"));
        std::env::remove_var(&new);
        std::env::remove_var(&old);
        assert_eq!(env(&new), None);
    }
}
