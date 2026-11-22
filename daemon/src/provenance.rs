//! What is known about the executable behind a connection, from the file on
//! disk: where it lives, who may write it, whether it still exists, and its
//! SHA-256.
//!
//! App identity in vallum is the process's exe path, which the process does
//! not choose but the person who installed it did. Two things make that
//! identity worth more than a name: the hash, which lets a row be compared
//! with a known build (`app.hash` has been reserved on the wire since v0 for
//! exactly this), and the location flags, which catch the cases where a
//! familiar name sits in an unfamiliar place.
//!
//! Hashing a large binary is not free, so it happens once per (path, size,
//! mtime) on a worker thread and the result is patched into rows as it lands,
//! the way reverse-DNS names are. The flags come from one `stat` and are
//! available immediately.

use crate::intel::ExeFlag;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::SystemTime;

/// Files larger than this are not hashed; the flags still apply. A 2 GiB
/// Electron bundle would otherwise own a worker for a long time for little.
pub const HASH_MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provenance {
    /// `sha256:<hex>` once computed; `None` while pending or if unreadable.
    pub hash: Option<String>,
    pub flags: Vec<ExeFlag>,
    /// The hash worker has answered (with a hash, or with "cannot").
    pub settled: bool,
    /// What the package manager said owns the file: `Some(Owned(name))`,
    /// `Some(Unowned)`, or `None` when not asked, not answered yet, or no
    /// manager is known. Asked only for system directories; a binary under
    /// `$HOME` is unowned by construction and that is not news.
    pub package: Option<String>,
    /// The manager answered that nothing owns a file in a system directory.
    pub unpackaged: bool,
    /// For a deleted executable whose path holds a file in a system directory
    /// again: whether a package owns that file, i.e. the package manager
    /// replaced the binary under the running process. `None` until it answers,
    /// and for every other executable.
    pub replacement_packaged: Option<bool>,
}

/// Directories whose contents a distribution package is expected to own.
pub const SYSTEM_DIRS: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/etc/"];

pub fn in_system_dir(path: &str) -> bool {
    SYSTEM_DIRS.iter().any(|d| path.starts_with(d))
}

/// Which package manager this host has, by the binary's presence, checked
/// once. Only the local database is queried, never a network index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Pacman,
    Dpkg,
    Rpm,
}

pub fn detect_package_manager() -> Option<PackageManager> {
    if Path::new("/usr/bin/pacman").is_file() {
        Some(PackageManager::Pacman)
    } else if Path::new("/usr/bin/dpkg-query").is_file() {
        Some(PackageManager::Dpkg)
    } else if Path::new("/usr/bin/rpm").is_file() {
        Some(PackageManager::Rpm)
    } else {
        None
    }
}

/// On a merged-/usr system `/proc/<pid>/exe` says `/usr/bin/bash` while dpkg's
/// file list may still say `/bin/bash` (or the reverse). The other spelling.
pub fn merged_usr_alias(path: &str) -> Option<String> {
    for d in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] {
        let usr = format!("/usr/{d}/");
        let root = format!("/{d}/");
        if let Some(rest) = path.strip_prefix(&usr) {
            return Some(format!("{root}{rest}"));
        }
        if let Some(rest) = path.strip_prefix(&root) {
            return Some(format!("{usr}{rest}"));
        }
    }
    None
}

/// Owner of `path` per the manager: `Ok(Some(name version))`, `Ok(None)` for
/// "no package owns this", `Err` when the manager could not be asked. A miss
/// is retried under the merged-/usr alias before it counts.
pub fn package_owner(pm: PackageManager, path: &str) -> Result<Option<String>, String> {
    match package_owner_exact(pm, path)? {
        Some(owner) => Ok(Some(owner)),
        None => match merged_usr_alias(path) {
            Some(alias) => package_owner_exact(pm, &alias),
            None => Ok(None),
        },
    }
}

fn package_owner_exact(pm: PackageManager, path: &str) -> Result<Option<String>, String> {
    let (bin, args): (&str, Vec<&str>) = match pm {
        PackageManager::Pacman => ("/usr/bin/pacman", vec!["-Qqo", path]),
        PackageManager::Dpkg => ("/usr/bin/dpkg-query", vec!["-S", path]),
        PackageManager::Rpm => ("/usr/bin/rpm", vec!["-qf", path]),
    };
    let out = std::process::Command::new(bin)
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    Ok(parse_owner(pm, out.status.success(), &stdout, &stderr))
}

/// The pure half of [`package_owner`], pinned by tests against each
/// manager's real output shape.
pub fn parse_owner(pm: PackageManager, success: bool, stdout: &str, stderr: &str) -> Option<String> {
    let first = stdout.lines().next().unwrap_or("").trim();
    match pm {
        PackageManager::Pacman => {
            // `pacman -Qqo /usr/bin/x` prints the bare package name; on a miss
            // it exits 1 with "error: No package owns /usr/bin/x" on stderr.
            // A miss exits 1 with "error: No package owns ..." on stderr; any
            // other failure is also "nothing we can name".
            let _ = stderr;
            if success && !first.is_empty() {
                Some(first.to_string())
            } else {
                None
            }
        }
        PackageManager::Dpkg => {
            // "coreutils: /usr/bin/ls" or, with diversions, "diversion by ...".
            if success {
                first.split(':').next().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with("diversion")).map(str::to_string)
            } else {
                None
            }
        }
        PackageManager::Rpm => {
            // "coreutils-9.4-1.fc40.x86_64" or "file /usr/bin/x is not owned by any package".
            if success && !first.is_empty() && !first.contains("not owned") {
                Some(first.to_string())
            } else {
                None
            }
        }
    }
}

/// What the kernel appends to `/proc/<pid>/exe` once the file is unlinked.
pub const DELETED_MARKER: &str = " (deleted)";

/// The flags of a deleted executable whose replacement's owner was `asked`
/// about. A package-owned replacement is an upgrade: `exe-deleted` gives way
/// to `exe-changed` (the running code is not the file). An unowned one, or a
/// manager that could not answer, keeps `exe-deleted`. Before the answer,
/// `exe-deleted` is held back, and the row is settled when the answer lands
/// (`intel::reconcile_replaced`), so an upgrade never raises a warning first.
pub fn replaced_flags(mut flags: Vec<ExeFlag>, asked: bool, owned: Option<bool>) -> Vec<ExeFlag> {
    if !asked {
        return flags;
    }
    match owned {
        Some(false) => {}
        Some(true) => {
            flags.retain(|f| *f != ExeFlag::Deleted);
            if !flags.contains(&ExeFlag::ChangedSinceStart) {
                flags.push(ExeFlag::ChangedSinceStart);
            }
        }
        None => flags.retain(|f| *f != ExeFlag::Deleted),
    }
    flags
}

/// Classify an exe path from `/proc/<pid>/exe` and its metadata. Pure, so the
/// flags are pinned by tests rather than by what is on the test machine.
pub fn flags_for(exe: &str, home: Option<&str>, mode: Option<u32>, changed_since_start: bool) -> Vec<ExeFlag> {
    flags_for_with_mounts(exe, home, mode, changed_since_start, "")
}

/// `mounts` is the text of `/proc/self/mounts`, consulted only for the
/// AppImage case: a binary under `/tmp/.mount_*` is exempt from the temp-dir
/// flag only when that directory really is a FUSE or squashfs mount point,
/// which is what an AppImage runtime creates. A plain directory with that
/// name is a binary hiding behind a familiar prefix and is flagged.
pub fn flags_for_with_mounts(exe: &str, home: Option<&str>, mode: Option<u32>, changed_since_start: bool, mounts: &str) -> Vec<ExeFlag> {
    flags_for_with_ancestry(exe, home, mode, changed_since_start, mounts, &[])
}

/// `ancestors` is the process's ancestry by comm, parent first, as
/// `lineage::read` lists it. It decides one thing: a binary under a Go build
/// directory (`/tmp/go-build<digits>/`) whose `go` tool is within
/// [`GO_ANCESTOR_HOPS`] is a build-dir binary, not a temp-dir one. The path
/// alone is not enough (anything can mkdir a familiar name), and neither is
/// the parent alone (`go` runs plenty from elsewhere): both must hold, the
/// same bar the AppImage exemption sets with the mount table.
pub fn flags_for_with_ancestry(
    exe: &str,
    home: Option<&str>,
    mode: Option<u32>,
    changed_since_start: bool,
    mounts: &str,
    ancestors: &[&str],
) -> Vec<ExeFlag> {
    let mut out = Vec::new();
    let path = exe.strip_suffix(" (deleted)");
    if path.is_some() {
        out.push(ExeFlag::Deleted);
    }
    let path = path.unwrap_or(exe);
    let appimage = is_appimage_mount(mounts, path);
    if !appimage && ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|p| path.starts_with(p)) {
        if is_go_build_dir(path) && has_go_ancestor(ancestors) {
            out.push(ExeFlag::BuildDir);
        } else {
            out.push(ExeFlag::TempDir);
        }
    }
    if let Some(mode) = mode {
        if mode & 0o002 != 0 {
            out.push(ExeFlag::WorldWritable);
        }
    }
    if let Some(home) = home.filter(|h| !h.is_empty() && *h != "/") {
        let home = home.trim_end_matches('/');
        if let Some(rest) = path.strip_prefix(home).and_then(|r| r.strip_prefix('/')) {
            // ~/.local/bin is where XDG puts user-installed programs and where
            // pipx, uv and friends link theirs; only the directories below it
            // that are meant for data count as hidden.
            let hidden = rest.starts_with('.') && !rest.starts_with(".local/bin/");
            if hidden {
                out.push(ExeFlag::HiddenHome);
            }
        }
    }
    if changed_since_start {
        out.push(ExeFlag::ChangedSinceStart);
    }
    out
}

/// How far up the chain the `go` tool may sit for a build-dir binary: `go
/// test` runs the test binary directly, `go run` too; a test that shells out
/// to a sibling binary adds a hop or two. Beyond that the familiar prefix is
/// just a prefix.
pub const GO_ANCESTOR_HOPS: usize = 3;

/// Whether `path` is a file under `/tmp/go-build<digits>/`, where the go tool
/// puts what `go test` and `go run` build. `/tmp` only: that is where the go
/// tool's default temp dir is, and the other temp dirs are not its.
pub fn is_go_build_dir(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/tmp/go-build") else { return false };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && rest[digits..].starts_with('/') && rest.len() > digits + 1
}

/// Whether the `go` tool is the parent, or an ancestor within
/// [`GO_ANCESTOR_HOPS`]. `ancestors` is parent first.
pub fn has_go_ancestor(ancestors: &[&str]) -> bool {
    ancestors.iter().take(GO_ANCESTOR_HOPS).any(|c| *c == "go")
}

/// Whether `path` sits inside a `/tmp/.mount_*` directory that `mounts`
/// (the text of `/proc/self/mounts`) lists as a FUSE or squashfs mount.
pub fn is_appimage_mount(mounts: &str, path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/tmp/.mount_") else { return false };
    let Some(end) = rest.find('/') else { return false };
    let dir = &path[..("/tmp/.mount_".len() + end)];
    mounts.lines().any(|line| {
        let mut f = line.split_whitespace();
        let (Some(_dev), Some(point), Some(fstype)) = (f.next(), f.next(), f.next()) else { return false };
        point == dir && (fstype.starts_with("fuse") || fstype == "squashfs")
    })
}

/// One question for the worker. `key` is the cache key (the exe as
/// `/proc/<pid>/exe` spelled it); `path` is the file to read, which for a
/// deleted executable is the replacement at the same path; `hash` is false
/// when only the owner is wanted (the replacement is not the running code).
struct Job {
    key: String,
    id: FileId,
    path: String,
    hash: bool,
}

/// Identity of the file as last stat'ed: a change means re-hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    size: u64,
    mtime: Option<SystemTime>,
}

pub struct Prober {
    home: Option<String>,
    own_uid: u32,
    /// uid -> home directory from the passwd database, read on first use. In
    /// system mode the daemon's own $HOME is root's and says nothing about
    /// whose hidden directory a binary sits in.
    homes: HashMap<u32, Option<String>>,
    cache: HashMap<String, (FileId, Provenance)>,
    inflight: HashSet<String>,
    queue: Option<SyncSender<Job>>,
    done: Receiver<(String, FileId, Answer)>,
}

/// What the worker found out about one file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub hash: Option<String>,
    /// `Some(Ok(owner))` when a manager was asked, `Some(Err(_))` when it
    /// could not be, `None` when the path is not in a system directory.
    pub package: Option<Result<Option<String>, String>>,
}

impl Prober {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::sync_channel::<Job>(128);
        let (dtx, drx) = mpsc::channel();
        let pm = detect_package_manager();
        std::thread::Builder::new()
            .name("vallum-exe-hash".into())
            .spawn(move || {
                for job in rx {
                    let hash = if job.hash { hash_file(Path::new(&job.path)) } else { None };
                    let package = match pm {
                        Some(pm) if in_system_dir(&job.path) => Some(package_owner(pm, &job.path)),
                        _ => None,
                    };
                    if dtx.send((job.key, job.id, Answer { hash, package })).is_err() {
                        break;
                    }
                }
            })
            .ok();
        Self {
            home: std::env::var("HOME").ok(),
            own_uid: unsafe { libc::getuid() },
            homes: HashMap::new(),
            cache: HashMap::new(),
            inflight: HashSet::new(),
            queue: Some(tx),
            done: drx,
        }
    }

    /// No worker: flags only, hash never arrives. For tests and `--replay`.
    pub fn disabled() -> Self {
        let (_tx, rx) = mpsc::channel();
        Self {
            home: std::env::var("HOME").ok(),
            own_uid: unsafe { libc::getuid() },
            homes: HashMap::new(),
            cache: HashMap::new(),
            inflight: HashSet::new(),
            queue: None,
            done: rx,
        }
    }

    /// The home directory to judge hidden paths against for `uid`.
    fn home_for(&mut self, uid: Option<u32>) -> Option<String> {
        let uid = uid.unwrap_or(self.own_uid);
        if uid == self.own_uid && self.home.is_some() {
            return self.home.clone();
        }
        if let Some(h) = self.homes.get(&uid) {
            return h.clone();
        }
        let home = passwd_home(uid);
        if self.homes.len() < 1024 {
            self.homes.insert(uid, home.clone());
        }
        home
    }

    /// What is known about `exe` right now; queues a hash if none is known.
    /// `started_ms` is the process start time, for the changed-since-start
    /// flag; `uid` picks whose home a hidden path is judged against. With
    /// no ancestry known, a Go build directory is a temp directory.
    pub fn probe(&mut self, exe: &str, started_ms: Option<u64>, uid: Option<u32>) -> Provenance {
        self.probe_with_ancestry(exe, started_ms, uid, &[])
    }

    /// [`Prober::probe`] with the process's ancestry by comm, parent first,
    /// for the build-dir exemption (`flags_for_with_ancestry`). The flags are
    /// recomputed on every call, so two processes running the same build
    /// artifact are each judged by their own chain.
    pub fn probe_with_ancestry(&mut self, exe: &str, started_ms: Option<u64>, uid: Option<u32>, ancestors: &[&str]) -> Provenance {
        if exe.is_empty() {
            return Provenance::default();
        }
        let deleted = exe.ends_with(" (deleted)");
        let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
        let home = self.home_for(uid);
        let meta = std::fs::metadata(path).ok();
        let id = FileId {
            size: meta.as_ref().map(|m| m.len()).unwrap_or(0),
            mtime: meta.as_ref().and_then(|m| m.modified().ok()),
        };
        let mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.as_ref().map(|m| m.permissions().mode())
            }
            #[cfg(not(unix))]
            {
                None::<u32>
            }
        };
        let changed = match (started_ms, id.mtime) {
            (Some(start), Some(mtime)) => mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64 > start + 2_000)
                .unwrap_or(false),
            _ => false,
        };
        let mounts = if path.starts_with("/tmp/.mount_") {
            std::fs::read_to_string("/proc/self/mounts").unwrap_or_default()
        } else {
            String::new()
        };
        let flags = flags_for_with_ancestry(exe, home.as_deref(), mode, changed, &mounts, ancestors);
        // A deleted executable whose path holds a file in a system directory
        // again gets one question: does a package own that file? If so the
        // package manager replaced the binary under the running process (an
        // upgrade), which is a changed executable, not a deleted one. With no
        // worker nobody can answer, and the flags stay as the file says.
        let asked = deleted && meta.is_some() && in_system_dir(path) && self.queue.is_some();
        if let Some((cached_id, p)) = self.cache.get_mut(exe) {
            if *cached_id == id && (p.settled || self.inflight.contains(exe)) {
                p.flags = replaced_flags(flags, asked, p.replacement_packaged);
                return p.clone();
            }
            // Same file, but its job was dropped by a full queue: fall through
            // and ask again.
        }
        let mut p = Provenance {
            hash: None,
            flags: replaced_flags(flags.clone(), asked, None),
            settled: false,
            package: None,
            unpackaged: false,
            replacement_packaged: None,
        };
        // A deleted executable's file on disk, if a replacement exists, is not
        // the code that is running: hashing it would label the row with the
        // wrong build, and filing its owner as this exe's package (or its
        // absence as "unpackaged") would describe the wrong file. Only the
        // upgrade question is asked about it.
        let job = if asked {
            Some(Job { key: exe.to_string(), id, path: path.to_string(), hash: false })
        } else if deleted || meta.is_none() || id.size > HASH_MAX_BYTES || id.size == 0 {
            None
        } else {
            Some(Job { key: exe.to_string(), id, path: exe.to_string(), hash: true })
        };
        match (job, &self.queue) {
            (Some(job), Some(q)) => {
                if !self.inflight.contains(exe) {
                    match q.try_send(job) {
                        Ok(()) => {
                            self.inflight.insert(exe.to_string());
                        }
                        // Not cached as settled, so the next probe retries.
                        Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Disconnected(_)) => {
                            self.queue = None;
                            p.settled = true;
                            // Nobody will answer: the file's own word stands.
                            p.flags = flags;
                        }
                    }
                }
            }
            _ => p.settled = true,
        }
        self.cache.insert(exe.to_string(), (id, p.clone()));
        p
    }

    /// Move finished hashes into the cache. Returns the paths that settled.
    pub fn collect(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok((path, id, answer)) = self.done.try_recv() {
            self.inflight.remove(&path);
            let entry = self.cache.entry(path.clone()).or_insert_with(|| (id, Provenance::default()));
            if entry.0 == id && path.ends_with(DELETED_MARKER) {
                // The upgrade question (see `probe`): `exe-deleted` stands
                // unless a package owns the file now at the path. A manager
                // that could not be asked does not get the benefit of the doubt.
                let owned = matches!(answer.package, Some(Ok(Some(_))));
                if let Some(Ok(Some(owner))) = answer.package {
                    entry.1.package = Some(owner);
                }
                entry.1.replacement_packaged = Some(owned);
                let mut flags = std::mem::take(&mut entry.1.flags);
                if !flags.contains(&ExeFlag::Deleted) {
                    flags.insert(0, ExeFlag::Deleted);
                }
                entry.1.flags = replaced_flags(flags, true, Some(owned));
                entry.1.settled = true;
                out.push(path);
            } else if entry.0 == id {
                entry.1.hash = answer.hash;
                match answer.package {
                    Some(Ok(Some(owner))) => {
                        entry.1.package = Some(owner);
                        entry.1.unpackaged = false;
                    }
                    Some(Ok(None)) => {
                        entry.1.package = Some("none".into());
                        entry.1.unpackaged = true;
                    }
                    // Could not ask, or not a system path: say nothing.
                    Some(Err(_)) | None => {}
                }
                entry.1.settled = true;
                out.push(path);
            }
        }
        out
    }

    pub fn hash_of(&self, exe: &str) -> Option<&str> {
        self.cache.get(exe).and_then(|(_, p)| p.hash.as_deref())
    }

    /// The settled answer for `exe`, if the worker has one.
    pub fn settled(&self, exe: &str) -> Option<&Provenance> {
        self.cache.get(exe).map(|(_, p)| p).filter(|p| p.settled)
    }

    /// Drop cache entries for executables no longer running.
    pub fn retain(&mut self, live: &HashSet<String>) {
        self.cache.retain(|k, _| live.contains(k) || self.inflight.contains(k));
    }
}

/// Home directory of `uid` from `/etc/passwd`, or `None`.
pub fn passwd_home(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd_home_from(&text, uid)
}

pub fn passwd_home_from(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let _name = f.next()?;
        let _pw = f.next()?;
        let id: u32 = f.next()?.parse().ok()?;
        if id != uid {
            return None;
        }
        let _gid = f.next()?;
        let _gecos = f.next()?;
        let home = f.next()?;
        (!home.is_empty()).then(|| home.to_string())
    })
}

/// `sha256:<hex>` of a file, or `None` if it cannot be read in full.
pub fn hash_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > HASH_MAX_BYTES {
            return None;
        }
        h.update(&buf[..n]);
    }
    Some(format!("sha256:{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_flags_hold_deleted_until_asked_and_trade_it_for_changed_on_an_upgrade() {
        let raw = vec![ExeFlag::Deleted, ExeFlag::HiddenHome];
        assert_eq!(replaced_flags(raw.clone(), false, None), raw, "not asked: the file's word");
        assert_eq!(replaced_flags(raw.clone(), true, None), vec![ExeFlag::HiddenHome], "pending");
        assert_eq!(replaced_flags(raw.clone(), true, Some(false)), raw, "an unowned replacement");
        assert_eq!(
            replaced_flags(raw.clone(), true, Some(true)),
            vec![ExeFlag::HiddenHome, ExeFlag::ChangedSinceStart]
        );
        // An mtime that already said "changed" is not doubled.
        let both = vec![ExeFlag::Deleted, ExeFlag::ChangedSinceStart];
        assert_eq!(replaced_flags(both, true, Some(true)), vec![ExeFlag::ChangedSinceStart]);
    }

    #[test]
    fn an_upgrade_under_a_running_process_is_a_changed_exe_not_a_deleted_one() {
        // /usr/bin/env exists on every Linux this builds on, in a system directory.
        let exe = "/usr/bin/env (deleted)";
        let cases: [(Option<Result<Option<String>, String>>, Vec<ExeFlag>, Option<&str>, bool); 3] = [
            (Some(Ok(Some("coreutils".into()))), vec![ExeFlag::ChangedSinceStart], Some("coreutils"), true),
            (Some(Ok(None)), vec![ExeFlag::Deleted], None, false),
            (Some(Err("manager unavailable".into())), vec![ExeFlag::Deleted], None, false),
        ];
        for (answer, want_flags, want_package, owned) in cases {
            let (tx, rx) = mpsc::sync_channel::<Job>(4);
            let (dtx, drx) = mpsc::channel();
            let mut p = Prober {
                home: None,
                own_uid: 0,
                homes: HashMap::new(),
                cache: HashMap::new(),
                inflight: HashSet::new(),
                queue: Some(tx),
                done: drx,
            };
            let first = p.probe(exe, None, None);
            assert!(!first.settled);
            assert!(!first.flags.contains(&ExeFlag::Deleted), "no warning before the answer: {:?}", first.flags);
            let job = rx.try_recv().expect("the owner of the replacement is asked");
            assert_eq!((job.key.as_str(), job.path.as_str(), job.hash), (exe, "/usr/bin/env", false));
            let again = p.probe(exe, None, None);
            assert!(!again.flags.contains(&ExeFlag::Deleted));
            assert!(rx.try_recv().is_err(), "asked once while in flight");

            dtx.send((exe.to_string(), job.id, Answer { hash: Some("sha256:not-the-running-code".into()), package: answer }))
                .unwrap();
            assert_eq!(p.collect(), vec![exe.to_string()]);
            let done = p.settled(exe).expect("settled").clone();
            assert_eq!(done.flags, want_flags);
            assert_eq!(done.replacement_packaged, Some(owned));
            assert_eq!(done.package.as_deref(), want_package);
            assert!(!done.unpackaged, "the replacement is not this process's file");
            assert!(done.hash.is_none(), "a deleted executable is never hashed");
            assert_eq!(p.probe(exe, None, None).flags, want_flags, "the answer sticks");
        }
        // No worker, no answer: exe-deleted stands at once.
        let alone = Prober::disabled().probe(exe, None, None);
        assert!(alone.settled && alone.flags.contains(&ExeFlag::Deleted));
    }

    #[test]
    fn flags_read_the_path_and_mode() {
        assert!(flags_for("/usr/bin/firefox", Some("/home/u"), Some(0o755), false).is_empty());
        assert_eq!(
            flags_for("/tmp/x/agent (deleted)", Some("/home/u"), None, false),
            vec![ExeFlag::Deleted, ExeFlag::TempDir]
        );
        assert_eq!(flags_for("/dev/shm/a", None, Some(0o777), false), vec![ExeFlag::TempDir, ExeFlag::WorldWritable]);
        let mounts = "obsidian.AppImage /tmp/.mount_ObsidXYZ fuse.squashfuse ro,nosuid,nodev 0 0\ntmpfs /tmp tmpfs rw 0 0\n";
        assert!(flags_for_with_mounts("/tmp/.mount_ObsidXYZ/usr/bin/obsidian", Some("/home/u"), Some(0o755), false, mounts).is_empty(), "a mounted AppImage is not a temp-dir binary");
        assert_eq!(flags_for_with_mounts("/tmp/.mount_fakeXYZ/p", Some("/home/u"), Some(0o755), false, mounts), vec![ExeFlag::TempDir], "a plain directory wearing the prefix is");
        assert_eq!(flags_for("/tmp/.mount_ObsidXYZ/usr/bin/obsidian", Some("/home/u"), Some(0o755), false), vec![ExeFlag::TempDir], "no mount table, no exemption");
        assert!(is_appimage_mount("x /tmp/.mount_a squashfs ro 0 0", "/tmp/.mount_a/bin/x"));
        assert!(!is_appimage_mount("x /tmp/.mount_a ext4 rw 0 0", "/tmp/.mount_a/bin/x"));
        assert!(!is_appimage_mount("x /tmp/.mount_a fuse ro 0 0", "/tmp/.mount_ab/bin/x"), "prefix of another mount point");
        assert!(!is_appimage_mount("x /tmp/.mount_a fuse ro 0 0", "/tmp/.mount_a"), "the mount point itself is not a binary");
        assert_eq!(flags_for("/home/u/.cache/x/bin/x", Some("/home/u/"), Some(0o755), false), vec![ExeFlag::HiddenHome]);
        assert_eq!(flags_for("/home/u/.local/share/pnpm/node", Some("/home/u"), Some(0o755), false), vec![ExeFlag::HiddenHome]);
        assert!(flags_for("/home/u/.local/bin/uv", Some("/home/u"), Some(0o755), false).is_empty(), "~/.local/bin is a normal install location");
        assert!(flags_for("/home/u/Projects/x/target/debug/x", Some("/home/u"), Some(0o755), false).is_empty());
        assert!(flags_for("/home/other/.cache/x", Some("/home/u"), Some(0o755), false).is_empty(), "another user's home is not ours to judge");
        assert!(flags_for("/usr/bin/x", Some("/"), Some(0o755), false).is_empty(), "HOME=/ would otherwise flag every hidden path");
        assert_eq!(flags_for("/usr/bin/x", None, Some(0o755), true), vec![ExeFlag::ChangedSinceStart]);
    }

    #[test]
    fn a_go_build_under_the_go_tool_is_a_build_dir_and_nothing_else_is() {
        let test_bin = "/tmp/go-build2841973645/b001/vallum.test";
        let under_go = ["go", "bash", "kitty"];
        let no_go = ["bash", "kitty", "systemd"];
        let f = |exe: &str, anc: &[&str]| flags_for_with_ancestry(exe, Some("/home/u"), Some(0o755), false, "", anc);
        assert_eq!(f(test_bin, &under_go), vec![ExeFlag::BuildDir], "go test's binary, run by the go tool");
        assert_eq!(f(test_bin, &no_go), vec![ExeFlag::TempDir], "the familiar prefix is not a free pass");
        assert_eq!(f(test_bin, &[]), vec![ExeFlag::TempDir], "no ancestry known: a temp binary");
        assert_eq!(f("/tmp/go-build1/exe/main", &["go"]), vec![ExeFlag::BuildDir], "go run's layout");
        // The go tool within three hops counts; further up it does not.
        assert_eq!(f(test_bin, &["sh", "make", "go", "bash"]), vec![ExeFlag::BuildDir]);
        assert_eq!(f(test_bin, &["sh", "make", "bash", "go"]), vec![ExeFlag::TempDir], "four hops is too far");
        // A go parent does not launder an arbitrary temp binary, or a near-miss path.
        assert_eq!(f("/tmp/agent", &under_go), vec![ExeFlag::TempDir]);
        assert_eq!(f("/tmp/go-build/b001/x.test", &under_go), vec![ExeFlag::TempDir], "no digits");
        assert_eq!(f("/tmp/go-buildabc/b001/x.test", &under_go), vec![ExeFlag::TempDir]);
        assert_eq!(f("/tmp/go-build123x/b001/x.test", &under_go), vec![ExeFlag::TempDir], "digits then letters");
        assert_eq!(f("/tmp/go-build123", &under_go), vec![ExeFlag::TempDir], "the directory itself is not a binary");
        assert_eq!(f("/var/tmp/go-build123/b001/x.test", &under_go), vec![ExeFlag::TempDir], "only /tmp is the go tool's");
        assert_eq!(f("/dev/shm/go-build123/b001/x.test", &under_go), vec![ExeFlag::TempDir]);
        assert!(f("/home/u/go/bin/x", &under_go).is_empty(), "outside a temp dir the ancestry changes nothing");
        // The other flags are untouched by the exemption.
        assert_eq!(
            flags_for_with_ancestry(&format!("{test_bin} (deleted)"), Some("/home/u"), Some(0o755), false, "", &under_go),
            vec![ExeFlag::Deleted, ExeFlag::BuildDir]
        );
        assert_eq!(
            flags_for_with_ancestry(test_bin, Some("/home/u"), Some(0o777), true, "", &under_go),
            vec![ExeFlag::BuildDir, ExeFlag::WorldWritable, ExeFlag::ChangedSinceStart]
        );
        assert!(is_go_build_dir("/tmp/go-build7/b001/a.test") && !is_go_build_dir("/tmp/go-build7/") && !is_go_build_dir("/tmp/go-build7"));
        assert!(has_go_ancestor(&["go"]) && has_go_ancestor(&["a", "b", "go"]) && !has_go_ancestor(&["a", "b", "c", "go"]) && !has_go_ancestor(&[]));
        assert!(!has_go_ancestor(&["gopls"]) && !has_go_ancestor(&["Go"]), "comm is matched whole");
        // Through the prober: the same path, judged per call by its own chain.
        let mut p = Prober::disabled();
        assert_eq!(p.probe_with_ancestry(test_bin, None, None, &under_go).flags, vec![ExeFlag::BuildDir]);
        assert_eq!(p.probe_with_ancestry(test_bin, None, None, &no_go).flags, vec![ExeFlag::TempDir]);
        assert_eq!(p.probe(test_bin, None, None).flags, vec![ExeFlag::TempDir]);
    }

    #[test]
    fn package_owner_parsing_matches_each_manager() {
        use PackageManager::*;
        assert_eq!(parse_owner(Pacman, true, "firefox\n", ""), Some("firefox".into()));
        assert_eq!(parse_owner(Pacman, false, "", "error: No package owns /usr/bin/x\n"), None);
        assert_eq!(parse_owner(Dpkg, true, "coreutils: /usr/bin/ls\n", ""), Some("coreutils".into()));
        assert_eq!(parse_owner(Dpkg, true, "diversion by dash from: /bin/sh\n", ""), None);
        assert_eq!(parse_owner(Dpkg, false, "", "dpkg-query: no path found matching pattern /usr/bin/x\n"), None);
        assert_eq!(parse_owner(Rpm, true, "coreutils-9.4-1.fc40.x86_64\n", ""), Some("coreutils-9.4-1.fc40.x86_64".into()));
        assert_eq!(parse_owner(Rpm, false, "file /usr/bin/x is not owned by any package\n", ""), None);
        assert!(in_system_dir("/usr/bin/x") && in_system_dir("/opt/app/bin/x"));
        assert_eq!(merged_usr_alias("/usr/bin/bash").as_deref(), Some("/bin/bash"));
        assert_eq!(merged_usr_alias("/lib64/ld-linux-x86-64.so.2").as_deref(), Some("/usr/lib64/ld-linux-x86-64.so.2"));
        assert_eq!(merged_usr_alias("/opt/x/bin/y"), None);
        assert!(!in_system_dir("/home/u/.cargo/bin/x") && !in_system_dir("/tmp/x"));
    }

    #[test]
    fn hashing_matches_a_known_digest_and_lands_asynchronously() {
        let dir = std::env::temp_dir().join(format!("vallum-prov-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bin");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            hash_file(&file).unwrap(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let exe = file.to_string_lossy().to_string();
        let mut p = Prober::spawn();
        let first = p.probe(&exe, None, None);
        assert!(first.hash.is_none() && !first.settled, "the hash is computed off the caller's thread");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut settled = Vec::new();
        while settled.is_empty() && std::time::Instant::now() < deadline {
            settled = p.collect();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(settled, vec![exe.clone()]);
        let again = p.probe(&exe, None, None);
        assert!(again.settled);
        assert_eq!(again.hash.as_deref(), p.hash_of(&exe));
        assert!(again.hash.unwrap().ends_with("f20015ad"));

        // A changed file is re-hashed; a missing one settles with no hash.
        std::fs::write(&file, b"abcd").unwrap();
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let _ = std::fs::File::options().write(true).open(&file).unwrap().set_modified(t);
        let changed = p.probe(&exe, None, None);
        assert!(!changed.settled && changed.hash.is_none());
        let gone = p.probe(&dir.join("missing").to_string_lossy(), None, None);
        assert!(gone.settled && gone.hash.is_none());
        // Deleted while running: flagged, never hashed, never asked about.
        let del = p.probe(&format!("{exe} (deleted)"), None, None);
        assert!(del.settled && del.hash.is_none() && !del.unpackaged);
        assert!(del.flags.contains(&ExeFlag::Deleted), "{:?}", del.flags);
        assert_eq!(Prober::disabled().probe("/tmp/x", None, None).flags, vec![ExeFlag::TempDir]);
        assert!(Prober::disabled().probe("/tmp/x", None, None).settled);
        // Hidden-home is judged against the socket owner's home, not ours.
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:Alice:/home/alice:/bin/zsh\nbroken:x:notanumber\n";
        assert_eq!(passwd_home_from(passwd, 1001).as_deref(), Some("/home/alice"));
        assert_eq!(passwd_home_from(passwd, 0).as_deref(), Some("/root"));
        assert_eq!(passwd_home_from(passwd, 7), None);
        assert_eq!(flags_for("/home/alice/.cache/x", passwd_home_from(passwd, 1001).as_deref(), Some(0o755), false), vec![ExeFlag::HiddenHome]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
