use crate::event::{AppIdentity, AppOwner};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DesktopRecord {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub exec_base: String,
    pub wm_class: String,
    pub path: PathBuf,
}

/// `nobody`: the uid a kernel or a service drops to for work that belongs to
/// no one, and the overflow uid an unmapped user namespace reports. Neither
/// is a person, whatever `UID_MIN` says.
const NOBODY_UID: u32 = 65534;
const OVERFLOW_UID: u32 = u32::MAX;

/// Most users a desktop ever has; a bound on the per-user caches below.
const MAX_USERS: usize = 64;

/// A passwd entry, reduced to what naming a process needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passwd {
    pub name: String,
    pub home: String,
}

#[derive(Default)]
pub struct AppResolver {
    desktops: Vec<DesktopRecord>,
    /// (process uid, exe path or basename) → identity. The uid is part of
    /// the key because the system daemon names the same binary under two
    /// users as two rows, each with its owner.
    cache: HashMap<(u32, String), AppIdentity>,
    our_uid: u32,
    /// `--system`: the daemon is root and resolves every logged-in user's
    /// processes, not only its own uid's. A user daemon never does: another
    /// uid's process is a system service to it.
    system: bool,
    /// The lowest human uid (`/etc/login.defs` `UID_MIN`). Below it a
    /// process belongs to a service account and stays `system` in either
    /// mode.
    uid_min: u32,
    /// uid → passwd entry, looked up once per uid; `None` when the database
    /// has no entry.
    passwd: HashMap<u32, Option<Passwd>>,
    /// uid → that user's own `.desktop` files (`~/.local/share/applications`),
    /// scanned on first sight. The user daemon reads its own at startup via
    /// `$HOME`; the system daemon has root's.
    user_desktops: HashMap<u32, Vec<DesktopRecord>>,
}

impl AppResolver {
    /// `system` is the daemon's `--system` mode.
    pub fn new(system: bool) -> Self {
        let mut r = Self {
            desktops: Vec::new(),
            cache: HashMap::new(),
            our_uid: current_uid(),
            system,
            uid_min: crate::suggest::uid_min(),
            passwd: HashMap::new(),
            user_desktops: HashMap::new(),
        };
        r.scan_desktops();
        r
    }

    pub fn our_uid(&self) -> u32 {
        self.our_uid
    }

    /// Whether `uid` is a person's, as opposed to root's or a service
    /// account's. Only the system daemon acts on the answer.
    fn is_human(&self, uid: u32) -> bool {
        uid >= self.uid_min && uid != NOBODY_UID && uid != OVERFLOW_UID
    }

    pub fn resolve(&mut self, pid: u32, uid: u32, exe: &str, comm: &str) -> AppIdentity {
        // Another uid's process is a system service to the user daemon. The
        // system daemon is root: a service account's process (and nobody's)
        // is still `system`, but a logged-in user's apps are named the way
        // the user's own daemon would name them, and carry the owner.
        let foreign = uid != self.our_uid && pid != 0;
        if foreign && !(self.system && self.is_human(uid)) {
            return system_identity(pid);
        }
        // A binary replaced under a running process (a package upgrade, or one that
        // unlinked itself) reads `/usr/bin/x (deleted)`. It is still app `x`: the
        // root helper strips the marker the same way (`helper/src/forest.rs`), and
        // the per-app rules, blocks and org policy key on this id. The `exe-deleted`
        // indicator, which keeps the full path, is what says the file is gone.
        let exe_base = basename(exe.strip_suffix(DELETED_MARKER).unwrap_or(exe));
        let key = if !exe.is_empty() {
            (uid, exe.to_string())
        } else {
            (uid, comm.to_string())
        };
        if let Some(hit) = self.cache.get(&key) {
            let mut cloned = hit.clone();
            cloned.pid = pid;
            return cloned;
        }
        let owner = if foreign { Some(self.owner(uid)) } else { None };
        let rec = self.match_desktop(&exe_base, comm, uid);
        let mut ident = if let Some(d) = rec {
            AppIdentity {
                id: d.id.clone(),
                name: d.name.clone(),
                icon: d.icon.clone(),
                desktop: d.id.clone() + ".desktop",
                pid,
                system: false,
                exe: exe.to_string(),
                owner,
            }
        } else {
            let id = if !exe_base.is_empty() {
                sanitize_id(&exe_base)
            } else if !comm.is_empty() {
                sanitize_id(comm)
            } else {
                format!("pid-{pid}")
            };
            AppIdentity {
                id: id.clone(),
                name: pretty_name(&id),
                icon: id.clone(),
                desktop: String::new(),
                pid,
                system: false,
                exe: exe.to_string(),
                owner,
            }
        };
        // "system" and "unknown" are the rows vallum files other users' and
        // unattributed sockets under, and the panel refuses to block either.
        // A process of ours that named its binary or a .desktop file after one
        // would make itself unblockable, so it gets a distinct id instead.
        if is_reserved_id(&ident.id) {
            ident.id = format!("{}-app", ident.id.to_ascii_lowercase());
            ident.desktop = String::new();
        }
        self.cache.insert(key, ident.clone());
        ident
    }

    /// The account behind `uid`, looked up once. A uid the database does not
    /// know is still a person's (it is above `UID_MIN`), so the row names it
    /// by number rather than falling back to `system`.
    fn owner(&mut self, uid: u32) -> AppOwner {
        let entry = self.passwd_for(uid);
        AppOwner {
            uid,
            name: entry.map(|p| p.name).unwrap_or_else(|| uid.to_string()),
        }
    }

    fn passwd_for(&mut self, uid: u32) -> Option<Passwd> {
        if let Some(hit) = self.passwd.get(&uid) {
            return hit.clone();
        }
        let entry = passwd_entry(uid);
        if self.passwd.len() < MAX_USERS {
            self.passwd.insert(uid, entry.clone());
        }
        entry
    }

    /// The desktop record for an executable: the process owner's own
    /// `.desktop` files first (the system daemon, naming another user's app),
    /// then the shared ones scanned at startup.
    fn match_desktop(&mut self, exe_base: &str, comm: &str, uid: u32) -> Option<DesktopRecord> {
        if self.system && uid != self.our_uid {
            self.scan_user_desktops(uid);
            if let Some(d) = self.user_desktops.get(&uid).and_then(|v| find_desktop(v, exe_base, comm)) {
                return Some(d.clone());
            }
        }
        find_desktop(&self.desktops, exe_base, comm).cloned()
    }

    fn scan_user_desktops(&mut self, uid: u32) {
        if self.user_desktops.contains_key(&uid) || self.user_desktops.len() >= MAX_USERS {
            return;
        }
        let mut recs = Vec::new();
        if let Some(home) = self.passwd_for(uid).map(|p| p.home).filter(|h| !h.is_empty() && h != "/") {
            scan_desktop_dir(&PathBuf::from(home).join(".local/share/applications"), &mut recs);
        }
        self.user_desktops.insert(uid, recs);
    }

    fn scan_desktops(&mut self) {
        let mut dirs = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(PathBuf::from(home).join(".local/share/applications"));
        }
        let data_dirs = std::env::var("XDG_DATA_DIRS")
            .unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
        for d in data_dirs.split(':') {
            if !d.is_empty() {
                dirs.push(PathBuf::from(d).join("applications"));
            }
        }
        for dir in dirs {
            scan_desktop_dir(&dir, &mut self.desktops);
        }
    }
}

fn find_desktop<'a>(desktops: &'a [DesktopRecord], exe_base: &str, comm: &str) -> Option<&'a DesktopRecord> {
    let needle = exe_base.to_lowercase();
    let comm_l = comm.to_lowercase();
    desktops.iter().find(|d| {
        (!d.exec_base.is_empty() && d.exec_base == needle)
            || (!d.wm_class.is_empty() && d.wm_class == needle)
            || (!d.id.is_empty() && d.id.to_lowercase() == needle)
            || (!comm_l.is_empty() && (d.exec_base == comm_l || d.wm_class == comm_l))
    })
}

fn scan_desktop_dir(dir: &Path, out: &mut Vec<DesktopRecord>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("desktop") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Some(rec) = parse_desktop(&text, &p) {
                out.push(rec);
            }
        }
    }
}

/// The passwd entry for `uid` through the C library (`getpwuid_r`), so an
/// account that lives in NSS rather than `/etc/passwd` is named too. `None`
/// when there is no entry.
#[cfg(unix)]
pub fn passwd_entry(uid: u32) -> Option<Passwd> {
    use std::ffi::CStr;
    // Larger than any sysconf(_SC_GETPW_R_SIZE_MAX) answer in practice; one
    // retry at four times that covers a long GECOS or shell.
    let mut len = 16 * 1024;
    loop {
        let mut buf = vec![0u8; len];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to memory that outlives the call, and the
        // buffer length is the one passed; the entry is read only while
        // `buf` is alive and `result` points into it.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut result) };
        if rc == libc::ERANGE && len < 64 * 1024 {
            len *= 4;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_string_lossy().into_owned();
        let home = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_string_lossy().into_owned();
        return Some(Passwd { name, home });
    }
}

#[cfg(not(unix))]
pub fn passwd_entry(_uid: u32) -> Option<Passwd> {
    None
}

/// The ids of rows no user process may claim (see `resolve`). The panel's
/// isBlockable refuses the same two, compared the same way.
pub fn is_reserved_id(id: &str) -> bool {
    matches!(id.to_ascii_lowercase().as_str(), "system" | "unknown")
}

pub fn system_identity(pid: u32) -> AppIdentity {
    AppIdentity {
        id: "system".into(),
        name: "system".into(),
        icon: "system".into(),
        desktop: String::new(),
        pid,
        system: true,
        exe: String::new(),
        owner: None,
    }
}

pub fn unknown_identity(pid: u32) -> AppIdentity {
    AppIdentity {
        id: "unknown".into(),
        name: "unknown".into(),
        icon: "unknown".into(),
        desktop: String::new(),
        pid,
        system: false,
        exe: String::new(),
        owner: None,
    }
}

pub fn parse_desktop(text: &str, path: &Path) -> Option<DesktopRecord> {
    let mut in_entry = false;
    let mut name = String::new();
    let mut exec = String::new();
    let mut icon = String::new();
    let mut wm = String::new();
    let mut hidden = false;
    let mut no_display = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "Name" => name = v.to_string(),
            "Exec" => exec = v.to_string(),
            "Icon" => icon = v.to_string(),
            "StartupWMClass" => wm = v.to_lowercase(),
            "Hidden" if v.eq_ignore_ascii_case("true") => hidden = true,
            "NoDisplay" if v.eq_ignore_ascii_case("true") => no_display = true,
            _ => {}
        }
    }
    if hidden || no_display {
        return None;
    }
    if name.is_empty() && exec.is_empty() {
        return None;
    }
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let exec_base = exec_basename(&exec);
    if name.is_empty() && exec_base.is_empty() && file_stem.is_empty() {
        return None;
    }
    if icon.is_empty() {
        icon = exec_base.clone();
    }
    Some(DesktopRecord {
        id: file_stem,
        name,
        icon,
        exec_base,
        wm_class: wm,
        path: path.to_path_buf(),
    })
}

fn exec_basename(exec: &str) -> String {
    let first = exec.split_whitespace().next().unwrap_or("");
    let first = first.trim_matches('"');
    basename(first).to_lowercase()
}

/// What the kernel appends to `/proc/<pid>/exe` once the file is unlinked.
const DELETED_MARKER: &str = " (deleted)";

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

pub fn sanitize_id(raw: &str) -> String {
    let mut s = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            s.push(c.to_ascii_lowercase());
        } else if c == '-' || c.is_whitespace() {
            if !s.ends_with('-') {
                s.push('-');
            }
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "app".into()
    } else {
        s
    }
}

fn pretty_name(id: &str) -> String {
    let mut out = String::new();
    let mut cap = true;
    for c in id.chars() {
        if c == '-' || c == '_' {
            out.push(' ');
            cap = true;
        } else if cap {
            out.extend(c.to_uppercase());
            cap = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        libc_uid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
fn libc_uid() -> u32 {
    // Avoid a libc crate dep: read from /proc/self or use the libc syscall via std.
    // std doesn't expose uid; parse `id -u` fallback, or use the nix-less libc wrapper.
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(uid) = rest.split_whitespace().next().and_then(|t| t.parse().ok()) {
                    return uid;
                }
            }
        }
    }
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn read_exe(pid: u32) -> String {
    let p = format!("/proc/{pid}/exe");
    std::fs::read_link(&p)
        .ok()
        .and_then(|s| s.to_str().map(|t| t.to_string()))
        .unwrap_or_default()
}

pub fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn read_status_uid(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver with no I/O: the desktop files, uid line and passwd
    /// answers are all given, so the cases below are pinned by the code,
    /// not by the test machine.
    fn resolver(our_uid: u32, system: bool, desktops: Vec<DesktopRecord>) -> AppResolver {
        let mut r = AppResolver {
            desktops,
            cache: HashMap::new(),
            our_uid,
            system,
            uid_min: 1000,
            passwd: HashMap::new(),
            user_desktops: HashMap::new(),
        };
        r.passwd.insert(1000, Some(Passwd { name: "alice".into(), home: "/home/alice".into() }));
        r.passwd.insert(1001, Some(Passwd { name: "guest".into(), home: "/home/guest".into() }));
        r.passwd.insert(998, Some(Passwd { name: "systemd-timesync".into(), home: "/".into() }));
        r.passwd.insert(1002, None);
        r.passwd.insert(600, None);
        // Pre-seeded so no test ever scans a real home directory: on the
        // author's machine a Brave PWA shortcut in ~/.local/share/applications
        // would otherwise name uid 1000's brave after the PWA.
        for uid in [1000, 1001, 1002, 600] {
            r.user_desktops.insert(uid, Vec::new());
        }
        r
    }

    fn firefox() -> DesktopRecord {
        DesktopRecord {
            id: "firefox".into(),
            name: "Firefox".into(),
            icon: "firefox".into(),
            exec_base: "firefox".into(),
            wm_class: "firefox".into(),
            path: PathBuf::from("/usr/share/applications/firefox.desktop"),
        }
    }

    #[test]
    fn hidden_desktop_is_ignored() {
        let hidden = "[Desktop Entry]\nName=Secret\nExec=secret\nHidden=true\n";
        assert!(parse_desktop(hidden, Path::new("/usr/share/applications/secret.desktop")).is_none());
        let nodisp = "[Desktop Entry]\nName=Helper\nExec=helper\nNoDisplay=true\n";
        assert!(parse_desktop(nodisp, Path::new("/usr/share/applications/helper.desktop")).is_none());
    }

    #[test]
    fn parse_firefox_desktop() {
        let text = "[Desktop Entry]\nName=Firefox\nExec=/usr/lib/firefox/firefox %u\nIcon=firefox\nStartupWMClass=firefox\n";
        let rec = parse_desktop(text, Path::new("/usr/share/applications/firefox.desktop")).unwrap();
        assert_eq!(rec.name, "Firefox");
        assert_eq!(rec.exec_base, "firefox");
        assert_eq!(rec.icon, "firefox");
        assert_eq!(rec.id, "firefox");
        assert_eq!(rec.wm_class, "firefox");
    }

    #[test]
    fn sanitize_keeps_simple_ids() {
        assert_eq!(sanitize_id("firefox"), "firefox");
        assert_eq!(sanitize_id("Code - OSS"), "code-oss");
    }

    #[test]
    fn other_uid_is_system() {
        let mut r = resolver(1000, false, vec![]);
        let id = r.resolve(1, 0, "/usr/bin/sshd", "sshd");
        assert!(id.system);
        assert_eq!(id.id, "system");
    }

    #[test]
    fn the_user_daemon_names_only_its_own_processes() {
        // (a) Unchanged: to a user daemon every other uid is a system service,
        // root's timesyncd and another person's browser alike, and its own
        // rows carry no owner.
        let mut r = resolver(1000, false, vec![firefox()]);
        let own = r.resolve(10, 1000, "/usr/lib/firefox/firefox", "firefox");
        assert_eq!((own.id.as_str(), own.system, own.owner.as_ref()), ("firefox", false, None));
        for (pid, uid, exe, comm) in [
            (2, 0, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn"),
            (3, 998, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn"),
            (4, 1001, "/usr/lib/brave-bin/brave", "brave"),
        ] {
            let id = r.resolve(pid, uid, exe, comm);
            assert!(id.system, "uid {uid} on the user daemon");
            assert_eq!(id.id, "system");
            assert!(id.owner.is_none());
        }
        assert!(serde_json::to_value(&own).unwrap().get("owner").is_none(), "no owner key on the user daemon's rows");
    }

    #[test]
    fn the_system_daemon_names_a_users_app_and_its_owner() {
        // (b) Root, --system: uid 1000's brave is brave, owned by alice, with
        // the user's own .desktop file consulted for its name.
        let mut r = resolver(0, true, vec![firefox()]);
        let brave = r.resolve(4242, 1000, "/usr/lib/brave-bin/brave", "brave");
        assert_eq!(brave.id, "brave");
        assert!(!brave.system, "a person's app is not a system row");
        assert_eq!(brave.owner, Some(AppOwner { uid: 1000, name: "alice".into() }));
        let v = serde_json::to_value(&brave).unwrap();
        assert_eq!(v["owner"], serde_json::json!({ "uid": 1000, "name": "alice" }));
        // The .desktop heuristics apply as they do on the user daemon.
        let ff = r.resolve(4243, 1000, "/usr/lib/firefox/firefox", "firefox");
        assert_eq!((ff.id.as_str(), ff.name.as_str(), ff.desktop.as_str()), ("firefox", "Firefox", "firefox.desktop"));
        assert_eq!(ff.owner_name(), Some("alice"));
        // The user's own applications directory names what the shared ones do not.
        r.user_desktops.get_mut(&1001).unwrap().push(DesktopRecord {
            id: "com.example.Tool".into(),
            name: "Example Tool".into(),
            icon: "tool".into(),
            exec_base: "tool-bin".into(),
            wm_class: String::new(),
            path: PathBuf::from("/home/guest/.local/share/applications/com.example.Tool.desktop"),
        });
        let tool = r.resolve(4244, 1001, "/home/guest/.local/bin/tool-bin", "tool-bin");
        assert_eq!((tool.id.as_str(), tool.name.as_str()), ("com.example.Tool", "Example Tool"));
        assert_eq!(tool.owner_name(), Some("guest"));
        // One binary under two users is two rows, each with its owner; the cache
        // keys on the uid.
        let brave_guest = r.resolve(4245, 1001, "/usr/lib/brave-bin/brave", "brave");
        assert_eq!(brave_guest.id, brave.id);
        assert_eq!(brave_guest.owner_name(), Some("guest"));
        assert_eq!(r.resolve(4246, 1000, "/usr/lib/brave-bin/brave", "brave").owner_name(), Some("alice"));
        // A human uid the passwd database does not know is named by number.
        let orphan = r.resolve(4247, 1002, "/opt/x/x", "x");
        assert_eq!((orphan.id.as_str(), orphan.system), ("x", false));
        assert_eq!(orphan.owner, Some(AppOwner { uid: 1002, name: "1002".into() }));
        // Another user's process cannot claim a reserved row either.
        assert_eq!(r.resolve(4248, 1000, "/tmp/x/system", "system").id, "system-app");
        assert_eq!(r.resolve(4249, 1000, "/tmp/x/unknown", "unknown").id, "unknown-app");
    }

    #[test]
    fn root_and_service_uids_stay_system_on_the_system_daemon() {
        // (c) The system daemon is uid 0, so root's own processes resolve as
        // they always have (tailscaled is `tailscaled`, blockable by id), with
        // no owner. On the user daemon a uid 0 process stays `system`.
        let mut r = resolver(0, true, vec![]);
        let ts = r.resolve(2, 0, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn");
        assert_eq!((ts.id.as_str(), ts.system, ts.owner.as_ref()), ("systemd-timesyncd", false, None));
        let mut user = resolver(1000, false, vec![]);
        let ts = user.resolve(2, 0, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn");
        assert_eq!((ts.id.as_str(), ts.system), ("system", true));
        // (d) A service account's process is `system` in system mode too:
        // below UID_MIN, nobody, and the overflow uid.
        for (pid, uid, exe, comm) in [
            (3, 998, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn"),
            (5, 999, "/usr/bin/NetworkManager", "NetworkManager"),
            (6, NOBODY_UID, "/usr/bin/dnsmasq", "dnsmasq"),
            (7, OVERFLOW_UID, "/usr/bin/x", "x"),
        ] {
            let id = r.resolve(pid, uid, exe, comm);
            assert!(id.system, "uid {uid} on the system daemon");
            assert_eq!(id.id, "system");
            assert!(id.owner.is_none());
        }
        // The line is the host's: a distribution that starts people at 500
        // names uid 600's app, one that starts them at 2000 does not name 1000's.
        r.uid_min = 500;
        assert_eq!(r.resolve(8, 600, "/usr/bin/curl", "curl").id, "curl");
        r.uid_min = 2000;
        r.cache.clear();
        assert!(r.resolve(9, 1000, "/usr/lib/brave-bin/brave", "brave").system);
    }

    #[test]
    fn groups_by_desktop_not_pid() {
        let mut r = resolver(1000, false, vec![firefox()]);
        let a = r.resolve(10, 1000, "/usr/lib/firefox/firefox", "firefox");
        let b = r.resolve(11, 1000, "/usr/lib/firefox/firefox", "firefox");
        assert_eq!(a.id, b.id);
        assert_eq!(a.id, "firefox");
        assert_ne!(a.pid, b.pid);
        // b came from the cache; both carry the executable for the panel.
        assert_eq!(a.exe, "/usr/lib/firefox/firefox");
        assert_eq!(b.exe, "/usr/lib/firefox/firefox");
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["exe"], "/usr/lib/firefox/firefox");
        assert!(serde_json::to_value(system_identity(1)).unwrap().get("exe").is_none());
    }

    #[test]
    fn a_process_of_ours_never_takes_a_reserved_id() {
        let mut r = resolver(
            1000,
            false,
            vec![DesktopRecord {
                id: "System".into(),
                name: "System".into(),
                icon: "system".into(),
                exec_base: "evil".into(),
                wm_class: String::new(),
                path: PathBuf::from("/home/u/.local/share/applications/System.desktop"),
            }],
        );
        for (exe, comm) in [("/tmp/x/evil", "evil"), ("/tmp/x/system", "system"), ("/tmp/x/Unknown", "Unknown")] {
            let id = r.resolve(20, 1000, exe, comm);
            assert!(!is_reserved_id(&id.id), "{exe} became {}", id.id);
            assert!(!id.system);
        }
        assert_eq!(r.resolve(21, 1000, "/tmp/x/evil", "evil").id, "system-app");
        // Vallum's own rows keep theirs.
        assert_eq!(system_identity(1).id, "system");
        assert_eq!(unknown_identity(1).id, "unknown");
    }

    #[test]
    fn a_binary_replaced_under_a_running_process_keeps_its_app() {
        let mut r = resolver(
            1000,
            false,
            vec![DesktopRecord {
                id: "firefox".into(),
                name: "Firefox".into(),
                icon: "firefox".into(),
                exec_base: "firefox".into(),
                wm_class: String::new(),
                path: PathBuf::from("/usr/share/applications/firefox.desktop"),
            }],
        );
        let live = r.resolve(30, 1000, "/usr/bin/tailscaled", "tailscaled");
        let upgraded = r.resolve(31, 1000, "/usr/bin/tailscaled (deleted)", "tailscaled");
        assert_eq!(upgraded.id, live.id, "an upgrade must not mint a second app");
        assert_eq!(upgraded.id, "tailscaled");
        assert_eq!(upgraded.name, live.name);
        // The path keeps the marker: the exe-deleted indicator and provenance read it.
        assert_eq!(upgraded.exe, "/usr/bin/tailscaled (deleted)");
        // The .desktop match survives too, so the row keeps its name and icon.
        let ff = r.resolve(32, 1000, "/usr/lib/firefox/firefox (deleted)", "firefox");
        assert_eq!((ff.id.as_str(), ff.name.as_str()), ("firefox", "Firefox"));
        // A reserved name still cannot be claimed through the marker.
        assert_eq!(r.resolve(33, 1000, "/tmp/x/system (deleted)", "system").id, "system-app");
        // Only the trailing marker is stripped.
        assert_eq!(r.resolve(34, 1000, "/opt/a (deleted)/b", "b").id, "b");
    }

    #[test]
    fn the_passwd_lookup_names_root_and_declines_an_absent_uid() {
        // Through the C library, so NSS accounts are named too. Root exists
        // on every host; a uid at the top of the overflow range on none.
        let root = passwd_entry(0).expect("root has a passwd entry");
        assert_eq!(root.name, "root");
        assert!(!root.home.is_empty());
        assert_eq!(passwd_entry(OVERFLOW_UID - 7), None);
    }
}
