//! What is installed, reachable and missing on this host. Reads only; a
//! non-root run reports what it can see and says what it cannot.

use crate::client::{Client, ConnectError};
use crate::paths;
use crate::render::table;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOL_PATH: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ok,
    Missing,
    Warn,
    Unknown,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Missing => "missing",
            State::Warn => "warn",
            State::Unknown => "unknown",
        }
    }
}

/// `ID` and `ID_LIKE` from os-release, lowercased, as one family word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Arch,
    Debian,
    Fedora,
    Suse,
    Alpine,
    Other,
}

pub fn family_from(os_release: &str) -> Family {
    let mut ids = String::new();
    for line in os_release.lines() {
        let line = line.trim();
        for key in ["ID=", "ID_LIKE="] {
            if let Some(v) = line.strip_prefix(key) {
                ids.push(' ');
                ids.push_str(&v.trim_matches('"').to_ascii_lowercase());
            }
        }
    }
    for word in ids.split_whitespace() {
        match word {
            "arch" | "archlinux" | "omarchy" | "manjaro" | "endeavouros" | "cachyos" => return Family::Arch,
            "debian" | "ubuntu" | "linuxmint" | "pop" | "raspbian" => return Family::Debian,
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "amzn" => return Family::Fedora,
            "suse" | "opensuse" | "opensuse-tumbleweed" | "opensuse-leap" | "sles" => return Family::Suse,
            "alpine" => return Family::Alpine,
            _ => {}
        }
    }
    Family::Other
}

pub fn pretty_name(os_release: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.trim().strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        .unwrap_or_else(|| "unknown Linux".into())
}

/// The package that provides `tool` on `family`, for the hint.
pub fn package_for(tool: &str, family: Family) -> &'static str {
    match (tool, family) {
        ("nft", _) => "nftables",
        ("conntrack", Family::Debian) => "conntrack",
        ("conntrack", _) => "conntrack-tools",
        _ => "",
    }
}

pub fn install_hint(family: Family, packages: &[&str]) -> String {
    let list = packages.join(" ");
    match family {
        Family::Arch => format!("pacman -S {list}"),
        Family::Debian => format!("apt install {list}"),
        Family::Fedora => format!("dnf install {list}"),
        Family::Suse => format!("zypper install {list}"),
        Family::Alpine => format!("apk add {list}"),
        Family::Other => format!("install {list} with your package manager"),
    }
}

fn which(tool: &str) -> Option<PathBuf> {
    TOOL_PATH
        .iter()
        .map(|d| Path::new(d).join(tool))
        .find(|p| p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false))
}

/// A root-owned, non-writable, executable regular file.
fn root_executable(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.file_type().is_symlink() {
        return Err("is a symlink".into());
    }
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    if m.uid() != 0 {
        return Err(format!("owned by uid {}, not root", m.uid()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!("writable by group or others (mode {:o})", m.mode() & 0o7777));
    }
    if m.mode() & 0o111 == 0 {
        return Err("not executable".into());
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Option<String> {
    let out = Command::new("systemctl").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Whether `name` is a group in the text of `/etc/group`. The system daemon
/// resolves the status group from that file alone (never NSS; see
/// `docs/system-status.md`), so the doctor reads the same source: a group
/// that only a directory service knows is still missing to the daemon.
pub fn group_defined(group_file: &str, name: &str) -> bool {
    group_file.lines().any(|line| line.split(':').next() == Some(name))
}

fn status_group_check() -> Check {
    match std::fs::read_to_string("/etc/group") {
        Ok(text) => status_group_from(
            &text,
            &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
            &std::fs::read_to_string("/etc/login.defs").unwrap_or_default(),
        ),
        Err(e) => Check { name: "status group", state: State::Unknown, detail: format!("/etc/group: {e}") },
    }
}

/// The status group as the system daemon resolves it: `kub0`, or for one
/// release the 0.4.x name, and neither while both exist.
fn status_group_from(group_file: &str, passwd: &str, login_defs: &str) -> Check {
    let (group, old) = (paths::STATUS_GROUP, paths::old::STATUS_GROUP);
    let name = "status group";
    // The rule kub0d applies: a system group that is nobody's primary group.
    let refused = |g: &str| {
        group_file
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() >= 3 && f[0] == g).then(|| f[2].parse::<u32>().ok()).flatten()
            })
            .and_then(|gid| paths::rename::status_group_refusal(g, gid, passwd, login_defs))
    };
    match (group_defined(group_file, group), group_defined(group_file, old)) {
        (true, false) => match refused(group) {
            Some(why) => Check { name, state: State::Missing, detail: format!("{why}; kub0d leaves its sockets root's") },
            None => Check { name, state: State::Ok, detail: format!("{group} in /etc/group") },
        },
        (false, true) => Check {
            name,
            state: State::Warn,
            detail: match refused(old) {
                Some(why) => format!("{why}; kub0d leaves its sockets root's, and kub0 install will not rename it"),
                None => format!("{old} (the 0.4.x name) answers for one more release; `sudo kub0 install` renames it to {group} in place"),
            },
        },
        (true, true) => Check {
            name,
            state: State::Warn,
            detail: format!(
                "both {group} and {old} exist, so the system daemon uses neither and its sockets stay root's; \
                 kub0 install will not merge them: decide which members belong, then remove one by hand"
            ),
        },
        (false, false) => Check {
            name,
            state: State::Missing,
            detail: format!("{group} absent from /etc/group; the system daemon serves no status socket without it (kub0 install creates it)"),
        },
    }
}

/// What a 0.4.x install left under `root` (`/` outside tests), and what
/// 0.4.5 and 0.4.6 kept of it for compatibility (links at the old binary
/// paths, the unit alias). `kub0 install` removes or moves each; none of
/// them stops anything working, so they are warnings.
fn leftovers(root: &Path) -> Vec<String> {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let mut out = Vec::new();
    let unit_dir = at(paths::UNIT_DIR);
    // A regular file is the old unit; a symlink by that name is the alias
    // 0.4.5 and 0.4.6 gave kub0d.
    for unit in [paths::old::UNIT, paths::old::EXPIRY_SERVICE, paths::old::EXPIRY_TIMER] {
        let p = unit_dir.join(unit);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => out.push(format!("{} (the alias 0.4.5 and 0.4.6 gave kub0d)", p.display())),
            Ok(_) => out.push(format!("{} (the 0.4.x unit)", p.display())),
            Err(_) => {}
        }
    }
    for policy in [paths::old::POLKIT_POLICY, paths::old::CAPTURE_POLICY] {
        let policy = at(policy);
        if paths::rename::present(&policy) {
            out.push(format!("{} (a 0.4.x polkit policy)", policy.display()));
        }
    }
    let (old_state, new_state) = (at(paths::rename::OLD_STATE_ROOT), at(paths::rename::STATE_ROOT));
    if std::fs::symlink_metadata(&old_state).is_ok() {
        out.push(if paths::rename::present(&new_state) {
            format!("{} beside {} (left untouched when both held state; check it, then remove it)", old_state.display(), new_state.display())
        } else {
            format!("{} not moved yet (kub0d moves it to {} when it starts)", old_state.display(), new_state.display())
        });
    }
    let data = at(paths::old::DATA_DIR);
    if paths::rename::present(&data) {
        out.push(format!("{} (0.4.x geo databases; kub0d reads {})", data.display(), paths::DATA_DIR));
    }
    // Whatever is at an old binary path: a 0.4.x binary, or the link 0.4.5
    // and 0.4.6 left there. Nothing runs either now.
    let old_lib = at(paths::old::LIB_DIR);
    let mut old_binaries = 0;
    for old in [paths::old::DAEMON, paths::old::HELPER, paths::old::INSTALLED_CLI, paths::old::COLLECTOR] {
        let o = at(old);
        if std::fs::symlink_metadata(&o).is_ok() {
            old_binaries += 1;
            out.push(format!("{} (a 0.4.x binary path; nothing runs it now)", o.display()));
        }
    }
    if old_binaries == 0 && std::fs::symlink_metadata(&old_lib).is_ok() {
        out.push(format!("{} (the 0.4.x binary directory)", old_lib.display()));
    }
    out
}

/// The release after this one drops `/var/lib/vallum`, so a host whose state
/// never reached `/var/lib/kub0` (a move the kernel refused, a mount point,
/// state at both) must say so now: this row fails until it is resolved.
fn state_dir_check(root: &Path) -> Check {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let (old, new) = (at(paths::rename::OLD_STATE_ROOT), at(paths::rename::STATE_ROOT));
    let name = "state directory";
    if !paths::rename::present(&old) {
        let detail = if paths::rename::present(&new) { new.display().to_string() } else { format!("{} (created on first start)", new.display()) };
        return Check { name, state: State::Ok, detail };
    }
    if paths::rename::current(&new, &old) == old {
        return Check {
            name,
            state: State::Missing,
            detail: format!(
                "the state is still only at {} (not moved to {}); the next release drops the old path: restart kub0d or run \
                 `sudo kub0 install`, and if the kernel refuses the move (another filesystem, a mount point) move it by hand",
                old.display(),
                new.display()
            ),
        };
    }
    Check {
        name,
        state: State::Missing,
        detail: format!(
            "both {} and {} hold state; kub0d uses {} and the next release drops {}: check it, then remove it",
            new.display(),
            old.display(),
            new.display(),
            old.display()
        ),
    }
}

/// Local polkit rules that name a 0.4.x action id (`ai.kub0.vallum.*`) no
/// longer match anything: the actions are `ai.kub0.agent.*` now.
fn polkit_rules_naming_old(dirs: &[&Path]) -> Vec<String> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            if std::fs::read_to_string(&f).is_ok_and(|t| t.contains("ai.kub0.vallum.")) {
                out.push(f.display().to_string());
            }
        }
    }
    out
}

fn polkit_rules_check() -> Check {
    let found = polkit_rules_naming_old(&[Path::new("/etc/polkit-1/rules.d"), Path::new("/usr/share/polkit-1/rules.d")]);
    Check {
        name: "polkit rules",
        state: if found.is_empty() { State::Ok } else { State::Warn },
        detail: if found.is_empty() {
            "no local rule names a 0.4.x action".into()
        } else {
            format!(
                "{} name ai.kub0.vallum.*, which no action has any more: rename those ids to ai.kub0.agent.* (and ai.kub0.agent.compat.* for the old helper path)",
                found.join(", ")
            )
        },
    }
}

fn leftovers_check() -> Check {
    let found = leftovers(Path::new("/"));
    Check {
        name: "0.4.x leftovers",
        state: if found.is_empty() { State::Ok } else { State::Warn },
        detail: if found.is_empty() { "none".into() } else { format!("{} (sudo kub0 install tidies them)", found.join("; ")) },
    }
}

fn groups() -> Vec<String> {
    Command::new("id")
        .arg("-nG")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

fn socket_check(name: &'static str, path: &Path, root_only: bool) -> Check {
    // `Path::exists` folds EACCES into "absent": /run/kub0 is root:kub0
    // 0750 (root:root before the group resolves), so a non-member's stat of the
    // system socket fails on the directory whether or not the daemon runs. Keep
    // the three answers apart: gone, unreadable, present.
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Check { name, state: State::Missing, detail: format!("{} absent", path.display()) };
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && root_only => {
            return Check {
                name,
                state: State::Unknown,
                detail: format!(
                    "{} admits root and the {} group, not this user; `sudo kub0 doctor` probes it (kub0d.service below says whether it runs)",
                    path.display(),
                    paths::STATUS_GROUP
                ),
            };
        }
        Err(e) => return Check { name, state: State::Warn, detail: format!("{}: {e}", path.display()) },
    }
    match Client::connect(path) {
        Ok(c) => Check {
            name,
            state: State::Ok,
            detail: format!(
                "{}: kub0d {} ({} mode, pid {}){}",
                path.display(),
                c.hello.version,
                c.hello.mode,
                c.hello.pid,
                if c.hello.connected { format!(", logged in as {}", c.hello.github_username) } else { ", not logged in".into() }
            ),
        },
        Err(ConnectError::Denied(_)) if root_only => Check {
            name,
            state: State::Ok,
            detail: format!(
                "{} present; it admits root and the {} group, not this user, so `sudo kub0` reaches it",
                path.display(),
                paths::STATUS_GROUP
            ),
        },
        Err(e) => Check { name, state: State::Warn, detail: e.to_string() },
    }
}

pub fn checks() -> Vec<Check> {
    let mut out = Vec::new();
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let family = family_from(&os_release);
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    out.push(Check {
        name: "host",
        state: State::Ok,
        detail: format!("{} (kernel {}, {:?} family)", pretty_name(&os_release), kernel.trim(), family),
    });
    let me = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "?".into());
    out.push(Check { name: "cli", state: State::Ok, detail: format!("kub0 {} at {me}", env!("CARGO_PKG_VERSION")) });

    let system = socket_check("system daemon", &paths::system_socket(), true);
    let user_socket = paths::user_socket();
    out.push(one_daemon(socket_check("user daemon", &user_socket, false), nobody_listens(&user_socket), &system));
    out.push(system);

    if which("systemctl").is_some() {
        let active = systemctl(&["is-active", "kub0d"]).unwrap_or_default();
        let enabled = systemctl(&["is-enabled", "kub0d"]).unwrap_or_default();
        let state = if active == "active" { State::Ok } else if active == "inactive" || active == "failed" { State::Warn } else { State::Missing };
        out.push(Check {
            name: "kub0d.service",
            state,
            detail: if active.is_empty() { "unit not installed (kub0 install)".into() } else { format!("{active}, {enabled}") },
        });
    } else {
        out.push(Check { name: "kub0d.service", state: State::Unknown, detail: "no systemctl on this host; start /usr/lib/kub0/kub0d --system from your init".into() });
    }

    for (name, path) in [("daemon binary", paths::DAEMON), ("helper binary", paths::HELPER), ("installed cli", paths::INSTALLED_CLI)] {
        let p = Path::new(path);
        out.push(match root_executable(p) {
            Ok(()) => Check { name, state: State::Ok, detail: path.to_string() },
            Err(e) if !p.exists() => Check { name, state: State::Missing, detail: format!("{path} absent (kub0 install); {e}") },
            Err(e) => Check { name, state: State::Warn, detail: format!("{path}: {e}") },
        });
    }
    out.push(Check {
        name: "polkit policy",
        state: if Path::new(paths::POLKIT_POLICY).exists() { State::Ok } else if Path::new(paths::POLKIT_DIR).exists() { State::Warn } else { State::Ok },
        detail: if Path::new(paths::POLKIT_POLICY).exists() {
            paths::POLKIT_POLICY.into()
        } else if Path::new(paths::POLKIT_DIR).exists() {
            "absent; the desktop panel's blocks will not authorize (kub0 install)".into()
        } else {
            "no polkit on this host; servers do not need it".into()
        },
    });

    let mut missing: Vec<&str> = Vec::new();
    for tool in ["nft", "conntrack"] {
        match which(tool) {
            Some(p) => out.push(Check { name: if tool == "nft" { "nftables" } else { "conntrack" }, state: State::Ok, detail: p.display().to_string() }),
            None => {
                missing.push(package_for(tool, family));
                out.push(Check {
                    name: if tool == "nft" { "nftables" } else { "conntrack" },
                    state: State::Missing,
                    detail: format!("{tool} not found; blocking needs it: {}", install_hint(family, &[package_for(tool, family)])),
                });
            }
        }
    }
    let cg = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    out.push(Check {
        name: "cgroup v2",
        state: if cg { State::Ok } else { State::Missing },
        detail: if cg { "/sys/fs/cgroup/cgroup.controllers".into() } else { "unified cgroup hierarchy not mounted; app blocks need it".into() },
    });

    let sys_acct = paths::system_account().exists();
    let gate = paths::execgate_state();
    out.push(match std::fs::read_to_string(&gate) {
        Ok(text) => {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            let (state, detail) = gate_check(&v, sys_acct, crate::render::now_ms());
            Check { name: "exec gate", state, detail: format!("{}: {detail}", gate.display()) }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Check { name: "exec gate", state: State::Warn, detail: "no state file yet; the system daemon writes it once it starts".into() },
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Check {
            name: "exec gate",
            state: State::Unknown,
            detail: format!("{}: readable by root and members of the kub0 group only", gate.display()),
        },
        Err(e) => Check { name: "exec gate", state: State::Unknown, detail: format!("{}: {e}", gate.display()) },
    });

    let usr_acct = paths::user_account();
    out.push(Check {
        name: "accounts",
        state: if sys_acct || usr_acct.exists() { State::Ok } else { State::Warn },
        detail: format!(
            "system {}; user {}",
            if sys_acct { "present".to_string() } else { "absent (sudo kub0 login)".to_string() },
            if usr_acct.exists() { "present".to_string() } else { format!("absent ({})", usr_acct.display()) }
        ),
    });
    out.push(status_group_check());
    out.push(state_dir_check(Path::new("/")));
    out.push(leftovers_check());
    // rules.d is readable only by root (and polkitd).
    if paths::euid() == 0 {
        out.push(polkit_rules_check());
    }
    if paths::euid() != 0 {
        let in_group = groups().iter().any(|g| g == paths::STATUS_GROUP || g == paths::old::STATUS_GROUP);
        out.push(Check {
            name: "status membership",
            state: if in_group { State::Ok } else { State::Unknown },
            detail: status_membership_detail(in_group),
        });
    }
    out.push(Check {
        name: "blocking",
        state: if missing.is_empty() && cg { State::Ok } else { State::Missing },
        detail: if missing.is_empty() && cg { "every requirement present".into() } else if missing.is_empty() { "cgroup v2 missing".into() } else { install_hint(family, &missing) },
    });
    out
}

/// What membership of the status group gives this user on the system daemon.
fn status_membership_detail(in_group: bool) -> String {
    let group = paths::STATUS_GROUP;
    if in_group {
        format!(
            "in {group}: you read the system daemon and raise its protection without sudo (block an app, untrust, resume, watch, tag); \
             lowering it (unblock, trust, pause, policy snooze), logging the host in and address blocks are `sudo kub0`"
        )
    } else {
        format!(
            "not in {group}; the system daemon is `sudo kub0` for you (membership would let you read and raise without sudo; \
             `sudo kub0 install` adds the installing user, and a new login applies it)"
        )
    }
}

/// Prints the report; returns the exit code (0 when nothing is missing).
/// No daemon is behind this socket: it is not there, or nothing accepts on it
/// (the file a stopped daemon left). A daemon that accepts and then says
/// nothing, or hangs up, is listening: that one is broken, not absent.
fn nobody_listens(path: &Path) -> bool {
    matches!(Client::connect(path), Err(ConnectError::Absent(_)))
}

/// One daemon (#61): beside a system daemon that answers, having no daemon of
/// one's own is how it should be, not something to warn about. The panel reads
/// the system daemon and starts its own only for capture, or when it cannot
/// use the system one. A user daemon that answers is reported as it is, and so
/// is one that is there and not answering: `absent` is only "nobody listens".
fn one_daemon(user: Check, absent: bool, system: &Check) -> Check {
    if !absent || user.state == State::Ok || system.state != State::Ok {
        return user;
    }
    Check {
        name: user.name,
        state: State::Ok,
        detail: "not running, and not needed: the panel and kub0 use the system daemon (the panel starts one of its own only for capture)".into(),
    }
}

/// The exec gate row from the system daemon's state file: armed and the key count, and
/// where the keys are from when that is not a sync since the daemon started. A gate on
/// the org list saved before the start is armed, and as old as that list. A logged-in
/// host whose gate has no org list in use is not protected by it yet (none saved, and
/// none taken from the API: unreachable, or over the 500-row limit): that is a warning,
/// where an org list that simply holds no key is not. A state file from 0.4.7 or older
/// has neither field and reads as before.
fn gate_check(v: &serde_json::Value, logged_in: bool, now: u64) -> (State, String) {
    let flag = |k: &str| v.get(k).and_then(|b| b.as_bool());
    let received = v.get("listReceivedAt").and_then(|t| t.as_u64());
    let keys = v.get("keys").and_then(|k| k.as_u64()).unwrap_or(0);
    let detail = format!("armed {}, keys {keys}", flag("armed").unwrap_or(false));
    if flag("listRestored") == Some(true) {
        let saved = crate::render::ago(received.unwrap_or(0), now);
        return (State::Ok, format!("{detail} from the org list saved {saved} (no sync since the daemon started)"));
    }
    if logged_in && flag("enabled") == Some(true) && received == Some(0) {
        return (
            State::Warn,
            format!("{detail}: no org list in use (none saved, and none taken from the kub0 API since the daemon started)"),
        );
    }
    (State::Ok, detail)
}

pub fn run(json: bool) -> i32 {
    let checks = checks();
    let missing = checks.iter().filter(|c| c.state == State::Missing).count();
    if json {
        let rows: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| serde_json::json!({ "name": c.name, "state": c.state.word(), "detail": c.detail }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "checks": rows, "missing": missing })).unwrap());
    } else {
        let rows: Vec<Vec<String>> = checks.iter().map(|c| vec![c.name.to_string(), c.state.word().to_string(), c.detail.clone()]).collect();
        print!("{}", table(&["check", "state", "detail"], &rows));
        if missing == 0 {
            println!("\nnothing missing");
        } else {
            println!("\n{missing} missing");
        }
    }
    if missing == 0 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_membership_says_what_it_grants_and_keeps_sudo_for_lowering() {
        let member = status_membership_detail(true);
        assert!(member.contains("raise") && member.contains("without sudo") && member.contains("`sudo kub0`"), "{member}");
        let other = status_membership_detail(false);
        assert!(other.contains("not in kub0") && other.contains("sudo kub0"), "{other}");
    }

    #[test]
    fn the_exec_gate_row_says_where_the_keys_are_from() {
        use serde_json::json;
        let now = 100_000_000;
        let synced = json!({"enabled": true, "armed": true, "keys": 55, "listReceivedAt": now - 40_000, "listRestored": false});
        assert_eq!(gate_check(&synced, true, now), (State::Ok, "armed true, keys 55".to_string()));

        let restored = json!({"enabled": true, "armed": true, "keys": 55, "listReceivedAt": now - 11_520_000, "listRestored": true});
        let (state, detail) = gate_check(&restored, true, now);
        assert_eq!(state, State::Ok);
        assert_eq!(detail, "armed true, keys 55 from the org list saved 3h 12m ago (no sync since the daemon started)");

        // Logged in, no list saved and none received: the gate protects nothing yet.
        let waiting = json!({"enabled": true, "armed": false, "keys": 0, "listReceivedAt": 0, "listRestored": false});
        let (state, detail) = gate_check(&waiting, true, now);
        assert_eq!(state, State::Warn);
        assert!(detail.starts_with("armed false, keys 0: no org list in use"), "{detail}");
        // Not logged in, there is no org list to wait for.
        assert_eq!(gate_check(&waiting, false, now).0, State::Ok);
        // An org list with no key in it was received: nothing is missing.
        let empty = json!({"enabled": true, "armed": false, "keys": 0, "listReceivedAt": now - 1_000, "listRestored": false});
        assert_eq!(gate_check(&empty, true, now), (State::Ok, "armed false, keys 0".to_string()));
        // 0.4.7's state file.
        let old = json!({"enabled": true, "armed": false, "keys": 0});
        assert_eq!(gate_check(&old, true, now), (State::Ok, "armed false, keys 0".to_string()));
    }

    /// On a host with the system daemon installed and the panel reading it, the
    /// user daemon's socket is gone or dead. Doctor used to report that as
    /// `missing` or `warn` (Connection refused) on every healthy one-daemon host.
    #[test]
    fn no_user_daemon_beside_a_system_daemon_is_not_a_warning() {
        let check = |state, detail: &str| Check { name: "user daemon", state, detail: detail.into() };
        let system_ok = Check { name: "system daemon", state: State::Ok, detail: "kub0d 0.5.0".into() };
        for state in [State::Warn, State::Missing] {
            let c = one_daemon(check(state, "/run/user/1000/kub0.sock: Connection refused (os error 111)"), true, &system_ok);
            assert_eq!(c.state, State::Ok);
            assert!(c.detail.starts_with("not running, and not needed"), "{}", c.detail);
        }
        // One that answers (capture on) is shown as it is.
        let running = one_daemon(check(State::Ok, "kub0d 0.5.0 (user mode, pid 7)"), false, &system_ok);
        assert_eq!(running.detail, "kub0d 0.5.0 (user mode, pid 7)");
        // One that accepts and never greets is the daemon the panel is reading
        // (capture on), and it is broken: that warning stays.
        let wedged = one_daemon(check(State::Warn, "waiting for the daemon's greeting: timed out"), false, &system_ok);
        assert_eq!((wedged.state, wedged.detail.as_str()), (State::Warn, "waiting for the daemon's greeting: timed out"));
        // With no system daemon to use, a missing user daemon is still missing.
        for sys in [State::Missing, State::Unknown, State::Warn] {
            let system = Check { name: "system daemon", state: sys, detail: String::new() };
            assert_eq!(one_daemon(check(State::Missing, "absent"), true, &system).state, State::Missing);
        }
        // What "nobody listens" means, on real sockets: no file, and a file
        // nothing accepts on. A listener that says nothing is not absent.
        let dir = std::env::temp_dir().join(format!("kub0-doctor-listen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(nobody_listens(&dir.join("none.sock")));
        let stale = dir.join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        assert!(stale.exists() && nobody_listens(&stale), "the file a stopped daemon left");
        let silent = dir.join("silent.sock");
        let _held = std::os::unix::net::UnixListener::bind(&silent).unwrap();
        assert!(!nobody_listens(&silent), "it accepts: wedged, not absent");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_absent_socket_is_missing() {
        let dir = std::env::temp_dir().join(format!("kub0-doctor-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = socket_check("system daemon", &dir.join("kub0.sock"), true);
        assert_eq!(c.state, State::Missing);
        assert!(c.detail.ends_with("absent"), "{}", c.detail);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_root_only_directory_is_unknown_not_missing() {
        if paths::euid() == 0 {
            return; // root reads everything; the EACCES branch cannot be reached
        }
        let dir = std::env::temp_dir().join(format!("kub0-doctor-eacces-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let sys = socket_check("system daemon", &dir.join("kub0.sock"), true);
        let usr = socket_check("user daemon", &dir.join("kub0.sock"), false);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(sys.state, State::Unknown, "{}", sys.detail);
        assert!(sys.detail.contains("sudo kub0 doctor"), "{}", sys.detail);
        assert_eq!(usr.state, State::Warn, "{}", usr.detail);
    }

    #[test]
    fn the_status_group_is_read_from_etc_group_by_whole_name() {
        let text = "root:x:0:\nkub0:x:981:alice\nusers:x:984:\n";
        assert!(group_defined(text, "kub0"));
        assert!(group_defined("kub0:x:981:", "kub0"), "no members, no trailing newline");
        assert!(!group_defined("root:x:0:\nusers:x:984:\n", "kub0"));
        assert!(!group_defined("", "kub0"));
        assert!(!group_defined("kub0-old:x:1:\nvallum:x:2:\n", "kub0"), "a prefix or a suffix is another group");
        assert!(!group_defined("#kub0:x:981:\n", "kub0"), "a commented row is no group");
        assert!(!group_defined("alice:x:1000:kub0\n", "kub0"), "a member list is not a group name");
    }

    #[test]
    fn the_status_group_answers_to_its_old_name_for_one_release_and_never_both() {
        assert_eq!(status_group_from("kub0:x:981:alice\n", "", "").state, State::Ok);
        let upg = status_group_from("kub0:x:1001:\n", "kub0:x:1001:1001::/home/kub0:/bin/sh\n", "");
        assert_eq!(upg.state, State::Missing, "a user's private group is not the status group: {}", upg.detail);
        let old = status_group_from("vallum-status:x:981:alice\n", "", "");
        assert_eq!(old.state, State::Warn, "{}", old.detail);
        assert!(old.detail.contains("renames it to kub0 in place"), "{}", old.detail);
        let both = status_group_from("kub0:x:1000:\nvallum-status:x:981:alice\n", "", "");
        assert_eq!(both.state, State::Warn);
        assert!(both.detail.contains("uses neither") && both.detail.contains("will not merge"), "{}", both.detail);
        assert_eq!(status_group_from("users:x:984:\n", "", "").state, State::Missing);
    }

    #[test]
    fn the_doctor_reports_what_a_0_4_install_left() {
        let root = std::env::temp_dir().join(format!("kub0-doctor-leftovers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        assert!(leftovers(&root).is_empty(), "a fresh host");
        for dir in [paths::UNIT_DIR, paths::LIB_DIR, paths::old::LIB_DIR, paths::POLKIT_DIR] {
            std::fs::create_dir_all(at(dir)).unwrap();
        }
        // The old directory, empty, is itself a leftover.
        assert_eq!(leftovers(&root).len(), 1, "{:?}", leftovers(&root));
        assert!(leftovers(&root)[0].ends_with("/usr/lib/vallum (the 0.4.x binary directory)"));
        // Linked the way 0.4.5 and 0.4.6 linked them, with the unit alias:
        // not leftovers then, leftovers now that nothing runs them.
        for (old, new) in [(paths::old::DAEMON, paths::DAEMON), (paths::old::HELPER, paths::HELPER), (paths::old::INSTALLED_CLI, paths::INSTALLED_CLI)] {
            std::fs::write(at(new), b"bin").unwrap();
            std::os::unix::fs::symlink(at(new), at(old)).unwrap();
        }
        std::os::unix::fs::symlink("kub0d.service", at(paths::UNIT_DIR).join(paths::old::UNIT)).unwrap();
        std::fs::write(at(paths::old::COLLECTOR), b"collector").unwrap();
        std::fs::write(at(paths::old::CAPTURE_POLICY), b"<policyconfig/>").unwrap();
        let linked = leftovers(&root).join("\n");
        for want in ["vallumd.service (the alias 0.4.5 and 0.4.6 gave kub0d)", "vallum/vallumd (a 0.4.x binary path", "vallum-block (a 0.4.x binary path", "vallum/kub0 (a 0.4.x binary path", "vallum-capture (a 0.4.x binary path", "ai.kub0.vallum.capture.policy (a 0.4.x polkit policy)"] {
            assert!(linked.contains(want), "{want} missing from:\n{linked}");
        }
        assert!(!linked.contains("binary directory"), "the directory is not listed beside its files:\n{linked}");
        // The 0.4.x install as it was.
        std::fs::remove_file(at(paths::old::HELPER)).unwrap();
        std::fs::write(at(paths::old::HELPER), b"old helper").unwrap();
        std::fs::remove_file(at(paths::UNIT_DIR).join(paths::old::UNIT)).unwrap();
        std::fs::write(at(paths::UNIT_DIR).join(paths::old::UNIT), b"[Unit]").unwrap();
        std::fs::write(at(paths::UNIT_DIR).join(paths::old::EXPIRY_TIMER), b"[Timer]").unwrap();
        std::fs::write(at(paths::old::POLKIT_POLICY), b"<policyconfig/>").unwrap();
        std::fs::create_dir_all(at(paths::rename::OLD_STATE_ROOT)).unwrap();
        std::fs::create_dir_all(at(paths::old::DATA_DIR)).unwrap();
        let found = leftovers(&root).join("\n");
        for want in ["vallumd.service (the 0.4.x unit)", "vallum-expiry.timer", "ai.kub0.vallum.policy", "/var/lib/vallum not moved yet", "/usr/share/vallum", "vallum-block (a 0.4.x binary path"] {
            assert!(found.contains(want), "{want} missing from:\n{found}");
        }
        std::fs::create_dir_all(at(paths::rename::STATE_ROOT)).unwrap();
        assert!(leftovers(&root).join("\n").contains("left untouched when both held state"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The gate for the release that drops the old names: state still only
    /// at /var/lib/vallum, or at both, fails the doctor.
    #[test]
    fn the_doctor_fails_while_state_has_not_reached_the_new_directory() {
        let root = std::env::temp_dir().join(format!("kub0-doctor-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        assert_eq!(state_dir_check(&root).state, State::Ok, "a fresh host");
        std::fs::create_dir_all(at(paths::rename::OLD_STATE_ROOT)).unwrap();
        std::fs::write(at(paths::rename::OLD_STATE_ROOT).join("account.json"), "{}").unwrap();
        let c = state_dir_check(&root);
        assert_eq!(c.state, State::Missing, "only at the old path: {}", c.detail);
        std::fs::create_dir_all(at(paths::rename::STATE_ROOT).join("lost+found")).unwrap();
        assert_eq!(state_dir_check(&root).state, State::Missing, "an empty mount point at the new path changes nothing");
        std::fs::write(at(paths::rename::STATE_ROOT).join("account.json"), "{}").unwrap();
        let c = state_dir_check(&root);
        assert!(c.state == State::Missing && c.detail.contains("both"), "{}", c.detail);
        std::fs::remove_dir_all(at(paths::rename::OLD_STATE_ROOT)).unwrap();
        assert_eq!(state_dir_check(&root).state, State::Ok, "moved");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_polkit_rules_naming_an_old_action_are_reported() {
        let d = std::env::temp_dir().join(format!("kub0-doctor-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("10-other.rules"), "polkit.addRule(function(a, s) { return null; });").unwrap();
        assert!(polkit_rules_naming_old(&[&d, Path::new("/nonexistent")]).is_empty());
        std::fs::write(d.join("50-kub0.rules"), "if (action.id == \"ai.kub0.vallum.block-app\") return polkit.Result.YES;").unwrap();
        assert_eq!(polkit_rules_naming_old(&[&d]), [d.join("50-kub0.rules").display().to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn family_reads_id_then_id_like() {
        assert_eq!(family_from("ID=omarchy\nID_LIKE=arch\n"), Family::Arch);
        assert_eq!(family_from("ID=\"ubuntu\"\nID_LIKE=debian\n"), Family::Debian);
        assert_eq!(family_from("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"), Family::Fedora);
        assert_eq!(family_from("ID=opensuse-tumbleweed\nID_LIKE=\"suse opensuse\"\n"), Family::Suse);
        assert_eq!(family_from("ID=alpine\n"), Family::Alpine);
        assert_eq!(family_from("ID=nixos\n"), Family::Other);
        assert_eq!(pretty_name("PRETTY_NAME=\"Debian GNU/Linux 13\"\nID=debian"), "Debian GNU/Linux 13");
        assert_eq!(pretty_name(""), "unknown Linux");
    }

    #[test]
    fn hints_name_the_distro_package() {
        assert_eq!(install_hint(Family::Debian, &[package_for("nft", Family::Debian), package_for("conntrack", Family::Debian)]), "apt install nftables conntrack");
        assert_eq!(install_hint(Family::Arch, &[package_for("conntrack", Family::Arch)]), "pacman -S conntrack-tools");
        assert_eq!(install_hint(Family::Fedora, &["nftables"]), "dnf install nftables");
        assert!(install_hint(Family::Other, &["nftables"]).contains("package manager"));
    }
}
