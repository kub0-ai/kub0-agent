//! Lowering protection from a desktop: when the system daemon would refuse a
//! request to this (non-root) caller, `kub0` re-runs itself through pkexec, so
//! the password prompt comes from polkit (`ai.kub0.agent.kub0`, auth_admin)
//! rather than a `sudo` hint. Root under pkexec or sudo then names the user it
//! acts for (`as_uid`, from `PKEXEC_UID`, else `SUDO_UID`), so the helper's
//! ownership checks act on that person and not on root.

use crate::paths;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Absolute, never PATH-resolved: whatever answers a bare `pkexec` in the
/// user's PATH would be handed the password prompt.
pub const PKEXEC: &str = "/usr/bin/pkexec";

/// What the decision to re-run through pkexec rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elevation {
    pub euid: u32,
    /// The request needs root on the system daemon (`args::needs_root`).
    pub needs_root: bool,
    /// The daemon this caller reached is the system daemon. A user daemon's
    /// owner may lower protection on it without root, and root would reach a
    /// different daemon.
    pub system_daemon: bool,
    /// `WAYLAND_DISPLAY` or `DISPLAY`: someone at a desktop to answer a prompt.
    pub display: bool,
    pub pkexec: bool,
    /// The installed `kub0` the polkit action names exists.
    pub installed: bool,
    /// `KUB0_NO_PKEXEC` is set.
    pub opted_out: bool,
}

pub fn should_pkexec(e: &Elevation) -> bool {
    e.euid != 0 && e.needs_root && e.system_daemon && e.display && e.pkexec && e.installed && !e.opted_out
}

fn executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn set(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty())
}

/// The decision's inputs from this process and host.
pub fn here(needs_root: bool, system_daemon: bool) -> Elevation {
    Elevation {
        euid: paths::euid(),
        needs_root,
        system_daemon,
        display: set("WAYLAND_DISPLAY") || set("DISPLAY"),
        pkexec: executable(Path::new(PKEXEC)),
        installed: executable(Path::new(paths::CLI_LINK)),
        opted_out: std::env::var_os("KUB0_NO_PKEXEC").is_some(),
    }
}

/// The command line pkexec runs: the installed `kub0` with the same arguments.
pub fn pkexec_argv(argv: &[String]) -> Vec<String> {
    let mut out = vec![paths::CLI_LINK.to_string()];
    out.extend(argv.iter().cloned());
    out
}

/// Replace this process with `pkexec <installed kub0> <argv>`: its output and
/// exit code are the command's. Returns only when the exec itself failed.
pub fn reexec(argv: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(PKEXEC).args(pkexec_argv(argv)).exec();
    eprintln!("kub0: running {PKEXEC}: {err}; run: sudo kub0 …");
    3
}

/// The user root acts for: the one pkexec names (`PKEXEC_UID`, which wins
/// when both are set), else the one sudo names (`SUDO_UID`, when it is not
/// root itself). `None` for anyone but root, and for a plain root shell,
/// which acts as itself. A `PKEXEC_UID` that is set but not a uid names
/// nobody: it is not a reason to fall back to sudo's word.
pub fn as_uid(euid: u32, pkexec_uid: Option<&str>, sudo_uid: Option<&str>) -> Option<u32> {
    if euid != 0 {
        return None;
    }
    if let Some(p) = pkexec_uid.map(str::trim).filter(|p| !p.is_empty()) {
        return p.parse().ok();
    }
    sudo_uid?.trim().parse().ok().filter(|uid| *uid != 0)
}

/// What to do with a wanted `as_uid` once the daemon has said hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsUid {
    Send(u32),
    /// Nothing to send, or a read, which acts for no one, to a daemon that
    /// does not know the field.
    Omit,
    /// A change to a daemon that would ignore `as_uid` and act as root.
    Refuse,
}

pub const OLD_DAEMON: &str = "this daemon is older than the CLI and cannot act for another user; update kub0d";

pub fn as_uid_plan(wanted: Option<u32>, daemon_honours: bool, read: bool) -> AsUid {
    match wanted {
        None => AsUid::Omit,
        Some(uid) if daemon_honours => AsUid::Send(uid),
        Some(_) if read => AsUid::Omit,
        Some(_) => AsUid::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP_MEMBER: Elevation = Elevation {
        euid: 1000,
        needs_root: true,
        system_daemon: true,
        display: true,
        pkexec: true,
        installed: true,
        opted_out: false,
    };

    #[test]
    fn a_desktop_member_lowering_on_the_system_daemon_goes_through_pkexec() {
        assert!(should_pkexec(&DESKTOP_MEMBER));
        for (what, e) in [
            ("root", Elevation { euid: 0, ..DESKTOP_MEMBER }),
            ("a raise", Elevation { needs_root: false, ..DESKTOP_MEMBER }),
            ("the user daemon", Elevation { system_daemon: false, ..DESKTOP_MEMBER }),
            ("headless", Elevation { display: false, ..DESKTOP_MEMBER }),
            ("no pkexec", Elevation { pkexec: false, ..DESKTOP_MEMBER }),
            ("no installed kub0", Elevation { installed: false, ..DESKTOP_MEMBER }),
            ("KUB0_NO_PKEXEC", Elevation { opted_out: true, ..DESKTOP_MEMBER }),
        ] {
            assert!(!should_pkexec(&e), "{what}: keep the sudo hint");
        }
    }

    #[test]
    fn pkexec_runs_the_installed_kub0_with_the_same_arguments() {
        let argv: Vec<String> = ["--json", "unblock", "firefox", "--to", "192.0.2.1"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pkexec_argv(&argv), ["/usr/bin/kub0", "--json", "unblock", "firefox", "--to", "192.0.2.1"]);
        assert_eq!(PKEXEC, "/usr/bin/pkexec");
    }

    #[test]
    fn root_under_pkexec_acts_for_the_user_pkexec_names() {
        assert_eq!(as_uid(0, Some("1000"), None), Some(1000));
        assert_eq!(as_uid(0, Some(" 1000\n"), None), Some(1000));
        assert_eq!(as_uid(0, None, None), None, "a root shell acts as root");
        assert_eq!(as_uid(1000, Some("1001"), None), None, "only root names another user");
        assert_eq!(as_uid(0, Some("x"), None), None);
        assert_eq!(as_uid(0, Some(""), None), None);
    }

    #[test]
    fn sudo_acts_for_its_caller_and_pkexec_wins() {
        assert_eq!(as_uid(0, None, Some("1000")), Some(1000), "sudo kub0 acts for the sudo caller");
        assert_eq!(as_uid(0, Some(""), Some("1000")), Some(1000), "an empty PKEXEC_UID is unset");
        assert_eq!(as_uid(0, Some("1001"), Some("1000")), Some(1001), "PKEXEC_UID wins");
        assert_eq!(as_uid(0, Some("x"), Some("1000")), None, "a bad PKEXEC_UID is no reason to trust sudo's");
        assert_eq!(as_uid(0, None, Some("0")), None, "sudo from root is root");
        assert_eq!(as_uid(0, None, Some("x")), None);
        assert_eq!(as_uid(1000, None, Some("1001")), None, "only root names another user");
    }

    #[test]
    fn as_uid_goes_only_to_a_daemon_that_honours_it() {
        assert_eq!(as_uid_plan(Some(1000), true, false), AsUid::Send(1000));
        assert_eq!(as_uid_plan(Some(1000), true, true), AsUid::Send(1000));
        assert_eq!(as_uid_plan(Some(1000), false, false), AsUid::Refuse, "never act as root instead");
        assert_eq!(as_uid_plan(Some(1000), false, true), AsUid::Omit, "a read acts for no one");
        assert_eq!(as_uid_plan(None, false, false), AsUid::Omit);
        assert_eq!(as_uid_plan(None, true, false), AsUid::Omit);
        assert!(OLD_DAEMON.contains("update kub0d"));
    }
}
