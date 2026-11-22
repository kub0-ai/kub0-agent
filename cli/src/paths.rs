//! Where things live. The system-mode paths match the daemon's (both take
//! them from `daemon/src/rename.rs`); a test in the daemon crate's suite pins
//! the rest to each other.

use std::path::PathBuf;

pub(crate) use crate::rename;

pub const SYSTEM_SOCKET: &str = rename::SYSTEM_SOCKET;
pub const HELPER: &str = "/usr/lib/kub0/kub0-block";
pub const DAEMON: &str = "/usr/lib/kub0/kub0d";
pub const INSTALLED_CLI: &str = "/usr/lib/kub0/kub0";
pub const LIB_DIR: &str = "/usr/lib/kub0";
pub const CLI_LINK: &str = "/usr/bin/kub0";
pub const POLKIT_DIR: &str = "/usr/share/polkit-1/actions";
pub const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/ai.kub0.agent.policy";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const UNIT: &str = "kub0d.service";
pub const EXPIRY_SERVICE: &str = "kub0-expiry.service";
pub const EXPIRY_TIMER: &str = "kub0-expiry.timer";
pub const DATA_DIR: &str = "/usr/share/kub0";
pub const GEO_DIR: &str = "/usr/share/kub0/geoip";
/// The read-only diagnostics group `docs/system-status.md` describes.
pub const STATUS_GROUP: &str = rename::STATUS_GROUP;

/// The 0.4.x names: what `kub0 install` moves or removes on a host that
/// still has them, and what `kub0 doctor` reports while any are left.
pub mod old {
    pub const LIB_DIR: &str = "/usr/lib/vallum";
    pub const DAEMON: &str = "/usr/lib/vallum/vallumd";
    pub const HELPER: &str = "/usr/lib/vallum/vallum-block";
    pub const INSTALLED_CLI: &str = "/usr/lib/vallum/kub0";
    pub const COLLECTOR: &str = "/usr/lib/vallum/vallum-capture";
    pub const CAPTURE_POLICY: &str = "/usr/share/polkit-1/actions/ai.kub0.vallum.capture.policy";
    pub const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/ai.kub0.vallum.policy";
    pub const UNIT: &str = "vallumd.service";
    pub const EXPIRY_SERVICE: &str = "vallum-expiry.service";
    pub const EXPIRY_TIMER: &str = "vallum-expiry.timer";
    pub const DATA_DIR: &str = "/usr/share/vallum";
    pub const STATUS_GROUP: &str = super::rename::OLD_STATUS_GROUP;
}

/// The system daemon's command socket. A 0.4.x daemon's socket is not
/// tried: `kub0 install` replaces that daemon.
pub fn system_socket() -> PathBuf {
    PathBuf::from(SYSTEM_SOCKET)
}

/// The system daemon's account file, in the state directory in use.
pub fn system_account() -> PathBuf {
    rename::state_path("account.json")
}

/// The system daemon's own state (watch rules, names, history), in the state
/// directory in use.
pub fn daemon_state() -> PathBuf {
    rename::state_path("daemon")
}

/// The exec gate's local state, in the state directory in use.
pub fn execgate_dir() -> PathBuf {
    rename::state_path("execgate")
}

pub fn execgate_state() -> PathBuf {
    execgate_dir().join("state.json")
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The per-user daemon's socket: `$XDG_RUNTIME_DIR/kub0.sock`, the daemon's
/// own default.
pub fn user_socket() -> PathBuf {
    user_socket_from(std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from), euid())
}

pub fn user_socket_from(xdg_runtime: Option<PathBuf>, uid: u32) -> PathBuf {
    let dir = match xdg_runtime {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => PathBuf::from(format!("/run/user/{uid}")),
    };
    dir.join(rename::USER_SOCKET_NAME)
}

/// The user daemon's account file, the daemon's own default
/// (`$XDG_STATE_HOME/kub0/account.json`, else `~/.local/state/kub0`), or a
/// 0.4.x user daemon's until it moves its directory.
pub fn user_account() -> PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
            home.join(".local/state")
        });
    rename::current(&state.join(rename::USER_STATE_NAME), &state.join(rename::OLD_USER_STATE_NAME)).join("account.json")
}

/// Which daemon a command goes to when the caller did not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    System,
    User,
}

/// Root talks to the system daemon when there is one. Anyone else talks to
/// the system daemon when its socket lets them in (members of its group:
/// `system_connects`, a connect that succeeded), else to their own. An
/// explicit `--system`/`--user` overrides both.
pub fn pick_target(
    explicit: Option<Target>,
    uid: u32,
    system_exists: bool,
    system_connects: bool,
    user_exists: bool,
) -> Target {
    if let Some(t) = explicit {
        return t;
    }
    if uid == 0 {
        if system_exists || !user_exists {
            Target::System
        } else {
            Target::User
        }
    } else if system_connects {
        Target::System
    } else {
        Target::User
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_socket_follows_xdg_runtime_dir() {
        let dir = std::env::temp_dir().join(format!("kub0-user-socket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(user_socket_from(Some(dir.clone()), 1000), dir.join("kub0.sock"), "nothing running: the new name");
        // 0.4.5 and 0.4.6 fell back to a 0.4.x user daemon's socket here.
        std::fs::write(dir.join(format!("{}.sock", rename::OLD_USER_STATE_NAME)), b"").unwrap();
        assert_eq!(user_socket_from(Some(dir.clone()), 1000), dir.join("kub0.sock"), "a 0.4.x socket beside it is not ours");
        assert_eq!(user_socket_from(None, 1234), PathBuf::from("/run/user/1234/kub0.sock"));
        assert_eq!(user_socket_from(Some(PathBuf::new()), 7), PathBuf::from("/run/user/7/kub0.sock"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_prefers_the_system_daemon() {
        assert_eq!(pick_target(None, 0, true, true, true), Target::System);
        assert_eq!(pick_target(None, 0, true, false, true), Target::System, "root never needs the probe");
        assert_eq!(pick_target(None, 0, false, false, true), Target::User);
        assert_eq!(pick_target(None, 0, false, false, false), Target::System);
        assert_eq!(pick_target(Some(Target::User), 0, true, true, true), Target::User);
    }

    #[test]
    fn a_user_reaches_the_system_daemon_when_its_socket_lets_them_in() {
        // A member of the socket's group: the system daemon, even with a
        // user daemon running beside it.
        assert_eq!(pick_target(None, 1000, true, true, true), Target::System);
        assert_eq!(pick_target(None, 1000, true, true, false), Target::System);
        // Not a member (or no system daemon): their own.
        assert_eq!(pick_target(None, 1000, true, false, true), Target::User);
        assert_eq!(pick_target(None, 1000, true, false, false), Target::User);
        assert_eq!(pick_target(None, 1000, false, false, false), Target::User);
        // The flags still win.
        assert_eq!(pick_target(Some(Target::User), 1000, true, true, true), Target::User);
        assert_eq!(pick_target(Some(Target::System), 1000, false, false, true), Target::System);
    }
}
