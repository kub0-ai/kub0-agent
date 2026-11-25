//! Who may read what the daemon keeps on disk.
//!
//! The system daemon answers root and members of the `kub0` group on its
//! socket, and nobody else (SECURITY.md). Its files hold what the socket
//! says: which account connected where, what the exec gate stopped and from
//! which path. They are kept to the same readers, by the directory and not
//! file by file, so a file some later code writes with an ordinary mode is
//! covered too:
//!
//! * the daemon's own state directory is its owner's alone (0700);
//! * the exec gate's directory is root's and the status group's (2750,
//!   `root:kub0`), because the per-user daemon mirrors `state.json` from it,
//!   and root's alone when that group cannot be used;
//! * the state root itself stays 0755: the helper's `status` verb runs as the
//!   panel's user, in or out of the group, and reads the block markers and
//!   the endpoint owner map there. Those say which apps are blocked and which
//!   addresses, and nothing about who connected where.
//!
//! Every start applies this again, so a tree an earlier version left open
//! (0755 directories, 0644 files) is closed by the first start of this one.
//! Nothing here follows a symbolic link.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Create `dir` for its owner alone if it is not there. One that exists is
/// left as it is: an explicit `--state-dir` is used as given.
pub fn create_private(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// `dir` is its owner's alone: created 0700 if absent; otherwise the group
/// and other bits come off it and off each entry directly in it. The
/// directory goes first, since that is what closes the rest. Returns whether
/// anything had to change.
pub fn make_private(dir: &Path) -> io::Result<bool> {
    create_private(dir)?;
    let mut changed = keep_bits(dir, 0o700)?;
    for entry in std::fs::read_dir(dir)? {
        changed |= keep_bits(&entry?.path(), 0o700)?;
    }
    Ok(changed)
}

/// What `share_with_group` left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shared {
    /// `root:<gid>`, 2750: the group's members may enter and read.
    WithGroup(u32),
    /// 0700: the group was not given, or the directory could not be given to
    /// it.
    OwnerOnly,
}

/// `dir` is its owner's and, when `gid` names one, that group's to read:
/// mode 2750 and group `gid`, with the set-group-ID bit so files written
/// there later belong to the group as well. Every entry directly in it loses
/// its other bits and joins the group. Without a group (`None`, or 0, or a
/// group the kernel will not take) it is `make_private`: closed, not left as
/// it was.
pub fn share_with_group(dir: &Path, gid: Option<u32>) -> io::Result<Shared> {
    create_private(dir)?;
    let Some(gid) = gid.filter(|g| *g != 0) else {
        make_private(dir)?;
        return Ok(Shared::OwnerOnly);
    };
    // Closed first: between here and the last line an account outside the
    // group sees a directory it cannot enter, whatever it was before.
    keep_bits(dir, 0o700)?;
    if lchgrp(dir, gid).is_err() {
        make_private(dir)?;
        return Ok(Shared::OwnerOnly);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if keep_bits(&path, 0o770).is_ok() {
            let _ = lchgrp(&path, gid);
        }
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2750))?;
    Ok(Shared::WithGroup(gid))
}

/// Clear every permission bit of `path` outside `keep` (set-user-ID,
/// set-group-ID and sticky included). A symbolic link is not touched, and
/// not followed. Returns whether the mode changed.
fn keep_bits(path: &Path, keep: u32) -> io::Result<bool> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(false);
    }
    let mode = meta.mode() & 0o7777;
    let want = mode & keep;
    if mode == want {
        return Ok(false);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(want))?;
    Ok(true)
}

/// Give `path` (not what a link at it points to) to group `gid`, keeping its
/// owner.
fn lchgrp(path: &Path, gid: u32) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has a NUL"))?;
    // uid -1: leave the owner.
    if unsafe { libc::lchown(c.as_ptr(), u32::MAX, gid) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kub0-statedir-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    fn put(p: &Path, m: u32) {
        std::fs::write(p, "x").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// A group this process is in that is not the one its files get by
    /// default, so a change of group is one the test can see.
    fn another_group_of_mine() -> Option<u32> {
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        let mut gids = vec![0 as libc::gid_t; n.max(0) as usize];
        let n = unsafe { libc::getgroups(n, gids.as_mut_ptr()) };
        let egid = unsafe { libc::getegid() };
        gids.truncate(n.max(0) as usize);
        gids.into_iter().find(|g| *g != egid && *g != 0)
    }

    /// The tree a 0.5.1 system install leaves: every directory 0755, the
    /// daemon's records 0644 beside a 0600 history.
    fn as_installed(root: &Path) {
        for d in ["daemon", "execgate", "cgroup-restore"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            std::fs::set_permissions(root.join(d), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for (f, m) in [
            ("daemon/unknown.ndjson", 0o644),
            ("daemon/activity.ndjson", 0o644),
            ("daemon/hosts.json", 0o644),
            ("daemon/history.sqlite", 0o600),
            ("execgate/state.json", 0o644),
            ("execgate/trusted.json", 0o644),
            ("execgate/org-list.json", 0o600),
            ("cgroup-restore/firefox.json", 0o644),
        ] {
            put(&root.join(f), m);
        }
    }

    #[test]
    fn an_open_tree_from_an_earlier_version_is_closed() {
        let root = tmp("closed");
        as_installed(&root);
        assert!(make_private(&root.join("daemon")).unwrap(), "it reports that it changed something");
        assert_eq!(mode(&root.join("daemon")), 0o700);
        for f in ["unknown.ndjson", "activity.ndjson", "hosts.json", "history.sqlite"] {
            assert_eq!(mode(&root.join("daemon").join(f)), 0o600, "{f}");
        }
        assert!(!make_private(&root.join("daemon")).unwrap(), "a second start has nothing to change");
        make_private(&root.join("cgroup-restore")).unwrap();
        assert_eq!((mode(&root.join("cgroup-restore")), mode(&root.join("cgroup-restore/firefox.json"))), (0o700, 0o600));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn without_a_group_the_gate_directory_is_the_owners_alone() {
        for gid in [None, Some(0)] {
            let root = tmp("nogroup");
            as_installed(&root);
            assert_eq!(share_with_group(&root.join("execgate"), gid).unwrap(), Shared::OwnerOnly);
            assert_eq!(mode(&root.join("execgate")), 0o700, "closed, not left 0755");
            assert_eq!(mode(&root.join("execgate/state.json")), 0o600);
            std::fs::remove_dir_all(&root).unwrap();
        }
        // A group this process may not give a file to: the same.
        if unsafe { libc::geteuid() } != 0 {
            let root = tmp("badgroup");
            as_installed(&root);
            assert_eq!(share_with_group(&root.join("execgate"), Some(u32::MAX - 7)).unwrap(), Shared::OwnerOnly);
            assert_eq!(mode(&root.join("execgate")), 0o700);
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn with_a_group_the_gate_directory_is_the_groups_to_read_and_no_one_elses() {
        let Some(gid) = another_group_of_mine() else {
            eprintln!("skipped: this account is in no second group to hand a directory to");
            return;
        };
        let root = tmp("group");
        as_installed(&root);
        let gate = root.join("execgate");
        assert_eq!(share_with_group(&gate, Some(gid)).unwrap(), Shared::WithGroup(gid));
        let m = std::fs::metadata(&gate).unwrap();
        assert_eq!((m.mode() & 0o7777, m.gid()), (0o2750, gid));
        // What was there: no other bits, and the group's.
        let state = std::fs::metadata(gate.join("state.json")).unwrap();
        assert_eq!((state.mode() & 0o7777, state.gid()), (0o640, gid));
        assert_eq!(mode(&gate.join("org-list.json")), 0o600, "a root-only file stays root-only");
        // What is written there afterwards, the way the daemon writes it.
        #[cfg(target_os = "linux")]
        {
            crate::trust::write_atomic(&gate.join("state.json"), b"{}", crate::trust::STATE_FILE_MODE).unwrap();
            let state = std::fs::metadata(gate.join("state.json")).unwrap();
            assert_eq!((state.mode() & 0o7777, state.gid()), (0o640, gid), "a rewritten state.json is still the group's");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_link_in_the_directory_is_not_followed() {
        let root = tmp("link");
        std::fs::create_dir_all(root.join("daemon")).unwrap();
        let outside = root.join("outside");
        put(&outside, 0o644);
        std::os::unix::fs::symlink(&outside, root.join("daemon/hosts.json")).unwrap();
        make_private(&root.join("daemon")).unwrap();
        share_with_group(&root.join("daemon"), None).unwrap();
        assert_eq!(mode(&outside), 0o644, "the file the link points to is not this directory's");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_directory_given_explicitly_is_created_private_and_otherwise_left_alone() {
        let root = tmp("given");
        create_private(&root.join("new")).unwrap();
        assert_eq!(mode(&root.join("new")), 0o700);
        std::fs::set_permissions(root.join("new"), std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private(&root.join("new")).unwrap();
        assert_eq!(mode(&root.join("new")), 0o755, "an existing directory is used as given");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
