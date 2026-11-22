//! Root-written, per-app cgroup block markers for unprivileged status reads.
//!
//! nftables cannot be listed by the panel's UID. Markers are persisted state,
//! not proof that a kernel rule is still present; privileged status uses nft.
//! One file per app and boot avoids lost updates from concurrent helper
//! processes and prevents a reboot from reviving a rule nftables no longer has.

use crate::ids::sanitize_app;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The cgroup block markers, under the state directory in use
/// (`rename::state_root`).
pub fn marker_dir() -> PathBuf {
    crate::rename::state_path("cgroup-blocks")
}

fn boot_id() -> Result<String, String> {
    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| format!("read current boot id: {e}"))?;
    let id = id.trim();
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid current boot id".into());
    }
    Ok(id.to_ascii_lowercase())
}

fn secure_dir(path: &Path, owner: u32, create: bool) -> Result<bool, String> {
    if create {
        // An explicit mode: the umask can only clear bits, so a permissive umask
        // (Ubuntu's user-private-group 002) cannot leave the directory group-writable
        // and fail the check below.
        crate::rename::create_state_dir(path, 0o755).map_err(|e| format!("create block marker directory: {e}"))?;
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound && !create => return Ok(false),
        Err(e) => return Err(format!("inspect block marker directory: {e}")),
    };
    if !meta.file_type().is_dir() || meta.uid() != owner || meta.permissions().mode() & 0o022 != 0 {
        return Err("block marker directory is not a private, owner-controlled directory".into());
    }
    if create {
        // pkexec can run with a restrictive umask. Status runs as the panel's
        // ordinary UID, so it needs directory read/search permission.
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("make block markers readable: {e}"))?;
    }
    Ok(true)
}

fn marker_path(dir: &Path, app: &str, boot: &str) -> Result<PathBuf, String> {
    let app = sanitize_app(app)?;
    Ok(dir.join(format!("{app}.{boot}.block")))
}

fn initialized_path(dir: &Path, boot: &str) -> PathBuf {
    dir.join(format!(".initialized.{boot}"))
}

fn marker_is_regular(path: &Path, owner: u32) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() && m.uid() == owner => Ok(true),
        Ok(_) => Err(format!("unsafe block marker {}", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("inspect block marker {}: {e}", path.display())),
    }
}

fn create_regular(path: &Path, owner: u32) -> Result<(), String> {
    if marker_is_regular(&path, owner)? {
        return Ok(());
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            marker_is_regular(&path, owner).and_then(|regular| {
                if regular {
                    Ok(())
                } else {
                    Err("block marker disappeared during create".into())
                }
            })
        }
        Err(e) => Err(format!("create block marker {}: {e}", path.display())),
    }
}

fn initialize_at(dir: &Path, owner: u32, boot: &str) -> Result<(), String> {
    secure_dir(dir, owner, true)?;
    create_regular(&initialized_path(dir, boot), owner)
}

fn mark_at(dir: &Path, app: &str, owner: u32, boot: &str) -> Result<(), String> {
    initialize_at(dir, owner, boot)?;
    create_regular(&marker_path(dir, app, boot)?, owner)
}

fn unmark_at(dir: &Path, app: &str, owner: u32, boot: &str) -> Result<(), String> {
    if !secure_dir(dir, owner, false)? {
        return Ok(());
    }
    let path = marker_path(dir, app, boot)?;
    if !marker_is_regular(&path, owner)? {
        return Ok(());
    }
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove block marker {}: {e}", path.display())),
    }
}

fn list_at(dir: &Path, owner: u32, boot: &str) -> Result<Vec<String>, String> {
    if !secure_dir(dir, owner, false)? {
        return Ok(Vec::new());
    }
    let mut apps = Vec::new();
    let suffix = format!(".{boot}.block");
    let entries = fs::read_dir(dir).map_err(|e| format!("read block markers: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read block marker: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(app) = name.strip_suffix(&suffix) else {
            continue;
        };
        if sanitize_app(app).ok().as_deref() != Some(app) {
            continue;
        }
        if marker_is_regular(&entry.path(), owner)? {
            apps.push(app.to_string());
        }
    }
    apps.sort();
    Ok(apps)
}

pub fn mark(app: &str) -> Result<(), String> {
    mark_at(&marker_dir(), app, 0, &boot_id()?)
}

pub fn initialize() -> Result<(), String> {
    initialize_at(&marker_dir(), 0, &boot_id()?)
}

pub fn unmark(app: &str) -> Result<(), String> {
    unmark_at(&marker_dir(), app, 0, &boot_id()?)
}

pub fn list() -> Result<Vec<String>, String> {
    list_at(&marker_dir(), 0, &boot_id()?)
}

/// False on an upgraded host that has not yet had a privileged status/block
/// call. An empty list on such a host is unknown, not an authoritative zero.
pub fn initialized() -> Result<bool, String> {
    let dir = &marker_dir();
    if !secure_dir(dir, 0, false)? {
        return Ok(false);
    }
    marker_is_regular(&initialized_path(dir, &boot_id()?), 0)
}

pub fn clear_all() -> Result<(), String> {
    for app in list()? {
        unmark(&app)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
    const OLD_BOOT: &str = "87654321-4321-4321-4321-cba987654321";

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kub0-block-markers-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    // Explicit mode, like secure_dir: the tests must pass under any umask.
    fn create_private(dir: &Path) {
        fs::DirBuilder::new().mode(0o755).create(dir).unwrap();
    }

    #[test]
    fn per_app_markers_roundtrip_and_do_not_overwrite_each_other() {
        let dir = test_dir();
        // The test process may not own /tmp, so derive its UID from a new dir.
        create_private(&dir);
        let uid = fs::metadata(&dir).unwrap().uid();
        mark_at(&dir, "Firefox", uid, BOOT).unwrap();
        mark_at(&dir, "discord", uid, BOOT).unwrap();
        mark_at(&dir, "firefox", uid, BOOT).unwrap();
        assert_eq!(list_at(&dir, uid, BOOT).unwrap(), ["discord", "firefox"]);
        unmark_at(&dir, "firefox", uid, BOOT).unwrap();
        assert_eq!(list_at(&dir, uid, BOOT).unwrap(), ["discord"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prior_boot_and_legacy_markers_cannot_reappear_after_reboot() {
        let dir = test_dir();
        create_private(&dir);
        let uid = fs::metadata(&dir).unwrap().uid();
        mark_at(&dir, "firefox", uid, OLD_BOOT).unwrap();
        fs::write(dir.join("legacy.block"), b"").unwrap();
        assert!(list_at(&dir, uid, BOOT).unwrap().is_empty());
        assert!(!marker_is_regular(&initialized_path(&dir, BOOT), uid).unwrap());
        mark_at(&dir, "discord", uid, BOOT).unwrap();
        assert_eq!(list_at(&dir, uid, BOOT).unwrap(), ["discord"]);
        assert!(marker_is_regular(&initialized_path(&dir, BOOT), uid).unwrap());
        unmark_at(&dir, "discord", uid, BOOT).unwrap();
        assert!(list_at(&dir, uid, BOOT).unwrap().is_empty());
        assert!(marker_is_regular(&initialized_path(&dir, BOOT), uid).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_symlink_marker_and_directory() {
        let dir = test_dir();
        create_private(&dir);
        let uid = fs::metadata(&dir).unwrap().uid();
        std::os::unix::fs::symlink("/tmp", marker_path(&dir, "firefox", BOOT).unwrap()).unwrap();
        assert!(mark_at(&dir, "firefox", uid, BOOT).is_err());
        assert!(list_at(&dir, uid, BOOT).is_err());
        fs::remove_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/tmp", &dir).unwrap();
        assert!(mark_at(&dir, "firefox", uid, BOOT).is_err());
        fs::remove_file(dir).unwrap();
    }

    #[test]
    fn missing_directory_is_unknown_until_initialized_and_writable_directory_is_rejected() {
        let parent = test_dir();
        create_private(&parent);
        let uid = fs::metadata(&parent).unwrap().uid();
        let dir = parent.join("markers");
        assert!(!secure_dir(&dir, uid, false).unwrap());
        assert!(list_at(&dir, uid, BOOT).unwrap().is_empty());
        mark_at(&dir, "firefox", uid, BOOT).unwrap();
        assert!(secure_dir(&dir, uid, false).unwrap());
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(list_at(&dir, uid, BOOT).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
}
