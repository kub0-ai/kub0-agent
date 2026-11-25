use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// app-id → set of IP strings that app added via block-ips.
pub type OwnerMap = BTreeMap<String, BTreeSet<String>>;

/// Hold this for the entire nft set and owner-map transaction. A stable
/// sibling survives atomic replacement of endpoint-owners.json. The parent
/// must be controlled by the expected UID so checking the lock file before
/// opening it cannot race with an unprivileged symlink replacement.
pub fn lock(path: &Path, owner: u32) -> Result<File, String> {
    let parent = path.parent().ok_or("owner map has no parent directory")?;
    crate::rename::create_state_dir(parent, 0o755).map_err(|e| format!("create owner directory: {e}"))?;
    let dir = fs::symlink_metadata(parent).map_err(|e| format!("inspect owner directory: {e}"))?;
    if !dir.file_type().is_dir() || dir.uid() != owner || dir.permissions().mode() & 0o022 != 0 {
        return Err("owner directory is not controlled by the helper UID".into());
    }
    let lock_path = path.with_extension("json.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(m)
            if m.file_type().is_file()
                && m.uid() == owner
                && m.permissions().mode() & 0o077 == 0 => {}
        Ok(_) => return Err("unsafe endpoint owner lock file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("inspect endpoint owner lock: {e}")),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| format!("open endpoint owner lock: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("inspect open endpoint owner lock: {e}"))?;
    if !meta.file_type().is_file() || meta.uid() != owner || meta.permissions().mode() & 0o077 != 0
    {
        return Err("unsafe open endpoint owner lock file".into());
    }
    file.lock()
        .map_err(|e| format!("lock endpoint owners: {e}"))?;
    Ok(file)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OwnerFile {
    #[serde(default)]
    apps: BTreeMap<String, Vec<String>>,
}

/// The owner map at `path`. No file is no blocks yet. A file that is there
/// and cannot be read as the map (unreadable, empty, cut short, not this
/// JSON) is an error, never an empty map: the next save would write that
/// emptiness over the only record of who blocked what, and an unblock after
/// it would release an address another app still needs blocked.
pub fn load(path: &Path) -> Result<OwnerMap, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OwnerMap::new()),
        Err(e) => return Err(unusable(path, &e.to_string())),
    };
    // An object, and nothing in it but `apps`: serde would otherwise take
    // `[]`, or a map in some other shape, for a file with no owners in it.
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| unusable(path, &e.to_string()))?;
    if !value.is_object() {
        return Err(unusable(path, "not a JSON object"));
    }
    let parsed: OwnerFile = serde_json::from_value(value).map_err(|e| unusable(path, &e.to_string()))?;
    let mut map = OwnerMap::new();
    for (app, ips) in parsed.apps {
        map.insert(app, ips.into_iter().collect());
    }
    Ok(map)
}

/// What a caller is told when the record is there and unusable. The way out
/// is in the message, because nothing else will lift these blocks.
fn unusable(path: &Path, why: &str) -> String {
    format!(
        "{} cannot be read as the record of which app blocked which address ({why}); nothing was changed. \
         The addresses in it stay blocked. To lift every block and start again: sudo kub0 teardown --yes",
        path.display()
    )
}

/// The mode of the owner map. The panel runs `status` as the user it runs
/// as, and reads this file through it; it holds app ids and the addresses
/// blocked for them.
const OWNER_FILE_MODE: u32 = 0o644;

/// Replace the map at `path`: written beside it, synced, then renamed over
/// it, so a crash leaves the old map or the new one and never a file cut
/// short. The mode is set, not left to the caller's umask.
pub fn save(path: &Path, map: &OwnerMap) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().ok_or("owner map has no parent directory")?;
    crate::rename::create_state_dir(parent, 0o755).map_err(|e| format!("mkdir owners: {e}"))?;
    let mut file = OwnerFile::default();
    for (app, ips) in map {
        file.apps.insert(app.clone(), ips.iter().cloned().collect());
    }
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(OWNER_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(OWNER_FILE_MODE))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("write owners: {e}"));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename owners: {e}"));
    }
    // The rename is what a crash must not lose. The map is already in place,
    // so a directory that cannot be synced is not a failed save.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn grant(map: &mut OwnerMap, app: &str, ips: &[String]) {
    let entry = map.entry(app.to_string()).or_default();
    for ip in ips {
        entry.insert(ip.clone());
    }
}

/// Drop `app` as an owner. Returns IPs that no remaining app owns (safe to
/// delete from the host-wide set) and IPs still held by someone else.
pub fn exclusive_release(map: &mut OwnerMap, app: &str) -> (Vec<String>, Vec<String>) {
    let owned = map.remove(app).unwrap_or_default();
    let mut still: BTreeSet<String> = BTreeSet::new();
    for ips in map.values() {
        still.extend(ips.iter().cloned());
    }
    let mut released = Vec::new();
    let mut retained = Vec::new();
    for ip in owned {
        if still.contains(&ip) {
            retained.push(ip);
        } else {
            released.push(ip);
        }
    }
    (released, retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn release_keeps_shared_ip() {
        let mut map = OwnerMap::new();
        grant(&mut map, "firefox", &["1.2.3.4".into(), "9.9.9.9".into()]);
        grant(&mut map, "chrome", &["1.2.3.4".into()]);
        let (released, retained) = exclusive_release(&mut map, "firefox");
        assert_eq!(released, vec!["9.9.9.9".to_string()]);
        assert_eq!(retained, vec!["1.2.3.4".to_string()]);
        assert!(map.get("chrome").unwrap().contains("1.2.3.4"));
        assert!(!map.contains_key("firefox"));
    }

    #[test]
    fn release_last_owner_drops_all() {
        let mut map = OwnerMap::new();
        grant(&mut map, "spotify", &["193.182.8.20".into()]);
        let (released, retained) = exclusive_release(&mut map, "spotify");
        assert_eq!(released, vec!["193.182.8.20".to_string()]);
        assert!(retained.is_empty());
        assert!(map.is_empty());
    }

    #[test]
    fn roundtrip_file() {
        let dir = std::env::temp_dir().join(format!("vallum-owners-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint-owners.json");
        let mut map = OwnerMap::new();
        grant(&mut map, "firefox", &["8.8.8.8".into()]);
        save(&path, &map).unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.get("firefox").unwrap().contains("8.8.8.8"));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, OWNER_FILE_MODE, "the mode is set, whatever the umask");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn owner_lock_serializes_independent_openers() {
        let dir = std::env::temp_dir().join(format!("vallum-owner-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("endpoint-owners.json");
        let owner = fs::metadata(&dir).unwrap().uid();
        let first = lock(&path, owner).unwrap();
        let (tx, rx) = mpsc::channel();
        let second_path = path.clone();
        let waiter = std::thread::spawn(move || {
            tx.send("waiting").unwrap();
            let _second = lock(&second_path, owner).unwrap();
            tx.send("acquired").unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), "waiting");
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(first);
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), "acquired");
        waiter.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_owner_save_keeps_last_committed_map() {
        let dir = std::env::temp_dir().join(format!("vallum-owner-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint-owners.json");
        let mut old = OwnerMap::new();
        grant(&mut old, "app-a", &["93.184.216.34".into()]);
        save(&path, &old).unwrap();
        fs::create_dir(path.with_extension("json.tmp")).unwrap();
        let mut next = old.clone();
        grant(&mut next, "app-b", &["8.8.8.8".into()]);
        assert!(save(&path, &next).is_err());
        assert_eq!(load(&path).unwrap(), old);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_a_missing_file_is_an_empty_map() {
        let dir = std::env::temp_dir().join(format!("kub0-owner-load-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint-owners.json");
        assert_eq!(load(&path), Ok(OwnerMap::new()), "no file: no blocks yet");
        for damage in ["", "{", "[]", "null", "{\"app-a\": [\"203.0.113.7\"]}", "{\"apps\": {\"app-a\": [\"203.0.113.7\""] {
            fs::write(&path, damage).unwrap();
            let e = load(&path).expect_err(damage);
            assert!(e.contains("sudo kub0 teardown --yes") && e.contains("nothing was changed"), "{e}");
        }
        // Something there that is not a file at all: unreadable, not absent.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(load(&path).is_err(), "a path that cannot be read is not an empty map");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_save_does_not_follow_a_link_left_at_its_temporary_name() {
        let dir = std::env::temp_dir().join(format!("kub0-owner-tmp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint-owners.json");
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, "untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, path.with_extension("json.tmp")).unwrap();
        let mut map = OwnerMap::new();
        grant(&mut map, "app-a", &["203.0.113.7".into()]);
        assert!(save(&path, &map).is_err());
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "untouched");
        fs::remove_dir_all(dir).unwrap();
    }
}
