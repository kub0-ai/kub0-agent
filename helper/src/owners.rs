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
struct OwnerFile {
    #[serde(default)]
    apps: BTreeMap<String, Vec<String>>,
}

pub fn load(path: &Path) -> OwnerMap {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let parsed: OwnerFile = serde_json::from_str(&text).unwrap_or_default();
    let mut map = OwnerMap::new();
    for (app, ips) in parsed.apps {
        map.insert(app, ips.into_iter().collect());
    }
    map
}

pub fn save(path: &Path, map: &OwnerMap) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        crate::rename::create_state_dir(parent, 0o755).map_err(|e| format!("mkdir owners: {e}"))?;
    }
    let mut file = OwnerFile::default();
    for (app, ips) in map {
        file.apps.insert(app.clone(), ips.iter().cloned().collect());
    }
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write owners: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename owners: {e}"))
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
        let loaded = load(&path);
        assert!(loaded.get("firefox").unwrap().contains("8.8.8.8"));
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
        assert_eq!(load(&path), old);
        fs::remove_dir_all(dir).unwrap();
    }
}
