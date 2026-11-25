use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePid {
    pub cgroup: String,
    pub uid: u32,
    pub starttime: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreFile {
    #[serde(default)]
    pub pids: BTreeMap<String, RestorePid>,
}

pub fn parse_unified_cgroup(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.to_string());
        }
    }
    None
}

pub fn is_root_cgroup(path: &str) -> bool {
    let p = path.trim();
    p.is_empty() || p == "/"
}

pub fn sys_path(cgroup_root: &Path, rel: &str) -> PathBuf {
    let rel = rel.trim_start_matches('/');
    cgroup_root.join(rel)
}

/// The cgroup restore records, under the state directory in use.
pub fn restore_dir() -> PathBuf {
    crate::rename::state_path("cgroup-restore")
}

pub fn path_for(app: &str) -> PathBuf {
    restore_dir().join(format!("{app}.json"))
}

pub fn load(path: &Path) -> RestoreFile {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    // Old files stored bare cgroup strings. Fail closed instead of restoring
    // a PID without uid/starttime.
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save(path: &Path, file: &RestoreFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.is_dir() {
            // The state root is made 0755 on the way. These records name
            // processes, their owners and their cgroups, and only root's
            // helper reads them: the directory is root's alone.
            use std::os::unix::fs::PermissionsExt;
            crate::rename::create_state_dir(parent, 0o755).map_err(|e| format!("mkdir restore: {e}"))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("close restore: {e}"))?;
        }
    }
    let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write restore: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename restore: {e}"))
}

/// nft `socket cgroupv2 level N` — N is the number of path components
/// under the cgroup root (`vallum.slice/vallum-app` → 2).
pub fn cgroup_match_level(rel: &str) -> u32 {
    let n = rel
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .count();
    n.max(1) as u32
}

pub fn membership_matches(current: &str, original: &str) -> bool {
    let cur = current.trim();
    let orig = original.trim();
    if orig.is_empty() {
        return false;
    }
    cur == orig || cur.ends_with(orig) || orig.ends_with(cur)
}

/// Where a process that was never recorded should go on unblock.
///
/// Blocking records the processes it moved. Anything they fork afterwards is
/// born inside the blocked cgroup and has no record: a browser opening a tab,
/// an Electron app starting a helper. Those stragglers keep the cgroup busy,
/// so it cannot be removed. Their natural home is wherever their nearest
/// ancestor outside vallum's cgroup lives now, which after a restore is where
/// the recorded parent went back to.
///
/// `ppid` maps pid -> parent pid and `cgroup` maps pid -> its current cgroup
/// path, both from one read of /proc. Returns None if no ancestor has left.
pub fn straggler_home(
    pid: u32,
    ppid: &std::collections::HashMap<u32, u32>,
    cgroup: &std::collections::HashMap<u32, String>,
    blocked_prefix: &str,
) -> Option<String> {
    let mut cur = pid;
    // Bounded: a pid table is not a cycle, but a racy read of one might be.
    for _ in 0..64 {
        let parent = *ppid.get(&cur)?;
        if parent <= 1 {
            return None;
        }
        if let Some(cg) = cgroup.get(&parent) {
            let rel = cg.trim_start_matches('/');
            if !is_root_cgroup(cg) && !in_slice(rel, blocked_prefix) {
                return Some(cg.clone());
            }
        }
        cur = parent;
    }
    None
}

/// Whether a /proc cgroup path is vallum's own slice or inside it.
pub fn in_slice(cgroup: &str, slice: &str) -> bool {
    let rel = cgroup.trim_start_matches('/');
    let slice = slice.trim_matches('/');
    rel == slice || rel.starts_with(&format!("{slice}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_line() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope\n";
        assert_eq!(
            parse_unified_cgroup(text).unwrap(),
            "/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope"
        );
    }

    #[test]
    fn rejects_root() {
        assert!(is_root_cgroup(""));
        assert!(is_root_cgroup("/"));
        assert!(!is_root_cgroup("/user.slice"));
    }

    #[test]
    fn match_level_from_path() {
        assert_eq!(cgroup_match_level("vallum.slice/vallum-firefox"), 2);
        assert_eq!(cgroup_match_level("/vallum.slice/vallum-firefox/"), 2);
        assert_eq!(cgroup_match_level("a/b/c"), 3);
    }

    #[test]
    fn membership_compare() {
        let orig = "/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope";
        assert!(membership_matches(orig, orig));
        assert!(!membership_matches("/vallum.slice/vallum-firefox", orig));
    }

    #[test]
    fn straggler_goes_where_its_nearest_escaped_ancestor_lives() {
        use std::collections::HashMap;
        // 100 (restored, back in app.slice) -> 200 (forked while blocked) -> 300
        let ppid: HashMap<u32, u32> = [(300, 200), (200, 100), (100, 50), (50, 1)].into();
        let cgroup: HashMap<u32, String> = [
            (300, "/vallum.slice/vallum-firefox".to_string()),
            (200, "/vallum.slice/vallum-firefox".to_string()),
            (100, "/user.slice/app.slice/app-firefox.scope".to_string()),
            (50, "/user.slice/session.scope".to_string()),
        ]
        .into();
        let home = straggler_home(300, &ppid, &cgroup, "vallum.slice");
        assert_eq!(home.as_deref(), Some("/user.slice/app.slice/app-firefox.scope"));
    }

    #[test]
    fn straggler_with_no_escaped_ancestor_has_no_home() {
        use std::collections::HashMap;
        let ppid: HashMap<u32, u32> = [(300, 200), (200, 1)].into();
        let cgroup: HashMap<u32, String> =
            [(300, "/vallum.slice/vallum-x".to_string()), (200, "/vallum.slice/vallum-x".to_string())].into();
        assert_eq!(straggler_home(300, &ppid, &cgroup, "vallum.slice"), None);
        // Never the root cgroup, and never pid 1's.
        let ppid: HashMap<u32, u32> = [(300, 2), (2, 1)].into();
        let cgroup: HashMap<u32, String> = [(2, "/".to_string())].into();
        assert_eq!(straggler_home(300, &ppid, &cgroup, "vallum.slice"), None);
    }

    #[test]
    fn in_slice_matches_the_slice_and_its_children_only() {
        assert!(in_slice("/vallum.slice/vallum-firefox", "vallum.slice"));
        assert!(in_slice("/vallum.slice", "vallum.slice"));
        assert!(!in_slice("/vallum.slice-other/x", "vallum.slice"));
        assert!(!in_slice("/user.slice/app.slice/app-firefox.scope", "vallum.slice"));
    }
}
