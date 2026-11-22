use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeenEntry {
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeenFile {
    #[serde(default)]
    pub networks: HashMap<String, SeenEntry>,
}

/// How long a `last_seen`-only change may wait before it reaches disk.
///
/// Nothing reads `last_seen` back. The set exists to answer "has this prefix
/// ever been seen", which only `first_seen` (the key's presence) decides. Yet
/// every new connection to a known /24 bumped it, and the 5 s checkpoint then
/// rewrote the whole file: ~1,100 prefixes, 113 KB pretty-printed, 605 times
/// in an hour on a live laptop, one per checkpoint. A new prefix
/// still reaches disk at the next checkpoint, because losing one to a crash
/// would replay its new-network pulse after restart.
pub const TOUCH_FLUSH_INTERVAL: Duration = Duration::from_secs(15 * 60);

pub struct SeenSet {
    path: PathBuf,
    data: SeenFile,
    /// A prefix was added since the last write.
    dirty: bool,
    /// Only `last_seen` moved since the last write.
    touched: bool,
    last_write: Instant,
}

impl SeenSet {
    pub fn load(state_dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(state_dir);
        let path = state_dir.join("hosts.json");
        let data = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path,
            data,
            dirty: false,
            touched: false,
            last_write: Instant::now(),
        }
    }

    /// Record a network. Returns true if this prefix has never been seen.
    /// Port 53 callers should still record but skip the bar pulse themselves.
    pub fn observe(&mut self, key: &str, now: u64) -> bool {
        if key.is_empty() {
            return false;
        }
        match self.data.networks.get_mut(key) {
            Some(e) => {
                if e.last_seen != now {
                    e.last_seen = now;
                    self.touched = true;
                }
                false
            }
            None => {
                self.data.networks.insert(
                    key.to_string(),
                    SeenEntry {
                        first_seen: now,
                        last_seen: now,
                    },
                );
                self.dirty = true;
                true
            }
        }
    }

    /// Checkpoint: write when a prefix was added, or when `last_seen` bumps
    /// have waited [`TOUCH_FLUSH_INTERVAL`]. Called every few seconds.
    pub fn flush(&mut self) {
        self.flush_at(Instant::now());
    }

    pub fn flush_at(&mut self, now: Instant) {
        let due = self.touched && now.saturating_duration_since(self.last_write) >= TOUCH_FLUSH_INTERVAL;
        if self.dirty || due {
            self.write();
        }
    }

    /// Write now if anything at all changed, `last_seen` included.
    pub fn flush_all(&mut self) {
        if self.dirty || self.touched {
            self.write();
        }
    }

    fn write(&mut self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Compact: nobody reads this file but the daemon, and pretty-printing
        // made it a third larger.
        if let Ok(text) = serde_json::to_string(&self.data) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
        self.dirty = false;
        self.touched = false;
        self.last_write = Instant::now();
    }

    pub fn contains(&self, key: &str) -> bool {
        self.data.networks.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.data.networks.len()
    }
}

/// /24 for IPv4, /48 for IPv6. Mapped v4 is treated as v4.
pub fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return network_key(IpAddr::V4(v4));
            }
            let s = v.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_slash24() {
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 14))),
            "142.250.190.0/24"
        );
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 99))),
            "142.250.190.0/24"
        );
    }

    #[test]
    fn v6_slash48() {
        let ip: Ipv6Addr = "2001:db8:abcd:12::1".parse().unwrap();
        assert_eq!(network_key(IpAddr::V6(ip)), "2001:db8:abcd::/48");
        let ip2: Ipv6Addr = "2001:db8:abcd:99::ffff".parse().unwrap();
        assert_eq!(network_key(IpAddr::V6(ip2)), "2001:db8:abcd::/48");
    }

    #[test]
    fn mapped_v4_uses_slash24() {
        let mapped = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped();
        assert_eq!(network_key(IpAddr::V6(mapped)), "8.8.8.0/24");
    }

    #[test]
    fn observe_is_new_then_old() {
        let dir = std::env::temp_dir().join(format!("vallum-seen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut set = SeenSet::load(&dir);
        assert!(set.observe("1.2.3.0/24", 1000));
        assert!(!set.observe("1.2.3.0/24", 2000));
        set.flush();
        let set2 = SeenSet::load(&dir);
        assert!(set2.contains("1.2.3.0/24"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vallum-seen-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn on_disk(dir: &Path) -> SeenFile {
        serde_json::from_str(&std::fs::read_to_string(dir.join("hosts.json")).unwrap()).unwrap()
    }

    #[test]
    fn a_last_seen_bump_alone_does_not_rewrite_the_file() {
        let dir = scratch("touch");
        let mut set = SeenSet::load(&dir);
        assert!(set.observe("1.2.3.0/24", 1000));
        set.flush();
        let written = std::fs::read(dir.join("hosts.json")).unwrap();
        // The checkpoint runs every 5 s; a known prefix seen again must not
        // make every one of them rewrite the whole set.
        assert!(!set.observe("1.2.3.0/24", 2000));
        set.flush();
        assert_eq!(std::fs::read(dir.join("hosts.json")).unwrap(), written);
        // Positive control: the bump is held, not lost.
        set.flush_at(Instant::now() + TOUCH_FLUSH_INTERVAL);
        assert_eq!(on_disk(&dir).networks["1.2.3.0/24"].last_seen, 2000);
        assert_eq!(on_disk(&dir).networks["1.2.3.0/24"].first_seen, 1000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_prefix_reaches_disk_at_the_next_checkpoint() {
        let dir = scratch("new");
        let mut set = SeenSet::load(&dir);
        assert!(set.observe("1.2.3.0/24", 1000));
        set.flush();
        assert!(!set.observe("1.2.3.0/24", 2000));
        assert!(set.observe("5.6.7.0/24", 3000));
        set.flush();
        let disk = on_disk(&dir);
        assert!(disk.networks.contains_key("5.6.7.0/24"));
        // The bump rode along with the forced write.
        assert_eq!(disk.networks["1.2.3.0/24"].last_seen, 2000);
        // After restart a written prefix is not new again: no repeat pulse.
        let mut reloaded = SeenSet::load(&dir);
        assert!(!reloaded.observe("5.6.7.0/24", 4000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_all_writes_held_bumps_and_the_file_is_compact() {
        let dir = scratch("all");
        let mut set = SeenSet::load(&dir);
        set.observe("1.2.3.0/24", 1000);
        set.flush();
        set.observe("1.2.3.0/24", 2000);
        set.flush_all();
        let text = std::fs::read_to_string(dir.join("hosts.json")).unwrap();
        assert!(!text.contains('\n'), "hosts.json should be compact JSON");
        assert_eq!(on_disk(&dir).networks["1.2.3.0/24"].last_seen, 2000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pretty_printed_file_from_an_older_daemon_still_loads() {
        let dir = scratch("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("hosts.json"),
            "{\n  \"networks\": {\n    \"9.9.9.0/24\": {\n      \"first_seen\": 1,\n      \"last_seen\": 2\n    }\n  }\n}",
        )
        .unwrap();
        let set = SeenSet::load(&dir);
        assert!(set.contains("9.9.9.0/24"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cdn_rotation_same_prefix() {
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1))),
            network_key(IpAddr::V4(Ipv4Addr::new(104, 16, 1, 50)))
        );
    }
}
