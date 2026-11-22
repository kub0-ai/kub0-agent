//! Timed app/destination rules. Expiry is enforced by nftables, not a UI timer.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

/// The scoped (timed destination) records, under the state directory in use.
pub fn directory() -> PathBuf {
    crate::rename::state_path("scoped")
}
pub const COMMENT: &str = "vallum-scoped";
pub const MAX_RULES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub app: String,
    pub uid: u32,
    pub ip: IpAddr,
    pub expires_at: u64,
    pub group: String,
}
impl Rule {
    pub fn new(app: &str, uid: u32, ip: &str, seconds: u32, now: u64) -> Result<Self, String> {
        let app = crate::ids::sanitize_app(app)?;
        if uid == 0 || !(1..=86400).contains(&seconds) {
            return Err("rules require an unprivileged owner and duration 1..86400 seconds".into());
        }
        let ip: IpAddr = ip
            .parse()
            .map_err(|_| "destination must be a literal IPv4 or IPv6 address")?;
        if ip.is_unspecified() || ip.is_multicast() {
            return Err("destination must be a unicast address".into());
        }
        // Reversible encoding avoids truncation, hash collisions and cross-UID groups.
        let group = format!(
            "__vallum_scoped_{uid}_{}",
            app.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            app,
            uid,
            ip,
            expires_at: now
                .checked_add(u64::from(seconds) * 1000)
                .ok_or("invalid expiry")?,
            group,
        })
    }
    pub fn set(&self) -> String {
        format!("t{}_{}", if self.ip.is_ipv4() { 4 } else { 6 }, self.group)
    }
    pub fn path(&self) -> String {
        format!("vallum.slice/vallum-{}", self.group)
    }
    pub fn family(&self) -> &'static str {
        if self.ip.is_ipv4() {
            "ip"
        } else {
            "ip6"
        }
    }
    pub fn same_target(&self, other: &Self) -> bool {
        self.uid == other.uid && self.app == other.app && self.ip == other.ip
    }
    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::new(&self.app, self.uid, &self.ip.to_string(), 1, 0)?;
        if expected.group != self.group {
            return Err("invalid scoped group".into());
        }
        Ok(())
    }
}

fn state_dir() -> Result<PathBuf, String> {
    let p = directory();
    if unsafe { libc::geteuid() } == 0 {
        crate::rename::create_state_dir(&p, 0o755).map_err(|e| e.to_string())?;
    }
    for parent in p.ancestors() {
        let m = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe scoped state directory".into());
        }
    }
    Ok(p)
}
pub fn load(uid: u32) -> Result<Vec<Rule>, String> {
    let dir = match state_dir() {
        Ok(d) => d,
        Err(_) if !directory().exists() => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let p = dir.join(format!("{uid}.json"));
    let m = match fs::symlink_metadata(&p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o027 != 0 || m.len() > 256 * 1024 {
        return Err("unsafe scoped state file".into());
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|e| e.to_string())?;
    let rows: Vec<Rule> = serde_json::from_reader(f).map_err(|e| e.to_string())?;
    if rows.len() > MAX_RULES {
        return Err("scoped rule limit exceeded".into());
    }
    for r in &rows {
        r.validate()?;
        if r.uid != uid {
            return Err("scoped owner mismatch".into());
        }
    }
    Ok(rows)
}
pub fn clear_all() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 { return Err("scoped cleanup requires root".into()); }
    let dir = state_dir()?;
    for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
        let Some(uid) = path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u32>().ok()).filter(|u| *u != 0) else { continue; };
        load(uid)?; // validate root ownership, schema and UID before removing
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn save(uid: u32, rules: &[Rule]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || uid == 0 || rules.len() > MAX_RULES {
        return Err("invalid scoped write".into());
    }
    for r in rules {
        r.validate()?;
        if r.uid != uid {
            return Err("scoped owner mismatch".into());
        }
    }
    let dir = state_dir()?;
    let tmp = dir.join(format!(".{uid}.{}.tmp", std::process::id()));
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        serde_json::to_writer(&f, rules).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            return Err("unknown scoped owner".into());
        }
        use std::os::fd::AsRawFd;
        if unsafe { libc::fchown(f.as_raw_fd(), 0, (*pw).pw_gid) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        f.set_permissions(fs::Permissions::from_mode(0o640))
            .map_err(|e| e.to_string())?;
        fs::rename(&tmp, dir.join(format!("{uid}.json"))).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub struct Lock(fs::File);
impl Lock {
    pub fn acquire() -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        let p = state_dir()?.join("mutation.lock");
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p)
            .map_err(|e| e.to_string())?;
        let m = f.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Err("unsafe enforcement lock".into());
        }
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another enforcement change is in progress; retry".into());
        }
        Ok(Self(f))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rules_are_literal_bounded_and_owned() {
        let r = Rule::new("Firefox", 1000, "2001:db8::1", 900, 1000).unwrap();
        assert_eq!(r.expires_at, 901000);
        assert_eq!(r.family(), "ip6");
        r.validate().unwrap();
        assert_ne!(
            r.group,
            Rule::new("Firefox", 1001, "2001:db8::1", 900, 0)
                .unwrap()
                .group
        );
        for ip in [
            "example.com",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "127.0.0.1; drop",
        ] {
            assert!(Rule::new("Firefox", 1000, ip, 900, 0).is_err());
        }
        for s in [0, 86401] {
            assert!(Rule::new("Firefox", 1000, "127.0.0.1", s, 0).is_err());
        }
        assert!(Rule::new("system", 1000, "127.0.0.1", 1, 0).is_err());
        assert!(Rule::new("Firefox", 0, "127.0.0.1", 1, 0).is_err());
    }
}
