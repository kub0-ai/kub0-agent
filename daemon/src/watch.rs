//! User-authored watch rules: "tell me when anything reaches X".
//!
//! A watch rule is the one indicator the user writes themselves, which is why
//! a hit is `warning` whatever the destination looks like: the user has
//! already decided it matters. Rules live in `<state_dir>/watchlist.json` and
//! can be edited from the panel, from `kub0 watch`, or by hand; the daemon
//! re-reads the file when its modification time changes, so all three agree
//! without a restart.
//!
//! Nothing here leaves the machine. Hits are recorded in the local activity
//! log and shown on the row; they are not reported on the heartbeat.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const MAX_RULES: usize = 256;
pub const NOTE_MAX: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    /// An autonomous system number.
    Asn,
    /// ISO 3166-1 alpha-2.
    Country,
    /// An address or a CIDR range.
    Cidr,
    /// A PTR name or a suffix of one (`example.com` matches `cdn.example.com`).
    Host,
    /// A remote port.
    Port,
    /// An app id or executable path.
    App,
}

impl RuleKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "asn" => Some(Self::Asn),
            "country" => Some(Self::Country),
            "cidr" | "ip" | "net" | "network" => Some(Self::Cidr),
            "host" | "hostname" | "domain" => Some(Self::Host),
            "port" => Some(Self::Port),
            "app" | "exe" => Some(Self::App),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asn => "asn",
            Self::Country => "country",
            Self::Cidr => "cidr",
            Self::Host => "host",
            Self::Port => "port",
            Self::App => "app",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Derived from kind and value, so adding the same rule twice is one rule.
    pub id: String,
    pub kind: RuleKind,
    /// Normalised: ASN digits, upper-case country, canonical CIDR, lower-case host.
    pub value: String,
    #[serde(default)]
    pub note: String,
    /// Milliseconds since the epoch when the rule was written.
    pub ts: u64,
    /// Matches since the rule was written. Persisted so a restart does not
    /// reset the count the user is looking at.
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub last_hit: u64,
    /// The uid that set the rule through the system daemon's command socket,
    /// which its group shares: a member changes only the rules it set. Absent
    /// for root's, the user daemon's and hand-written rules; only root (or a
    /// user daemon's owner) changes those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<u32>,
    /// Parsed once for `Cidr`; never on the wire or on disk.
    #[serde(skip)]
    net: Option<(IpAddr, u8)>,
}

impl Rule {
    /// Build a rule from user input, normalising the value or refusing it.
    pub fn new(kind: RuleKind, value: &str, note: &str, ts: u64) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err("value must be 1..256 characters".into());
        }
        let value = match kind {
            RuleKind::Asn => value
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .map(|n| n.to_string())
                .map_err(|_| format!("{value} is not an ASN"))?,
            RuleKind::Country => {
                let v = value.to_ascii_uppercase();
                if v.len() != 2 || !v.chars().all(|c| c.is_ascii_uppercase()) {
                    return Err(format!("{value} is not a two-letter country code"));
                }
                v
            }
            RuleKind::Cidr => {
                let (net, bits) = parse_cidr(value)?;
                format!("{net}/{bits}")
            }
            RuleKind::Host => {
                let v = value.trim_matches('.').to_ascii_lowercase();
                if v.is_empty() || v.contains(char::is_whitespace) || !v.contains('.') {
                    return Err(format!("{value} is not a hostname or domain"));
                }
                v
            }
            RuleKind::Port => value
                .parse::<u16>()
                .map(|n| n.to_string())
                .map_err(|_| format!("{value} is not a port"))?,
            RuleKind::App => value.to_string(),
        };
        let note: String = note.chars().take(NOTE_MAX).collect();
        let mut h = DefaultHasher::new();
        (kind.as_str(), value.as_str()).hash(&mut h);
        let mut r = Rule {
            id: format!("w-{:08x}", h.finish() as u32),
            kind,
            value,
            note,
            ts,
            hits: 0,
            last_hit: 0,
            owner: None,
            net: None,
        };
        r.prepare();
        Ok(r)
    }

    /// Fill the parsed form after construction or a load from disk.
    pub fn prepare(&mut self) {
        self.net = match self.kind {
            RuleKind::Cidr => parse_cidr(&self.value).ok(),
            _ => None,
        };
    }

    /// In the user's words, for the indicator basis.
    pub fn describe(&self) -> String {
        let what = match self.kind {
            RuleKind::Asn => format!("AS{}", self.value),
            RuleKind::Country => format!("country {}", self.value),
            RuleKind::Cidr => format!("network {}", self.value),
            RuleKind::Host => format!("host *.{}", self.value),
            RuleKind::Port => format!("port {}", self.value),
            RuleKind::App => format!("app {}", self.value),
        };
        if self.note.is_empty() {
            what
        } else {
            format!("{what} ({})", self.note)
        }
    }

    pub fn matches(&self, m: &Match<'_>) -> bool {
        match self.kind {
            RuleKind::Asn => m.asn.is_some_and(|a| a.to_string() == self.value),
            RuleKind::Country => !self.value.is_empty() && m.country == self.value,
            RuleKind::Cidr => {
                let Some(ip) = m.remote else { return false };
                let Some((net, bits)) = self.net.or_else(|| parse_cidr(&self.value).ok()) else { return false };
                in_cidr(ip, net, bits)
            }
            RuleKind::Host => {
                if m.hostname.is_empty() {
                    return false;
                }
                let h = m.hostname.to_ascii_lowercase();
                let v = self.value.as_str();
                h == v || (h.len() > v.len() && h.ends_with(v) && h.as_bytes()[h.len() - v.len() - 1] == b'.')
            }
            RuleKind::Port => m.port.to_string() == self.value,
            RuleKind::App => m.app_id == self.value || m.exe == self.value,
        }
    }
}

/// What a rule is matched against.
pub struct Match<'a> {
    pub remote: Option<IpAddr>,
    pub port: u16,
    pub hostname: &'a str,
    pub asn: Option<u32>,
    pub country: &'a str,
    pub app_id: &'a str,
    pub exe: &'a str,
}

pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr, bits) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| format!("{s} is not an address or CIDR range"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        Some(b) => b
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|b| *b <= max)
            .ok_or_else(|| format!("{s} has an invalid prefix length"))?,
        None => max,
    };
    Ok((mask(ip, bits), bits))
}

fn mask(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) };
            IpAddr::V4((n & m).into())
        }
        IpAddr::V6(v) => {
            let n = u128::from(v);
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) };
            IpAddr::V6((n & m).into())
        }
    }
}

pub fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => mask(ip, bits) == net,
        // A v4-mapped v6 address against a v4 rule.
        (IpAddr::V6(v6), IpAddr::V4(_)) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| mask(IpAddr::V4(v4), bits) == net),
        _ => false,
    }
}

/// `<state_dir>/watchlist.json`, re-read when it changes on disk.
pub struct WatchStore {
    path: PathBuf,
    rules: Vec<Rule>,
    loaded_mtime: Option<SystemTime>,
    dirty: bool,
    /// Something a client would want to see moved: a rule, or a hit count.
    changed: bool,
    /// Rules set or replaced in memory since the last successful save. If the
    /// file changes underneath before they are written, they are kept, not
    /// discarded with the rest of memory's membership.
    unsaved: Vec<Rule>,
}

impl WatchStore {
    pub fn load(state_dir: &Path) -> Self {
        let mut s = Self {
            path: state_dir.join("watchlist.json"),
            rules: Vec::new(),
            loaded_mtime: None,
            dirty: false,
            changed: false,
            unsaved: Vec::new(),
        };
        s.reload();
        s
    }

    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            rules: Vec::new(),
            loaded_mtime: None,
            dirty: false,
            changed: false,
            unsaved: Vec::new(),
        }
    }

    fn reload(&mut self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let meta = std::fs::metadata(&self.path).ok();
        self.loaded_mtime = meta.as_ref().and_then(|m| m.modified().ok());
        let rules: Vec<Rule> = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        self.rules = rules.into_iter().take(MAX_RULES).collect();
        for r in &mut self.rules {
            r.prepare();
        }
    }

    /// Pick up an edit made by the CLI or by hand. Returns true if the rule
    /// list changed.
    ///
    /// The file is read *before* any pending in-memory write: a hit count
    /// bumped here and a rule added from the terminal must both survive, so
    /// the disk's rules win on membership and memory's counts are carried
    /// over by id, then the merged list is written once.
    pub fn refresh(&mut self) -> bool {
        if self.path.as_os_str().is_empty() {
            return false;
        }
        let mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        if mtime == self.loaded_mtime {
            if self.dirty {
                let _ = self.save();
            }
            return false;
        }
        let mem = std::mem::take(&mut self.rules);
        self.reload();
        // A rule the panel set whose write failed (a read-only or full state
        // directory) is still the user's rule; put it back beside the file's.
        let mut counts_carried = false;
        for r in std::mem::take(&mut self.unsaved) {
            if !self.rules.iter().any(|x| x.id == r.id) && self.rules.len() < MAX_RULES {
                self.rules.push(r);
                counts_carried = true;
            }
        }
        for r in &mut self.rules {
            if let Some(m) = mem.iter().find(|m| m.id == r.id) {
                if m.hits > r.hits || m.last_hit > r.last_hit {
                    r.hits = r.hits.max(m.hits);
                    r.last_hit = r.last_hit.max(m.last_hit);
                    counts_carried = true;
                }
            }
        }
        let same_rules = mem.len() == self.rules.len()
            && mem.iter().zip(self.rules.iter()).all(|(a, b)| a.id == b.id && a.note == b.note);
        if counts_carried {
            self.dirty = true;
            let _ = self.save();
        } else {
            self.dirty = false;
        }
        if !same_rules {
            self.changed = true;
        }
        !same_rules
    }

    /// True once per change a client should see (rules or hit counts), then
    /// false until the next one.
    pub fn take_changed(&mut self) -> bool {
        std::mem::replace(&mut self.changed, false)
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Add or replace (same id keeps its hit count).
    pub fn set(&mut self, rule: Rule) -> Result<(), String> {
        if let Some(existing) = self.rules.iter_mut().find(|r| r.id == rule.id) {
            existing.note = rule.note;
            existing.ts = rule.ts;
            let snapshot = existing.clone();
            self.unsaved.retain(|r| r.id != snapshot.id);
            self.unsaved.push(snapshot);
            self.dirty = true;
            self.changed = true;
            return Ok(());
        }
        if self.rules.len() >= MAX_RULES {
            return Err(format!("watchlist is full ({MAX_RULES} rules)"));
        }
        self.unsaved.push(rule.clone());
        self.rules.push(rule);
        self.dirty = true;
        self.changed = true;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Option<Rule> {
        let idx = self.rules.iter().position(|r| r.id == id)?;
        self.unsaved.retain(|r| r.id != id);
        self.dirty = true;
        self.changed = true;
        Some(self.rules.remove(idx))
    }

    /// Every rule matching `m`, as (id, description), with hit counts bumped.
    pub fn hits(&mut self, m: &Match<'_>, now: u64) -> Vec<(String, String)> {
        self.hits_where(m, now, |_| true)
    }

    /// Only the host-suffix rules: for a row whose PTR name arrived after the
    /// row did, so the other kinds, already evaluated, are not counted twice.
    pub fn host_hits(&mut self, m: &Match<'_>, now: u64) -> Vec<(String, String)> {
        self.hits_where(m, now, |r| r.kind == RuleKind::Host)
    }

    fn hits_where(&mut self, m: &Match<'_>, now: u64, keep: impl Fn(&Rule) -> bool) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for r in self.rules.iter_mut().filter(|r| keep(r)) {
            if r.matches(m) {
                r.hits += 1;
                r.last_hit = now;
                self.dirty = true;
                self.changed = true;
                out.push((r.id.clone(), r.describe()));
            }
        }
        out
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            self.dirty = false;
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.rules)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        self.loaded_mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        self.dirty = false;
        self.unsaved.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m<'a>(ip: &str, port: u16, host: &'a str, asn: Option<u32>, cc: &'a str, app: &'a str) -> Match<'a> {
        Match {
            remote: ip.parse().ok(),
            port,
            hostname: host,
            asn,
            country: cc,
            app_id: app,
            exe: "/usr/bin/x",
        }
    }

    #[test]
    fn rules_normalise_and_refuse() {
        assert_eq!(Rule::new(RuleKind::Asn, "AS13335", "", 1).unwrap().value, "13335");
        assert!(Rule::new(RuleKind::Asn, "cloudflare", "", 1).is_err());
        assert_eq!(Rule::new(RuleKind::Country, "de", "", 1).unwrap().value, "DE");
        assert!(Rule::new(RuleKind::Country, "DEU", "", 1).is_err());
        assert_eq!(Rule::new(RuleKind::Cidr, "10.1.2.3/8", "", 1).unwrap().value, "10.0.0.0/8");
        assert_eq!(Rule::new(RuleKind::Cidr, "1.2.3.4", "", 1).unwrap().value, "1.2.3.4/32");
        assert_eq!(Rule::new(RuleKind::Cidr, "2001:db8::1/32", "", 1).unwrap().value, "2001:db8::/32");
        assert!(Rule::new(RuleKind::Cidr, "1.2.3.4/33", "", 1).is_err());
        assert_eq!(Rule::new(RuleKind::Host, ".Example.COM.", "", 1).unwrap().value, "example.com");
        assert!(Rule::new(RuleKind::Host, "localhost", "", 1).is_err());
        assert!(Rule::new(RuleKind::Port, "70000", "", 1).is_err());
        assert!(Rule::new(RuleKind::App, "", "", 1).is_err());
        let long = "x".repeat(500);
        assert_eq!(Rule::new(RuleKind::App, "curl", &long, 1).unwrap().note.len(), NOTE_MAX);
        // Same kind and value, same id; the note does not change identity.
        assert_eq!(
            Rule::new(RuleKind::Asn, "13335", "a", 1).unwrap().id,
            Rule::new(RuleKind::Asn, "AS13335", "b", 2).unwrap().id
        );
        assert_ne!(
            Rule::new(RuleKind::Asn, "13335", "", 1).unwrap().id,
            Rule::new(RuleKind::Port, "13335", "", 1).unwrap().id
        );
    }

    #[test]
    fn every_kind_matches_what_it_says() {
        let row = m("203.0.113.9", 4444, "c2.evil.example", Some(64512), "RU", "curl");
        assert!(Rule::new(RuleKind::Asn, "64512", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::Country, "ru", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::Cidr, "203.0.113.0/24", "", 0).unwrap().matches(&row));
        assert!(!Rule::new(RuleKind::Cidr, "203.0.114.0/24", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::Host, "evil.example", "", 0).unwrap().matches(&row));
        assert!(!Rule::new(RuleKind::Host, "vil.example", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::Port, "4444", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::App, "curl", "", 0).unwrap().matches(&row));
        assert!(Rule::new(RuleKind::App, "/usr/bin/x", "", 0).unwrap().matches(&row));
        // Host suffix matching is on label boundaries, and a cidr rule loaded
        // from JSON (no parsed form) still matches.
        let row2 = m("203.0.113.9", 1, "notevil.example", None, "", "");
        assert!(!Rule::new(RuleKind::Host, "evil.example", "", 0).unwrap().matches(&row2));
        let raw: Rule = serde_json::from_str(r#"{"id":"w-x","kind":"cidr","value":"203.0.113.0/24","ts":0}"#).unwrap();
        assert!(raw.net.is_none() && raw.matches(&row));
        // A v4 rule still sees a v4-mapped v6 peer.
        let mapped = m("::ffff:203.0.113.9", 1, "", None, "", "");
        assert!(Rule::new(RuleKind::Cidr, "203.0.113.0/24", "", 0).unwrap().matches(&mapped));
        // Unknowns never match.
        let blank = m("", 0, "", None, "", "");
        assert!(!Rule::new(RuleKind::Cidr, "0.0.0.0/0", "", 0).unwrap().matches(&blank));
        assert!(!Rule::new(RuleKind::Host, "evil.example", "", 0).unwrap().matches(&blank));
        assert!(!Rule::new(RuleKind::Country, "RU", "", 0).unwrap().matches(&blank));
    }

    #[test]
    fn store_persists_counts_and_picks_up_outside_edits() {
        let dir = std::env::temp_dir().join(format!(
            "vallum-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = WatchStore::load(&dir);
        assert!(s.is_empty());
        s.set(Rule::new(RuleKind::Port, "4444", "reverse shells", 10).unwrap()).unwrap();
        let hits = s.hits(&m("1.2.3.4", 4444, "", None, "", "nc"), 11);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "port 4444 (reverse shells)");
        s.save().unwrap();
        let again = WatchStore::load(&dir);
        assert_eq!(again.rules()[0].hits, 1);
        assert_eq!(again.rules()[0].last_hit, 11);

        // An edit from outside (the CLI, an editor) is seen on refresh.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let extra = Rule::new(RuleKind::Country, "KP", "", 12).unwrap();
        std::fs::write(dir.join("watchlist.json"), serde_json::to_string(&vec![extra.clone()]).unwrap()).unwrap();
        // Force a distinct mtime even on coarse filesystems.
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let f = std::fs::File::options().write(true).open(dir.join("watchlist.json")).unwrap();
        let _ = f.set_modified(t);
        assert!(s.refresh());
        assert_eq!(s.rules().len(), 1);
        assert_eq!(s.rules()[0].id, extra.id);
        assert!(!s.refresh(), "nothing changed since");
        assert!(s.take_changed() && !s.take_changed());

        // An outside add while memory holds fresh hit counts: both survive.
        let port = Rule::new(RuleKind::Port, "4444", "", 20).unwrap();
        s.set(port.clone()).unwrap();
        s.save().unwrap();
        let _ = s.take_changed();
        assert_eq!(s.hits(&m("1.2.3.4", 4444, "", None, "", "nc"), 30).len(), 1);
        assert!(s.take_changed(), "a hit is a change a client should see");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut on_disk: Vec<Rule> = serde_json::from_str(&std::fs::read_to_string(dir.join("watchlist.json")).unwrap()).unwrap();
        on_disk.push(Rule::new(RuleKind::Country, "RU", "added outside", 40).unwrap());
        std::fs::write(dir.join("watchlist.json"), serde_json::to_string(&on_disk).unwrap()).unwrap();
        let t2 = std::time::SystemTime::now() + std::time::Duration::from_secs(10);
        let _ = std::fs::File::options().write(true).open(dir.join("watchlist.json")).unwrap().set_modified(t2);
        assert!(s.refresh(), "the outside add is seen");
        assert_eq!(s.len(), 3);
        let p = s.rules().iter().find(|r| r.id == port.id).unwrap();
        assert_eq!((p.hits, p.last_hit), (1, 30), "memory's hit count rode along");
        assert!(s.rules().iter().any(|r| r.value == "RU"), "disk's new rule is kept");
        let reread = WatchStore::load(&dir);
        assert_eq!(reread.rules().iter().find(|r| r.id == port.id).unwrap().hits, 1, "and the merge was written back");
        assert!(!s.refresh());
        for r in s.rules().iter().filter(|r| r.kind == RuleKind::Cidr) {
            assert!(r.net.is_some(), "cidr rules are prepared on load");
        }

        // A rule set in memory whose save never happened survives an outside
        // edit of the file instead of vanishing with memory's membership.
        let unsaved = Rule::new(RuleKind::Host, "unsaved.example", "", 50).unwrap();
        s.set(unsaved.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let disk: Vec<Rule> = serde_json::from_str(&std::fs::read_to_string(dir.join("watchlist.json")).unwrap()).unwrap();
        std::fs::write(dir.join("watchlist.json"), serde_json::to_string(&disk).unwrap()).unwrap();
        let t3 = std::time::SystemTime::now() + std::time::Duration::from_secs(20);
        let _ = std::fs::File::options().write(true).open(dir.join("watchlist.json")).unwrap().set_modified(t3);
        s.refresh();
        assert!(s.rules().iter().any(|r| r.id == unsaved.id), "the unsaved rule rode through the reload");
        assert!(WatchStore::load(&dir).rules().iter().any(|r| r.id == unsaved.id), "and was written this time");

        // Replacing keeps the id; removing works; the cap holds.
        s.set(Rule::new(RuleKind::Country, "kp", "note", 13).unwrap()).unwrap();
        assert_eq!(s.len(), 4, "KP, port, RU and the unsaved host rule");
        assert_eq!(s.rules().iter().find(|r| r.value == "KP").unwrap().note, "note");
        let ids: Vec<String> = s.rules().iter().map(|r| r.id.clone()).collect();
        for id in ids {
            assert!(s.remove(&id).is_some());
        }
        assert!(s.remove("nope").is_none());
        for i in 0..MAX_RULES {
            s.set(Rule::new(RuleKind::Port, &i.to_string(), "", 1).unwrap()).unwrap();
        }
        assert!(s.set(Rule::new(RuleKind::Port, "60000", "", 1).unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
