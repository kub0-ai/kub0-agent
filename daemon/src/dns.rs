//! Names the apps themselves asked for, from DNS answers the optional
//! collector saw arrive.
//!
//! A PTR lookup (`rdns.rs`) asks the resolver what an address is called, which
//! the user must opt into and which a CDN address often cannot answer. A DNS
//! answer the app received says what the app *asked for*, which is the name
//! that matters, costs no extra query, and reaches every attributed row. The
//! cache maps address -> (name, expiry) and is consulted when a connection is
//! first seen and again as answers land.
//!
//! Only answers to this uid's own queries arrive here: the collector reports a
//! response only when the same socket sent a query with the same transaction
//! id and question name to the server that answered (`capture.bpf.c`,
//! `dns_egress`/`dns_ingress`). This module adds the daemon's own gate: the
//! server must be a resolver named in `/etc/resolv.conf` (`Resolvers`), so a
//! same-uid process asking a server of its own choosing names nothing. A name
//! is therefore evidence of what this user's software resolved through the
//! system's resolver, not of what the address is in general. The row says
//! `dns` in `hostnameSource` so the two kinds of name are never confused.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Entries kept. Beyond it the oldest expiry goes first.
pub const CAP: usize = 10_000;
/// A TTL is honoured between these bounds: a zero TTL is still a name the app
/// just used, and a week-long TTL should not outlive the retention window.
pub const MIN_TTL_MS: u64 = 60_000;
pub const MAX_TTL_MS: u64 = 24 * 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Answer {
    pub ts: u64,
    pub uid: u32,
    pub name: String,
    pub ip: String,
    pub ttl: u32,
    /// The resolver that answered, which the collector matched to the query's
    /// destination. Empty from a collector built before it was reported.
    #[serde(default)]
    pub server: String,
}

/// Validate a decoded answer. The collector already filtered characters; this
/// is the daemon's own line, because it is the one that stores the result.
pub fn parse(v: &serde_json::Value, uid: u32, now: u64) -> Result<Answer, String> {
    if v.get("type").and_then(|s| s.as_str()) != Some("dns") {
        return Err("not a dns frame".into());
    }
    let num = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("invalid dns {k}"))
    };
    if num("uid")? != u64::from(uid) {
        return Err("dns owner mismatch".into());
    }
    let ts = num("ts")?;
    if ts == 0
        || ts > now.saturating_add(1000)
        || ts < now.saturating_sub(crate::history::RETENTION_MS)
    {
        return Err("invalid dns time".into());
    }
    let name = v
        .get("name")
        .and_then(|s| s.as_str())
        .ok_or("missing name")?
        .to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err("invalid dns name".into());
    }
    let ip: IpAddr = v
        .get("ip")
        .and_then(|s| s.as_str())
        .ok_or("missing ip")?
        .parse()
        .map_err(|_| "invalid dns ip")?;
    let ip = match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        a => a,
    };
    if ip.is_unspecified() {
        return Err("unspecified dns ip".into());
    }
    let ttl = num("ttl")?.min(u32::MAX as u64) as u32;
    let server = match v.get("server") {
        None => String::new(),
        Some(s) => {
            let addr: IpAddr = s
                .as_str()
                .ok_or("invalid dns server")?
                .parse()
                .map_err(|_| "invalid dns server")?;
            match addr {
                IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
                a => a,
            }
            .to_string()
        }
    };
    Ok(Answer {
        ts,
        uid,
        name,
        ip: ip.to_string(),
        ttl,
        server,
    })
}

/// The resolvers this host is configured to ask, read from `/etc/resolv.conf`
/// and re-read when its modification time changes. An answer from any other
/// server is not this host's name for an address, whoever asked for it.
#[derive(Debug, Default)]
pub struct Resolvers {
    servers: Vec<IpAddr>,
    mtime: Option<std::time::SystemTime>,
    checked: Option<std::time::Instant>,
}

/// How often the file's modification time is looked at.
const RESOLV_RECHECK: std::time::Duration = std::time::Duration::from_secs(10);

impl Resolvers {
    /// `nameserver` lines, in order, ignoring comments, options and anything
    /// that does not parse as an address (a zone suffix is cut off first).
    pub fn parse(text: &str) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            if parts.next() != Some("nameserver") {
                continue;
            }
            let Some(addr) = parts.next() else { continue };
            let addr = addr.split('%').next().unwrap_or("");
            if let Ok(ip) = addr.parse::<IpAddr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        out
    }

    pub fn from_list(servers: Vec<IpAddr>) -> Self {
        Self {
            servers,
            mtime: None,
            checked: None,
        }
    }

    /// Re-read `path` if its modification time moved since the last look.
    pub fn refresh(&mut self, path: &std::path::Path) {
        if self.checked.is_some_and(|t| t.elapsed() < RESOLV_RECHECK) {
            return;
        }
        self.checked = Some(std::time::Instant::now());
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime == self.mtime {
            return;
        }
        self.mtime = mtime;
        self.servers = match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(_) => Vec::new(),
        };
    }

    /// Whether an answer from `server` is this host's resolver speaking. An
    /// empty server (older collector) is accepted on the collector's own
    /// matching alone; with no readable configuration, only loopback is, since
    /// a local stub is the one resolver that needs no file to exist.
    pub fn accepts(&self, server: &str) -> bool {
        if server.is_empty() {
            return true;
        }
        let Ok(ip) = server.parse::<IpAddr>() else {
            return false;
        };
        if self.servers.is_empty() {
            return ip.is_loopback();
        }
        self.servers.contains(&ip)
    }

    pub fn servers(&self) -> &[IpAddr] {
        &self.servers
    }
}

#[derive(Default)]
pub struct Cache {
    names: HashMap<IpAddr, (String, u64)>,
    /// Expiry order, so eviction at the cap is a first-entry pop rather than a
    /// scan of every name on the daemon's loop.
    by_expiry: std::collections::BTreeSet<(u64, IpAddr)>,
    /// Set by `insert`, cleared by `take_fresh`: the sample loop re-checks
    /// unnamed rows only when something new could name them.
    fresh: bool,
}

impl Cache {
    pub fn insert(&mut self, a: &Answer) {
        let Ok(ip) = a.ip.parse::<IpAddr>() else {
            return;
        };
        let ttl = (u64::from(a.ttl) * 1000).clamp(MIN_TTL_MS, MAX_TTL_MS);
        let expires = a.ts.saturating_add(ttl);
        if let Some((_, old)) = self.names.get(&ip) {
            self.by_expiry.remove(&(*old, ip));
        } else if self.names.len() >= CAP {
            if let Some(first) = self.by_expiry.iter().next().copied() {
                self.by_expiry.remove(&first);
                self.names.remove(&first.1);
            }
        }
        self.names.insert(ip, (a.name.clone(), expires));
        self.by_expiry.insert((expires, ip));
        self.fresh = true;
    }

    /// The name this uid's software resolved `ip` from, if unexpired.
    pub fn lookup(&self, ip: IpAddr, now: u64) -> Option<&str> {
        self.names
            .get(&ip)
            .filter(|(_, e)| *e > now)
            .map(|(n, _)| n.as_str())
    }

    pub fn take_fresh(&mut self) -> bool {
        std::mem::replace(&mut self.fresh, false)
    }

    pub fn prune(&mut self, now: u64) {
        while let Some(first) = self.by_expiry.iter().next().copied() {
            if first.0 > now {
                break;
            }
            self.by_expiry.remove(&first);
            self.names.remove(&first.1);
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_nameservers_are_read_and_everything_else_ignored() {
        let text = "# generated\nsearch example.net\nnameserver 127.0.0.53 # stub\noptions edns0 trust-ad\nnameserver 2001:4860:4860::8888%eth0\nnameserver not-an-address\nnameserver 127.0.0.53\n";
        let got = Resolvers::parse(text);
        assert_eq!(
            got,
            vec![
                "127.0.0.53".parse::<IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ]
        );
        assert!(Resolvers::parse("").is_empty());
    }

    #[test]
    fn answers_are_accepted_only_from_configured_resolvers() {
        let r = Resolvers::from_list(vec![
            "127.0.0.53".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ]);
        assert!(r.accepts("127.0.0.53"));
        assert!(r.accepts("9.9.9.9"));
        assert!(
            !r.accepts("8.8.8.8"),
            "a server the host is not configured to ask"
        );
        assert!(!r.accepts("junk"));
        assert!(
            r.accepts(""),
            "an older collector that reports no server relies on its own matching"
        );
        let none = Resolvers::default();
        assert!(
            none.accepts("127.0.0.53") && none.accepts("::1"),
            "no configuration: a local stub is still a resolver"
        );
        assert!(
            !none.accepts("8.8.8.8"),
            "no configuration: a remote server is not"
        );
    }

    #[test]
    fn resolv_conf_is_reread_when_it_changes() {
        let dir = std::env::temp_dir().join(format!("vallum-resolv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("resolv.conf");
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();
        let mut r = Resolvers::default();
        r.refresh(&path);
        assert!(r.accepts("1.1.1.1") && !r.accepts("9.9.9.9"));
        std::fs::write(&path, "nameserver 9.9.9.9\n").unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();
        r.checked = None; // the recheck interval, elapsed
        r.refresh(&path);
        assert!(r.accepts("9.9.9.9") && !r.accepts("1.1.1.1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_server_is_parsed_and_mapped_like_the_address() {
        let v: serde_json::Value = serde_json::from_str(r#"{"type":"dns","ts":1000,"uid":1000,"name":"a.example","ip":"203.0.113.7","ttl":60,"server":"::ffff:127.0.0.53"}"#).unwrap();
        assert_eq!(parse(&v, 1000, 1000).unwrap().server, "127.0.0.53");
        let v: serde_json::Value = serde_json::from_str(
            r#"{"type":"dns","ts":1000,"uid":1000,"name":"a.example","ip":"203.0.113.7","ttl":60}"#,
        )
        .unwrap();
        assert_eq!(parse(&v, 1000, 1000).unwrap().server, "");
        let v: serde_json::Value = serde_json::from_str(r#"{"type":"dns","ts":1000,"uid":1000,"name":"a.example","ip":"203.0.113.7","ttl":60,"server":"nope"}"#).unwrap();
        assert!(parse(&v, 1000, 1000).is_err());
    }

    fn frame(name: &str, ip: &str, ttl: u64) -> serde_json::Value {
        serde_json::json!({"type":"dns","ts":1000,"uid":1000,"name":name,"ip":ip,"ttl":ttl})
    }

    #[test]
    fn answers_are_validated_normalised_and_owner_checked() {
        let a = parse(
            &frame("CDN.Example.COM", "::ffff:203.0.113.7", 300),
            1000,
            1000,
        )
        .unwrap();
        assert_eq!(a.name, "cdn.example.com");
        assert_eq!(a.ip, "203.0.113.7", "a v4-mapped answer is stored as v4");
        assert!(
            parse(&frame("x", "1.2.3.4", 1), 1001, 1000).is_err(),
            "another uid's answer"
        );
        assert!(parse(&frame("bad name", "1.2.3.4", 1), 1000, 1000).is_err());
        assert!(parse(&frame("a..b", "1.2.3.4", 1), 1000, 1000).is_err());
        assert!(
            parse(&frame(&"a".repeat(64), "1.2.3.4", 1), 1000, 1000).is_err(),
            "a label over 63"
        );
        assert!(parse(&frame("ok.example", "0.0.0.0", 1), 1000, 1000).is_err());
        assert!(parse(&frame("ok.example", "nope", 1), 1000, 1000).is_err());
        assert!(parse(&serde_json::json!({"type":"attempt"}), 1000, 1000).is_err());
        let mut late = frame("ok.example", "1.2.3.4", 1);
        late["ts"] = serde_json::json!(5000);
        assert!(parse(&late, 1000, 1000).is_err(), "a frame from the future");
    }

    #[test]
    fn cache_honours_bounded_ttls_and_reports_freshness() {
        let mut c = Cache::default();
        assert!(!c.take_fresh());
        c.insert(&parse(&frame("short.example", "1.1.1.1", 0), 1000, 1000).unwrap());
        c.insert(&parse(&frame("long.example", "2.2.2.2", 10_000_000), 1000, 1000).unwrap());
        assert!(c.take_fresh() && !c.take_fresh());
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        assert_eq!(
            c.lookup(ip1, 1000 + MIN_TTL_MS - 1),
            Some("short.example"),
            "a zero TTL still lives a minute"
        );
        assert_eq!(c.lookup(ip1, 1000 + MIN_TTL_MS), None);
        assert_eq!(c.lookup(ip2, 1000 + MAX_TTL_MS - 1), Some("long.example"));
        assert_eq!(
            c.lookup(ip2, 1000 + MAX_TTL_MS),
            None,
            "a week-long TTL is capped at a day"
        );
        c.prune(1000 + MAX_TTL_MS);
        assert!(c.is_empty());
        for i in 0..CAP + 5 {
            let mut a = parse(
                &frame(
                    "n.example",
                    &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                    100,
                ),
                1000,
                1000,
            )
            .unwrap();
            a.ts = 1000 + i as u64;
            c.insert(&a);
        }
        assert_eq!(c.len(), CAP, "bounded; the earliest expiries went first");
        assert_eq!(c.lookup("10.0.0.0".parse().unwrap(), 2000), None);
        // Re-answering an address replaces its expiry without growing the index.
        let mut again = parse(&frame("n.example", "10.0.1.0", 100), 1000, 1000).unwrap();
        again.ts = 999_999;
        c.insert(&again);
        assert_eq!(c.len(), CAP);
        assert_eq!(c.by_expiry.len(), CAP, "one index entry per address");
        c.prune(999_999 + 100_000 + 1);
        assert_eq!(
            c.len(),
            0,
            "every entry has expired, the re-answered one last"
        );
    }
}
