//! Fleet network policy: country, kub0-intel, and IP rules an org attaches to this
//! endpoint's host group. See `docs/FLEET-NETWORK-POLICY.md`.
//!
//! A rule's effective action is `block` only when both its own action and its policy's
//! mode say so. A block match is enforced only by the system kub0d (root), through
//! kub0-block `fleet-sync`; everywhere else it is reported as `would_block`. Matches on
//! shared infrastructure (CDNs, the big clouds' edge) and on snoozed rules are counted
//! but never enforced.
//!
//! The never-block floor is checked before any rule: a floor address is counted as
//! `suppressed` and never as a hit, so a poisoned feed shows up instead of hiding.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

/// Networks where one address serves many unrelated sites, so blocking it blocks
/// bystanders: CDNs and the big clouds' edge. Matches there are counted but never
/// enforced (decided 2026-10-05).
pub const SHARED_INFRA_ASNS: &[u32] = &[
    13335, 209242, // Cloudflare
    20940, 16625, 21342, 32787, // Akamai
    54113, // Fastly
    16509, 14618, // Amazon, CloudFront included
    15169, 396982, // Google
    8075, 8068, // Microsoft
    32934, // Meta
    714, 6185, // Apple
    22822, // Edgio
    60068, // CDN77
    2635, // Automattic
];

/// Destinations kept per rule between heartbeats. Matches the kub0 API's cap.
pub const MAX_DESTS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub enum Matcher {
    Country(BTreeSet<String>),
    /// Indicator address -> expiry, ms since the epoch.
    Intel(HashMap<IpAddr, u64>),
    Cidr(IpAddr, u8),
    /// A kind this build does not understand. Never matches.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: String,
    pub kind: String,
    pub action: String,
    pub name: String,
    pub app_path: String,
    pub matcher: Matcher,
    /// Intel only: indicators the server kept out of the set.
    pub server_suppressed: u64,
    pub server_withheld: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub user_can_snooze: String,
    pub version: i64,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicySet {
    pub policies: Vec<Policy>,
    /// The server's ETag, sent back as If-None-Match.
    pub etag: String,
}

/// One rule that matched one new connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub policy_id: String,
    pub rule_id: String,
    pub policy_version: i64,
    pub label: String,
    pub suppressed: bool,
    /// The rule's effective action is block and nothing exempts this address.
    pub would_block: bool,
    /// Connection matched the known applied block plan. Not an nft packet-drop measurement.
    pub blocked: bool,
    /// The address belongs to shared infrastructure: never enforced.
    pub shared: bool,
    pub snoozed: bool,
}

/// What evaluate needs beyond the rules and the floor.
#[derive(Debug, Default)]
pub struct EvalOpts<'a> {
    pub asn: Option<u32>,
    /// The system kub0d has applied the current block plan.
    pub enforcing: bool,
    pub snoozes: Option<&'a Snoozes>,
    /// Rules the applied plan actually covers.
    pub enforced_rules: Option<&'a BTreeSet<String>>,
}

/// The per-connection view the panel shows.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConnPolicy {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub label: String,
}

/// Observed connection-match counts on the heartbeat, not nft packet drops.
/// Field names are the kub0 API's; `blocked` matches the known applied block plan.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MatchReport {
    pub policy_id: String,
    pub rule_id: String,
    pub policy_version: i64,
    /// Observed new connection matches, not packets.
    pub hits: u64,
    pub would_block: u64,
    #[serde(default)]
    /// Observed matches to the known applied block plan, not measured drops.
    pub blocked: u64,
    #[serde(default)]
    pub shared_infra: u64,
    pub suppressed: u64,
    pub snoozed: bool,
    pub dests: Vec<String>,
}

/// The panel's view of one policy, with this device's counts since kub0d started.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct PolicyView {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub rules: Vec<RuleView>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct RuleView {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub action: String,
    #[serde(rename = "appPath", skip_serializing_if = "String::is_empty", default)]
    pub app_path: String,
    /// Intel: addresses in the set. Country: countries. Ip: 1.
    pub size: u64,
    /// Observed new connection matches, not packets.
    pub hits: u64,
    pub suppressed: u64,
    #[serde(rename = "wouldBlock", default)]
    pub would_block: u64,
    #[serde(default)]
    /// Observed matches to the known applied block plan, not measured drops.
    pub blocked: u64,
    #[serde(default)]
    pub shared: u64,
    #[serde(rename = "lastHitTs")]
    pub last_hit_ts: u64,
    /// `block` only when both the rule and its policy say block.
    #[serde(rename = "effectiveAction", default)]
    pub effective_action: String,
    /// The kernel enforces this rule on this endpoint right now.
    #[serde(default)]
    pub enforced: bool,
    /// Why a block rule is not enforced here, when it is not.
    #[serde(rename = "notEnforcedReason", default, skip_serializing_if = "String::is_empty")]
    pub not_enforced_reason: String,
    #[serde(rename = "canSnooze", default)]
    pub can_snooze: bool,
    #[serde(rename = "snoozedUntil", default)]
    pub snoozed_until: u64,
    #[serde(rename = "serverSuppressed")]
    pub server_suppressed: u64,
    #[serde(rename = "serverWithheld")]
    pub server_withheld: u64,
}

fn s(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

fn u(v: &serde_json::Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}

/// RFC 3339 to ms since the epoch, UTC only to the second. Returns 0 on anything else,
/// which the matcher treats as "already expired".
pub fn rfc3339_ms(t: &str) -> u64 {
    let b = t.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') {
        return 0;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { t.get(r)?.parse().ok() };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(sec)) =
        (num(0..4), num(5..7), num(8..10), num(11..13), num(14..16), num(17..19))
    else {
        return 0;
    };
    // Offset: Z, or +hh:mm / -hh:mm after optional fractional seconds.
    let rest = &t[19..];
    let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let offset_s: i64 = match rest.as_bytes().first() {
        Some(b'Z') | Some(b'z') => 0,
        Some(&sign @ (b'+' | b'-')) if rest.len() >= 6 => {
            let (Some(oh), Some(om)) = (rest[1..3].parse::<i64>().ok(), rest[4..6].parse::<i64>().ok())
            else {
                return 0;
            };
            let o = oh * 3600 + om * 60;
            if sign == b'+' { o } else { -o }
        }
        _ => return 0,
    };
    // Days from civil (Howard Hinnant).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - offset_s;
    if secs < 0 {
        return 0;
    }
    (secs as u64) * 1000
}

fn parse_cidr(c: &str) -> Option<(IpAddr, u8)> {
    let (a, bits) = match c.split_once('/') {
        Some((a, b)) => (a.parse::<IpAddr>().ok()?, b.parse::<u8>().ok()?),
        None => {
            let a = c.parse::<IpAddr>().ok()?;
            (a, if a.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if a.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((a, bits))
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (canonical(ip), canonical(net)) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// v4-mapped IPv6 as plain IPv4, so `::ffff:a.b.c.d` matches and floors like `a.b.c.d`.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// The words this build reads for a policy's `mode` and a rule's `action`. A policy set
/// with any other is refused whole: misread as monitor, a new blocking word would take
/// every block rule out of the kernel.
const MODES: &[&str] = &["monitor", "block"];

/// Parse `GET /detonate/api/enforce/netpolicy`. The set is taken only when this build
/// reads every policy and every rule in it: a policy or rule with no id, a mode or action
/// it does not know, or a block rule whose match it cannot read in full (a kind it does
/// not know, an address or country code it would drop) is an error, and the caller keeps
/// the set it had. A monitor rule it cannot read never matches but does not fail the set:
/// it cannot take anything out of the kernel. Errors name the policy and rule by index and
/// id, never a value from them.
pub fn parse(v: &serde_json::Value, etag: &str) -> Result<PolicySet, String> {
    let ps = v
        .get("policies")
        .and_then(|p| p.as_array())
        .ok_or("response has no policies array")?;
    let mut set = PolicySet {
        policies: Vec::new(),
        etag: etag.to_string(),
    };
    for (i, p) in ps.iter().enumerate() {
        let mut policy = Policy {
            id: s(p, "id"),
            name: s(p, "name"),
            mode: s(p, "mode"),
            user_can_snooze: s(p, "user_can_snooze"),
            version: p.get("version").and_then(|x| x.as_i64()).unwrap_or(0),
            rules: Vec::new(),
        };
        if policy.id.is_empty() {
            return Err(format!("policy {i} has no id"));
        }
        let at = format!("policy {i} ({:?})", policy.id);
        if !MODES.contains(&policy.mode.as_str()) {
            return Err(format!("{at} has a mode this kub0d does not know"));
        }
        let rules = p
            .get("rules")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{at} has no rules array"))?;
        for (j, r) in rules.iter().enumerate() {
            let id = s(r, "id");
            if id.is_empty() {
                return Err(format!("{at} rule {j} has no id"));
            }
            let action = s(r, "action");
            if !MODES.contains(&action.as_str()) {
                return Err(format!("{at} rule {j} ({id:?}) has an action this kub0d does not know"));
            }
            let kind = s(r, "kind");
            let (matcher, whole) = matcher(&kind, r);
            let rule = Rule {
                id,
                kind,
                action,
                name: s(r, "name"),
                app_path: s(r, "app_path"),
                matcher,
                server_suppressed: u(r, "suppressed"),
                server_withheld: u(r, "withheld"),
            };
            if !whole && effective_block(&policy, &rule) {
                return Err(format!("{at} rule {j} ({:?}) blocks with a match this kub0d cannot read", rule.id));
            }
            policy.rules.push(rule);
        }
        set.policies.push(policy);
    }
    Ok(set)
}

/// One rule's matcher, and whether every part of it was read: false for a kind this
/// build does not know and for any address, expiry or country code it had to drop.
fn matcher(kind: &str, r: &serde_json::Value) -> (Matcher, bool) {
    let m = r.get("match").cloned().unwrap_or_default();
    match kind {
        "country" => {
            let raw = m.get("countries").and_then(|c| c.as_array());
            let codes: BTreeSet<String> = raw
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str())
                .map(|c| c.trim().to_ascii_uppercase())
                .filter(|c| c.len() == 2)
                .collect();
            // Read in full only when every element is a code: duplicates collapse, but
            // nothing is dropped.
            let kept = raw.is_some_and(|a| a.iter().all(|c| c.as_str().is_some_and(|c| c.trim().len() == 2)));
            (Matcher::Country(codes), kept)
        }
        "intel" => {
            // The server leaves `set` out when no indicator qualifies.
            let raw = match r.get("set") {
                None => Some(&[][..]),
                Some(x) => x.as_array().map(|a| a.as_slice()),
            };
            let read = |e: &serde_json::Value| -> Option<(IpAddr, u64)> {
                let ip = e.get("ip")?.as_str()?.parse::<IpAddr>().ok()?;
                Some((canonical(ip), rfc3339_ms(e.get("expires")?.as_str()?)))
            };
            let set: HashMap<IpAddr, u64> = raw.into_iter().flatten().filter_map(read).collect();
            // An expiry that does not parse reads as 0, already expired: dropped too.
            let kept = raw.is_some_and(|a| a.iter().all(|e| read(e).is_some_and(|(_, exp)| exp != 0)));
            (Matcher::Intel(set), kept)
        }
        "ip" => match m.get("cidr").and_then(|c| c.as_str()).and_then(parse_cidr) {
            Some((net, bits)) => (Matcher::Cidr(net, bits), true),
            None => (Matcher::Unknown(kind.to_string()), false),
        },
        other => (Matcher::Unknown(other.to_string()), false),
    }
}

/// Addresses no rule may ever match, independent of what this host knows: loopback,
/// private, RFC 6598 shared space (the tailnet), link-local, multicast, broadcast,
/// unspecified, reserved IPv4, unique-local and link-local IPv6.
pub fn in_static_floor(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast()
                || v.is_unspecified()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}

/// The never-block floor: the static ranges plus addresses only this host knows (the
/// kub0 server it reports to and its DNS resolvers).
#[derive(Debug, Clone, Default)]
pub struct Floor {
    pub extra: HashSet<IpAddr>,
}

impl Floor {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        in_static_floor(ip) || self.extra.contains(&ip)
    }
}

/// `nameserver` lines of a resolv.conf. macOS generates /etc/resolv.conf too.
pub fn resolvers_from(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "nameserver").then(|| it.next()?.split('%').next()?.parse().ok())?
        })
        .map(canonical)
        .collect()
}

impl PolicySet {
    pub fn is_empty(&self) -> bool {
        self.policies.iter().all(|p| p.rules.is_empty())
    }

    /// Every rule that matches a new connection to `remote` by the process at `exe`,
    /// whose remote address geolocates to `country` (empty when unknown).
    pub fn evaluate(
        &self,
        remote: IpAddr,
        country: &str,
        exe: &str,
        floor: &Floor,
        opts: &EvalOpts,
        now_ms: u64,
    ) -> Vec<Hit> {
        let remote = canonical(remote);
        let floored = floor.contains(remote);
        let shared = opts.asn.is_some_and(|a| SHARED_INFRA_ASNS.contains(&a));
        let mut hits = Vec::new();
        for p in &self.policies {
            for r in &p.rules {
                if !r.app_path.is_empty() && r.app_path != exe {
                    continue;
                }
                let matched = match &r.matcher {
                    Matcher::Country(cs) => !country.is_empty() && cs.contains(country),
                    Matcher::Intel(set) => set.get(&remote).is_some_and(|exp| *exp > now_ms),
                    Matcher::Cidr(net, bits) => in_cidr(remote, *net, *bits),
                    Matcher::Unknown(_) => false,
                };
                if !matched {
                    continue;
                }
                let snoozed = opts
                    .snoozes
                    .is_some_and(|s| s.get(&r.id).is_some_and(|until| *until > now_ms));
                let would_block = effective_block(p, r) && !floored && !shared && !snoozed;
                let blocked = would_block
                    && opts.enforcing
                    && opts.enforced_rules.is_some_and(|e| e.contains(&r.id));
                hits.push(Hit {
                    policy_id: p.id.clone(),
                    rule_id: r.id.clone(),
                    policy_version: p.version,
                    label: rule_label(p, r),
                    suppressed: floored,
                    would_block,
                    blocked,
                    shared: shared && !floored,
                    snoozed,
                });
            }
        }
        hits
    }

    pub fn view(&self, ledger: &Ledger, snoozes: &Snoozes, enf: &Enforcement, now_ms: u64) -> Vec<PolicyView> {
        self.policies
            .iter()
            .map(|p| PolicyView {
                id: p.id.clone(),
                name: p.name.clone(),
                mode: p.mode.clone(),
                rules: p
                    .rules
                    .iter()
                    .map(|r| {
                        let local = ledger.local.get(&r.id).cloned().unwrap_or_default();
                        RuleView {
                            id: r.id.clone(),
                            kind: r.kind.clone(),
                            label: rule_label(p, r),
                            action: r.action.clone(),
                            app_path: r.app_path.clone(),
                            size: match &r.matcher {
                                Matcher::Country(c) => c.len() as u64,
                                Matcher::Intel(set) => set.len() as u64,
                                Matcher::Cidr(..) => 1,
                                Matcher::Unknown(_) => 0,
                            },
                            hits: local.hits,
                            suppressed: local.suppressed,
                            would_block: local.would_block,
                            blocked: local.blocked,
                            shared: local.shared,
                            last_hit_ts: local.last_ts,
                            effective_action: if effective_block(p, r) { "block" } else { "monitor" }.into(),
                            enforced: enf.enforcing && enf.rules.contains(&r.id),
                            not_enforced_reason: if !effective_block(p, r) || (enf.enforcing && enf.rules.contains(&r.id)) {
                                String::new()
                            } else if let Some(why) = enf.skipped.get(&r.id) {
                                why.clone()
                            } else {
                                enf.reason.clone()
                            },
                            can_snooze: can_snooze(p, r),
                            snoozed_until: snoozes.get(&r.id).copied().filter(|u| *u > now_ms).unwrap_or(0),
                            server_suppressed: r.server_suppressed,
                            server_withheld: r.server_withheld,
                        }
                    })
                    .collect(),
            })
            .collect()
    }
}

/// A rule's display label: its own name, else a sentence saying what it matches.
pub fn rule_label(p: &Policy, r: &Rule) -> String {
    if !r.name.trim().is_empty() {
        return r.name.trim().to_string();
    }
    let what = match &r.matcher {
        Matcher::Country(c) => format!("traffic to {}", c.iter().cloned().collect::<Vec<_>>().join(", ")),
        Matcher::Intel(_) => "kub0 threat intel addresses".to_string(),
        Matcher::Cidr(n, b) => format!("traffic to {n}/{b}"),
        Matcher::Unknown(k) => format!("unsupported {k} rule"),
    };
    let scope = if r.app_path.is_empty() {
        String::new()
    } else {
        format!(" from {}", r.app_path.rsplit('/').next().unwrap_or(&r.app_path))
    };
    let policy = if p.name.is_empty() { String::new() } else { format!("{}: ", p.name) };
    format!("{policy}{what}{scope}")
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalCount {
    /// Observed new connection matches, not packets.
    pub hits: u64,
    pub suppressed: u64,
    pub would_block: u64,
    /// Observed matches to the known applied block plan, not measured drops.
    pub blocked: u64,
    pub shared: u64,
    pub last_ts: u64,
}

/// Counts waiting for the next successful heartbeat, plus this run's totals for the
/// panel. Pending entries are keyed by rule, so a long outage grows nothing but counters.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    pending: BTreeMap<String, MatchReport>,
    pub local: HashMap<String, LocalCount>,
}

impl Ledger {
    pub fn record(&mut self, hit: &Hit, remote: IpAddr, ts: u64) {
        let e = self.pending.entry(hit.rule_id.clone()).or_insert_with(|| MatchReport {
            policy_id: hit.policy_id.clone(),
            rule_id: hit.rule_id.clone(),
            policy_version: hit.policy_version,
            hits: 0,
            would_block: 0,
            blocked: 0,
            shared_infra: 0,
            suppressed: 0,
            snoozed: false,
            dests: Vec::new(),
        });
        e.policy_version = e.policy_version.max(hit.policy_version);
        e.snoozed |= hit.snoozed;
        let l = self.local.entry(hit.rule_id.clone()).or_default();
        l.last_ts = ts;
        if hit.suppressed {
            // A floor address is never a destination worth reporting.
            e.suppressed += 1;
            l.suppressed += 1;
            return;
        }
        e.hits += 1;
        l.hits += 1;
        if hit.would_block {
            e.would_block += 1;
            l.would_block += 1;
        }
        if hit.blocked {
            e.blocked += 1;
            l.blocked += 1;
        }
        if hit.shared {
            e.shared_infra += 1;
            l.shared += 1;
        }
        let d = canonical(remote).to_string();
        if e.dests.len() < MAX_DESTS && !e.dests.contains(&d) {
            e.dests.push(d);
        }
    }

    /// Everything pending, for one heartbeat. Hand it back with `restore` if the POST fails.
    pub fn drain(&mut self) -> Vec<MatchReport> {
        std::mem::take(&mut self.pending).into_values().collect()
    }

    pub fn restore(&mut self, reports: Vec<MatchReport>) {
        for r in reports {
            match self.pending.get_mut(&r.rule_id) {
                None => {
                    self.pending.insert(r.rule_id.clone(), r);
                }
                Some(e) => {
                    e.hits += r.hits;
                    e.would_block += r.would_block;
                    e.blocked += r.blocked;
                    e.shared_infra += r.shared_infra;
                    e.suppressed += r.suppressed;
                    e.snoozed |= r.snoozed;
                    e.policy_version = e.policy_version.max(r.policy_version);
                    for d in r.dests {
                        if e.dests.len() < MAX_DESTS && !e.dests.contains(&d) {
                            e.dests.push(d);
                        }
                    }
                }
            }
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// `block` only when both the rule and its policy say so: the policy mode is the
/// master switch.
pub fn effective_block(p: &Policy, r: &Rule) -> bool {
    p.mode == "block" && r.action == "block"
}

/// Whether this device's user may snooze the rule (the policy's `user_can_snooze`).
pub fn can_snooze(p: &Policy, r: &Rule) -> bool {
    match p.user_can_snooze.as_str() {
        "all" => true,
        "none" => false,
        // The default, and anything this build does not know: monitor rules only.
        _ => !effective_block(p, r),
    }
}

/// Rule id -> snoozed until, ms since the epoch. Local to this device.
pub type Snoozes = HashMap<String, u64>;

pub fn snoozes_path(state_dir: &Path) -> PathBuf {
    state_dir.join("netpolicy-snoozes.json")
}

pub fn load_snoozes(state_dir: &Path) -> Snoozes {
    std::fs::read_to_string(snoozes_path(state_dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Write the snoozes, dropping any that have ended.
pub fn save_snoozes(state_dir: &Path, snoozes: &Snoozes, now_ms: u64) -> std::io::Result<()> {
    let live: Snoozes = snoozes.iter().filter(|(_, u)| **u > now_ms).map(|(k, v)| (k.clone(), *v)).collect();
    std::fs::create_dir_all(state_dir)?;
    let path = snoozes_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string(&live).unwrap_or_else(|_| "{}".into()))?;
    std::fs::rename(&tmp, &path)
}

/// Longest snooze a user can set from the panel.
pub const MAX_SNOOZE_MS: u64 = 24 * 60 * 60 * 1000;

/// Validate and apply a snooze request against the current policies.
pub fn snooze(set: &PolicySet, snoozes: &mut Snoozes, rule_id: &str, seconds: u64, now_ms: u64) -> Result<u64, String> {
    let (p, r) = set
        .policies
        .iter()
        .find_map(|p| p.rules.iter().find(|r| r.id == rule_id).map(|r| (p, r)))
        .ok_or("no such rule")?;
    if !can_snooze(p, r) {
        return Err("your organization does not allow snoozing this rule".into());
    }
    let until = now_ms + (seconds * 1000).clamp(60_000, MAX_SNOOZE_MS);
    snoozes.insert(rule_id.to_string(), until);
    Ok(until)
}

/// What the system kub0d last applied, for the panel and for evaluate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct Enforcement {
    /// `none` (no block rules), `monitor` (block rules, not enforced here: see reason),
    /// `enforcing`, or `error`.
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub reason: String,
    pub enforcing: bool,
    /// Rules the applied plan covers.
    pub rules: BTreeSet<String>,
    /// Block rules left out of the plan, with why.
    pub skipped: BTreeMap<String, String>,
    pub entries: u64,
    #[serde(rename = "sharedRanges")]
    pub shared_ranges: u64,
    /// Successful fleet-sync acknowledgement time; not refresh or observation time.
    #[serde(rename = "appliedTs")]
    pub applied_ts: u64,
}

/// The kernel block set one sync installs: every enforceable effective-block rule's
/// addresses. Floor and shared-infrastructure exemptions travel separately as `keep`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FleetPlan {
    pub block: Vec<String>,
    pub rules: BTreeSet<String>,
    pub skipped: BTreeMap<String, String>,
    /// The earliest intel expiry in the plan: re-plan then even if nothing else changed.
    pub next_expiry: Option<u64>,
    /// A country block rule was left out because the country database is missing or holds
    /// no countries: the plan is short of what the org asked for, so it must not replace
    /// one that was applied in full.
    pub no_country_db: bool,
}

/// Country and shared-infrastructure ranges, enumerated once and cached: one walk of
/// either database costs about a second in a release build.
pub struct RangeCache {
    geo: Option<crate::geo::GeoDb>,
    /// Whether `geo` places anything in a country, once looked at.
    geo_ok: Option<bool>,
    data_dir: PathBuf,
    asn: std::sync::Arc<crate::geo::AsnDb>,
    countries: HashMap<String, Vec<String>>,
    shared: Option<Vec<String>>,
}

impl RangeCache {
    pub fn new(data_dir: &Path, asn: std::sync::Arc<crate::geo::AsnDb>) -> Self {
        Self {
            geo: None,
            geo_ok: None,
            data_dir: data_dir.to_path_buf(),
            asn,
            countries: HashMap::new(),
            shared: None,
        }
    }

    pub fn countries(&mut self, ccs: &BTreeSet<String>) -> Vec<String> {
        let missing: BTreeSet<String> = ccs.iter().filter(|c| !self.countries.contains_key(*c)).cloned().collect();
        if !missing.is_empty() {
            let geo = self
                .geo
                .get_or_insert_with(|| crate::geo::GeoDb::load(&self.data_dir, None));
            let all = geo.networks_of_countries(&missing);
            // One walk for all missing countries, then split by looking each range up.
            let mut by: HashMap<String, Vec<String>> = missing.iter().map(|c| (c.clone(), Vec::new())).collect();
            for n in all {
                let ip = n.split('/').next().and_then(|a| a.parse::<IpAddr>().ok());
                if let Some(cc) = ip.and_then(|ip| geo.lookup(ip)).map(|h| h.country) {
                    if let Some(v) = by.get_mut(&cc) {
                        v.push(n);
                    }
                }
            }
            self.countries.extend(by);
        }
        ccs.iter().flat_map(|c| self.countries.get(c).cloned().unwrap_or_default()).collect()
    }

    pub fn shared(&mut self) -> Vec<String> {
        if self.shared.is_none() {
            self.shared = Some(self.asn.networks_of(SHARED_INFRA_ASNS));
        }
        self.shared.clone().unwrap_or_default()
    }

    pub fn has_asn(&self) -> bool {
        self.asn.has_mmdb()
    }

    /// Whether a country database loaded, and is one. Without it every country has no
    /// ranges. Loaded once: a database installed later takes a restart.
    pub fn has_geo(&mut self) -> bool {
        let geo = self
            .geo
            .get_or_insert_with(|| crate::geo::GeoDb::load(&self.data_dir, None));
        *self.geo_ok.get_or_insert_with(|| geo.has_country_data())
    }

    /// The country database's path, for errors.
    pub fn country_db_path(&self) -> PathBuf {
        self.data_dir.join("geoip/dbip-country-lite.mmdb")
    }
}

impl PolicySet {
    pub fn has_effective_block(&self) -> bool {
        self.policies.iter().any(|p| p.rules.iter().any(|r| effective_block(p, r)))
    }

    /// The block set for every enforceable, unsnoozed effective-block rule.
    pub fn plan(&self, ranges: &mut RangeCache, snoozes: &Snoozes, now_ms: u64) -> FleetPlan {
        let mut plan = FleetPlan::default();
        let mut block = BTreeSet::new();
        for p in &self.policies {
            for r in &p.rules {
                if !effective_block(p, r) {
                    continue;
                }
                if snoozes.get(&r.id).is_some_and(|u| *u > now_ms) {
                    plan.skipped.insert(r.id.clone(), "snoozed on this device".into());
                    continue;
                }
                if !r.app_path.is_empty() {
                    plan.skipped.insert(r.id.clone(), "app-scoped blocks are not enforced yet".into());
                    continue;
                }
                match &r.matcher {
                    // A country rule with no ranges blocks nothing: say so rather than
                    // count it covered.
                    Matcher::Country(_) if !ranges.has_geo() => {
                        let db = ranges.country_db_path();
                        plan.skipped.insert(r.id.clone(), format!("country database not loaded ({})", db.display()));
                        plan.no_country_db = true;
                        continue;
                    }
                    Matcher::Country(ccs) => {
                        let found = ranges.countries(ccs);
                        if found.is_empty() {
                            plan.skipped.insert(r.id.clone(), "no address ranges found for these countries".into());
                            continue;
                        }
                        block.extend(found);
                    }
                    Matcher::Intel(set) => {
                        for (ip, exp) in set {
                            if *exp > now_ms {
                                block.insert(match ip {
                                    IpAddr::V4(_) => format!("{ip}/32"),
                                    IpAddr::V6(_) => format!("{ip}/128"),
                                });
                                plan.next_expiry = Some(plan.next_expiry.map_or(*exp, |n| n.min(*exp)));
                            }
                        }
                    }
                    Matcher::Cidr(net, bits) => {
                        block.insert(format!("{net}/{bits}"));
                    }
                    Matcher::Unknown(k) => {
                        plan.skipped.insert(r.id.clone(), format!("{k} rules are not supported by this kub0d"));
                        continue;
                    }
                }
                plan.rules.insert(r.id.clone());
            }
        }
        plan.block = block.into_iter().collect();
        plan
    }
}

/// The address a `host[:port]` URL authority names, for the floor. Resolution failures
/// yield nothing: the static floor still stands.
pub fn server_addrs(server_url: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    let rest = server_url.split_once("://").map(|(_, r)| r).unwrap_or(server_url);
    let authority = rest.split('/').next().unwrap_or_default();
    let host_port = if authority.contains(':') && !authority.starts_with('[') {
        authority.to_string()
    } else if authority.starts_with('[') {
        if authority.contains("]:") { authority.to_string() } else { format!("{authority}:443") }
    } else {
        format!("{authority}:443")
    };
    match host_port.to_socket_addrs() {
        Ok(it) => it.map(|sa| canonical(sa.ip())).collect(),
        Err(_) => Vec::new(),
    }
}

/// The first address of RFC 6598 shared space, for tests of the floor.
pub fn rfc6598_example() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_790_000_000_000;

    fn set() -> PolicySet {
        parse(
            &json!({"policies":[{"id":"p1","name":"Known C2","mode":"monitor","user_can_snooze":"monitor_only","version":3,"rules":[
                {"id":"r-intel","kind":"intel","action":"monitor","match":{"min_confidence":0.8,"sources":["threatfox"]},
                 "set":[{"ip":"198.51.100.7","expires":"2099-01-01T00:00:00Z","source":"threatfox"},
                        {"ip":"198.51.100.8","expires":"2020-01-01T00:00:00Z","source":"threatfox"}],
                 "suppressed":2,"withheld":1},
                {"id":"r-kp","kind":"country","action":"monitor","match":{"countries":["KP","ir"]}},
                {"id":"r-net","kind":"ip","action":"monitor","app_path":"/usr/bin/curl","match":{"cidr":"203.0.113.0/24"}},
                {"id":"r-future","kind":"domain","action":"monitor","match":{"name":"x"}}
            ]}]}),
            "\"etag-1\"",
        ).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ids(h: &[Hit]) -> Vec<&str> {
        h.iter().map(|h| h.rule_id.as_str()).collect()
    }

    #[test]
    fn parses_every_kind_and_keeps_unknown_inert() {
        let s = set();
        assert_eq!(s.etag, "\"etag-1\"");
        assert_eq!(s.policies.len(), 1);
        let p = &s.policies[0];
        assert_eq!((p.version, p.rules.len()), (3, 4));
        assert!(matches!(p.rules[1].matcher, Matcher::Country(ref c) if c.contains("IR") && c.contains("KP")));
        assert!(matches!(p.rules[2].matcher, Matcher::Cidr(_, 24)));
        assert!(matches!(p.rules[3].matcher, Matcher::Unknown(ref k) if k == "domain"));
        assert_eq!((p.rules[0].server_suppressed, p.rules[0].server_withheld), (2, 1));
    }

    /// A set this build cannot read in full is refused whole, never read as fewer block
    /// rules: misreading one as monitor, or dropping it, would take its blocks out.
    #[test]
    fn parse_refuses_a_set_it_cannot_read_in_full() {
        let block = |rules: serde_json::Value| json!({"id":"np-1","name":"","mode":"block","version":1,"rules":rules});
        let ip = json!({"id":"nr-ip","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}});
        for (policies, want) in [
            (json!([{"id":"np-1","name":"","mode":"enforce","version":1,"rules":[ip]}]), "policy 0 (\"np-1\") has a mode this kub0d does not know"),
            (json!([{"id":"np-1","name":"","version":1,"rules":[ip]}]), "policy 0 (\"np-1\") has a mode"),
            (json!([{"policy_id":"np-1","name":"","mode":"block","version":1,"rules":[ip]}]), "policy 0 has no id"),
            (json!(["np-1"]), "policy 0 has no id"),
            (json!([{"id":"np-1","name":"","mode":"block","version":1}]), "policy 0 (\"np-1\") has no rules array"),
            (json!([{"id":"np-1","name":"","mode":"block","version":1,"rules":null}]), "has no rules array"),
            // One policy this build reads and one it does not: the whole set is refused.
            (json!([block(json!([ip])), {"id":"np-2","name":"","mode":"enforce","version":1,"rules":[]}]), "policy 1 (\"np-2\") has a mode"),
            (json!([block(json!([{"rule_id":"nr-1","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]))]), "policy 0 (\"np-1\") rule 0 has no id"),
            (json!([block(json!([ip, {"id":"nr-2","kind":"ip","action":"deny","match":{"cidr":"203.0.113.0/24"}}]))]), "policy 0 (\"np-1\") rule 1 (\"nr-2\") has an action this kub0d does not know"),
            (json!([block(json!([{"id":"nr-d","kind":"domain","action":"block","match":{"name":"x"}}]))]), "rule 0 (\"nr-d\") blocks with a match this kub0d cannot read"),
            (json!([block(json!([{"id":"nr-c","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/33"}}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-c","kind":"country","action":"block","match":{"countries":["KP","PRK"]}}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-c","kind":"country","action":"block","match":{"codes":["KP"]}}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-i","kind":"intel","action":"block","match":{},"set":[{"ip":"198.51.100.7","expires":"2099-01-01T00:00:00Z"},{"ip":"not-an-ip","expires":"2099-01-01T00:00:00Z"}]}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-i","kind":"intel","action":"block","match":{},"set":[{"ip":"198.51.100.7","expires":"soon"}]}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-i","kind":"intel","action":"block","match":{},"set":[{"ip":"198.51.100.7"}]}]))]), "blocks with a match"),
            (json!([block(json!([{"id":"nr-i","kind":"intel","action":"block","match":{},"set":{}}]))]), "blocks with a match"),
        ] {
            let err = parse(&json!({"policies": policies}), "").unwrap_err();
            assert!(err.contains(want), "{policies}: {err}");
            for value in ["enforce", "deny", "domain", "PRK", "not-an-ip", "soon", "198.51.100"] {
                assert!(!err.contains(value), "the error names where, never what: {err}");
            }
        }
        assert_eq!(parse(&json!({"policy":[]}), "").unwrap_err(), "response has no policies array");

        // Read in full: monitor rules this build cannot read never match and fail nothing,
        // an intel rule the server sent no set for is empty, and a monitor-only set reads
        // as no block at all, so an org that switches to monitor does clear.
        let ok = parse(
            &json!({"policies":[
                {"id":"np-1","name":"","mode":"block","version":1,"rules":[
                    ip,
                    {"id":"nr-d","kind":"domain","action":"monitor","match":{"name":"x"}},
                    {"id":"nr-i","kind":"intel","action":"block","match":{}},
                    {"id":"nr-c","kind":"country","action":"block","match":{"countries":["kp"," IR "]}}]},
                {"id":"np-2","name":"","mode":"monitor","version":1,"rules":[
                    {"id":"nr-x","kind":"ip","action":"block","match":{"cidr":"nope"}}]},
                {"id":"np-3","name":"","mode":"monitor","version":1,"rules":[]}]}),
            "\"e\"",
        )
        .unwrap();
        assert_eq!(ok.policies.len(), 3);
        assert!(matches!(ok.policies[0].rules[1].matcher, Matcher::Unknown(_)));
        assert!(matches!(ok.policies[0].rules[2].matcher, Matcher::Intel(ref s) if s.is_empty()));
        assert!(matches!(ok.policies[0].rules[3].matcher, Matcher::Country(ref c) if c.contains("KP") && c.contains("IR")));
        assert!(matches!(ok.policies[1].rules[0].matcher, Matcher::Unknown(_)));
        let monitor = parse(
            &json!({"policies":[{"id":"np-1","name":"","mode":"monitor","version":2,"rules":[
                {"id":"nr-ip","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}),
            "",
        )
        .unwrap();
        assert!(!monitor.is_empty() && !monitor.has_effective_block());
    }

    #[test]
    fn matches_intel_country_and_scoped_cidr() {
        let s = set();
        let f = Floor::default();
        assert_eq!(ids(&s.evaluate(ip("198.51.100.7"), "US", "/usr/bin/x", &f, &EvalOpts::default(), NOW)), vec!["r-intel"]);
        assert_eq!(ids(&s.evaluate(ip("::ffff:198.51.100.7"), "", "", &f, &EvalOpts::default(), NOW)), vec!["r-intel"]);
        assert_eq!(ids(&s.evaluate(ip("203.0.113.9"), "KP", "/usr/bin/curl", &f, &EvalOpts::default(), NOW)), vec!["r-kp", "r-net"]);
        // Near misses: expired indicator, other app, other country, outside the prefix.
        assert!(s.evaluate(ip("198.51.100.8"), "", "", &f, &EvalOpts::default(), NOW).is_empty());
        assert!(s.evaluate(ip("203.0.113.9"), "US", "/usr/bin/wget", &f, &EvalOpts::default(), NOW).is_empty());
        assert!(s.evaluate(ip("203.0.114.9"), "US", "/usr/bin/curl", &f, &EvalOpts::default(), NOW).is_empty());
        assert!(s.evaluate(ip("192.0.2.1"), "", "", &f, &EvalOpts::default(), NOW).is_empty());
    }

    #[test]
    fn floor_suppresses_instead_of_matching() {
        let s = parse(
            &json!({"policies":[{"id":"p","name":"","mode":"monitor","version":1,"rules":[
                {"id":"r","kind":"ip","action":"monitor","match":{"cidr":"198.51.100.0/24"}},
                {"id":"r2","kind":"ip","action":"monitor","match":{"cidr":"10.0.0.0/8"}}]}]}),
            "",
        ).unwrap();
        let mut f = Floor::default();
        f.extra.insert(ip("198.51.100.1")); // e.g. the kub0 server
        let h = s.evaluate(ip("198.51.100.1"), "", "", &f, &EvalOpts::default(), NOW);
        assert_eq!(h.len(), 1);
        assert!(h[0].suppressed && !h[0].would_block);
        let h = s.evaluate(ip("10.1.2.3"), "", "", &f, &EvalOpts::default(), NOW);
        assert!(h[0].suppressed);
        let h = s.evaluate(ip("198.51.100.2"), "", "", &f, &EvalOpts::default(), NOW);
        assert!(!h[0].suppressed);
    }

    #[test]
    fn static_floor_covers_the_documented_ranges() {
        for a in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.1.1", "224.0.0.1",
            "255.255.255.255", "0.1.2.3", "240.0.0.1", "::1", "fd00::1", "fe80::1", "ff02::1", "::ffff:10.0.0.1"] {
            assert!(in_static_floor(ip(a)), "{a} should be floor");
        }
        assert!(in_static_floor(rfc6598_example()));
        assert!(in_static_floor(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        for a in ["8.8.8.8", "198.51.100.7", "2606:4700::1111"] {
            assert!(!in_static_floor(ip(a)), "{a} should be public");
        }
        assert!(!in_static_floor(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn ledger_counts_caps_and_restores() {
        let mut l = Ledger::default();
        let hit = Hit {
            policy_id: "p".into(),
            rule_id: "r".into(),
            policy_version: 2,
            label: "x".into(),
            suppressed: false,
            would_block: false,
            blocked: false,
            shared: false,
            snoozed: false,
        };
        for i in 0..40u8 {
            l.record(&hit, IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)), NOW);
        }
        l.record(&hit, ip("198.51.100.0"), NOW); // duplicate dest
        let floored = Hit { suppressed: true, ..hit.clone() };
        l.record(&floored, ip("10.0.0.1"), NOW);
        let out = l.drain();
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!((r.hits, r.suppressed, r.would_block), (41, 1, 0));
        assert_eq!(r.dests.len(), MAX_DESTS);
        assert!(!r.dests.contains(&"10.0.0.1".to_string()), "a floor address was reported");
        assert_eq!(l.pending_len(), 0);
        l.record(&hit, ip("203.0.113.1"), NOW);
        l.restore(out);
        let again = l.drain();
        assert_eq!(again[0].hits, 42);
        assert_eq!(l.local["r"].hits, 42);
    }

    #[test]
    fn parses_rfc3339() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), 0);
        assert_eq!(rfc3339_ms("2026-10-05T00:00:00Z"), 1_791_158_400_000);
        assert_eq!(rfc3339_ms("2026-10-05T09:00:00.123456+09:00"), 1_791_158_400_000);
        assert_eq!(rfc3339_ms("garbage"), 0);
    }

    #[test]
    fn resolvers_and_server_addrs() {
        let r = resolvers_from("# x\nnameserver 1.1.1.1\nnameserver fe80::1%en0\nsearch lan\n");
        assert_eq!(r, vec![ip("1.1.1.1"), ip("fe80::1")]);
        assert_eq!(server_addrs("https://127.0.0.1:8443/x"), vec![ip("127.0.0.1")]);
        assert_eq!(server_addrs("http://[::1]/"), vec![ip("::1")]);
    }

    #[test]
    fn labels_say_what_the_rule_does() {
        let s = set();
        let p = &s.policies[0];
        assert_eq!(rule_label(p, &p.rules[1]), "Known C2: traffic to IR, KP");
        assert_eq!(rule_label(p, &p.rules[2]), "Known C2: traffic to 203.0.113.0/24 from curl");
    }

    fn block_set(mode: &str, snooze: &str) -> PolicySet {
        parse(
            &json!({"policies":[{"id":"p","name":"Block","mode":mode,"user_can_snooze":snooze,"version":2,"rules":[
                {"id":"r-ip","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}},
                {"id":"r-mon","kind":"ip","action":"monitor","match":{"cidr":"203.0.113.0/24"}},
                {"id":"r-app","kind":"ip","action":"block","app_path":"/usr/bin/curl","match":{"cidr":"192.0.2.0/24"}},
                {"id":"r-intel","kind":"intel","action":"block","match":{},
                 "set":[{"ip":"1.1.1.1","expires":"2099-01-01T00:00:00Z"},{"ip":"198.18.0.9","expires":"2020-01-01T00:00:00Z"}]}
            ]}]}),
            "",
        ).unwrap()
    }

    #[test]
    fn effective_block_needs_both_policy_and_rule() {
        let on = block_set("block", "monitor_only");
        let off = block_set("monitor", "monitor_only");
        let f = Floor::default();
        let enforced: BTreeSet<String> = ["r-ip".to_string()].into();
        let opts = EvalOpts { enforcing: true, enforced_rules: Some(&enforced), ..Default::default() };
        let h = on.evaluate(ip("198.51.100.7"), "", "", &f, &opts, NOW);
        assert!(h[0].would_block && h[0].blocked, "{h:?}");
        let h = off.evaluate(ip("198.51.100.7"), "", "", &f, &opts, NOW);
        assert!(!h[0].would_block && !h[0].blocked, "a monitor policy disarms its block rules");
        let h = on.evaluate(ip("203.0.113.7"), "", "", &f, &opts, NOW);
        assert!(!h[0].would_block, "a monitor rule in a block policy stays monitor");
        // Not enforcing (user-mode kub0d): would block, never blocked.
        let h = on.evaluate(ip("198.51.100.7"), "", "", &f, &EvalOpts::default(), NOW);
        assert!(h[0].would_block && !h[0].blocked);
    }

    #[test]
    fn shared_infrastructure_and_snooze_are_never_blocked() {
        let on = block_set("block", "all");
        let f = Floor::default();
        let enforced: BTreeSet<String> = ["r-intel".to_string(), "r-ip".to_string()].into();
        let shared = EvalOpts { asn: Some(13335), enforcing: true, enforced_rules: Some(&enforced), ..Default::default() };
        let h = on.evaluate(ip("1.1.1.1"), "", "", &f, &shared, NOW);
        assert_eq!(ids(&h), vec!["r-intel"]);
        assert!(h[0].shared && !h[0].would_block && !h[0].blocked, "{h:?}");
        let mut sn = Snoozes::new();
        sn.insert("r-ip".into(), NOW + 60_000);
        let snoozed = EvalOpts { enforcing: true, enforced_rules: Some(&enforced), snoozes: Some(&sn), ..Default::default() };
        let h = on.evaluate(ip("198.51.100.7"), "", "", &f, &snoozed, NOW);
        assert!(h[0].snoozed && !h[0].would_block && !h[0].blocked);
        let h = on.evaluate(ip("198.51.100.7"), "", "", &f, &snoozed, NOW + 120_000);
        assert!(!h[0].snoozed && h[0].would_block, "an ended snooze no longer exempts");
    }

    #[test]
    fn snooze_follows_the_policy_flag() {
        let now = NOW;
        let mut sn = Snoozes::new();
        let default = block_set("block", "monitor_only");
        assert!(snooze(&default, &mut sn, "r-ip", 3600, now).is_err(), "default: block rules cannot be snoozed");
        assert!(snooze(&default, &mut sn, "r-mon", 3600, now).is_ok());
        let none = block_set("block", "none");
        assert!(snooze(&none, &mut sn, "r-mon", 3600, now).is_err());
        let all = block_set("block", "all");
        let until = snooze(&all, &mut sn, "r-ip", 10 * 24 * 3600, now).unwrap();
        assert_eq!(until, now + MAX_SNOOZE_MS, "capped at a day");
        assert!(snooze(&all, &mut sn, "nope", 60, now).is_err());
    }

    #[test]
    fn snoozes_round_trip_and_drop_ended() {
        let dir = std::env::temp_dir().join(format!("vallum-snooze-{}", std::process::id()));
        let mut sn = Snoozes::new();
        sn.insert("live".into(), NOW + 1000);
        sn.insert("ended".into(), NOW - 1);
        save_snoozes(&dir, &sn, NOW).unwrap();
        let back = load_snoozes(&dir);
        assert_eq!(back.len(), 1);
        assert!(back.contains_key("live"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn plan_covers_enforceable_rules_and_says_why_not() {
        let on = block_set("block", "monitor_only");
        let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data");
        let mut ranges = RangeCache::new(&data, std::sync::Arc::new(crate::geo::AsnDb::empty()));
        let plan = on.plan(&mut ranges, &Snoozes::new(), NOW);
        assert_eq!(plan.block, vec!["1.1.1.1/32".to_string(), "198.51.100.0/24".to_string()]);
        assert!(plan.rules.contains("r-ip") && plan.rules.contains("r-intel"));
        assert!(!plan.rules.contains("r-mon"), "monitor rules are never in the block plan");
        assert_eq!(plan.skipped.get("r-app").map(String::as_str), Some("app-scoped blocks are not enforced yet"));
        assert_eq!(plan.next_expiry, Some(rfc3339_ms("2099-01-01T00:00:00Z")), "expired intel is left out");
        let mut sn = Snoozes::new();
        sn.insert("r-ip".into(), NOW + 1);
        let snoozed = on.plan(&mut ranges, &sn, NOW);
        assert_eq!(snoozed.block, vec!["1.1.1.1/32".to_string()]);
        assert!(snoozed.skipped.contains_key("r-ip"));
        assert!(block_set("monitor", "monitor_only").plan(&mut ranges, &sn, NOW).block.is_empty());
    }

    #[test]
    fn country_plan_uses_the_bundled_db() {
        let s = parse(
            &json!({"policies":[{"id":"p","name":"","mode":"block","version":1,"rules":[
                {"id":"r","kind":"country","action":"block","match":{"countries":["KP"]}}]}]}),
            "",
        ).unwrap();
        let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data");
        let mut ranges = RangeCache::new(&data, std::sync::Arc::new(crate::geo::AsnDb::empty()));
        let plan = s.plan(&mut ranges, &Snoozes::new(), NOW);
        assert!(!plan.block.is_empty() && plan.rules.contains("r"));
        let again = s.plan(&mut ranges, &Snoozes::new(), NOW);
        assert_eq!(plan.block, again.block, "cached ranges are stable");
    }

    #[test]
    fn country_rule_without_country_db_is_skipped_not_covered() {
        let s = parse(
            &json!({"policies":[{"id":"p","name":"","mode":"block","version":1,"rules":[
                {"id":"r","kind":"country","action":"block","match":{"countries":["KP"]}},
                {"id":"r-ip","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}),
            "",
        ).unwrap();
        // systemd's cwd is `/`, so a relative data dir loads no database at all.
        let mut ranges = RangeCache::new(Path::new("/nonexistent/data"), std::sync::Arc::new(crate::geo::AsnDb::empty()));
        let plan = s.plan(&mut ranges, &Snoozes::new(), NOW);
        assert!(!plan.rules.contains("r"), "a country rule with no ranges blocks nothing and is not covered");
        let why = plan.skipped.get("r").cloned().unwrap_or_default();
        assert!(why.contains("country database") && why.contains("/nonexistent/data"), "{why:?}");
        assert!(plan.rules.contains("r-ip"));
        assert_eq!(plan.block, vec!["198.51.100.0/24".to_string()]);
        assert!(plan.no_country_db, "short of what the org asked for, so it must not be applied");

        let nowhere = parse(
            &json!({"policies":[{"id":"p","name":"","mode":"block","version":1,"rules":[
                {"id":"r","kind":"country","action":"block","match":{"countries":["XX"]}}]}]}),
            "",
        ).unwrap();
        let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data");
        let mut ranges = RangeCache::new(&data, std::sync::Arc::new(crate::geo::AsnDb::empty()));
        let plan = nowhere.plan(&mut ranges, &Snoozes::new(), NOW);
        assert!(!plan.rules.contains("r") && plan.block.is_empty());
        assert!(plan.skipped.contains_key("r"));
        assert!(!plan.no_country_db, "the database is there; this country just has no ranges");
    }
}
