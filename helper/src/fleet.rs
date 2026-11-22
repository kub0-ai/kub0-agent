//! Org network-policy blocks ("fleet" rules), applied as ONE nft transaction.
//!
//! Two interval sets per family: `fleet4`/`fleet6` hold what an org policy blocks,
//! `fleetkeep4`/`fleetkeep6` hold what may never be blocked. A single rule per family
//! drops `@fleet` traffic unless it is also in `@fleetkeep`:
//!
//! ```text
//! ip daddr @fleet4 ip daddr != @fleetkeep4 counter drop comment "vallum-fleet"
//! ```
//!
//! The keep sets are the never-block floor. Their static ranges are computed HERE,
//! root-side, and a caller can only ever add to them, never remove: whatever the
//! daemon sends, loopback, private space, the tailnet's shared space and the host's
//! resolvers and gateways stay reachable. The rule lives in vallum's `out` chain
//! below the pause rule, so the panel's power switch pauses it with everything else.

use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const FLEET_COMMENT: &str = "vallum-fleet";
pub const SET4: &str = "fleet4";
pub const SET6: &str = "fleet6";
pub const KEEP4: &str = "fleetkeep4";
pub const KEEP6: &str = "fleetkeep6";
/// Block plus keep entries in one sync. A whole-country set is tens of thousands.
pub const MAX_ENTRIES: usize = 400_000;
const CHUNK: usize = 2_000;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FleetSpec {
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub keep: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    pub addr: IpAddr,
    pub len: u8,
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// `a.b.c.d`, `a.b.c.d/n`, `v6`, `v6/n`. Host bits are masked off; a v4-mapped v6
/// becomes v4. Anything else is refused.
pub fn parse_net(s: &str) -> Result<Net, String> {
    let s = s.trim();
    let (a, len) = match s.split_once('/') {
        Some((a, l)) => (
            a.parse::<IpAddr>().map_err(|_| format!("bad address in {s:?}"))?,
            Some(l.parse::<u8>().map_err(|_| format!("bad prefix in {s:?}"))?),
        ),
        None => (s.parse::<IpAddr>().map_err(|_| format!("bad address {s:?}"))?, None),
    };
    let (addr, max, len) = match a {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), 32, len.map(|l| l.saturating_sub(96))),
            None => (a, 128, len),
        },
        IpAddr::V4(_) => (a, 32, len),
    };
    let len = len.unwrap_or(max);
    if len > max {
        return Err(format!("prefix /{len} too long in {s:?}"));
    }
    Ok(Net { addr: mask(addr, len), len })
}

fn mask(a: IpAddr, len: u8) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            IpAddr::V4(Ipv4Addr::from(u32::from(v) & m))
        }
        IpAddr::V6(v) => {
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v) & m))
        }
    }
}

/// The never-block floor's fixed part: loopback, private, RFC 6598 shared space
/// (the tailnet), link-local, multicast, reserved and broadcast; ULA, link-local
/// and multicast for IPv6.
pub fn static_keep() -> Vec<Net> {
    let v4 = |a: [u8; 4], len| Net { addr: IpAddr::V4(Ipv4Addr::from(a)), len };
    let v6 = |a: &str, len| Net { addr: a.parse().unwrap(), len };
    vec![
        v4([0, 0, 0, 0], 8),
        v4([10, 0, 0, 0], 8),
        v4([100, 64, 0, 0], 10),
        v4([127, 0, 0, 0], 8),
        v4([169, 254, 0, 0], 16),
        v4([172, 16, 0, 0], 12),
        v4([192, 168, 0, 0], 16),
        v4([224, 0, 0, 0], 4),
        v4([240, 0, 0, 0], 4),
        v6("::1", 128),
        v6("fc00::", 7),
        v6("fe80::", 10),
        v6("ff00::", 8),
    ]
}

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub block4: Vec<Net>,
    pub block6: Vec<Net>,
    pub keep4: Vec<Net>,
    pub keep6: Vec<Net>,
}

/// Validate a caller's spec and fold in the floor. `host` is the host's own
/// resolvers and gateways, read root-side by the caller of this function.
pub fn plan(spec: &FleetSpec, host: &[IpAddr]) -> Result<Plan, String> {
    if spec.block.len() + spec.keep.len() > MAX_ENTRIES {
        return Err(format!(
            "{} entries is over the {MAX_ENTRIES} limit",
            spec.block.len() + spec.keep.len()
        ));
    }
    let mut p = Plan::default();
    for s in &spec.block {
        let n = parse_net(s)?;
        if n.len == 0 {
            return Err(format!("refusing to block everything ({s:?})"));
        }
        if n.addr.is_ipv4() { p.block4.push(n) } else { p.block6.push(n) }
    }
    let host_nets = host.iter().map(|ip| parse_net(&ip.to_string())).collect::<Result<Vec<_>, _>>()?;
    let caller_keep = spec.keep.iter().map(|s| parse_net(s)).collect::<Result<Vec<_>, _>>()?;
    for n in static_keep().into_iter().chain(host_nets).chain(caller_keep) {
        if n.addr.is_ipv4() { p.keep4.push(n) } else { p.keep6.push(n) }
    }
    for v in [&mut p.block4, &mut p.block6, &mut p.keep4, &mut p.keep6] {
        v.sort();
        v.dedup();
    }
    Ok(p)
}

/// The nft script for one sync. `rule4`/`rule6` say whether the drop rule already
/// exists; the script adds it only when it does not. Sets are flushed and refilled
/// inside the same transaction, so there is no moment with a half-built set.
pub fn render(table: &str, p: &Plan, rule4: bool, rule6: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!("add table inet {table}\n"));
    s.push_str(&format!(
        "add chain inet {table} out {{ type filter hook output priority 0; policy accept; }}\n"
    ));
    for (set, kind) in [(SET4, "ipv4_addr"), (SET6, "ipv6_addr"), (KEEP4, "ipv4_addr"), (KEEP6, "ipv6_addr")] {
        s.push_str(&format!(
            "add set inet {table} {set} {{ type {kind}; flags interval; auto-merge; }}\n"
        ));
        s.push_str(&format!("flush set inet {table} {set}\n"));
    }
    for (set, nets) in [(KEEP4, &p.keep4), (KEEP6, &p.keep6), (SET4, &p.block4), (SET6, &p.block6)] {
        for chunk in nets.chunks(CHUNK) {
            let elems: Vec<String> = chunk.iter().map(Net::to_string).collect();
            s.push_str(&format!("add element inet {table} {set} {{ {} }}\n", elems.join(", ")));
        }
    }
    if !rule4 {
        s.push_str(&format!(
            "add rule inet {table} out ip daddr @{SET4} ip daddr != @{KEEP4} counter drop comment \"{FLEET_COMMENT}\"\n"
        ));
    }
    if !rule6 {
        s.push_str(&format!(
            "add rule inet {table} out ip6 daddr @{SET6} ip6 daddr != @{KEEP6} counter drop comment \"{FLEET_COMMENT}\"\n"
        ));
    }
    s
}

/// Whether a chain listing already carries each family's fleet drop rule.
pub fn rules_present(listing: &str) -> (bool, bool) {
    let has = |set: &str| {
        listing
            .lines()
            .any(|l| l.contains(&format!("@{set}")) && l.contains(FLEET_COMMENT) && l.contains("drop"))
    };
    (has(SET4), has(SET6))
}

/// Handles of every fleet rule in an `nft -a list chain` listing.
pub fn rule_handles(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter(|l| l.contains(&format!("comment \"{FLEET_COMMENT}\"")))
        .filter_map(|l| {
            let h = l.rsplit("# handle").next()?.trim();
            (!h.is_empty() && h.chars().all(|c| c.is_ascii_digit())).then(|| h.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(block: &[&str], keep: &[&str]) -> FleetSpec {
        FleetSpec {
            block: block.iter().map(|s| s.to_string()).collect(),
            keep: keep.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parses_masks_and_unmaps() {
        assert_eq!(parse_net("198.51.100.7").unwrap().to_string(), "198.51.100.7/32");
        assert_eq!(parse_net("198.51.100.77/24").unwrap().to_string(), "198.51.100.0/24");
        assert_eq!(parse_net("::ffff:198.51.100.7").unwrap().to_string(), "198.51.100.7/32");
        assert_eq!(parse_net("::ffff:198.51.100.0/120").unwrap().to_string(), "198.51.100.0/24");
        assert_eq!(parse_net("2001:db8::1/32").unwrap().to_string(), "2001:db8::/32");
        for bad in ["", "x", "1.2.3.4/33", "::/129", "1.2.3.4/-1", "1.2.3.4/8/9"] {
            assert!(parse_net(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn the_floor_is_always_kept_and_callers_can_only_add() {
        let host: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "fe80::1".parse().unwrap()];
        let p = plan(&spec(&["198.51.100.7", "10.0.0.5"], &["104.16.0.0/13"]), &host).unwrap();
        let keep4: Vec<String> = p.keep4.iter().map(Net::to_string).collect();
        let tailnet = format!("{}/10", Ipv4Addr::new(100, 64, 0, 0));
        for want in ["10.0.0.0/8", tailnet.as_str(), "127.0.0.0/8", "192.168.0.0/16", "1.1.1.1/32", "104.16.0.0/13"] {
            assert!(keep4.contains(&want.to_string()), "keep4 lacks {want}: {keep4:?}");
        }
        assert!(p.keep6.iter().any(|n| n.to_string() == "fe80::/10"));
        // A block entry inside the floor stays in the block set: the keep set beats it
        // in the kernel, and dropping it here would hide what the org asked for.
        assert!(p.block4.iter().any(|n| n.to_string() == "10.0.0.5/32"));
    }

    #[test]
    fn refuses_everything_and_oversize() {
        assert!(plan(&spec(&["0.0.0.0/0"], &[]), &[]).is_err());
        assert!(plan(&spec(&["::/0"], &[]), &[]).is_err());
        assert!(plan(&spec(&["not-an-ip"], &[]), &[]).is_err());
        let huge: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("198.51.{}.{}", (i / 256) % 256, i % 256)).collect();
        let s = FleetSpec { block: huge, keep: Vec::new() };
        assert!(plan(&s, &[]).is_err());
    }

    #[test]
    fn unknown_spec_fields_are_refused() {
        let r: Result<FleetSpec, _> = serde_json::from_str(r#"{"block":[],"keep":[],"unkeep":["10.0.0.0/8"]}"#);
        assert!(r.is_err(), "a spec that can say anything but block and keep is refused");
    }

    #[test]
    fn render_is_one_transaction_with_negated_keep_and_idempotent_rules() {
        let p = plan(&spec(&["198.51.100.7", "2001:db8::/32"], &[]), &[]).unwrap();
        let s = render("vallum", &p, false, false);
        assert!(s.contains("add set inet vallum fleet4 { type ipv4_addr; flags interval; auto-merge; }"));
        assert!(s.contains("flush set inet vallum fleet4\n"));
        assert!(s.contains("add element inet vallum fleet4 { 198.51.100.7/32 }"));
        assert!(s.contains("add element inet vallum fleet6 { 2001:db8::/32 }"));
        assert!(s.contains(
            "add rule inet vallum out ip daddr @fleet4 ip daddr != @fleetkeep4 counter drop comment \"vallum-fleet\""
        ));
        assert!(s.find("flush set inet vallum fleet4").unwrap() < s.find("add element inet vallum fleet4").unwrap());
        let again = render("vallum", &p, true, true);
        assert!(!again.contains("add rule"), "rules already present are not added twice");
        let empty = render("vallum", &plan(&spec(&[], &[]), &[]).unwrap(), true, true);
        assert!(!empty.contains("add element inet vallum fleet4"), "empty set renders no element line");
    }

    #[test]
    fn listing_parsers() {
        let listing = r#"table inet vallum { # handle 7
	chain out { # handle 1
		accept comment "vallum-paused" # handle 9
		ip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 drop comment "vallum-fleet" # handle 12
		ip6 daddr @fleet6 ip6 daddr != @fleetkeep6 counter packets 0 bytes 0 drop comment "vallum-fleet" # handle 13
		ip daddr @blocked4 drop # handle 5
	}
}"#;
        assert_eq!(rules_present(listing), (true, true));
        assert_eq!(rule_handles(listing), vec!["12".to_string(), "13".to_string()]);
        assert_eq!(rules_present("chain out {\n}\n"), (false, false));
    }
}
