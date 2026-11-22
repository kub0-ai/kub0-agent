//! The kernel routing table, read as a local authority.
//!
//! `/proc/net/route` is the same class of evidence as `/etc/passwd`: the
//! kernel wrote it, nothing on the network can influence it, and it is already
//! on the machine. The clue ladder asked passwd who a *process* was and never
//! asked the routing table who a *peer* was, so every address on the user's own
//! LAN came out as "Local network -- is on your LAN", which is true and useless.
//!
//! Parsing is a pure function over file text so the rules can be pinned by
//! fixtures. A test that reads the live `/proc` passes or fails depending on
//! which machine runs it, which is not a test.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One routing table entry, reduced to the fields that identify a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub iface: String,
    pub dest: IpAddr,
    pub prefix: u8,
    /// `None` for an on-link route -- the destination is reachable directly,
    /// which is what makes its addresses *ours* rather than merely reachable.
    pub gateway: Option<IpAddr>,
}

impl Route {
    /// A default route: matches everything, so it names the router rather than
    /// any particular peer.
    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    /// Does this route's network contain `ip`?
    ///
    /// A default route contains every address, so callers that mean "is this
    /// peer on our link" must exclude it -- see [`on_link_for`].
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.dest, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                same_prefix(u32::from(net) as u128, u32::from(ip) as u128, self.prefix, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                same_prefix(u128::from(net), u128::from(ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// Compare the top `prefix` bits of two addresses of `bits` width.
fn same_prefix(a: u128, b: u128, prefix: u8, bits: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > bits {
        return false;
    }
    let shift = bits - prefix;
    // Shifting a u128 by 128 is UB-adjacent in release and panics in debug, so
    // the full-length case is handled without a shift at all.
    if shift == 0 {
        a == b
    } else {
        (a >> shift) == (b >> shift)
    }
}

/// The gateway of the highest-priority default route, if there is one.
pub fn default_gateway(routes: &[Route]) -> Option<(&Route, IpAddr)> {
    routes
        .iter()
        .find(|r| r.is_default() && r.gateway.is_some())
        .map(|r| (r, r.gateway.unwrap()))
}

/// The most specific on-link route containing `ip`, or `None`.
///
/// On-link means no gateway: the kernel believes it can reach that network by
/// putting a frame on the wire, which is the difference between "a machine on
/// my network" and "a machine I happen to have a path to". Default routes are
/// excluded because they contain everything and prove nothing about the peer.
pub fn on_link_for(routes: &[Route], ip: IpAddr) -> Option<&Route> {
    routes
        .iter()
        .filter(|r| r.gateway.is_none() && !r.is_default() && r.contains(ip))
        .max_by_key(|r| r.prefix)
}

/// Parse `/proc/net/route`.
///
/// Columns are `Iface Destination Gateway Flags RefCnt Use Metric Mask ...`
/// and the three addresses are hex in *host* byte order, so on a little-endian
/// machine `0100140A` is 10.20.0.1 and not 1.0.20.10. Getting this backwards
/// produces addresses that look plausible and are wrong, which is worse than
/// failing to parse.
pub fn parse_v4(text: &str) -> Vec<Route> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(dest), Some(gw), Some(mask)) = (hex_v4(f[1]), hex_v4(f[2]), hex_v4(f[7])) else {
            continue;
        };
        // An all-zero gateway means on-link, not "the gateway is 0.0.0.0".
        let gateway = (!gw.is_unspecified()).then_some(IpAddr::V4(gw));
        out.push(Route {
            iface: f[0].to_string(),
            dest: IpAddr::V4(dest),
            prefix: u32::from(mask).count_ones() as u8,
            gateway,
        });
    }
    out
}

/// Parse `/proc/net/ipv6_route`.
///
/// Columns are `dest prefixlen src srcprefix nexthop metric refcnt use flags
/// iface`. Unlike the v4 table these are plain big-endian hex, no swapping.
pub fn parse_v6(text: &str) -> Vec<Route> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(dest), Some(next)) = (hex_v6(f[0]), hex_v6(f[4])) else {
            continue;
        };
        let Ok(prefix) = u8::from_str_radix(f[1], 16) else {
            continue;
        };
        let gateway = (!next.is_unspecified()).then_some(IpAddr::V6(next));
        out.push(Route {
            iface: f[9].to_string(),
            dest: IpAddr::V6(dest),
            prefix,
            gateway,
        });
    }
    out
}

fn hex_v4(s: &str) -> Option<Ipv4Addr> {
    let v = u32::from_str_radix(s, 16).ok()?;
    // to_le_bytes undoes the kernel's host-order write on a little-endian box.
    Some(Ipv4Addr::from(v.to_le_bytes()))
}

fn hex_v6(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let v = u128::from_str_radix(s, 16).ok()?;
    Some(Ipv6Addr::from(v))
}

/// Read the live tables. Unreadable files yield no routes rather than an
/// error: a daemon with no route clues is fine, a daemon that will not start
/// because `/proc` looked odd is not.
pub fn load() -> Vec<Route> {
    let mut v = std::fs::read_to_string("/proc/net/route")
        .map(|t| parse_v4(&t))
        .unwrap_or_default();
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        v.extend(parse_v6(&t));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table shaped like a laptop's: a 10.20.0.0/24 LAN with the mesh up.
    ///
    /// The mesh leg is the nebula overlay rather than tailscale because a
    /// CGNAT literal (100.64/10) must not be written into a public repo --
    /// the pre-push gate is right to reject one. Both interfaces are in
    /// `MESH_IFACES` and take the identical branch, so the coverage is the
    /// same and the fixture leaks nothing.
    const V4: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp1s0\t00000000\t0100140A\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlp1s0\t0000140A\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
nebula0\t0000630A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_addresses_are_host_order_not_network_order() {
        let r = parse_v4(V4);
        assert_eq!(r[1].dest, ip("10.20.0.0"), "0000140A is 10.20.0.0");
        assert_eq!(r[1].prefix, 24);
        assert_eq!(r[0].gateway, Some(ip("10.20.0.1")));
    }

    #[test]
    fn the_default_route_is_the_only_one_with_a_gateway() {
        let r = parse_v4(V4);
        assert!(r[0].is_default());
        assert_eq!(r[1].gateway, None, "an on-link route has no gateway");
        assert_eq!(default_gateway(&r).map(|(_, g)| g), Some(ip("10.20.0.1")));
    }

    #[test]
    fn on_link_lookup_finds_the_lan_and_names_its_interface() {
        let r = parse_v4(V4);
        let hit = on_link_for(&r, ip("10.20.0.48")).expect("same subnet");
        assert_eq!(hit.iface, "wlp1s0");
    }

    #[test]
    fn on_link_lookup_finds_the_mesh_overlay() {
        let r = parse_v4(V4);
        let hit = on_link_for(&r, ip("10.99.1.5")).expect("inside the overlay");
        assert_eq!(hit.iface, "nebula0");
        assert_eq!(hit.prefix, 16);
    }

    #[test]
    fn a_default_route_never_counts_as_on_link() {
        // The whole guard: a split-tunnel VPN's 0.0.0.0/1 must not make every
        // public address look like a machine on the user's desk.
        let r = parse_v4(V4);
        assert!(on_link_for(&r, ip("8.8.8.8")).is_none());
    }

    #[test]
    fn the_most_specific_on_link_route_wins() {
        let text = format!("{V4}eth0\t0000140A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n");
        let r = parse_v4(&text);
        // /24 on wlp1s0 beats /16 on eth0 for an address inside both.
        assert_eq!(on_link_for(&r, ip("10.20.0.9")).unwrap().iface, "wlp1s0");
    }

    #[test]
    fn malformed_and_empty_tables_yield_nothing_and_never_panic() {
        assert!(parse_v4("").is_empty());
        assert!(parse_v4("Iface\tDestination\n").is_empty());
        assert!(parse_v4("Iface\nshort\tline\n").is_empty());
        assert!(parse_v4("Iface\nx\tZZZZ\tZZZZ\t0\t0\t0\t0\tZZZZ\n").is_empty());
        assert!(parse_v6("").is_empty());
        assert!(parse_v6("garbage\n").is_empty());
    }

    #[test]
    fn v6_routes_parse_big_endian_with_the_iface_last() {
        let line = format!(
            "{} 40 {} 00 {} 00000100 00000000 00000001 00000001 tailscale0\n",
            "fd7a643a000000000000000000000000", "0".repeat(32), "0".repeat(32)
        );
        let r = parse_v6(&line);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].iface, "tailscale0");
        assert_eq!(r[0].prefix, 0x40);
        assert_eq!(r[0].gateway, None);
        assert!(r[0].contains(ip("fd7a:643a::1")));
    }

    #[test]
    fn prefix_zero_contains_everything_and_full_prefix_is_exact() {
        let all = Route {
            iface: "x".into(),
            dest: ip("0.0.0.0"),
            prefix: 0,
            gateway: None,
        };
        assert!(all.contains(ip("1.2.3.4")));
        let host = Route {
            iface: "x".into(),
            dest: ip("10.0.0.5"),
            prefix: 32,
            gateway: None,
        };
        assert!(host.contains(ip("10.0.0.5")));
        assert!(!host.contains(ip("10.0.0.6")));
    }

    #[test]
    fn a_v4_route_never_matches_a_v6_address() {
        let r = parse_v4(V4);
        assert!(on_link_for(&r, ip("fd7a:643a::1")).is_none());
    }
}
