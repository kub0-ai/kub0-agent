//! Which addresses an endpoint block may never take.
//!
//! An endpoint block is host-wide: the address goes into a set every app's
//! traffic is checked against. So the question is not "does this app talk to
//! it" but "can the whole machine afford to lose it". Loopback cannot (with
//! systemd-resolved every app resolves names through 127.0.0.53, so blocking it
//! takes DNS down for everything), nor can the configured nameservers, nor
//! link-local and multicast (neighbour discovery, DHCPv6, mDNS), nor the
//! unspecified and broadcast addresses, which are not endpoints at all.
//!
//! The helper enforces this rather than trusting the panel to have filtered:
//! it is the privileged side, and it is the only side that can read which
//! nameservers this machine actually uses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why `ip` must not be blocked host-wide, or None if it may be.
pub fn refusal(ip: &IpAddr, nameservers: &[IpAddr]) -> Option<&'static str> {
    let ip = unmap(ip);
    if nameservers.iter().any(|n| unmap(n) == ip) {
        return Some("a nameserver this machine uses");
    }
    match ip {
        IpAddr::V4(v4) => refusal_v4(&v4),
        IpAddr::V6(v6) => refusal_v6(&v6),
    }
}

fn refusal_v4(ip: &Ipv4Addr) -> Option<&'static str> {
    if ip.is_unspecified() || ip.is_broadcast() {
        Some("not an endpoint")
    } else if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_link_local() {
        Some("link-local")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64 {
        // Tailscale/Headscale peers and their coordination path live here.
        Some("tailnet / shared address space (100.64.0.0/10)")
    } else {
        None
    }
}

/// The default route's next hop. The endpoint set is host-wide, so blocking it
/// cuts every app off the router itself, DHCP renewals included.
pub fn gateway_refusal(ip: &IpAddr, gateways: &[IpAddr]) -> Option<&'static str> {
    let ip = unmap(ip);
    gateways
        .iter()
        .any(|g| unmap(g) == ip)
        .then_some("this machine's default gateway")
}

/// Default-route gateways from /proc/net/route. The kernel prints each
/// network-order address as a native u32 in hex, so native bytes give it back.
pub fn parse_proc_net_route(text: &str) -> Vec<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 || f[1] != "00000000" {
                return None;
            }
            let g = u32::from_str_radix(f[2], 16).ok()?;
            (g != 0).then(|| IpAddr::V4(Ipv4Addr::from(g.to_ne_bytes())))
        })
        .collect()
}

/// Default-route next hops from /proc/net/ipv6_route (already byte-order hex).
pub fn parse_ipv6_route(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 5 || f[1] != "00" || f[0].chars().any(|c| c != '0') {
                return None;
            }
            let hop = u128::from_str_radix(f[4], 16).ok()?;
            (hop != 0).then(|| IpAddr::V6(Ipv6Addr::from(hop)))
        })
        .collect()
}

fn refusal_v6(ip: &Ipv6Addr) -> Option<&'static str> {
    let first = ip.segments()[0];
    if ip.is_unspecified() {
        Some("not an endpoint")
    } else if ip.is_loopback() {
        Some("loopback")
    } else if first & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0] {
        // The IPv6 half of the tailnet: Tailscale's and Headscale's default ULA.
        Some("tailnet (fd7a:115c:a1e0::/48)")
    } else {
        None
    }
}

/// The addresses refused by lookup rather than by range, spelled the way the
/// panel compares them: IPv4-mapped forms unmapped, sorted, no repeats.
pub fn critical_list(nameservers: &[IpAddr], gateways: &[IpAddr]) -> Vec<String> {
    let mut out: Vec<String> = nameservers.iter().chain(gateways).map(|i| unmap(i).to_string()).collect();
    out.sort();
    out.dedup();
    out
}

/// `::ffff:a.b.c.d` is the IPv4 address as far as blocking goes.
fn unmap(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        },
        v4 => *v4,
    }
}

/// `nameserver` lines from a resolv.conf. Anything unparsable is skipped: a
/// missing entry here can only make the guard stricter elsewhere, never let a
/// nameserver through, because loopback stubs are refused on their own.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            if w.next()? != "nameserver" {
                return None;
            }
            // A scoped v6 nameserver (fe80::1%eth0) is link-local anyway.
            w.next()?.split('%').next()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn machine_critical_addresses_are_refused() {
        for (s, why) in [
            ("127.0.0.53", "loopback"),
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("::ffff:127.0.0.1", "loopback"),
            ("169.254.169.254", "link-local"),
            ("fe80::1", "link-local"),
            ("224.0.0.251", "multicast"),
            ("ff02::fb", "multicast"),
            ("0.0.0.0", "not an endpoint"),
            ("255.255.255.255", "not an endpoint"),
            ("::", "not an endpoint"),
        ] {
            assert_eq!(refusal(&ip(s), &[]), Some(why), "{s}");
        }
    }

    #[test]
    fn nameservers_are_refused_in_either_spelling() {
        let ns = [ip("192.168.1.1"), ip("2606:4700:4700::1111")];
        assert_eq!(refusal(&ip("192.168.1.1"), &ns), Some("a nameserver this machine uses"));
        assert_eq!(refusal(&ip("::ffff:192.168.1.1"), &ns), Some("a nameserver this machine uses"));
        assert_eq!(refusal(&ip("2606:4700:4700::1111"), &ns), Some("a nameserver this machine uses"));
    }

    #[test]
    fn ordinary_remote_endpoints_are_allowed() {
        let ns = [ip("192.168.1.1")];
        for s in ["93.184.216.34", "192.168.1.20", "10.0.0.5", "2001:db8::1", "::ffff:93.184.216.34"] {
            assert_eq!(refusal(&ip(s), &ns), None, "{s}");
        }
    }

    #[test]
    fn tailnet_range_is_refused_and_its_neighbours_are_not() {
        for s in ["100.64.0.1", "100.100.100.100", "100.127.255.254", "::ffff:100.64.0.7"] {
            assert_eq!(
                refusal(&ip(s), &[]),
                Some("tailnet / shared address space (100.64.0.0/10)"),
                "{s}"
            );
        }
        for s in ["100.63.255.255", "100.128.0.1", "99.64.0.1"] {
            assert_eq!(refusal(&ip(s), &[]), None, "{s}");
        }
        for s in ["fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ab12:4843:cd96:6258:b240"] {
            assert_eq!(refusal(&ip(s), &[]), Some("tailnet (fd7a:115c:a1e0::/48)"), "{s}");
        }
        // Other ULAs are someone's LAN, and blockable like any LAN address.
        for s in ["fd7a:115c:a1e1::1", "fd00::1", "fd7a:115d:a1e0::1"] {
            assert_eq!(refusal(&ip(s), &[]), None, "{s}");
        }
    }

    #[test]
    fn default_gateway_is_refused_in_either_spelling() {
        let gw = [ip("192.168.1.1")];
        for s in ["192.168.1.1", "::ffff:192.168.1.1"] {
            assert_eq!(gateway_refusal(&ip(s), &gw), Some("this machine's default gateway"), "{s}");
        }
        assert_eq!(gateway_refusal(&ip("192.168.1.20"), &gw), None);
    }

    #[test]
    fn proc_net_route_yields_only_default_gateways() {
        // 192.168.1.1 via wlan0 is the default; the on-link /24 has no gateway,
        // and neither does a point-to-point default (wg0), which must not
        // come back as 0.0.0.0.
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                    wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n\
                    wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n";
        if cfg!(target_endian = "little") {
            assert_eq!(parse_proc_net_route(text), vec![ip("192.168.1.1")]);
        }
        assert!(parse_proc_net_route("Iface\tDestination\tGateway\n").is_empty());
    }

    #[test]
    fn ipv6_route_yields_only_default_next_hops() {
        // Row 2 is the `lo` reject default every host carries (next hop ::).
        // Rows 4 and 5 are not defaults: a zero address with a /96 prefix,
        // and a nonzero one printed with a /0.
        let text = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlan0\n\
                    00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n\
                    fd7a115ca1e0ab120000000000000000 30 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 tailscale0\n\
                    00000000000000000000000000000000 60 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003 wlan0\n\
                    20010db8000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000003 00000400 00000001 00000000 00000003 wlan0\n";
        assert_eq!(parse_ipv6_route(text), vec![ip("fe80::1")]);
    }

    #[test]
    fn critical_list_is_unmapped_sorted_and_unique() {
        let ns = [ip("::ffff:192.168.1.1"), ip("1.1.1.1")];
        let gw = [ip("192.168.1.1"), ip("fe80::1")];
        assert_eq!(critical_list(&ns, &gw), vec!["1.1.1.1", "192.168.1.1", "fe80::1"]);
        assert!(critical_list(&[], &[]).is_empty());
    }

    #[test]
    fn resolv_conf_nameservers_parse() {
        let text = "# generated\nnameserver 127.0.0.53\noptions edns0\nnameserver fe80::1%wlan0\nnameserver 1.1.1.1\nnameserver bogus\nsearch lan\n";
        assert_eq!(parse_resolv_conf(text), vec![ip("127.0.0.53"), ip("fe80::1"), ip("1.1.1.1")]);
    }
}
