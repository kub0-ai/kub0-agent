//! The kernel's socket tables (`/proc/net/{tcp,tcp6,udp,udp6}`), read so a
//! block can close the connections an app already had open.
//!
//! Why that is needed at all: nftables' `socket cgroupv2` matches the cgroup a
//! socket was *created* in, which the kernel stamps on the socket once and
//! never updates. Moving a process into `vallum.slice` therefore catches every
//! socket it opens afterwards and none it already had, so an established
//! HTTP/2, WebSocket or QUIC session keeps flowing under a block that reports
//! itself verified. Flushing conntrack does not help: the socket is still
//! open, and its next packet simply creates a new entry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn ss_flag(self) -> &'static str {
        match self {
            Proto::Tcp => "-t",
            Proto::Udp => "-u",
        }
    }
}

// TCP states as /proc/net/tcp prints them (include/net/tcp_states.h).
const TCP_TIME_WAIT: u8 = 0x06;
const TCP_CLOSE: u8 = 0x07;
const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u64,
}

impl Flow {
    /// A socket with a peer: the only kind that can be named exactly.
    ///
    /// An unconnected UDP socket is left alone on purpose. It can only be
    /// named by its local port, which SO_REUSEPORT lets other processes share
    /// (mDNS on 5353 is the everyday case), so killing by that name could
    /// take down a socket belonging to something else.
    pub fn is_connected(&self) -> bool {
        if self.remote.ip().is_unspecified() || self.remote.port() == 0 {
            return false;
        }
        match self.proto {
            Proto::Tcp => !matches!(self.state, TCP_TIME_WAIT | TCP_CLOSE | TCP_LISTEN),
            Proto::Udp => true,
        }
    }

    /// `ss` arguments that destroy exactly this socket (SOCK_DESTROY). The
    /// full 4-tuple is given so the filter cannot match a socket of any other
    /// process. SocketAddr's Display already brackets IPv6 the way ss wants.
    pub fn ss_kill_args(&self) -> Vec<String> {
        vec![
            "-K".into(),
            "-n".into(),
            "-a".into(),
            self.proto.ss_flag().into(),
            "src".into(),
            self.local.to_string(),
            "dst".into(),
            self.remote.to_string(),
        ]
    }
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` table. Malformed rows are skipped.
pub fn parse_table(text: &str, proto: Proto, v6: bool) -> Vec<Flow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_addr(cols[1], v6), parse_addr(cols[2], v6)) else {
            continue;
        };
        let Ok(state) = u8::from_str_radix(cols[3], 16) else {
            continue;
        };
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        out.push(Flow {
            proto,
            local,
            remote,
            state,
            inode,
        });
    }
    out
}

/// `0100007F:0035` / 32-hex-digit IPv6 form, both in the kernel's in-memory
/// (little-endian per 32-bit word) byte order.
pub fn parse_addr(col: &str, v6: bool) -> Option<SocketAddr> {
    let (addr, port) = col.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if !v6 {
        if addr.len() != 8 {
            return None;
        }
        let n = u32::from_str_radix(addr, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(n.to_le_bytes()))
    } else {
        if addr.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let n = u32::from_str_radix(&addr[word * 8..word * 8 + 8], 16).ok()?;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&n.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    };
    Some(SocketAddr::new(ip, port))
}

/// The flows from `targets` that are still connected in a fresh read of the
/// tables. A destroyed TCP socket lingers in CLOSE until its owner closes the
/// fd, and a destroyed UDP socket loses its peer, so neither counts.
///
/// This check is not optional: `ss -K` exits 0 whether or not the kernel
/// actually destroyed anything (a kernel without INET_UDP_DIAG, for one,
/// quietly leaves every UDP socket open).
pub fn survivors(targets: &[Flow], after: &[Flow]) -> Vec<Flow> {
    targets
        .iter()
        .filter(|t| {
            after.iter().any(|a| {
                a.inode == t.inode && a.proto == t.proto && a.remote == t.remote && a.is_connected()
            })
        })
        .cloned()
        .collect()
}

/// Connected-flow closure cannot cover pre-existing unconnected UDP sockets.
/// They can call sendto() after the cgroup move using their old socket cgroup.
pub fn unconnected_udp_count(flows: &[Flow]) -> usize {
    flows
        .iter()
        .filter(|f| f.proto == Proto::Udp && !f.is_connected())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0
   1: 0F02000A:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0 20 4 30 10 -1
   2: 0F02000A:C352 22D8B85D:01BB 06 00000000:00000000 03:00000A00 00000000     0        0 0 3 0
   3: 0F02000A:C354 22D8B85D:01BB 07 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0
   4: garbage";

    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000000000000000000001000000:E3C1 B80D0120000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4444 2 0 0
  11: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 5555 2 0 0";

    #[test]
    fn tcp_rows_parse_in_kernel_byte_order() {
        let f = parse_table(TCP, Proto::Tcp, false);
        assert_eq!(f.len(), 4, "garbage row skipped");
        assert_eq!(f[1].local.to_string(), "10.0.2.15:50000");
        assert_eq!(f[1].remote.to_string(), "93.184.216.34:443");
        assert_eq!(f[1].state, 0x01);
        assert_eq!(f[1].inode, 2222);
    }

    #[test]
    fn only_live_peered_sockets_count_as_connected() {
        let f = parse_table(TCP, Proto::Tcp, false);
        assert!(!f[0].is_connected(), "listener");
        assert!(f[1].is_connected(), "established");
        assert!(!f[2].is_connected(), "time-wait");
        assert!(!f[3].is_connected(), "closed (already destroyed)");
    }

    #[test]
    fn udp6_parses_and_unconnected_udp_is_left_alone() {
        let f = parse_table(UDP6, Proto::Udp, true);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].local.to_string(), "[::1]:58305");
        assert_eq!(f[0].remote.to_string(), "[2001:db8::1]:443");
        assert!(f[0].is_connected());
        assert!(
            !f[1].is_connected(),
            "unbound peer: cannot be named exactly"
        );
    }

    #[test]
    fn kill_args_name_the_full_four_tuple() {
        let f = parse_table(TCP, Proto::Tcp, false);
        assert_eq!(
            f[1].ss_kill_args(),
            [
                "-K",
                "-n",
                "-a",
                "-t",
                "src",
                "10.0.2.15:50000",
                "dst",
                "93.184.216.34:443"
            ]
        );
        let u = parse_table(UDP6, Proto::Udp, true);
        assert_eq!(
            u[0].ss_kill_args(),
            [
                "-K",
                "-n",
                "-a",
                "-u",
                "src",
                "[::1]:58305",
                "dst",
                "[2001:db8::1]:443"
            ]
        );
    }

    #[test]
    fn survivors_are_targets_still_connected_after() {
        let before = parse_table(TCP, Proto::Tcp, false);
        let targets: Vec<Flow> = before
            .iter()
            .filter(|f| f.is_connected())
            .cloned()
            .collect();
        assert_eq!(targets.len(), 1);

        // Destroyed: the same inode is now in CLOSE.
        let mut closed = targets[0].clone();
        closed.state = TCP_CLOSE;
        assert!(survivors(&targets, &[closed]).is_empty());

        // Gone entirely: the owner already closed the fd.
        assert!(survivors(&targets, &[]).is_empty());

        // ss said nothing useful and the socket is still established.
        assert_eq!(survivors(&targets, &targets).len(), 1);
    }

    #[test]
    fn a_destroyed_udp_socket_loses_its_peer() {
        let u = parse_table(UDP6, Proto::Udp, true);
        let targets = vec![u[0].clone()];
        let mut disconnected = u[0].clone();
        disconnected.remote = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        assert!(survivors(&targets, &[disconnected]).is_empty());
        assert_eq!(survivors(&targets, &targets).len(), 1);
    }

    #[test]
    fn unconnected_udp_is_counted_as_unclosed_even_with_no_connected_survivors() {
        let flows = parse_table(UDP6, Proto::Udp, true);
        assert_eq!(unconnected_udp_count(&flows), 1);
        assert!(survivors(&[], &flows).is_empty());
    }
}
