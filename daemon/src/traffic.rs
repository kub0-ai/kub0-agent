//! TCP payload counters from Linux sock_diag; never interpret queue depth as bytes.
use crate::event::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bytes {
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppTraffic {
    pub id: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_rate: Option<f64>,
    pub rx_rate: Option<f64>,
    pub measured: usize,
    pub tcp: usize,
}

#[derive(Debug, Clone)]
pub struct SocketTraffic {
    pub bytes: Bytes,
    pub cookie: u64,
    pub local: crate::event::Endpoint,
    pub remote: crate::event::Endpoint,
}

#[derive(Default)]
pub struct Tracker {
    previous: HashMap<String, (u64, Bytes, u64)>,
    totals: HashMap<String, (u64, u64)>,
}

impl Tracker {
    /// `clock_ms` is monotonic. First observations establish a baseline; totals
    /// count only measured deltas, never traffic from before monitoring began.
    pub fn sample(
        &mut self,
        rows: &[Connection],
        stats: &HashMap<u64, SocketTraffic>,
        clock_ms: u64,
    ) -> Vec<AppTraffic> {
        let mut apps: HashMap<String, AppTraffic> = HashMap::new();
        let mut next = HashMap::new();
        for row in rows.iter().filter(|r| r.proto == "tcp") {
            let total = self.totals.entry(row.app.id.clone()).or_default();
            let a = apps
                .entry(row.app.id.clone())
                .or_insert_with(|| AppTraffic {
                    id: row.app.id.clone(),
                    tx_bytes: total.0,
                    rx_bytes: total.1,
                    tx_rate: Some(0.0),
                    rx_rate: Some(0.0),
                    measured: 0,
                    tcp: 0,
                });
            a.tcp += 1;
            let Some(stat) = stats
                .get(&row.inode)
                .filter(|s| s.local == row.local && s.remote == row.remote)
            else {
                a.tx_rate = None;
                a.rx_rate = None;
                continue;
            };
            a.measured += 1;
            if let Some((cookie, before, then)) =
                self.previous.get(&row.id).filter(|(cookie, before, then)| {
                    *cookie == stat.cookie
                        && before.tx <= stat.bytes.tx
                        && before.rx <= stat.bytes.rx
                        && *then < clock_ms
                })
            {
                let _ = cookie;
                let tx = stat.bytes.tx - before.tx;
                let rx = stat.bytes.rx - before.rx;
                total.0 = total.0.saturating_add(tx);
                total.1 = total.1.saturating_add(rx);
                let seconds = (clock_ms - then) as f64 / 1000.0;
                a.tx_rate = a.tx_rate.map(|rate| rate + tx as f64 / seconds);
                a.rx_rate = a.rx_rate.map(|rate| rate + rx as f64 / seconds);
            } else {
                a.tx_rate = None;
                a.rx_rate = None;
            }
            a.tx_bytes = total.0;
            a.rx_bytes = total.1;
            next.insert(row.id.clone(), (stat.cookie, stat.bytes, clock_ms));
        }
        self.previous = next;
        apps.into_values().collect()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    fn u32_at(b: &[u8], n: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(b.get(n..n + 4)?.try_into().ok()?))
    }
    fn u64_at(b: &[u8], n: usize) -> Option<u64> {
        Some(u64::from_ne_bytes(b.get(n..n + 8)?.try_into().ok()?))
    }
    fn ip(b: &[u8], v6: bool) -> Option<String> {
        if v6 {
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b.get(..16)?).ok()?);
            Some(
                addr.to_ipv4_mapped()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| addr.to_string()),
            )
        } else {
            Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(b.get(..4)?).ok()?).to_string())
        }
    }

    /// Stable Linux UAPI layouts, decoded bytewise (unaligned netlink attributes).
    fn parse_diag(b: &[u8]) -> Option<(u64, SocketTraffic)> {
        if b.len() < 72 {
            return None;
        }
        let v6 = match b[0] as i32 {
            libc::AF_INET => false,
            libc::AF_INET6 => true,
            _ => return None,
        };
        let inode = u32_at(b, 68)? as u64;
        if inode == 0 {
            return None;
        }
        let local = crate::event::Endpoint {
            ip: ip(&b[8..24], v6)?,
            port: u16::from_be_bytes(b[4..6].try_into().ok()?),
        };
        let remote = crate::event::Endpoint {
            ip: ip(&b[24..40], v6)?,
            port: u16::from_be_bytes(b[6..8].try_into().ok()?),
        };
        let cookie = u32_at(b, 44)? as u64 | ((u32_at(b, 48)? as u64) << 32);
        let mut n = 72;
        while n + 4 <= b.len() {
            let len = u16::from_ne_bytes(b[n..n + 2].try_into().ok()?) as usize;
            let kind = u16::from_ne_bytes(b[n + 2..n + 4].try_into().ok()?) & 0x3fff;
            if len < 4 || n + len > b.len() {
                return None;
            }
            if kind == 2 {
                // INET_DIAG_INFO, struct tcp_info
                let info = &b[n + 4..n + len];
                return Some((
                    inode,
                    SocketTraffic {
                        local,
                        remote,
                        cookie,
                        bytes: Bytes {
                            tx: u64_at(info, 120)?,
                            rx: u64_at(info, 128)?,
                        },
                    },
                ));
            }
            n += (len + 3) & !3;
        }
        None
    }

    fn dump(family: i32, sequence: u32, out: &mut HashMap<u64, SocketTraffic>) -> io::Result<()> {
        // SAFETY: syscall owns a new descriptor; OwnedFd closes it on every path.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                4,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut request = [0u8; 72]; // nlmsghdr(16) + inet_diag_req_v2(56)
        request[0..4].copy_from_slice(&72u32.to_ne_bytes());
        request[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[16] = family as u8;
        request[17] = libc::IPPROTO_TCP as u8;
        request[18] = 2; // extension bitmap: INET_DIAG_INFO = 2
        request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent != request.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut buffer = vec![0u8; 256 * 1024];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "sock_diag timeout"));
            }
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
            if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if ready <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "sock_diag unavailable",
                ));
            }
            let got = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_TRUNC,
                )
            };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            if got as usize > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated sock_diag datagram",
                ));
            }
            let b = &buffer[..got as usize];
            let mut n = 0;
            while n + 16 <= b.len() {
                let len = u32_at(b, n).unwrap() as usize;
                if len < 16 || n + len > b.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink message",
                    ));
                }
                let kind = u16::from_ne_bytes(b[n + 4..n + 6].try_into().unwrap());
                if u32_at(b, n + 8) != Some(sequence) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "netlink sequence mismatch",
                    ));
                }
                if kind == 3 {
                    if u16::from_ne_bytes(b[n + 6..n + 8].try_into().unwrap()) & 0x10 != 0
                        || (len >= 20 && u32_at(b, n + 16) != Some(0))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "sock_diag dump interrupted",
                        ));
                    }
                    return Ok(());
                }
                if kind == 2 {
                    return Err(io::Error::other("sock_diag refused"));
                }
                if kind == 20 {
                    if let Some((ino, stat)) = parse_diag(&b[n + 16..n + len]) {
                        out.insert(ino, stat);
                    }
                }
                n += (len + 3) & !3;
            }
        }
    }

    pub fn read() -> HashMap<u64, SocketTraffic> {
        let mut out = HashMap::new();
        for (sequence, family) in [(1, libc::AF_INET), (2, libc::AF_INET6)] {
            let mut family_stats = HashMap::new();
            if dump(family, sequence, &mut family_stats).is_ok() {
                out.extend(family_stats);
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn decode_counters_and_refuse_short_kernel_layouts() {
            let mut b = vec![0; 72 + 4 + 136];
            b[0] = libc::AF_INET as u8;
            b[8..12].copy_from_slice(&[127, 0, 0, 1]);
            b[24..28].copy_from_slice(&[127, 0, 0, 1]);
            b[4..6].copy_from_slice(&1234u16.to_be_bytes());
            b[6..8].copy_from_slice(&443u16.to_be_bytes());
            b[68..72].copy_from_slice(&42u32.to_ne_bytes());
            b[72..74].copy_from_slice(&140u16.to_ne_bytes());
            b[74..76].copy_from_slice(&2u16.to_ne_bytes());
            b[196..204].copy_from_slice(&987654321u64.to_ne_bytes());
            b[204..212].copy_from_slice(&123456789u64.to_ne_bytes());
            let (ino, stat) = parse_diag(&b).unwrap();
            assert_eq!(ino, 42);
            assert_eq!(stat.local.port, 1234);
            assert_eq!(
                stat.bytes,
                Bytes {
                    tx: 987654321,
                    rx: 123456789
                }
            );
            b.truncate(204);
            b[72..74].copy_from_slice(&132u16.to_ne_bytes());
            assert!(parse_diag(&b).is_none());
            assert!(parse_diag(&[0; 20]).is_none());
        }
    }
}

pub fn read() -> HashMap<u64, SocketTraffic> {
    #[cfg(target_os = "linux")]
    {
        linux::read()
    }
    #[cfg(not(target_os = "linux"))]
    {
        HashMap::new()
    }
}
