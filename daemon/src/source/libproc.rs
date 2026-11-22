//! macOS libproc source driver.
//!
//! Samples live sockets by walking every process's file descriptors through
//! `proc_pidinfo(2)`/`proc_pidfdinfo(2)`. This is the Darwin analogue of the
//! `procfs` driver: a snapshot poller, not an interception point.
//!
//! # Why this is the macOS entry point and not Endpoint Security
//!
//! Endpoint Security has no network-connect event. Verified against
//! `MacOSX.sdk` on macOS 26.6.2: of 156 `ES_EVENT_TYPE_*` symbols the only
//! connect events are `UIPC_{BIND,CONNECT}` (unix-domain IPC) and
//! `XPC_CONNECT`. Per-flow allow/deny on macOS needs a `NEFilterDataProvider`
//! System Extension, which needs a restricted entitlement and a Developer ID.
//! Observation needs neither, which is the entire point of this module: vallum
//! can see and report on a Mac today, and gains enforcement later without the
//! rest of the daemon learning a second shape.
//!
//! # No entitlement, and an honest blind spot
//!
//! `proc_pidfdinfo` on a process owned by another uid fails with `EPERM` for an
//! unprivileged caller. Those processes are skipped silently and *counted*, not
//! guessed at — a source that quietly reported a partial view as a complete one
//! would be worse than one that cannot see. Running as root removes the blind
//! spot; nothing here requires it.
//!
//! # The FFI is hand-declared, and that is the risk
//!
//! The `libc` crate exposes the libproc *functions* on Apple targets but not
//! `struct socket_info` and friends, so they are declared here. A `#[repr(C)]`
//! whose offsets disagree with the kernel does not crash — it yields plausible
//! garbage addresses and ports. Literal assertions below pin the Rust layout;
//! tests/darwin-native-gate.py independently compares it to native SDK headers
//! on each CI architecture. Apple execution remains required to prove compatibility.

use crate::flow::{
    Action, App, Flow, FlowState, Peer, Provenance, SourceKind, Verdict, SCHEMA_VERSION,
};
use crate::source::{Source, SourceError};
use std::collections::HashSet;
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants from <sys/proc_info.h>. libc has PROC_PIDLISTFDS,
// PROX_FDTYPE_SOCKET and PROC_PIDPATHINFO_MAXSIZE; the rest it does not.
// ---------------------------------------------------------------------------

const PROC_PIDFDSOCKETINFO: c_int = 3;

const SOCKINFO_IN: c_int = 1;
const SOCKINFO_TCP: c_int = 2;

const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

// TCP states. Only the ones this module distinguishes are named; the rest are
// deliberately lumped, because the schema has three flow states and inventing
// finer ones here would put vocabulary in the wire format that no other source
// can produce.
const TSI_S_CLOSED: c_int = 0;
const TSI_S_LISTEN: c_int = 1;
const TSI_S_ESTABLISHED: c_int = 4;
const TSI_S_TIME_WAIT: c_int = 10;

/// Ceiling on pids per poll. A Mac runs a few hundred processes; six thousand
/// is generous slack for a fork storm and still bounds one poll's work.
const MAX_PIDS: usize = 6144;

/// Ceiling on descriptors inspected per process. A browser legitimately holds
/// thousands; this bounds a single pathological process, not the fleet.
const MAX_FDS_PER_PROC: usize = 4096;

// ---------------------------------------------------------------------------
// FFI struct definitions.
//
// Offsets below are measured, not derived. Fields this module never reads are
// opaque byte arrays sized to hold the gap, which keeps the declaration small
// enough to audit against the header by eye.
// ---------------------------------------------------------------------------

/// `struct in_sockinfo` — 80 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfo {
    /// Foreign port, network byte order, widened into an `int`.
    insi_fport: c_int,
    /// Local port, network byte order.
    insi_lport: c_int,
    /// Generation count *of this instance*. Exists precisely to disambiguate a
    /// recycled socket structure, which is why flow identity leans on it.
    insi_gencnt: u64,
    _insi_flags: u32,
    _insi_flow: u32,
    /// `INI_IPV4` or `INI_IPV6`.
    insi_vflag: u8,
    _insi_ip_ttl: u8,
    _rfu_1: u32,
    /// Foreign address. 16 bytes whichever family: an IPv4 address lives in the
    /// **last four**, behind `in4in6_addr`'s 12 bytes of padding.
    insi_faddr: [u8; 16],
    /// Local address, same layout.
    insi_laddr: [u8; 16],
    /// `insi_v4` + `insi_v6`, neither of which this module reads.
    _tail: [u8; 16],
}

/// `struct tcp_sockinfo` — 120 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: c_int,
    /// `tcpsi_timer[4]`, `tcpsi_mss`, `tcpsi_flags`, `rfu_1`, `tcpsi_tp`.
    _tail: [u8; 36],
}

/// The `soi_proto` union — 528 bytes.
///
/// Only two arms are ever read, and they agree where it matters: `pri_in` is an
/// `in_sockinfo` at offset 0, and `pri_tcp`'s first member `tcpsi_ini` is also
/// an `in_sockinfo` at offset 0. So the addresses and ports can be read the
/// same way for both kinds, and only the TCP state needs the wider view.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketProto {
    tcp: TcpSockinfo,
    _rest: [u8; 408],
}

/// `struct socket_info` — 768 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    /// `soi_stat` (a `vinfo_stat`), `soi_so`, `soi_pcb`, `soi_type`.
    _head: [u8; 156],
    soi_protocol: c_int,
    soi_family: c_int,
    /// `soi_options` through `soi_snd`.
    _mid: [u8; 68],
    /// `SOCKINFO_IN`, `SOCKINFO_TCP`, ...
    soi_kind: c_int,
    _rfu_1: u32,
    soi_proto: SocketProto,
}

/// `struct socket_fdinfo` — 792 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    /// `struct proc_fileinfo`.
    _pfi: [u8; 24],
    psi: SocketInfo,
}

// Baseline Rust layout checks only. SDK drift is detected by the independent
// native C/Rust comparison, not by these literals or fixed-width fields.
const _: () = {
    assert!(std::mem::size_of::<InSockinfo>() == 80);
    assert!(std::mem::size_of::<TcpSockinfo>() == 120);
    assert!(std::mem::size_of::<SocketProto>() == 528);
    assert!(std::mem::size_of::<SocketInfo>() == 768);
    assert!(std::mem::size_of::<SocketFdInfo>() == 792);
    assert!(std::mem::offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(std::mem::offset_of!(InSockinfo, insi_laddr) == 48);
    assert!(std::mem::offset_of!(TcpSockinfo, tcpsi_state) == 80);
    assert!(std::mem::offset_of!(SocketInfo, soi_protocol) == 156);
    assert!(std::mem::offset_of!(SocketInfo, soi_family) == 160);
    assert!(std::mem::offset_of!(SocketInfo, soi_kind) == 232);
    assert!(std::mem::offset_of!(SocketInfo, soi_proto) == 240);
    assert!(std::mem::offset_of!(SocketFdInfo, psi) == 24);
};

// ---------------------------------------------------------------------------
// Pure helpers. Everything below this line is testable on any host, which is
// why the parsing lives here rather than inline in the unsafe walk.
// ---------------------------------------------------------------------------

/// `ntohs` on a port the kernel widened into an `int`.
///
/// The value is already network byte order; only the low 16 bits are the port.
fn ntohs(v: c_int) -> u16 {
    u16::from_be(v as u16)
}

/// Render a libproc address field as a string.
///
/// `vflag` decides how to read the same 16 bytes. The IPv4 case is the trap:
/// the address is at offset 12, because the union's IPv4 arm is an
/// `in4in6_addr` whose first 12 bytes are padding. Reading from offset 0 yields
/// `0.0.0.0` for every flow, with no error anywhere.
fn render_addr(vflag: u8, raw: &[u8; 16]) -> Option<String> {
    if vflag & INI_IPV4 != 0 {
        let o = std::net::Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        if o.is_unspecified() {
            return None;
        }
        Some(o.to_string())
    } else if vflag & INI_IPV6 != 0 {
        let o = std::net::Ipv6Addr::from(*raw);
        if o.is_unspecified() {
            return None;
        }
        // An IPv4-mapped address renders as its v4 form so that the same peer
        // does not key two different network entries in the seen-set.
        match o.to_ipv4_mapped() {
            Some(v4) => Some(v4.to_string()),
            None => Some(o.to_string()),
        }
    } else {
        None
    }
}

/// Map a libproc TCP state onto the schema's three flow states.
///
/// This keeps `procfs`'s contract exactly (`docs/SCHEMA.md` 5): a sampler
/// "contributes nothing to History", and the deny-listed `closed` state stays
/// something only `opensnitch` produces.
///
/// The temptation is to emit `closed` for a socket caught in `TIME_WAIT`, since
/// libproc hands the state over for free. That is wrong, and quietly so: a
/// poller only sees teardown if a poll lands inside it, so History would fill
/// with whichever connections happened to die on a tick boundary and silently
/// omit every one that didn't. An arbitrary subset presented as a record is
/// worse than an empty record. Teardown states are dropped here, and a real
/// close is a *disappearance* between two samples — see `poll`.
///
/// `LISTEN` is dropped for a different reason: a server socket is not a flow,
/// and drawing one as an arc to `0.0.0.0` is how the panel gets noisy.
fn map_tcp_state(state: c_int) -> Option<FlowState> {
    match state {
        TSI_S_LISTEN | TSI_S_CLOSED | TSI_S_TIME_WAIT => None,
        TSI_S_ESTABLISHED => Some(FlowState::Live),
        // SYN_SENT, SYN_RECEIVED, and the FIN_WAIT family are all a connection
        // that exists. Reporting them as `live` is accurate; inventing a
        // fourth state to describe them is not this driver's call to make.
        _ => Some(FlowState::Live),
    }
}

/// Stable identity for one socket, used to emit a flow once rather than on
/// every poll.
///
/// A snapshot poller sees the same established connection forever, so identity
/// is what keeps the UI from redrawing it every tick. Three candidates were
/// available and only one survives contact:
///
/// * `(pid, fd)` — fd numbers are recycled immediately, so a close-then-open in
///   the same slot reads as the *same* flow and a genuine new connection is
///   never reported.
/// * the 5-tuple — survives fd churn, but a reconnect from the same ephemeral
///   port to the same server is indistinguishable from the original.
/// * `insi_gencnt` — the kernel's own "generation count of this instance",
///   which exists for exactly this problem. Paired with the 5-tuple so that a
///   generation counter reset cannot collide two live sockets.
fn flow_key(gencnt: u64, proto: &str, local: Option<&Peer>, remote: &Peer) -> String {
    let (lip, lport) = match local {
        Some(p) => (p.ip.as_str(), p.port),
        None => ("", 0),
    };
    format!(
        "{gencnt}:{proto}:{lip}:{lport}:{}:{}",
        remote.ip, remote.port
    )
}

/// Whether a socket seen at this instant is worth emitting.
///
/// Two different descriptors can name the *same* socket: a process that
/// inherited a connection and has it on stdin, stdout and a working fd reports
/// it three times in one walk, with identical generation counts because it is
/// one socket. Checking only the previous poll's set lets all three through and
/// draws the same connection three times.
///
/// `HashSet::insert` returning `false` is the within-poll answer, so the same
/// call both records the socket and reports whether it had already been seen a
/// moment ago.
fn should_emit(key: &str, current: &mut HashSet<String>, seen: &HashSet<String>) -> bool {
    let first_sighting_this_poll = current.insert(key.to_string());
    first_sighting_this_poll && !seen.contains(key)
}

fn pid_capacity(need: c_int) -> usize {
    (need.max(0) as usize).saturating_add(64).min(MAX_PIDS)
}

fn retain_pids(pids: &mut Vec<c_int>, got: c_int) {
    pids.truncate((got.max(0) as usize).min(pids.len()));
    pids.retain(|p| *p > 0);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The source.
// ---------------------------------------------------------------------------

/// One observed socket, already normalised out of the FFI structs.
struct Observed {
    key: String,
    proto: String,
    state: FlowState,
    local: Option<Peer>,
    remote: Peer,
    pid: u32,
}

pub struct LibprocSource {
    /// Sockets already reported. Bounded by live socket count, not by uptime,
    /// because it is rebuilt from the current sample on every poll.
    seen: HashSet<String>,
    /// Processes skipped on the last poll because they belong to another uid.
    /// Surfaced rather than swallowed: a partial view reported as a complete
    /// one is the failure mode worth guarding against.
    denied: usize,
}

impl Default for LibprocSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LibprocSource {
    pub fn new() -> Self {
        LibprocSource {
            seen: HashSet::new(),
            denied: 0,
        }
    }

    /// Processes the last poll could not inspect for lack of privilege.
    pub fn denied_last_poll(&self) -> usize {
        self.denied
    }

    /// Every pid on the box, or an error if the call itself failed.
    fn list_pids() -> Result<Vec<c_int>, SourceError> {
        // SAFETY: the NULL/0 form asks the kernel for the size it would write
        // and touches no memory of ours.
        let need = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if need <= 0 {
            return Err(SourceError::Failed(format!(
                "proc_listallpids sizing returned {need}"
            )));
        }
        // libproc returns entry counts; only the buffer argument is bytes.
        let count = pid_capacity(need);
        let mut pids = vec![0 as c_int; count];
        let bytes = (count * std::mem::size_of::<c_int>()) as c_int;
        // SAFETY: the buffer is `count` ints long and `bytes` describes exactly
        // that, so the kernel cannot write past it.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut c_void, bytes) };
        if got <= 0 {
            return Err(SourceError::Failed(format!(
                "proc_listallpids returned {got}"
            )));
        }
        retain_pids(&mut pids, got);
        Ok(pids)
    }

    /// Socket descriptors held by one process.
    ///
    /// An error here is per-process and never fatal: a process can exit between
    /// being listed and being asked, and most of them belong to another uid.
    fn socket_fds(pid: c_int) -> Option<Vec<c_int>> {
        // SAFETY: sizing call, NULL buffer.
        let need = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if need <= 0 {
            return None;
        }
        let slot = std::mem::size_of::<libc::proc_fdinfo>();
        let count = (need as usize / slot + 16).min(MAX_FDS_PER_PROC);
        let mut buf: Vec<libc::proc_fdinfo> = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            count
        ];
        let bytes = (count * slot) as c_int;
        // SAFETY: buffer holds `count` entries and `bytes` says so.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr() as *mut c_void,
                bytes,
            )
        };
        if got <= 0 {
            return None;
        }
        buf.truncate(got as usize / slot);
        Some(
            buf.into_iter()
                .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
                .map(|f| f.proc_fd)
                .collect(),
        )
    }

    /// Normalise one socket descriptor, or `None` if it is not an inbound- or
    /// outbound-addressed IP socket we can describe.
    fn describe(pid: c_int, fd: c_int) -> Option<Observed> {
        let mut info = std::mem::MaybeUninit::<SocketFdInfo>::zeroed();
        let size = std::mem::size_of::<SocketFdInfo>() as c_int;
        // SAFETY: `info` is exactly `size` bytes and the kernel is told so. A
        // short write is rejected below rather than read as valid.
        let got = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                info.as_mut_ptr() as *mut c_void,
                size,
            )
        };
        if got != size {
            // EPERM for another uid's process, or a descriptor closed under us.
            return None;
        }
        // SAFETY: the kernel wrote a full struct's worth, checked above.
        let info = unsafe { info.assume_init() };
        let psi = &info.psi;

        if psi.soi_family != libc::AF_INET && psi.soi_family != libc::AF_INET6 {
            return None;
        }

        // Both arms of the union start with an `in_sockinfo`, so addresses read
        // the same way; only the state needs to know which kind it is.
        let ini = &psi.soi_proto.tcp.tcpsi_ini;
        let (proto, state) = match psi.soi_kind {
            SOCKINFO_TCP => ("tcp", map_tcp_state(psi.soi_proto.tcp.tcpsi_state)?),
            SOCKINFO_IN if psi.soi_protocol == libc::IPPROTO_UDP => {
                // UDP has no state. A socket with a foreign address is a
                // connected datagram flow; one without is a listener, and a
                // listener is not a flow.
                ("udp", FlowState::Live)
            }
            _ => return None,
        };

        let remote_ip = render_addr(ini.insi_vflag, &ini.insi_faddr)?;
        let remote = Peer {
            ip: remote_ip,
            port: ntohs(ini.insi_fport),
            host: None,
        };
        // A flow with no peer port is not addressed anywhere yet.
        if remote.port == 0 {
            return None;
        }
        let local = render_addr(ini.insi_vflag, &ini.insi_laddr).map(|ip| Peer {
            ip,
            port: ntohs(ini.insi_lport),
            host: None,
        });

        Some(Observed {
            key: flow_key(ini.insi_gencnt, proto, local.as_ref(), &remote),
            proto: proto.to_string(),
            state,
            local,
            remote,
            pid: pid as u32,
        })
    }

    /// Absolute executable path for a pid, empty when it cannot be read.
    ///
    /// `key` is the one identity every source must produce, so an empty path is
    /// a reason to drop the flow rather than to emit an unattributable one.
    fn exe_path(pid: c_int) -> String {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buffer is exactly the length passed.
        let n = unsafe {
            libc::proc_pidpath(
                pid,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return String::new();
        }
        buf.truncate(n as usize);
        // The kernel writes a NUL-terminated path; take it as such rather than
        // trusting the returned length to exclude the terminator.
        match CStr::from_bytes_until_nul(&buf) {
            Ok(c) => c.to_string_lossy().into_owned(),
            Err(_) => String::from_utf8_lossy(&buf).into_owned(),
        }
    }
}

impl Source for LibprocSource {
    fn name(&self) -> &'static str {
        "libproc"
    }

    fn poll(&mut self) -> Result<Vec<Flow>, SourceError> {
        let pids = Self::list_pids()?;
        let mut denied = 0usize;
        let mut current: HashSet<String> = HashSet::new();
        let mut out: Vec<Flow> = Vec::new();
        let ts = now_ms();

        for pid in pids {
            let fds = match Self::socket_fds(pid) {
                Some(f) => f,
                None => {
                    denied += 1;
                    continue;
                }
            };
            let mut exe: Option<String> = None;
            for fd in fds {
                let ob = match Self::describe(pid, fd) {
                    Some(o) => o,
                    None => continue,
                };
                if !should_emit(&ob.key, &mut current, &self.seen) {
                    continue;
                }
                // Resolved once per process, and only for a process that
                // actually produced a flow.
                let path = exe.get_or_insert_with(|| Self::exe_path(pid));
                if path.is_empty() {
                    continue;
                }
                out.push(Flow {
                    schema: SCHEMA_VERSION,
                    kind: "flow".into(),
                    ts,
                    id: format!("lp:{}", ob.key),
                    source: SourceKind::Libproc,
                    state: ob.state,
                    app: App {
                        key: path.clone(),
                        name: None,
                        desktop: None,
                        icon: None,
                        pid: Some(ob.pid),
                        hash: None,
                        container: None,
                        system: false,
                    },
                    proto: ob.proto,
                    local: ob.local,
                    remote: ob.remote,
                    verdict: Verdict {
                        action: Action::Observed,
                        rule_id: None,
                        // This driver decides nothing. Reporting `default`
                        // would claim a verdict vallum never reached.
                        provenance: Provenance::Observation,
                    },
                    geo: None,
                    // No byte measurement is collected by this source. `None`
                    // means unmeasured, not measured-and-idle.
                    bytes: None,
                    new_network: false,
                    network_key: String::new(),
                });
            }
        }

        // A socket that was here last poll and is gone now is simply forgotten.
        //
        // That is a decision, not an omission. A disappearance is a definite
        // transition and could be emitted as `closed`, which would give macOS a
        // History the Linux build does not have — and that asymmetry is the
        // reason not to. `procfs` contributes nothing to History, `closed` stays
        // something only `opensnitch` produces, and the two platforms report the
        // same shape. It would also still be a partial record: a connection born
        // and closed inside one poll interval is never seen at all, so the
        // feature would arrive looking more complete than it is.
        //
        // Rebuilt from the live sample, so the set tracks open sockets rather
        // than growing for the lifetime of the daemon.
        self.seen = current;
        self.denied = denied;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_counts_are_entries_and_bounded() {
        assert_eq!(pid_capacity(800), 864);
        assert_eq!(pid_capacity(c_int::MAX), MAX_PIDS);
        let mut pids = vec![0, -1, 42, 43];
        retain_pids(&mut pids, c_int::MAX);
        assert_eq!(pids, vec![42, 43]);
        retain_pids(&mut pids, -1);
        assert!(pids.is_empty());
    }

    #[test]
    fn ipv4_address_is_read_from_the_last_four_bytes() {
        // The whole in4in6_addr trap in one assertion: 12 bytes of padding,
        // then the address. Reading from offset 0 gives 0.0.0.0 silently.
        let mut raw = [0u8; 16];
        raw[12..16].copy_from_slice(&[142, 250, 1, 1]);
        assert_eq!(render_addr(INI_IPV4, &raw).as_deref(), Some("142.250.1.1"));
    }

    #[test]
    fn unspecified_address_is_not_a_peer() {
        assert_eq!(render_addr(INI_IPV4, &[0u8; 16]), None);
        assert_eq!(render_addr(INI_IPV6, &[0u8; 16]), None);
    }

    #[test]
    fn ipv4_mapped_v6_collapses_to_its_v4_form() {
        // Otherwise the same peer keys two different network entries in the
        // seen-set and shows up twice in the panel.
        let mut raw = [0u8; 16];
        raw[10] = 0xff;
        raw[11] = 0xff;
        raw[12..16].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(render_addr(INI_IPV6, &raw).as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn ports_are_network_byte_order() {
        // 443 big-endian is 0x01BB; the kernel hands it over inside an int.
        assert_eq!(ntohs(0x0000_BB01_u32 as c_int), 443);
        assert_eq!(ntohs(0), 0);
    }

    #[test]
    fn listen_sockets_are_not_flows() {
        assert_eq!(map_tcp_state(TSI_S_LISTEN), None);
        assert_eq!(map_tcp_state(TSI_S_ESTABLISHED), Some(FlowState::Live));
        // An unnamed in-between state is still a connection.
        assert_eq!(map_tcp_state(6), Some(FlowState::Live));
    }

    #[test]
    fn teardown_states_never_become_history() {
        // A sampler that files whichever connections happened to die on a tick
        // boundary is reporting an arbitrary subset as a record. Matches
        // `procfs`, which drops these before a Connection is ever built.
        assert_eq!(map_tcp_state(TSI_S_CLOSED), None);
        assert_eq!(map_tcp_state(TSI_S_TIME_WAIT), None);
    }

    #[test]
    fn generation_count_separates_a_reconnect_from_its_predecessor() {
        // The reason identity is not the 5-tuple: same pid, same ports, same
        // peer, different socket instance. A key built from the tuple alone
        // would report the second connection as the first and never surface it.
        let remote = Peer {
            ip: "1.1.1.1".into(),
            port: 443,
            host: None,
        };
        let local = Peer {
            ip: "192.168.1.5".into(),
            port: 51000,
            host: None,
        };
        let a = flow_key(10, "tcp", Some(&local), &remote);
        let b = flow_key(11, "tcp", Some(&local), &remote);
        assert_ne!(a, b);
        assert_eq!(a, flow_key(10, "tcp", Some(&local), &remote));
    }

    #[test]
    fn one_socket_on_several_descriptors_is_emitted_once() {
        // Found on a live Mac, not in review: sshd holds its connection on more
        // than one fd, so the descriptor walk reaches the same socket twice and
        // the panel drew the same connection twice. Checking only the previous
        // poll's set cannot catch it, because both sightings are new.
        let seen = HashSet::new();
        let mut current = HashSet::new();
        let key = "4987471:tcp:10.99.1.3:22:10.99.1.1:60836";
        assert!(should_emit(key, &mut current, &seen));
        assert!(!should_emit(key, &mut current, &seen));
        assert!(!should_emit(key, &mut current, &seen));
    }

    #[test]
    fn a_socket_already_reported_last_poll_stays_quiet() {
        let mut seen = HashSet::new();
        seen.insert("k".to_string());
        let mut current = HashSet::new();
        assert!(!should_emit("k", &mut current, &seen));
        // ...but it is still recorded, or it would be re-announced next poll.
        assert!(current.contains("k"));
    }

    #[test]
    fn a_socket_with_no_local_endpoint_still_keys_stably() {
        let remote = Peer {
            ip: "8.8.8.8".into(),
            port: 53,
            host: None,
        };
        let k = flow_key(7, "udp", None, &remote);
        assert_eq!(k, flow_key(7, "udp", None, &remote));
        assert!(k.contains("8.8.8.8"));
    }
}
