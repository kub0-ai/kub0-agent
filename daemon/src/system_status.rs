//! Fixed, read-only system diagnostics. Never shares command/event framing.
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SYSTEM_STATUS_SOCKET: &str = crate::rename::STATUS_SOCKET;
pub const INSTALLED_CLI: &str = "/usr/lib/kub0/kub0d";
/// The local group that reads this socket and, on the system daemon, reaches
/// the command socket too (read and raise; lowering stays root's).
pub const STATUS_GROUP: &str = crate::rename::STATUS_GROUP;
use crate::rename::OLD_STATUS_GROUP;
const REQUEST: &[u8] = b"status\n";
const LIMIT: usize = 4096;
const DEADLINE: Duration = Duration::from_millis(750);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub mode: String,
    pub producer_version: String,
    pub observed_at: u64,
    #[serde(deserialize_with = "required_optional_bool")]
    pub policy_refresh_ok: Option<bool>,
    pub policy_known: bool,
    pub reported_last_applied_at: u64,
    pub current_kernel_verification: String,
}
fn required_optional_bool<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<bool>, D::Error> {
    Option::<bool>::deserialize(d)
}
#[derive(Default)]
pub struct PlanMetadata {
    /// Retired at the final account check; replans cannot revive this generation.
    pub account_retired: bool,
    pub known: bool,
    pub applied_at: u64,
    pub refresh_ok: Option<bool>,
}
pub type PlanState = Mutex<PlanMetadata>;
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Check every ancestor without following symlinks. No environment overrides.
pub fn protected_path(path: &Path, socket: bool) -> io::Result<()> {
    protected_path_until(path, socket, Path::new("/"))
}
// Private implementation seam: production always checks through filesystem root.
fn protected_path_until(path: &Path, socket: bool, end: &Path) -> io::Result<()> {
    if !path.is_absolute() || !path.starts_with(end) {
        return Err(invalid("absolute protected path required"));
    }
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if m.uid() != 0
            || m.file_type().is_symlink()
            || (m.mode() & 0o002 != 0 || ((!socket || ancestor != path) && m.mode() & 0o020 != 0))
        {
            return Err(invalid(
                "untrusted path ownership, symlink or writable mode",
            ));
        }
        if ancestor != path && !m.is_dir() {
            return Err(invalid("invalid ancestor"));
        }
        if ancestor == path {
            if socket {
                if !m.file_type().is_socket() || m.mode() & 0o7777 != 0o660 {
                    return Err(invalid("invalid status socket mode/type"));
                }
            } else if !m.is_file() || m.mode() & 0o6000 != 0 || m.mode() & 0o111 == 0 {
                return Err(invalid("invalid installed executable"));
            }
        }
        if ancestor == end {
            break;
        }
    }
    Ok(())
}
/// A root-owned, non-writable local account file, at most `cap` bytes.
fn trusted_file(path: &str, cap: u64) -> io::Result<Vec<u8>> {
    let f = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(invalid(&format!("untrusted {path}")));
    }
    let mut bytes = Vec::new();
    f.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(invalid(&format!("{path} too large")));
    }
    Ok(bytes)
}
fn local_group() -> io::Result<u32> {
    let bytes = trusted_file("/etc/group", 65536)?;
    let passwd = trusted_file("/etc/passwd", 1 << 20)?;
    // Absent is the defaults; present, it has to be as trustworthy as the rest.
    let login_defs = match trusted_file("/etc/login.defs", 1 << 20) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let (gid, _) = parse_group_with(&bytes, &passwd, &login_defs)?;
    Ok(gid)
}
/// The status group's GID from `/etc/group` (see `parse_group_named`).
#[cfg(test)]
fn parse_group(bytes: &[u8]) -> io::Result<u32> {
    parse_group_named(bytes).map(|(gid, _)| gid)
}
/// The status group from `/etc/group`, refused unless it is a system group
/// (per `/etc/login.defs`) that is no account's primary group in
/// `/etc/passwd`: a `kub0` group that was there first, a user's private
/// group say, is never handed the command socket.
fn parse_group_with(group: &[u8], passwd: &[u8], login_defs: &[u8]) -> io::Result<(u32, &'static str)> {
    let (gid, name) = parse_group_named(group)?;
    let passwd = std::str::from_utf8(passwd).map_err(|_| invalid("invalid /etc/passwd"))?;
    let login_defs = String::from_utf8_lossy(login_defs);
    if let Some(why) = crate::rename::status_group_refusal(name, gid, passwd, &login_defs) {
        return Err(invalid(&format!("{why}; the sockets stay root's")));
    }
    Ok((gid, name))
}
/// The status group's GID and its name, `kub0`. The 0.4.x group answered
/// for 0.4.5 and 0.4.6; now it has to be renamed (`kub0 install` does it in
/// place) before anyone but root reaches the sockets.
fn parse_group_named(bytes: &[u8]) -> io::Result<(u32, &'static str)> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid /etc/group"))?;
    // Validate every local row first: skipping malformed aliases can hide a
    // shared numeric GID that libc accepts. This is deliberately not NSS parsing.
    let mut groups = Vec::new();
    for line in text.lines() {
        // Only ASCII indentation marks local comments; Unicode whitespace may
        // belong to a libc group name and must reach strict row validation.
        let content = line.trim_start_matches([' ', '\t', '\n', '\r', '\x0c', '\x0b']);
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 4
            || fields[0].is_empty()
            || fields[0].starts_with(['+', '-'])
            || fields[0].contains(',')
            || line.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid("invalid local group entry; diagnostics unavailable"));
        }
        if fields[2].is_empty() || !fields[2].bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid local group gid; diagnostics unavailable"));
        }
        let gid: u32 = fields[2].parse()
            .map_err(|_| invalid("invalid local group gid; diagnostics unavailable"))?;
        groups.push((fields[0], gid));
    }
    let pick = |want: &str| -> io::Result<Option<u32>> {
        let mut matches = groups.iter().filter(|(name, _)| *name == want);
        let Some(&(_, gid)) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(invalid("duplicate status group"));
        }
        Ok(Some(gid))
    };
    // Both at once is never resolved by picking one: a `kub0` group that was
    // there first (a user's private group, say) must not be handed the
    // command socket.
    let (name, gid) = match (pick(STATUS_GROUP)?, pick(OLD_STATUS_GROUP)?) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                "both the kub0 and the vallum-status group exist; neither is used (kub0 install renames vallum-status to kub0 and refuses while both exist)",
            ))
        }
        (Some(gid), None) => (STATUS_GROUP, gid),
        (None, Some(_)) => {
            return Err(invalid(
                "the 0.4.x status group has not been renamed to kub0; run: sudo kub0 install (it renames the group in place, same GID and members)",
            ))
        }
        (None, None) => return Err(invalid("pre-existing kub0 group missing; diagnostics unavailable")),
    };
    if gid == 0 {
        return Err(invalid("status gid collides with root command group"));
    }
    if groups.iter().any(|(other, other_gid)| *other != name && *other_gid == gid) {
        return Err(invalid("status gid is shared by another local group"));
    }
    Ok((gid, name))
}
/// The connecting process's uid, from `SO_PEERCRED`. Shared with the command
/// socket's request path (`daemon/src/control.rs`).
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(invalid("invalid peer credential length"));
    }
    Ok(cred.uid)
}
#[cfg(target_os = "linux")]
fn root_peer(stream: &UnixStream) -> io::Result<()> {
    if peer_uid(stream)? != 0 {
        return Err(invalid("system peer is not root"));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn peer_uid(_: &UnixStream) -> io::Result<u32> {
    Err(invalid("SO_PEERCRED unavailable on this platform"))
}
#[cfg(not(target_os = "linux"))]
fn root_peer(_: &UnixStream) -> io::Result<()> {
    Err(invalid("Linux SO_PEERCRED diagnostics unavailable"))
}

fn read_eof(s: &mut UnixStream, limit: usize, until: Instant) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0; 129];
    loop {
        if Instant::now() >= until {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "status deadline"));
        }
        match s.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > limit {
                    return Err(invalid("status frame overflow"));
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e),
        }
    }
}
fn write_deadline(s: &mut UnixStream, mut bytes: &[u8], until: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= until {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "status deadline"));
        }
        match s.write(bytes) {
            Ok(0) => return Err(invalid("status write closed")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn serve(mut s: UnixStream, snapshot: &impl Fn() -> Status) -> io::Result<()> {
    s.set_nonblocking(true)?;
    let until = Instant::now() + DEADLINE;
    if read_eof(&mut s, 128, until)? != REQUEST {
        return Err(invalid("only fixed status request accepted"));
    }
    let bytes = serde_json::to_vec(&snapshot())?;
    if bytes.len() > LIMIT {
        return Err(invalid("status output overflow"));
    }
    write_deadline(&mut s, &bytes, until)
}
pub fn validate_response(bytes: &[u8]) -> io::Result<Status> {
    if bytes.len() > LIMIT {
        return Err(invalid("status output overflow"));
    }
    let v: Status = serde_json::from_slice(bytes)?;
    if v.mode != "system"
        || v.producer_version != env!("CARGO_PKG_VERSION")
        || v.current_kernel_verification != "unknown"
        || v.observed_at == 0
        || v.observed_at > now() + 1000
        || now().saturating_sub(v.observed_at) > 5000
        || v.reported_last_applied_at > v.observed_at
    {
        return Err(invalid("invalid or stale status fields"));
    }
    Ok(v)
}
#[cfg(target_os = "linux")]
fn connect_bounded(path: &Path) -> io::Result<UnixStream> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(invalid("socket path too long"));
    }
    for (a, b) in addr.sun_path.iter_mut().zip(bytes) {
        *a = *b as _;
    }
    let result = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as _,
        )
    };
    // Local nonblocking AF_UNIX connect succeeds immediately or fails, including
    // EAGAIN on a full backlog. Never wait for a flooded diagnostic listener.
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stream)
}
#[cfg(not(target_os = "linux"))]
fn connect_bounded(_: &Path) -> io::Result<UnixStream> {
    Err(invalid("Linux diagnostics unavailable"))
}
fn query(path: &Path) -> io::Result<Status> {
    protected_path(path, true)?;
    let mut s = connect_bounded(path)?;
    root_peer(&s)?;
    s.set_nonblocking(true)?;
    let until = Instant::now() + DEADLINE;
    write_deadline(&mut s, REQUEST, until)?;
    s.shutdown(std::net::Shutdown::Write)?;
    validate_response(&read_eof(&mut s, LIMIT, until)?)
}
pub fn client() -> io::Result<Status> {
    protected_path(Path::new(INSTALLED_CLI), false)?;
    let path = Path::new(SYSTEM_STATUS_SOCKET);
    let gid = local_group()?;
    if fs::symlink_metadata(path)?.gid() != gid
        || fs::symlink_metadata(path.parent().unwrap())?.gid() != gid
    {
        return Err(invalid("status authorization group mismatch"));
    }
    query(path)
}
fn chown(path: &Path, gid: u32) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("bad path"))?;
    if unsafe { libc::lchown(p.as_ptr(), 0, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
/// The status group's gid, from the same strict `/etc/group` read the
/// diagnostics socket uses. The system daemon's command socket is group-owned
/// by it too (`daemon/src/control.rs`: the group raises, root lowers).
pub fn status_group() -> io::Result<u32> {
    local_group()
}

/// The command socket's pathname metadata after setup: a root-owned socket,
/// mode 0660, in exactly `gid` (the status group, or 0 when it is missing).
pub fn verify_command(path: &Path, gid: u32) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    check_command(m.file_type().is_socket(), m.uid(), m.gid(), m.mode(), gid)
}

fn check_command(socket: bool, uid: u32, gid: u32, mode: u32, want_gid: u32) -> io::Result<()> {
    if !socket || uid != 0 || gid != want_gid || mode & 0o7777 != 0o660 {
        return Err(invalid(if want_gid == 0 {
            "command socket must remain root:root 0660"
        } else {
            "command socket must remain root:kub0 0660"
        }));
    }
    Ok(())
}
pub fn start(snapshot: impl Fn() -> Status + Send + 'static) -> io::Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(invalid("Linux diagnostics unavailable"));
    }
    let gid = local_group()?;
    let path = Path::new(SYSTEM_STATUS_SOCKET);
    let parent = path.parent().unwrap();
    // Verify before changing only the group, never group-write or setgid.
    for ancestor in parent.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != 0
            || m.mode() & 0o022 != 0
            || m.mode() & 0o6000 != 0
        {
            return Err(invalid("unprotected diagnostics parent"));
        }
    }
    chown(parent, gid)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_socket() || m.uid() != 0 {
            return Err(invalid("unsafe existing status path"));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    chown(path, gid)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    protected_path(path, true)?;
    if fs::symlink_metadata(path)?.gid() != gid || fs::symlink_metadata(parent)?.gid() != gid {
        return Err(invalid("status inode group mismatch"));
    }
    // One worker, one frame, backlog eight. No per-reader threads or event-loop work.
    if unsafe { libc::listen(listener.as_raw_fd(), 8) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::thread::Builder::new()
        .name("system-status".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let _ = serve(s, &snapshot);
                    }
                    Err(_) => break,
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status() -> Status {
        Status {
            mode: "system".into(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            observed_at: now(),
            policy_refresh_ok: Some(false),
            policy_known: true,
            reported_last_applied_at: now() - 100,
            current_kernel_verification: "unknown".into(),
        }
    }
    #[test]
    fn strict_allowlist_and_freshness() {
        let bytes = serde_json::to_vec(&status()).unwrap();
        assert!(validate_response(&bytes).is_ok());
        let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut missing = object.clone();
        missing.as_object_mut().unwrap().remove("policy_refresh_ok");
        assert!(validate_response(&serde_json::to_vec(&missing).unwrap()).is_err());
        missing = object.clone();
        missing["policy_known"] = serde_json::json!("true");
        assert!(validate_response(&serde_json::to_vec(&missing).unwrap()).is_err());
        object["token"] = "secret".into();
        assert!(validate_response(&serde_json::to_vec(&object).unwrap()).is_err());
        for bad in [b"{}".as_slice(), b"{", b"{}{}", b"null", &[b'x'; LIMIT + 1]] {
            assert!(validate_response(bad).is_err());
        }
        let mut old = status();
        old.observed_at = now() - 6000;
        assert!(validate_response(&serde_json::to_vec(&old).unwrap()).is_err());
        old = status();
        old.current_kernel_verification = "verified".into();
        assert!(validate_response(&serde_json::to_vec(&old).unwrap()).is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            "\"mode\":\"system\"",
            "\"mode\":\"system\",\"mode\":\"system\"",
        );
        assert!(validate_response(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn mutation_overflow_unknown_and_truncated_requests_never_call_snapshot() {
        for request in [
            b"pause\n".as_slice(),
            b"status\nstatus\n",
            b"status",
            b"{}",
            &[b'x'; 129],
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(request).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(serve(server, &|| panic!("invalid request reached snapshot")).is_err());
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
        }
    }
    #[test]
    fn valid_frame_reads_through_eof_and_observes_response_only() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(REQUEST).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let worker = std::thread::spawn(move || serve(server, &status).unwrap());
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        worker.join().unwrap();
        let v = validate_response(&bytes).unwrap();
        assert_eq!(v.current_kernel_verification, "unknown");
        assert!(v.policy_known);
        assert_eq!(v.policy_refresh_ok, Some(false));
    }
    #[test]
    fn slow_reader_and_partial_response_have_absolute_deadline() {
        let (_client, mut server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let start = Instant::now();
        assert!(read_eof(&mut server, 128, start + Duration::from_millis(25)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"{\"mode\":").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        server.set_nonblocking(true).unwrap();
        assert!(validate_response(
            &read_eof(&mut server, LIMIT, Instant::now() + DEADLINE).unwrap()
        )
        .is_err());
    }
    #[test]
    fn the_command_socket_is_root_owned_0660_in_exactly_the_expected_group() {
        const SOCK: bool = true;
        assert!(check_command(SOCK, 0, 981, 0o140660, 981).is_ok(), "root:kub0 0660");
        assert!(check_command(SOCK, 0, 0, 0o140660, 0).is_ok(), "root:root 0660 without the group");
        // A wrong owner, group or mode fails closed, in either direction.
        assert!(check_command(SOCK, 0, 0, 0o660, 981).is_err(), "root:root where the group was set");
        assert!(check_command(SOCK, 0, 981, 0o660, 0).is_err(), "a group where none was set");
        assert!(check_command(SOCK, 0, 982, 0o660, 981).is_err(), "another group");
        assert!(check_command(SOCK, 1000, 981, 0o660, 981).is_err(), "not root-owned");
        for mode in [0o666, 0o670, 0o760, 0o600, 0o2660, 0o4660] {
            assert!(check_command(SOCK, 0, 981, mode, 981).is_err(), "mode {mode:o}");
        }
        assert!(check_command(false, 0, 981, 0o660, 981).is_err(), "not a socket");
    }
    #[test]
    fn local_group_only_no_nss_fallback() {
        assert!(parse_group(b"root:x:0:\n").is_err());
        assert!(parse_group(b"kub0:x:0:reader\n").is_err());
        assert!(parse_group(b"other:x:1000:\nkub0:x:1000:reader\n").is_err());
        assert!(parse_group(b"kub0:x:1000:reader\nother:x:01000:\n").is_err());
        assert_eq!(parse_group(b"root:x:0:\nother:x:999:\nkub0:x:1000:reader\n").unwrap(), 1000);
        assert_eq!(parse_group(b"kub0:x:1000:reader\n").unwrap(), 1000);
        assert!(parse_group(b"kub0:x:1:\nkub0:x:2:\n").is_err());
        assert!(parse_group(b"kub0:x:not-a-gid:\n").is_err());
    }
    #[test]
    fn the_status_group_is_kub0_and_the_old_name_is_not_a_second_one() {
        assert_eq!(parse_group_named(b"kub0:x:981:alice\n").unwrap(), (981, "kub0"));
        // 0.4.5 and 0.4.6 used the 0.4.x group until `kub0 install` renamed
        // it. Now it is not the status group, and the error says what is.
        let old = format!("root:x:0:\n{OLD_STATUS_GROUP}:x:981:alice\n");
        let e = parse_group_named(old.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("has not been renamed to kub0") && e.contains("sudo kub0 install"), "{e}");
        let both = format!("kub0:x:1000:\n{OLD_STATUS_GROUP}:x:981:alice\n");
        let e = parse_group_named(both.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("neither is used"), "{e}");
    }
    #[test]
    fn the_status_group_is_refused_unless_a_system_group_nobody_has_as_primary() {
        let passwd = b"root:x:0:0::/root:/bin/sh\nkub0:x:1001:1001::/home/kub0:/bin/sh\n";
        assert_eq!(parse_group_with(b"kub0:x:981:alice\n", passwd, b"").unwrap(), (981, "kub0"));
        let e = parse_group_with(b"kub0:x:1001:\n", passwd, b"").unwrap_err().to_string();
        assert!(e.contains("outside this host's system GIDs") && e.contains("stay root's"), "{e}");
        let e = parse_group_with(b"kub0:x:981:\n", b"svc:x:900:981::/:/bin/false\n", b"").unwrap_err().to_string();
        assert!(e.contains("primary group of the account svc"), "{e}");
        let e = parse_group_with(b"kub0:x:981:\n", b"", b"SYS_GID_MIN 101\nSYS_GID_MAX 499\n").unwrap_err().to_string();
        assert!(e.contains("101-499"), "{e}");
    }
    #[test]
    fn local_group_rejects_malformed_aliases() {
        for alias in [
            "other:x: 1000:", "other:x:1000", "other:x:1000:reader:extra",
            "other:x:1000 :", "other:x:+1000:", "other:x:-1000:",
            "other:x:1_000:", "other:x::", "other:x:4294967296:",
            "other:x:unknown:", ":x:1000:", "+other:x:1000:",
            "other name:x:1000:", "other:x:999", "other:x:999:reader:extra",
        ] {
            for text in [
                format!("{alias}\nkub0:x:1000:reader\n"),
                format!("kub0:x:1000:reader\n{alias}\n"),
            ] {
                assert!(parse_group(text.as_bytes()).is_err(), "accepted {alias:?}");
            }
        }
        assert!(parse_group(b"kub0:x:+1000:reader\n").is_err());
        assert!(parse_group(b"kub0:x: 1000:reader\n").is_err());
        assert!(parse_group(b"kub0:x:1000:reader\nother:x:999:\xff\n").is_err());
        assert_eq!(parse_group(
            b"\n  # ignored:x:1000:extra:fields\n \nroot:x:0:\nother:x:00999:alice,bob\nkub0:x:01000:reader\n"
        ).unwrap(), 1000);
        assert_eq!(parse_group(b"other:x:4294967295:\nkub0:x:1:\n").unwrap(), 1);
    }
    #[test]
    fn local_group_rejects_unicode_comment_prefixes() {
        for prefix in ['\u{00a0}', '\u{2003}', '\u{0085}', '\u{2009}', '\u{3000}'] {
            let alias = format!("{prefix}#alias:x:1000:reader");
            for text in [
                format!("{alias}\nkub0:x:1000:\n"),
                format!("kub0:x:1000:\n{alias}\n"),
            ] {
                assert!(parse_group(text.as_bytes()).is_err(), "accepted {alias:?}");
            }
            // Unicode-only rows must be validated too, rather than treated as blank.
            assert!(parse_group(format!("{prefix}\nkub0:x:1000:\n").as_bytes()).is_err());
        }
    }
    #[test]
    fn local_group_preserves_ascii_comments_and_blank_rows() {
        for prefix in ["", " ", "\t", "\r", "\x0c", "\x0b", " \t\r\x0c\x0b"] {
            let comment = format!("{prefix}#alias:x:1000:reader Unicode: \u{00a0}\u{2003}\u{0085}\u{2009}\u{3000}");
            for text in [
                format!("{prefix}\r\n{comment}\r\nkub0:x:1000:\r\n"),
                format!("kub0:x:1000:\r\n{comment}\r\n{prefix}\r\n"),
            ] {
                assert_eq!(parse_group(text.as_bytes()).unwrap(), 1000, "rejected {prefix:?}");
            }
        }
    }
    #[test]
    fn private_path_rejections() {
        let dir = std::env::temp_dir().join(format!("kub0-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(protected_path(&path, true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        // /tmp is writable and must fail even under namespace UID0.
        assert!(protected_path(&path, true).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(protected_path(&link, true).is_err());
        assert!(protected_path(&dir.join("missing"), true).is_err());
        drop(listener);
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn actual_peer_credentials_reject_nonroot() {
        let (a, _) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
        let result = root_peer(&a);
        assert_eq!(
            result.is_ok(),
            unsafe { libc::geteuid() } == 0,
            "peer check: {result:?}"
        );
    }
    // Needs a private user namespace, and no sandbox that blocks sockets. Both
    // socket pathname and root peer are namespace-local, never host-root proof.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires private namespace UID0 and mapped UID/GID 1000"]
    fn namespace_authorization_fixture() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = std::env::temp_dir().join(format!("kub0-root-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        chown(&dir, 1000).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        let path = dir.join("status.sock");
        let listener = UnixListener::bind(&path).unwrap();
        chown(&path, 1000).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(protected_path_until(&path, true, &dir).is_ok());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(protected_path_until(&path, true, &dir).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(protected_path_until(&path, true, &dir).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let link = dir.join("linked.sock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(protected_path_until(&link, true, &dir).is_err());

        let command_path = dir.join("command.sock");
        let command = UnixListener::bind(&command_path).unwrap();
        chown(&command_path, 0).unwrap();
        fs::set_permissions(&command_path, fs::Permissions::from_mode(0o660)).unwrap();
        verify_command(&command_path, 0).unwrap();
        let worker = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            serve(s, &status).unwrap();
        });
        let run = |authorized: bool| {
            let mut child = std::process::Command::new("/usr/bin/setpriv");
            child.args(["--reuid", "1000"]);
            if authorized {
                child.args(["--regid", "1000", "--groups", "1000"]);
            } else {
                child.args(["--regid", "0", "--clear-groups"]);
            }
            child
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "system_status::tests::namespace_reader_probe",
                    "--ignored",
                    "--nocapture",
                ])
                .env("KUB0_PRIVATE_STATUS_DIR", &dir)
                .env(
                    "KUB0_PRIVATE_AUTHORIZED",
                    if authorized { "yes" } else { "no" },
                )
                .status()
                .unwrap()
                .success()
        };
        assert!(run(false));
        assert!(run(true));
        worker.join().unwrap();
        verify_command(&command_path, 0).unwrap();
        drop(command);
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "private child of namespace_authorization_fixture only"]
    fn namespace_reader_probe() {
        let dir = std::path::PathBuf::from(std::env::var("KUB0_PRIVATE_STATUS_DIR").unwrap());
        assert_eq!(unsafe { libc::geteuid() }, 1000);
        // A real non-root peer, not a mocked credential structure.
        let (s, _) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&s).unwrap(), 1000);
        assert!(root_peer(&s).is_err());
        let path = dir.join("status.sock");
        if std::env::var("KUB0_PRIVATE_AUTHORIZED").unwrap() == "no" {
            assert!(UnixStream::connect(&path).is_err());
            return;
        }
        protected_path_until(&path, true, &dir).unwrap();
        assert!(UnixStream::connect(dir.join("command.sock")).is_err());
        let mut s = connect_bounded(&path).unwrap();
        root_peer(&s).unwrap();
        let until = Instant::now() + DEADLINE;
        write_deadline(&mut s, REQUEST, until).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            validate_response(&read_eof(&mut s, LIMIT, until).unwrap())
                .unwrap()
                .mode,
            "system"
        );
    }
}
