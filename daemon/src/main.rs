use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use vallumd::activity::{self, ActivityApp, ActivityKind, ActivityLog};
use vallumd::event::{connection_id, now_ms, AppIdentity, Connection, DaemonMode, Endpoint, Event, Listener};
use vallumd::intel::{self, Severity};
use vallumd::flow::{Flow, Geo};
use vallumd::geo::GeoDb;
use vallumd::identity::{read_comm, read_exe, read_status_uid, unknown_identity, AppResolver};
use vallumd::kub0::{self, AccountFile, Kub0Runtime};
use vallumd::procfs::{parse_proc_net, ParsedSocket, Protocol};
use vallumd::seen::{network_key, SeenSet};
#[cfg(target_os = "macos")]
use vallumd::source::libproc::LibprocSource;
use vallumd::source::opensnitch::OpenSnitchSource;
use vallumd::source::{Backfill, Source, SourceError};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COVERAGE: &str = "tcp+connected-udp";
const UDP_TTL_MS: u64 = 30_000;
const UNKNOWN_LOG_CAP: usize = 10_000;

const SYSTEM_SOCKET: &str = vallumd::rename::SYSTEM_SOCKET;
const SYSTEM_STATE_DIR: &str = "/var/lib/kub0/daemon";
/// Where the system kub0d reads its geo databases. systemd starts it in `/`, where
/// the user-mode default (`data`, relative) finds nothing.
const SYSTEM_DATA_DIR: &str = "/usr/share/kub0";

struct Args {
    socket: PathBuf,
    interval: Duration,
    replay: Option<PathBuf>,
    replay_loop: bool,
    rdns: bool,
    mmdb: Option<PathBuf>,
    data_dir: PathBuf,
    state_dir: PathBuf,
    self_test: bool,
    source: SourceSel,
    os_db: Option<PathBuf>,
    os_settings: Option<PathBuf>,
    os_backfill: Backfill,
    os_time_utc: bool,
    emit_flows: bool,
    capture: bool,
    /// Send destination network keys on the heartbeat for org prevalence.
    share_destinations: bool,
    /// Per-user mode: move a 0.4.x `$XDG_STATE_HOME/vallum` to the default
    /// state directory before starting. Only the panel asks, when it starts
    /// its own daemon; a bare start never moves anything.
    migrate_state: bool,
    mode: DaemonMode,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SourceSel {
    Procfs,
    Opensnitch,
    /// Gated rather than accepted-and-refused elsewhere: a flag the binary
    /// cannot honour should not parse. `--source libproc` on Linux is an
    /// unknown source, which is what it is.
    #[cfg(target_os = "macos")]
    Libproc,
}

/// The sources this build can actually run, for help and error text.
const SOURCE_NAMES: &str = if cfg!(target_os = "macos") {
    "procfs|opensnitch|libproc"
} else {
    "procfs|opensnitch"
};

fn default_socket() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("kub0.sock");
        }
    }
    PathBuf::from(format!("/tmp/kub0-{}.sock", uid_guess()))
}

fn uid_guess() -> u32 {
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join(vallumd::rename::USER_STATE_NAME);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/state").join(vallumd::rename::USER_STATE_NAME)
}

/// The temp root an explicit `--state-dir` sits under, if any.
///
/// Account state must survive temporary-file cleanup. Only explicit overrides are
/// checked; private test environments can still use temporary XDG/HOME defaults.
fn temp_root_of(dir: &Path) -> Option<PathBuf> {
    temp_root_of_with(dir, &std::env::temp_dir())
}

fn temp_root_of_with(dir: &Path, extra_root: &Path) -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = [
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/dev/shm",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    roots.push(extra_root.to_path_buf());
    let abs = std::path::absolute(dir).ok()?;
    let lexical = normalize_absolute_path(&abs);
    let resolved = resolve_existing_parent(&abs);
    // An empty or "/" TMPDIR would otherwise match every path and refuse them all.
    for root in roots.into_iter().filter(|r| !r.as_os_str().is_empty()) {
        let Ok(root) = std::path::absolute(root) else {
            continue;
        };
        let resolved_root = resolve_existing_parent(&root);
        let root = normalize_absolute_path(&root);
        if root.parent().is_none() {
            continue;
        }
        // Check both the supplied path and its target: a temporary symlink can
        // disappear even when its target is durable. Resolve existing parents
        // before appending new components, since the state directory may not exist.
        if [&root, &resolved_root].into_iter().any(|candidate| {
            candidate.parent().is_some()
                && (lexical.starts_with(candidate) || resolved.starts_with(candidate))
        }) {
            return Some(root);
        }
    }
    None
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn resolve_existing_parent(path: &Path) -> PathBuf {
    for parent in path.ancestors() {
        if let Ok(resolved) = parent.canonicalize() {
            let suffix = path
                .strip_prefix(parent)
                .expect("ancestor is a path prefix");
            return normalize_absolute_path(&resolved.join(suffix));
        }
    }
    normalize_absolute_path(path)
}

fn temp_state_dir_message(dir: &Path, root: &Path) -> String {
    format!(
        "refusing --state-dir {}: it is under temporary storage {}. Cleanup could delete \
         account.json and stop heartbeats. Use a durable path such as {} \
         (the system-mode default), or omit --state-dir to use your configured default.",
        dir.display(),
        root.display(),
        SYSTEM_STATE_DIR
    )
}

fn default_socket_for(mode: DaemonMode) -> PathBuf {
    match mode {
        DaemonMode::System => PathBuf::from(SYSTEM_SOCKET),
        DaemonMode::User => default_socket(),
    }
}

fn default_state_dir_for(mode: DaemonMode) -> PathBuf {
    match mode {
        DaemonMode::System => PathBuf::from(SYSTEM_STATE_DIR),
        DaemonMode::User => default_state_dir(),
    }
}

fn default_data_dir_for(mode: DaemonMode) -> PathBuf {
    match mode {
        DaemonMode::System => PathBuf::from(SYSTEM_DATA_DIR),
        DaemonMode::User => PathBuf::from("data"),
    }
}

fn socket_mode_bits(mode: DaemonMode) -> u32 {
    match mode {
        DaemonMode::System => 0o660,
        DaemonMode::User => 0o600,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    Help,
    Version,
    UnknownArgument(String),
    UnknownSource(String),
    UnknownBackfill(String),
    MissingStateDir,
    MissingDataDir,
    /// (the --state-dir given, the temp root it sits under)
    TempStateDir(PathBuf, PathBuf),
}

fn parse_args() -> Args {
    match try_parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(ParseError::Help) => {
            print_help();
            std::process::exit(0);
        }
        Err(ParseError::Version) => {
            println!("kub0d {VERSION}");
            std::process::exit(0);
        }
        Err(ParseError::UnknownArgument(other)) => {
            eprintln!("unknown argument: {other}");
            print_help();
            std::process::exit(2);
        }
        Err(ParseError::UnknownSource(other)) => {
            eprintln!("unknown source: {other} ({SOURCE_NAMES})");
            std::process::exit(2);
        }
        Err(ParseError::UnknownBackfill(other)) => {
            eprintln!("unknown backfill: {other} (none|today|all)");
            std::process::exit(2);
        }
        Err(ParseError::TempStateDir(dir, root)) => {
            eprintln!("{}", temp_state_dir_message(&dir, &root));
            std::process::exit(2);
        }
        Err(ParseError::MissingStateDir) => {
            eprintln!("--state-dir needs a nonempty path");
            std::process::exit(2);
        }
        Err(ParseError::MissingDataDir) => {
            eprintln!("--data-dir needs a nonempty path");
            std::process::exit(2);
        }
    }
}

fn try_parse_args<I, S>(argv: I) -> Result<Args, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut socket = None;
    let mut interval = Duration::from_millis(500);
    let mut replay = None;
    let mut replay_loop = false;
    let mut rdns = false;
    let mut mmdb = None;
    let mut data_dir = None;
    let mut state_dir = None;
    let mut self_test = false;
    let mut source = if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        { SourceSel::Libproc }
        #[cfg(not(target_os = "macos"))]
        { SourceSel::Procfs }
    } else { SourceSel::Procfs };
    let mut os_db = None;
    let mut os_settings = None;
    let mut system = false;
    // `Today` is the decided default, not a placeholder: replay from local
    // midnight, so History opens with context the user recognises and startup
    // stays bounded by one day of traffic however old the database is.
    //
    // The alternatives, kept because `--os-backfill` still accepts them:
    //   None — start at the newest row. Nothing is replayed, and the History
    //          tab is useless until traffic happens, which defeats the point of
    //          reading their database at all.
    //   All  — replay everything. The right flag for a forensic look at an
    //          established install; on a long-lived one it is also tens of
    //          thousands of flows through the enrichment path at startup.
    //
    // This looked like a safety question and is not. Backfilled rows are
    // separated from live ones structurally rather than by volume: every row
    // this driver emits carries `state: Closed` and `Provenance::External`, so
    // the ask/prompt path of `docs/SCHEMA.md` 4.1 keys on `state: Live` and
    // cannot see them whether three arrive or thirty thousand. Do not weaken
    // either field to make a display easier; they are what keeps the count
    // honest. See `docs/SCHEMA.md` 5.1.
    let mut os_backfill = Backfill::Today;
    let mut os_time_utc = false;
    let mut emit_flows = false;
    let mut capture = false;
    let mut share_destinations = false;
    let mut migrate_state = false;
    let mut args = argv.into_iter().map(|s| s.as_ref().to_string());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = Some(PathBuf::from(args.next().unwrap_or_default())),
            "--interval-ms" => {
                let ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(500);
                interval = Duration::from_millis(ms.max(100));
            }
            "--replay" => replay = args.next().map(PathBuf::from),
            "--replay-loop" => replay_loop = true,
            "--rdns" => rdns = true,
            "--mmdb" => mmdb = args.next().map(PathBuf::from),
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    args.next()
                        .filter(|s| !s.is_empty() && !s.starts_with('-'))
                        .ok_or(ParseError::MissingDataDir)?,
                ))
            }
            "--state-dir" => {
                let dir = PathBuf::from(
                    args.next()
                        .filter(|s| !s.is_empty() && !s.starts_with('-'))
                        .ok_or(ParseError::MissingStateDir)?,
                );
                if let Some(root) = temp_root_of(&dir) {
                    return Err(ParseError::TempStateDir(dir, root));
                }
                state_dir = Some(dir);
            }
            "--system" => system = true,
            "--self-test" => self_test = true,
            "--source" => {
                source = match args.next().unwrap_or_default().as_str() {
                    "procfs" => SourceSel::Procfs,
                    "opensnitch" => SourceSel::Opensnitch,
                    #[cfg(target_os = "macos")]
                    "libproc" => SourceSel::Libproc,
                    other => return Err(ParseError::UnknownSource(other.to_string())),
                }
            }
            "--os-db" => os_db = args.next().map(PathBuf::from),
            "--os-settings" => os_settings = args.next().map(PathBuf::from),
            "--os-backfill" => {
                os_backfill = match args.next().unwrap_or_default().as_str() {
                    "none" => Backfill::None,
                    "today" => Backfill::Today,
                    "all" => Backfill::All,
                    other => return Err(ParseError::UnknownBackfill(other.to_string())),
                }
            }
            "--os-time-utc" => os_time_utc = true,
            "--emit-flows" => emit_flows = true,
            "--capture" if cfg!(target_os = "linux") => capture = true,
            "--share-destinations" => share_destinations = true,
            "--migrate-state" => migrate_state = true,
            "-h" | "--help" => return Err(ParseError::Help),
            "--version" => return Err(ParseError::Version),
            other => return Err(ParseError::UnknownArgument(other.to_string())),
        }
    }
    let mode = if system {
        DaemonMode::System
    } else {
        DaemonMode::User
    };
    if migrate_state && mode == DaemonMode::System {
        // System state moves only in `kub0d migrate-state` (the unit's
        // ExecStartPre) and in `kub0 install`, never on a start.
        return Err(ParseError::UnknownArgument("--migrate-state with --system (system state moves only in `kub0d migrate-state`)".into()));
    }
    Ok(Args {
        socket: socket.unwrap_or_else(|| default_socket_for(mode)),
        interval,
        replay,
        replay_loop,
        rdns,
        mmdb,
        data_dir: data_dir.unwrap_or_else(|| default_data_dir_for(mode)),
        state_dir: state_dir.unwrap_or_else(|| default_state_dir_for(mode)),
        self_test,
        source,
        os_db,
        os_settings,
        os_backfill,
        os_time_utc,
        emit_flows,
        capture,
        share_destinations,
        migrate_state,
        mode,
    })
}

fn print_help() {
    eprintln!(
        "kub0d {VERSION}\n\
         Unprivileged outbound connection monitor.\n\n\
         Commands:\n\
         connect [--json] [--server-url URL] [--auth-url URL] [--system] [--state-dir DIR]\n\
                             device-code login; writes a 0600 account file\n\
         status [--system] [--state-dir DIR]\n\
                             github username + node name (never the token)\n\
         disconnect [--system] [--state-dir DIR]\n\
                             delete the account file\n\
         history [--system] [--state-dir DIR] [--query TEXT] [--hours 1..168] [--format csv|ndjson]\n\
                             read-only export of local connection observations\n\n\
         --socket PATH       unix socket (default $XDG_RUNTIME_DIR/kub0.sock)\n\
         --interval-ms N     sample interval, default 500\n\
         --replay FILE       play canned NDJSON instead of /proc\n\
         --replay-loop       loop the replay file\n\
         --rdns              opt-in reverse DNS (off by default)\n\
         --mmdb PATH         DB-IP Country Lite .mmdb\n\
         --data-dir PATH     world/geo/flag assets (default ./data; /usr/share/kub0 with --system)\n\
         --state-dir PATH    durable account/history state (default ~/.local/state/kub0)\n\
         --system            root mode: /run/kub0/kub0.sock (0660), /var/lib/kub0/daemon,\n\
                             geo databases from /usr/share/kub0\n\
         --self-test         parse built-in fixtures and exit\n\n\
         --source NAME       procfs (Linux default) | opensnitch | libproc (macOS default)\n\
         --emit-flows        also write raw vallum v0 flow records\n\n\
         --capture           optional Linux user-mode connect/UDP attempts; requires root-owned collector\n\
         --share-destinations  send /24 and /48 keys of new public destinations on the kub0 heartbeat\n\
                             for org prevalence (never addresses or apps); off by default\n\
         --migrate-state     user mode: first move a 0.4.x ~/.local/state/vallum to the default state\n\
                             directory (one release; the panel passes it)\n\n\
         opensnitch source (read-only; never writes their database):\n\
         --os-db PATH        event database, bypassing settings discovery\n\
         --os-settings PATH  settings.conf (default ~/.config/opensnitch/settings.conf)\n\
         --os-backfill WHEN  none | today (default) | all\n\
         --os-time-utc       read their timestamps as UTC instead of local"
    );
}

/// Destination sharing when the daemon starts: the flag, or on the system daemon what
/// `kub0 share on` saved. A user daemon is started by the panel with the flag its
/// own switch decides, so it reads no file.
fn share_destinations_at_start(flag: bool, mode: DaemonMode, state_dir: &Path) -> bool {
    flag || (mode == DaemonMode::System && kub0::load_settings(state_dir).share_destinations)
}

fn account_file_path_mode(mode: DaemonMode, state_dir: &Path) -> PathBuf {
    kub0::account_path_for(mode == DaemonMode::System, state_dir)
}

fn boot_kub0(mode: DaemonMode, state_dir: &Path, runtime: &Kub0Runtime) -> PathBuf {
    let system = mode == DaemonMode::System;
    let account_path = account_file_path_mode(mode, state_dir);
    if !system {
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()));
        let _ = kub0::try_adopt_account(false, &account_path, &home);
    }
    if let Some(a) = kub0::read_account(&account_path) {
        runtime.set_connected(true);
        runtime.set_github_username(&a.github_username);
        runtime.publish_fleet(kub0::FleetSnapshot {
            connected: true,
            ..Default::default()
        });
    } else {
        runtime.set_connected(false);
        runtime.publish_fleet(kub0::FleetSnapshot::default());
    }
    account_path
}

/// System mode only: the gate runs unless `KUB0_EXEC_GATE=0`. User mode does
/// not read the variable and logs nothing (fanotify permission events need
/// CAP_SYS_ADMIN, which the per-user daemon never has).
///
/// The gate is told which account is on disk, so it can arm from the org list saved
/// under that account before the first sync. With no account file the gate starts
/// without the saved list and the copy is removed. A file that does not read names no
/// account either, but says nothing about the copy: it stays, and the heartbeat's
/// first tick that reads the file settles it.
fn start_exec_gate(mode: DaemonMode, account_path: &Path) {
    if mode != DaemonMode::System {
        return;
    }
    if vallumd::rename::env("KUB0_EXEC_GATE").as_deref() == Some("0") {
        eprintln!("exec gate disabled by KUB0_EXEC_GATE=0");
        return;
    }
    match kub0::load_account(account_path) {
        Ok(Some(a)) => vallumd::execgate::start(Some(&kub0::account_id(&a))),
        Ok(None) => {
            vallumd::execgate::start(None);
            // No account, no org list. A daemon that stopped before its heartbeat saw
            // the logout left the copy on disk, and without an account no heartbeat
            // runs here to remove it.
            vallumd::execgate::clear_fleet();
        }
        Err(_) => vallumd::execgate::start(None),
    }
}

/// Closes the fanotify group fd when the daemon returns. A signal that kills
/// the process closes it too: the kernel then allows every pending exec.
struct ExecGateGuard;

impl Drop for ExecGateGuard {
    fn drop(&mut self) {
        vallumd::execgate::shutdown();
    }
}

/// The rename's one-time move of a 0.4.x state directory
/// (`rename::move_state`), said in the journal. `false` only when state is
/// still waiting at `old` because the kernel refused the move; the caller
/// then runs from there rather than from an empty new directory.
fn move_state_logged(old: &Path, new: &Path) -> bool {
    use vallumd::rename::Moved;
    let (o, n) = (old.display(), new.display());
    match vallumd::rename::move_state(old, new) {
        Ok(Moved::Moved) => {
            eprintln!("kub0d: moved {o} to {n}; its account, exec-gate trusts and scoped records came with it");
            true
        }
        Ok(Moved::NothingToMove) => true,
        Ok(Moved::BothExist) => {
            eprintln!("kub0d: {n} and {o} both hold state; using {n} and leaving {o} untouched (check it, then remove it by hand)");
            true
        }
        Err(e) => {
            eprintln!("kub0d: cannot move {o} to {n} ({e}); nothing was moved, and this run keeps using {o}");
            false
        }
    }
}

/// `kub0d migrate-state`: the system unit's `ExecStartPre=+`, run outside the
/// sandbox that keeps `/var/lib` read-only for the daemon itself (a rename
/// needs write access to the parent). It moves `/var/lib/vallum` when it
/// should and otherwise makes sure `/var/lib/kub0` exists, so the unit's
/// `ReadWritePaths=` has a directory to bind. It exits 0 even when the move
/// fails: the daemon then runs from the old directory rather than not at all.
fn migrate_state_command(rest: &[String]) -> i32 {
    use vallumd::rename::{present, OLD_STATE_ROOT, STATE_ROOT};
    if !rest.is_empty() {
        eprintln!("migrate-state accepts no arguments");
        return 2;
    }
    let (old, new) = (Path::new(OLD_STATE_ROOT), Path::new(STATE_ROOT));
    if let Some(why) = old_system_daemon() {
        eprintln!("kub0d: {why}; {OLD_STATE_ROOT} stays where it is");
        return 0;
    }
    move_state_logged(old, new);
    if !present(old) && !present(new) {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().recursive(true).mode(0o755).create(new) {
            eprintln!("kub0d: cannot create {STATE_ROOT}: {e}");
        }
    }
    0
}

/// Before anything opens state, pick the default state directory in use.
/// A start never moves system state: only `kub0d migrate-state` (the unit's
/// `ExecStartPre`) and `kub0 install` do, so a run by hand while a stopped
/// 0.4.x install still owns `/var/lib/vallum` leaves it where it is. The
/// per-user daemon moves `$XDG_STATE_HOME/vallum` only with
/// `--migrate-state`, which the panel passes, and never while a 0.4.x user
/// daemon runs. Where a move fails, this run is pinned to the old directory,
/// as the journal says. Any other `--state-dir` is used as given.
fn prepare_state(args: &mut Args) {
    use vallumd::rename;
    match args.mode {
        DaemonMode::System => {
            if args.state_dir != Path::new(SYSTEM_STATE_DIR) {
                return;
            }
            args.state_dir = rename::state_path("daemon");
        }
        DaemonMode::User => {
            let default = default_state_dir();
            if args.state_dir != default {
                return;
            }
            let Some(old) = default.parent().map(|p| p.join(rename::OLD_USER_STATE_NAME)) else {
                return;
            };
            args.state_dir = if !args.migrate_state {
                rename::current(&default, &old)
            } else if let Some(why) = old_user_daemon(&old) {
                // This run shares its directory, as two runs always did.
                eprintln!("kub0d: {why}; {} stays where it is", old.display());
                rename::current(&default, &old)
            } else if move_state_logged(&old, &default) {
                rename::current(&default, &old)
            } else {
                old
            };
        }
    }
    let _ = std::fs::create_dir_all(&args.state_dir);
}

/// Why a 0.4.x system daemon counts as running, if one does: a root process
/// whose argv[0] is a `vallumd` run with `--system`, or a live socket at its
/// old path. Its state directory must not move while it runs.
fn old_system_daemon() -> Option<String> {
    if vallumd::rename::old_daemon_running_in(Path::new("/proc"), 0, vallumd::rename::OldDaemon::System) {
        return Some("a 0.4.x system daemon (vallumd --system) is still running".into());
    }
    let sock = Path::new(vallumd::rename::OLD_SYSTEM_SOCKET);
    old_daemon_running(sock).then(|| format!("a 0.4.x daemon still answers on {}", sock.display()))
}

/// The same for this user's 0.4.x per-user daemon using `old` (the
/// directory about to move): found by its process, whatever socket it was
/// given, never by a socket path that could belong to another directory.
fn old_user_daemon(old: &Path) -> Option<String> {
    let uid = unsafe { libc::geteuid() };
    vallumd::rename::old_daemon_running_in(Path::new("/proc"), uid, vallumd::rename::OldDaemon::User(old))
        .then(|| format!("a 0.4.x per-user daemon (vallumd) is still running on {}", old.display()))
}

/// A 0.4.x daemon is listening at `old_socket`: a real socket there (not
/// the link 0.4.5 and 0.4.6 left) that accepts a connection. Its state directory
/// must not move while it runs.
fn old_daemon_running(old_socket: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::symlink_metadata(old_socket).is_ok_and(|m| m.file_type().is_socket())
        && std::os::unix::net::UnixStream::connect(old_socket).is_ok()
}

/// The client verbs moved to `kub0` (#61 step 2). Each old verb answers with
/// the command that replaced it and exits non-zero, so a script that still
/// calls it fails loudly rather than reading nothing.
fn retired_client_verb(verb: &str) -> Option<&'static str> {
    match verb {
        "connect" => Some("kub0 login"),
        "disconnect" => Some("kub0 logout"),
        "status" => Some("kub0 whoami"),
        "history" => Some("kub0 history"),
        "brief" => Some("kub0 brief"),
        "investigate" => Some("kub0 why <app|ip|kind:value>"),
        "timeline" => Some("kub0 intel --timeline"),
        "watch" => Some("kub0 watches, kub0 watch add|rm"),
        _ => None,
    }
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(verb) = argv.first() {
        if let Some(instead) = retired_client_verb(verb) {
            // The name it was run as.
            let me = Path::new(&argv0).file_name().and_then(|n| n.to_str()).unwrap_or("kub0d");
            eprintln!("{me} {verb} is retired; use: {instead}");
            std::process::exit(2);
        }
    }
    match argv.first().map(|s| s.as_str()) {
        Some("migrate-state") => std::process::exit(migrate_state_command(&argv[1..])),
        Some("system-status") => {
            if argv.len() != 1 {
                eprintln!("system-status accepts no arguments");
                std::process::exit(2);
            }
            match vallumd::system_status::client() {
                Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
                Err(e) => {
                    eprintln!("system status unavailable: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        _ => {}
    }
    let mut args = parse_args();
    if args.capture
        && (args.mode != DaemonMode::User
            || args.source != SourceSel::Procfs
            || args.replay.is_some())
    {
        eprintln!("--capture requires Linux user-mode procfs monitoring");
        std::process::exit(2);
    }
    if args.self_test {
        match run_self_test() {
            Ok(()) => {
                println!("self-test ok");
                return;
            }
            Err(e) => {
                eprintln!("self-test failed: {e}");
                std::process::exit(1);
            }
        }
    }
    // After the self-test, which opens no state and must never move any.
    prepare_state(&mut args);
    if args.rdns {
        eprintln!("kub0d: reverse-DNS is on (opt-in). This performs outbound lookups.");
    }
    if let Some(path) = &args.replay {
        if let Err(e) = run_replay(path, &args) {
            eprintln!("kub0d replay failed: {e}");
            std::process::exit(1);
        }
        return;
    }
    let r = match args.source {
        SourceSel::Procfs => run_live(&args),
        SourceSel::Opensnitch => run_opensnitch(&args),
        #[cfg(target_os = "macos")]
        SourceSel::Libproc => run_libproc(&args),
    };
    if let Err(e) = r {
        eprintln!("kub0d: {e}");
        std::process::exit(1);
    }
}

/// How much history a reconnecting client is handed.
///
/// A source backed by a database can produce far more rows than a socket
/// sampler ever will, and the snapshot is re-serialised to every client that
/// connects. Bounded so that a long backfill cannot turn every reconnect into a
/// multi-megabyte write.
const HISTORY_CAP: usize = 500;
/// A source flow older than this is replayed history, not a new connection, and is
/// never counted against a network-policy rule.
const POLICY_FRESH_MS: u64 = 10 * 60 * 1000;

/// Serve flows read out of OpenSnitch's event database.
///
/// The driver reports only what the source actually said. Geo lookup and
/// new-network detection are vallum's own and belong here, not in the driver:
/// every future source gets the same enrichment for free, and the driver stays
/// a thing that can be reasoned about as "does it faithfully read their table".
fn run_opensnitch(args: &Args) -> Result<(), String> {
    let mut src = match &args.os_db {
        Some(p) => OpenSnitchSource::open_db(p, args.os_backfill, args.os_time_utc),
        None => OpenSnitchSource::open(
            args.os_settings.as_deref(),
            args.os_backfill,
            args.os_time_utc,
        ),
    }
    .map_err(|e| match e {
        // Not installed or not configured to keep a file is the common case on
        // a machine that simply does not run OpenSnitch. Say what to do about
        // it rather than printing a stack of nouns.
        SourceError::Unavailable(m) => format!(
            "opensnitch source unavailable: {m}\n\
             hint: in OpenSnitch, Preferences -> Database -> Database type: File"
        ),
        SourceError::Failed(m) => format!("opensnitch source failed: {m}"),
    })?;

    // Built before the loop takes the source as a trait object: the database
    // path is OpenSnitch's own detail, and widening `Source` with a method that
    // exists to decorate one log line would put it in every future driver.
    let detail = format!(
        "db={} backfill={}",
        src.db_path().display(),
        match args.os_backfill {
            Backfill::None => "none",
            Backfill::Today => "today",
            Backfill::All => "all",
        }
    );
    run_source(args, &mut src, "opensnitch", &detail)
}

/// macOS live socket sampling. The Darwin analogue of `run_live`.
///
/// Construction cannot fail: unlike the OpenSnitch driver there is no database
/// to find and no other program that has to be installed and configured. The
/// first `poll` is where a real failure would surface.
#[cfg(target_os = "macos")]
fn run_libproc(args: &Args) -> Result<(), String> {
    let mut src = LibprocSource::new();
    run_source(args, &mut src, "libproc", "")
}

/// Drive any source: poll, enrich, project down to the legacy record, publish.
///
/// A source-specific entry point does exactly two things — build its source and
/// say what to call it in the status line. Everything after that is identical
/// for all of them, which is the point of the `Source` trait: a second copy of
/// this loop is how listen and intercept turn into two products.
fn run_source(
    args: &Args,
    src: &mut dyn Source,
    label: &str,
    detail: &str,
) -> Result<(), String> {
    let geo = GeoDb::load(&args.data_dir, args.mmdb.as_deref());
    let mut seen = SeenSet::load(&args.state_dir);
    let kub0_rt = Kub0Runtime::new();
    kub0_rt.boot_netpolicy(&args.data_dir, &args.state_dir);
    kub0_rt.set_sharing_destinations(share_destinations_at_start(args.share_destinations, args.mode, &args.state_dir));
    let account_path = boot_kub0(args.mode, &args.state_dir, &kub0_rt);
    // Before the heartbeat thread, so its first refresh_fleet publishes keys.
    start_exec_gate(args.mode, &account_path);
    let _exec_gate = ExecGateGuard;
    let mut server = Server::bind(
        &args.socket,
        args.rdns,
        args.mode,
        Arc::clone(&kub0_rt),
        &args.state_dir,
    )
    .map_err(|e| format!("bind {}: {e}", args.socket.display()))?;
    let mut heartbeat = HeartbeatWatch::new(
        account_path,
        args.state_dir.clone(),
        Arc::clone(&kub0_rt),
        args.mode == DaemonMode::System,
    );
    let policy_asn = kub0_rt.asn();
    server.emit_boot(label);

    eprintln!(
        "kub0d: source={label} interval={}ms{}{detail}",
        args.interval.as_millis(),
        if detail.is_empty() { "" } else { " " }
    );
    if !geo.has_mmdb() {
        eprintln!("kub0d: no MMDB loaded from {}; country/arcs will be empty", args.data_dir.display());
    }
    if !kub0_rt.asn().has_mmdb() {
        eprintln!("kub0d: no ASN database in {}; block rules will not be enforced", args.data_dir.display());
    }

    let mut history: Vec<Connection> = Vec::new();
    let mut last_flush = Instant::now();
    loop {
        // The SIGTERM handler only sets a flag. This loop has to leave so
        // the exec-gate guard can shut the gate down.
        if vallumd::execgate::stop_requested() {
            break;
        }
        let t0 = Instant::now();
        server.accept_new(&history);
        for (from, cmd) in server.drain_commands() {
            handle_cmd(&cmd, None, &mut server, from);
        }

        match src.poll() {
            Ok(flows) => {
                for mut f in flows {
                    enrich(&mut f, &geo, &policy_asn, &mut seen);
                    if args.emit_flows {
                        server.broadcast(&f.to_line());
                    }
                    let mut conn = f.to_legacy();
                    // Backfilled history is not a new connection; counting it would
                    // report last week's traffic as today's policy matches.
                    if now_ms().saturating_sub(f.ts) < POLICY_FRESH_MS {
                        conn.policy = server.kub0.evaluate_connection(
                            &conn.remote.ip,
                            &conn.country,
                            &conn.exe,
                            f.ts,
                        );
                    }
                    if f.new_network {
                        server.emit_new_network(&conn.network_key, &conn.country, Some(&conn.app));
                    }
                    server.note_app(&conn.app);
                    history.retain(|c| c.id != conn.id);
                    history.push(conn.clone());
                    if history.len() > HISTORY_CAP {
                        history.drain(..history.len() - HISTORY_CAP);
                    }
                    server.broadcast(&Event::Connect { ts: f.ts, conn }.to_line());
                    server.kub0.note_connection();
                }
            }
            Err(e) => {
                // A source that stopped answering is not the same as a quiet
                // one, and the UI is told which. The loop keeps running: the
                // database can come back when opensnitch-ui is restarted.
                server.broadcast(
                    &Event::Status {
                        message: format!("{label}: {e}"),
                    }
                    .to_line(),
                );
            }
        }

        server.broadcast(
            &Event::Tick {
                ts: now_ms(),
                count: history.len(),
                scanned_fd_dirs: 0,
                unreadable_fd_dirs: 0,
            }
            .to_line(),
        );

        if last_flush.elapsed() > Duration::from_secs(5) {
            seen.flush();
            last_flush = Instant::now();
        }
        heartbeat.tick();
        if server.take_account_changed() {
            heartbeat.tick_force();
        }
        server.poll_kub0_activity();
        server.poll_exec_gate();
        server.poll_fleet(None);
        let spent = t0.elapsed();
        if !vallumd::execgate::stop_requested() && args.interval > spent {
            server.idle(args.interval - spent);
        }
    }
    Ok(())
}

/// Add what vallum knows on top of what the source reported.
fn enrich(f: &mut Flow, geo: &GeoDb, asn: &vallumd::geo::AsnDb, seen: &mut SeenSet) {
    let Ok(ip) = f.remote.ip.parse::<std::net::IpAddr>() else {
        return;
    };
    if let Some(hit) = geo.lookup(ip) {
        let (asn, org) = asn.lookup(ip).map(|(a, o)| (Some(a), o)).unwrap_or((None, None));
        f.geo = Some(Geo {
            country: hit.country,
            lat: hit.lat,
            lon: hit.lon,
            asn,
            org,
        });
    }
    let key = network_key(ip);
    // `observe` is stateful and returns "first time". Historical rows are fed
    // through the same seen-set as live ones on purpose: a prefix the user
    // already saw yesterday is not new today just because vallum restarted.
    f.new_network = seen.observe(&key, f.ts);
    f.network_key = key;
}

fn run_self_test() -> Result<(), String> {
    let tcp = include_str!("../../tests/fixtures/proc_net_tcp.txt");
    let rows = parse_proc_net(tcp, Protocol::Tcp, false);
    if rows.is_empty() {
        return Err("fixture produced zero tcp rows".into());
    }
    let udp = include_str!("../../tests/fixtures/proc_net_udp.txt");
    let urows = parse_proc_net(udp, Protocol::Udp, false);
    if !urows.iter().any(|s| s.remote_is_unspecified()) {
        return Err("expected an unresolved UDP row in fixture".into());
    }
    Ok(())
}

struct Server {
    listener: UnixListener,
    clients: Vec<Client>,
    rdns: bool,
    mode: DaemonMode,
    kub0: Arc<Kub0Runtime>,
    activity: ActivityLog,
    seen_apps: HashSet<String>,
    fleet_gen: u64,
    history: Option<vallumd::history::History>,
    history_error: String,
    capture_status: Option<vallumd::capture::Status>,
    /// Current listening sockets, for the greeting. `sample()` keeps it current.
    listeners: Vec<Listener>,
    /// The user's watch rules, for the greeting. `Live` owns the store.
    watch_rules: Vec<vallumd::watch::Rule>,
    /// Request/reply state for the `kub0` CLI (`daemon/src/control.rs`).
    next_client_id: u64,
    daemon_uid: u32,
    started_at: Instant,
    socket_path: PathBuf,
    state_dir: PathBuf,
    account_path: PathBuf,
    /// Set by a worker that wrote or removed the account file; the loop
    /// forces a heartbeat check so the change is live within a second
    /// rather than a heartbeat interval.
    account_changed: Arc<AtomicBool>,
    /// Replies produced off the loop (a login, a helper run), addressed by
    /// client id. Drained every loop with the commands.
    replies_tx: std::sync::mpsc::Sender<(u64, String)>,
    replies_rx: std::sync::mpsc::Receiver<(u64, String)>,
    /// Activity records produced off the loop: the outcome of a block or an
    /// unblock the daemon ran for a request. Drained with the replies.
    activity_tx: std::sync::mpsc::Sender<vallumd::activity::ActivityEntry>,
    activity_rx: std::sync::mpsc::Receiver<vallumd::activity::ActivityEntry>,
    /// The one login allowed at a time, with the flag that cancels it when
    /// its client goes away.
    login: Option<(u64, Arc<AtomicBool>)>,
}

struct Client {
    /// Stable for the client's life; the reply queue addresses by it, since
    /// the `clients` index moves when a dead client is dropped.
    id: u64,
    /// Who connected, from `SO_PEERCRED`. Decides what a request may do.
    peer: vallumd::control::Peer,
    stream: UnixStream,
    buf: Vec<u8>,
    /// Nothing more will ever be read from this client. It may still be
    /// listening, so it stays in the broadcast set, but it leaves the
    /// wait_io() read set: EOF polls as readable forever.
    eof: bool,
    out: vallumd::outq::OutQueue,
}

impl Client {
    /// False once the client is gone (or has stopped reading); drop it.
    fn send(&mut self, line: &str) -> bool {
        self.out.send(&mut self.stream, line) != vallumd::outq::Flush::Dead
    }
}

const MAX_CMD_BUF: usize = 64 * 1024;

/// Drain complete NDJSON lines (ending in `\n`) from `buf`. The remainder
/// stays so a split frame is not parsed or dropped.
fn take_complete_lines(buf: &mut Vec<u8>) -> Vec<String> {
    let mut cmds = Vec::new();
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = buf.drain(..=pos).collect();
        let s = String::from_utf8_lossy(&line);
        let s = s.trim();
        if !s.is_empty() {
            cmds.push(s.to_string());
        }
    }
    cmds
}

// Shared by every server source; user mode never starts a producer.
fn setup_system_diagnostics(
    mode: DaemonMode,
    kub0: &Arc<Kub0Runtime>,
    start: impl FnOnce(
        Box<dyn Fn() -> vallumd::system_status::Status + Send + Sync>,
    ) -> std::io::Result<()>,
) {
    if mode != DaemonMode::System {
        return;
    }
    let rt = Arc::clone(kub0);
    if let Err(e) = start(Box::new(move || system_snapshot(&rt))) {
        eprintln!("kub0d: system diagnostics unavailable: {e}");
    }
}

fn system_snapshot(rt: &Kub0Runtime) -> vallumd::system_status::Status {
    let plan = rt.system_plan.lock().unwrap();
    vallumd::system_status::Status {
        mode: "system".into(),
        producer_version: env!("CARGO_PKG_VERSION").into(),
        observed_at: now_ms(),
        policy_refresh_ok: plan.refresh_ok,
        policy_known: plan.known,
        reported_last_applied_at: plan.applied_at,
        current_kernel_verification: "unknown".into(),
    }
}

/// The group the system daemon's command socket is given: the status group
/// when it resolves, so its members reach the daemon (reads and raises; a
/// lowering verb still needs root), else root's, as before, with the reason
/// to log. Never anything for the user daemon, whose socket is 0600.
fn command_socket_gid(
    mode: DaemonMode,
    group: impl FnOnce() -> std::io::Result<u32>,
) -> (u32, Option<String>) {
    if mode != DaemonMode::System {
        return (0, None);
    }
    match group() {
        Ok(gid) if gid != 0 => (gid, None),
        Ok(_) => (0, Some("command socket stays root:root 0660: the status group resolved to gid 0".into())),
        Err(e) => (
            0,
            Some(format!(
                "command socket stays root:root 0660 (only root can reach the system daemon): {e}"
            )),
        ),
    }
}

/// `lchown` the command socket to root and `gid`. A group the kernel will not
/// take (an unmapped gid in a user namespace) leaves it root's, as before.
fn chown_command_socket(path: &Path, gid: u32) -> std::io::Result<u32> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "socket path has a NUL"))?;
    if unsafe { libc::lchown(p.as_ptr(), 0, gid) } == 0 {
        return Ok(gid);
    }
    let err = std::io::Error::last_os_error();
    if gid == 0 {
        return Err(err);
    }
    eprintln!("kub0d: command socket stays root:root 0660: chown to gid {gid}: {err}");
    if unsafe { libc::lchown(p.as_ptr(), 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(0)
}

fn validate_command_path(path: &Path) -> std::io::Result<()> {
    let absolute = std::path::absolute(path)?;
    let reserved = Path::new(vallumd::system_status::SYSTEM_STATUS_SOCKET);
    if normalize_absolute_path(&absolute) == reserved
        || resolve_existing_parent(&absolute) == resolve_existing_parent(reserved)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reserved system diagnostics socket cannot be a command socket",
        ));
    }
    Ok(())
}

impl Server {
    fn bind(
        path: &Path,
        rdns: bool,
        mode: DaemonMode,
        kub0: Arc<Kub0Runtime>,
        state_dir: &Path,
    ) -> std::io::Result<Self> {
        Self::bind_with_diagnostics(
            path,
            rdns,
            mode,
            kub0,
            state_dir,
            vallumd::system_status::status_group,
            |producer| vallumd::system_status::start(producer),
        )
    }

    fn bind_with_diagnostics(
        path: &Path,
        rdns: bool,
        mode: DaemonMode,
        kub0: Arc<Kub0Runtime>,
        state_dir: &Path,
        group: impl FnOnce() -> std::io::Result<u32>,
        start: impl FnOnce(
            Box<dyn Fn() -> vallumd::system_status::Status + Send + Sync>,
        ) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        validate_command_path(path)?;
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(socket_mode_bits(mode)),
            );
        }
        // The group the system daemon's command socket is in. Its members
        // may read and raise (`daemon/src/control.rs`); 0 keeps it root's.
        let mut gid = 0;
        if mode == DaemonMode::System {
            let (wanted, why) = command_socket_gid(mode, group);
            if let Some(why) = why {
                eprintln!("kub0d: {why}");
            }
            gid = chown_command_socket(path, wanted)?;
            vallumd::system_status::verify_command(path, gid)?;
        }
        setup_system_diagnostics(mode, &kub0, start);
        if mode == DaemonMode::System {
            vallumd::system_status::verify_command(path, gid)?;
        }
        let activity = ActivityLog::load(state_dir);
        let (replies_tx, replies_rx) = std::sync::mpsc::channel();
        let (activity_tx, activity_rx) = std::sync::mpsc::channel();
        let (history, history_error) = match vallumd::history::History::open(state_dir, now_ms()) {
            Ok(h) => (Some(h), String::new()),
            Err(e) => {
                eprintln!("kub0d: history unavailable: {e}");
                (None, e)
            }
        };
        Ok(Self {
            listener,
            clients: Vec::new(),
            rdns,
            mode,
            kub0,
            activity,
            seen_apps: HashSet::new(),
            fleet_gen: 0,
            history,
            history_error,
            capture_status: None,
            listeners: Vec::new(),
            watch_rules: Vec::new(),
            next_client_id: 1,
            daemon_uid: current_uid(),
            started_at: Instant::now(),
            socket_path: path.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            account_path: account_file_path_mode(mode, state_dir),
            account_changed: Arc::new(AtomicBool::new(false)),
            replies_tx,
            replies_rx,
            activity_tx,
            activity_rx,
            login: None,
        })
    }

    fn flush_history(&mut self) {
        if let Some(history) = self.history.as_mut() {
            self.history_error = match history.flush(now_ms()) {
                Ok(()) => String::new(),
                Err(e) => {
                    eprintln!("kub0d: history write failed: {e}");
                    e
                }
            };
        }
    }

    fn accept_new(&mut self, snapshot: &[Connection]) {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let peer = vallumd::control::Peer {
                        uid: vallumd::system_status::peer_uid(&stream).ok(),
                    };
                    let id = self.next_client_id;
                    self.next_client_id += 1;
                    let mut c = Client {
                        id,
                        peer,
                        stream,
                        buf: Vec::new(),
                        eof: false,
                        out: vallumd::outq::OutQueue::new(vallumd::outq::DEFAULT_CAP),
                    };
                    let hello = Event::Hello {
                        requests: true,
                        as_uid: true,
                        version: VERSION.into(),
                        pid: std::process::id(),
                        coverage: COVERAGE.into(),
                        rdns: self.rdns,
                        mode: self.mode,
                        account: self.kub0.hello_account(),
                    };
                    if !c.send(&hello.to_line()) {
                        continue;
                    }
                    if let Some(status) = &self.capture_status {
                        if !c.send(
                            &Event::CaptureStatus {
                                ts: now_ms(),
                                status: status.clone(),
                            }
                            .to_line(),
                        ) {
                            continue;
                        }
                    }
                    let fleet = self.kub0.fleet_event(now_ms());
                    if !c.send(&fleet.to_line()) {
                        continue;
                    }
                    let replay = self.activity.replay_newest(activity::HELLO_REPLAY);
                    let act = Event::Activity { entries: replay };
                    if !c.send(&act.to_line()) {
                        continue;
                    }
                    // Additive frames: an older panel ignores a type it does
                    // not know (Health.classifyLine reports `unknown`).
                    if !c.send(
                        &Event::Listeners {
                            ts: now_ms(),
                            listeners: self.listeners.clone(),
                        }
                        .to_line(),
                    ) {
                        continue;
                    }
                    if !c.send(
                        &Event::Watchlist {
                            ts: now_ms(),
                            rules: self.watch_rules.clone(),
                            error: String::new(),
                        }
                        .to_line(),
                    ) {
                        continue;
                    }
                    let snap = Event::Snapshot {
                        ts: now_ms(),
                        connections: snapshot.to_vec(),
                    };
                    if c.send(&snap.to_line()) {
                        self.clients.push(c);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn broadcast(&mut self, line: &str) {
        self.clients.retain_mut(|c| c.send(line));
    }

    /// Wait out the rest of a sample interval. With output held back for a
    /// client, wait in short slices and keep flushing, so a large greeting
    /// reaches a slow reader in well under a second rather than one socket
    /// buffer per sample.
    fn idle(&mut self, dur: Duration) {
        let until = Instant::now() + dur;
        while self.clients.iter().any(|c| !c.out.is_empty()) {
            if vallumd::execgate::stop_requested() {
                return;
            }
            let now = Instant::now();
            if now >= until {
                return;
            }
            std::thread::sleep((until - now).min(Duration::from_millis(10)));
            self.flush_pending();
        }
        // thread::sleep restarts after EINTR, so one sleep would hide SIGTERM
        // for the whole remainder.
        while Instant::now() < until {
            if vallumd::execgate::stop_requested() {
                return;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(200)));
        }
    }

    /// Push out whatever a full socket held back earlier.
    fn flush_pending(&mut self) {
        self.clients.retain_mut(|c| {
            c.out.is_empty() || c.out.flush(&mut c.stream) != vallumd::outq::Flush::Dead
        });
    }

    fn drain_commands(&mut self) -> Vec<(u64, String)> {
        // Every loop that reads commands also comes through here, so this is
        // where held-back output gets its next chance to go out.
        self.flush_pending();
        self.deliver_replies();
        let mut cmds = Vec::new();
        for c in &mut self.clients {
            let mut tmp = [0u8; 4096];
            loop {
                match c.stream.read(&mut tmp) {
                    Ok(0) => {
                        c.eof = true;
                        break;
                    }
                    Ok(n) => {
                        c.buf.extend_from_slice(&tmp[..n]);
                        let id = c.id;
                        cmds.extend(take_complete_lines(&mut c.buf).into_iter().map(|l| (id, l)));
                        if c.buf.len() > MAX_CMD_BUF {
                            c.buf.clear();
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        c.eof = true;
                        break;
                    }
                }
            }
        }
        cmds
    }

    /// Wait for a command or new client while flushing queued output whenever
    /// a socket becomes writable. A pending greeting must not lose the IPC
    /// wake that brings the panel out of battery passive mode.
    fn wait_io(&mut self, timeout: Duration) {
        use std::os::fd::AsRawFd;
        Self::wait_io_clients(self.listener.as_raw_fd(), &mut self.clients, timeout);
    }

    fn wait_io_clients(listener_fd: std::os::fd::RawFd, clients: &mut Vec<Client>, timeout: Duration) {
        use std::os::fd::AsRawFd;
        let until = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= until {
                return;
            }
            let mut fds = vec![libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            for c in clients.iter() {
                let mut events = 0;
                if !c.eof {
                    events |= libc::POLLIN;
                }
                if !c.out.is_empty() {
                    events |= libc::POLLOUT;
                }
                if events != 0 {
                    fds.push(libc::pollfd {
                        fd: c.stream.as_raw_fd(),
                        events,
                        revents: 0,
                    });
                }
            }
            let remaining = until - now;
            let ms = remaining.as_millis().max(1).min(libc::c_int::MAX as u128) as libc::c_int;
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    if vallumd::execgate::stop_requested() {
                        return;
                    }
                    continue;
                }
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                return;
            }
            if rc == 0 {
                return;
            }
            let input = fds.iter().any(|fd| fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0);
            clients.retain_mut(|c| {
                c.out.is_empty() || c.out.flush(&mut c.stream) != vallumd::outq::Flush::Dead
            });
            if input {
                return;
            }
        }
    }

    fn emit_boot(&mut self, source: &str) {
        self.emit_kind(ActivityKind::DaemonStart, None, serde_json::json!({}));
        self.emit_kind(
            ActivityKind::SourceChanged,
            None,
            serde_json::json!({ "source": source }),
        );
        self.poll_kub0_activity();
    }

    fn push_activity(&mut self, entry: vallumd::activity::ActivityEntry) {
        match self.activity.append(entry) {
            Ok(stored) => {
                let ev = Event::Activity {
                    entries: vec![stored],
                };
                self.broadcast(&ev.to_line());
            }
            Err(e) => eprintln!("kub0d: activity append failed: {e}"),
        }
    }

    fn emit_kind(&mut self, kind: ActivityKind, app: Option<ActivityApp>, detail: serde_json::Value) {
        self.push_activity(vallumd::activity::ActivityEntry::new(
            now_ms(),
            kind,
            app,
            detail,
        ));
    }

    fn note_app(&mut self, app: &AppIdentity) {
        if app.id.is_empty() {
            return;
        }
        if !self.seen_apps.insert(app.id.clone()) {
            return;
        }
        self.emit_kind(
            ActivityKind::AppFirstSeen,
            Some(ActivityApp {
                id: app.id.clone(),
                name: app.name.clone(),
            }),
            serde_json::json!({}),
        );
    }

    fn emit_new_network(&mut self, network: &str, country: &str, app: Option<&AppIdentity>) {
        let app = app.map(|a| ActivityApp {
            id: a.id.clone(),
            name: a.name.clone(),
        });
        self.emit_kind(
            ActivityKind::NewNetwork,
            app,
            serde_json::json!({ "network": network, "country": country }),
        );
    }

    fn poll_kub0_activity(&mut self) {
        let acct = self.kub0.hello_account();
        let fresh = self
            .activity
            .observe_kub0(now_ms(), acct.connected, acct.last_heartbeat_ok);
        for e in fresh {
            let ev = Event::Activity { entries: vec![e] };
            self.broadcast(&ev.to_line());
        }
    }

    /// Matches from the exec gate become activity entries (live in system
    /// mode; in user mode mirrored from the system daemon's state file), and a
    /// changed gate frame re-broadcasts the fleet event. Nothing here leaves
    /// the machine: the deny names a local path and is never on the heartbeat.
    fn poll_exec_gate(&mut self) {
        let polled = vallumd::execgate::poll();
        for deny in polled.events {
            let app = ActivityApp {
                id: format!("exec:{}", deny.sha256),
                name: deny.comm.clone(),
            };
            let detail = serde_json::to_value(&deny).unwrap_or_else(|_| serde_json::json!({}));
            self.push_activity(vallumd::activity::ActivityEntry::new(
                deny.ts,
                ActivityKind::ExecGateDeny,
                Some(app),
                detail,
            ));
        }
        if polled.changed {
            self.kub0.touch_fleet();
        }
    }

    fn poll_fleet(&mut self, live: Option<&mut Live>) {
        let gen = self.kub0.fleet_generation();
        if gen == self.fleet_gen {
            return;
        }
        self.fleet_gen = gen;
        let ev = self.kub0.fleet_event(now_ms());
        self.broadcast(&ev.to_line());
        let Some(live) = live else { return };
        let reports = self.kub0.fleet_snapshot().fleet_tags;
        if retag_unattributed(live, &reports) {
            let snap = Event::Snapshot {
                ts: now_ms(),
                connections: live.snapshot(),
            };
            self.broadcast(&snap.to_line());
        }
    }
}

struct HeartbeatWatch {
    path: PathBuf,
    state_dir: PathBuf,
    runtime: Arc<Kub0Runtime>,
    handle: Option<JoinHandle<()>>,
    interval: Duration,
    last_check: Instant,
    system: bool,
}

impl HeartbeatWatch {
    fn new(path: PathBuf, state_dir: PathBuf, runtime: Arc<Kub0Runtime>, system: bool) -> Self {
        let interval = kub0::heartbeat_interval();
        let mut watch = Self {
            path,
            state_dir,
            runtime,
            handle: None,
            interval,
            last_check: Instant::now(),
            system,
        };
        watch.tick_force();
        watch
    }

    fn tick(&mut self) {
        if self.last_check.elapsed() < self.interval {
            return;
        }
        self.tick_force();
    }

    fn tick_force(&mut self) {
        self.last_check = Instant::now();
        if !self.system {
            let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()));
            let _ = kub0::try_adopt_account(false, &self.path, &home);
        }
        let dead = self
            .handle
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(true);
        if dead {
            self.handle = spawn_heartbeat_thread(
                self.path.clone(),
                self.state_dir.clone(),
                Arc::clone(&self.runtime),
                self.system,
            );
        }
    }
}

/// Dedicated thread. Not started when the account file is absent.
fn spawn_heartbeat_thread(
    account_path: PathBuf,
    state_dir: PathBuf,
    runtime: Arc<Kub0Runtime>,
    system: bool,
) -> Option<JoinHandle<()>> {
    if !account_path.is_file() {
        runtime.set_connected(false);
        return None;
    }
    Some(std::thread::spawn(move || {
        heartbeat_loop(account_path, state_dir, runtime, system);
    }))
}

fn http_agent() -> ureq::Agent {
    vallumd::device::http_agent()
}

/// POST /ingest/heartbeat. Failures are logged here and never returned to sampling.
/// Tags never fail the heartbeat: an unreadable body yields no fleet reports.
fn post_heartbeat(
    agent: &ureq::Agent,
    server_url: &str,
    token: &str,
    node_name: &str,
    lsm_capable: bool,
    event_count: u64,
    blocks_active: u64,
    tags: Vec<kub0::HeartbeatTag>,
    policy_matches: Vec<vallumd::netpolicy::MatchReport>,
    dest_networks: Vec<String>,
) -> Result<(u16, Vec<vallumd::tags::FleetReport>, Option<Vec<kub0::Prevalence>>), String> {
    let url = kub0::heartbeat_url(server_url);
    let payload = kub0::heartbeat_payload(
        node_name,
        VERSION,
        lsm_capable,
        event_count,
        blocks_active,
        tags,
        policy_matches,
        dest_networks,
    );
    match agent
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send_json(&payload)
    {
        Ok(mut resp) => {
            let code = resp.status().as_u16();
            let (reports, prevalence) = if code == 200 {
                match resp.body_mut().read_json::<serde_json::Value>() {
                    Ok(v) => (kub0::parse_fleet_tags(&v), kub0::parse_prevalence(&v)),
                    Err(_) => (Vec::new(), None),
                }
            } else {
                (Vec::new(), None)
            };
            Ok((code, reports, prevalence))
        }
        Err(e) => Err(kub0::redact_secret(&e.to_string(), token)),
    }
}

/// POST /ingest/outcomes: the status and, past 2xx, up to 200 chars of the body
/// (the kub0 API names the refused field there). Err is a transport failure.
fn post_outcomes(
    agent: &ureq::Agent,
    url: &str,
    token: &str,
    report: &vallumd::outcomes::Report,
) -> Result<(u16, String), String> {
    match agent
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .send_json(report)
    {
        Ok(mut resp) => {
            let code = resp.status().as_u16();
            let body = if (200..300).contains(&code) {
                String::new()
            } else {
                resp.body_mut()
                    .read_to_string()
                    .unwrap_or_default()
                    .chars()
                    .take(200)
                    .collect()
            };
            Ok((code, body))
        }
        Err(e) => Err(kub0::redact_secret(&e.to_string(), token)),
    }
}

fn get_json(agent: &ureq::Agent, url: &str, token: &str) -> Result<serde_json::Value, String> {
    let mut resp = agent
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|e| kub0::redact_secret(&e.to_string(), token))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("HTTP {status}"));
    }
    resp.body_mut()
        .read_json()
        .map_err(|e| kub0::redact_secret(&e.to_string(), token))
}

/// GET the org network policy. `Ok(None)` is a 304: unchanged. Only a 200 whose body
/// has a `policies` array this build reads in full replaces the set (see
/// `netpolicy::parse`), and `[]` is how the server says "none". A 404 is a route that was
/// never reached (an older server, a missing ingress), so it is an error like any other:
/// the caller keeps enforcing the last set it received.
fn fetch_netpolicy(
    agent: &ureq::Agent,
    url: &str,
    token: &str,
    etag: &str,
) -> Result<Option<vallumd::netpolicy::PolicySet>, String> {
    let mut req = agent
        .get(url)
        .header("Authorization", format!("Bearer {token}"));
    if !etag.is_empty() {
        req = req.header("If-None-Match", etag);
    }
    let mut resp = req
        .call()
        .map_err(|e| kub0::redact_secret(&e.to_string(), token))?;
    match resp.status().as_u16() {
        // "Unchanged" only means something against a set the server gave: a 304 to a
        // request that named no ETag (a fresh process, a new account) is not an answer.
        304 if etag.is_empty() => Err("HTTP 304 to a request without an ETag".into()),
        304 => Ok(None),
        200 => {
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let v: serde_json::Value = resp
                .body_mut()
                .read_json()
                .map_err(|e| kub0::redact_secret(&e.to_string(), token))?;
            vallumd::netpolicy::parse(&v, &etag).map(Some)
        }
        code => Err(format!("HTTP {code}")),
    }
}

/// Refresh last-good fleet from `/api/nodes` and `/api/enforce/denylist`.
/// Failures are never fatal; last-good numbers are kept. The caller publishes
/// only after confirming that the account still matches the request's account.
fn refresh_fleet(
    agent: &ureq::Agent,
    server_url: &str,
    token: &str,
    node: &str,
    runtime: &Kub0Runtime,
    last_ok: Option<bool>,
    last_ts: u64,
    last_err: &mut String,
    fleet_tags: Option<Vec<vallumd::tags::FleetReport>>,
) -> kub0::FleetSnapshot {
    // Built by kub0::*_url, not from a shared base: the deny-list is served
    // under /detonate and the other two are not. See kub0::deny_list_url.
    let nodes_url = kub0::nodes_url(server_url);
    let deny_url = kub0::deny_list_url(server_url);
    let mut snap = runtime.fleet_snapshot();
    snap.connected = runtime.hello_account().connected;
    snap.last_heartbeat_ok = last_ok;
    snap.last_heartbeat_ts = last_ts;
    let mut errs: Vec<String> = Vec::new();
    match get_json(agent, &nodes_url, token) {
        Ok(v) => {
            match kub0::parse_endpoints(&v) {
                Ok(endpoints) => {
                    let (org, limit, state) = kub0::parse_nodes(&v, node);
                    snap.org_endpoints = org;
                    snap.node_limit = limit;
                    snap.self_state = state;
                    snap.endpoints = endpoints;
                    snap.endpoints_updated_at = now_ms();
                    snap.endpoints_refresh_ok = Some(true);
                }
                Err(e) => {
                    snap.endpoints_refresh_ok = Some(false);
                    errs.push(e.into());
                }
            }
        }
        Err(e) => {
            snap.endpoints_refresh_ok = Some(false);
            errs.push(format!("nodes: {e}"));
        }
    }
    match get_json(agent, &deny_url, token) {
        // A 200 that carries no `entries` at all is not the org's list (an error body, a
        // proxy's page, another API shape). Read as an empty list it would take out the
        // gate's keys and the copy on disk with them. `"entries": null` is a list: an
        // empty one.
        Ok(v) if v.get("entries").is_none() => {
            errs.push("denylist: HTTP 200 without an entries field".into());
        }
        Ok(v) => {
            let (ver, entries) = kub0::parse_denylist(&v);
            snap.denylist_version = ver;
            snap.denylist_reported = kub0::denylist_reported_len(&v);
            snap.denylist = entries;
            // No-op unless the system exec gate is running. User mode never starts it.
            // `denylist` is capped for the panel. The second argument is the org's
            // full row count, so a list over 500 rows does not replace the key set.
            //
            // Here and not after a failed fetch: the snapshot's rows are then whatever
            // this process last held, which after a restart is nothing, and handing
            // the gate nothing would take out the keys it loaded from disk at start.
            vallumd::execgate::publish(&snap.denylist, snap.denylist_reported);
        }
        Err(e) => errs.push(format!("denylist: {e}")),
    }
    runtime.set_policy_floor(kub0::host_policy_floor(server_url));
    let etag = runtime.policies().etag.clone();
    match fetch_netpolicy(agent, &kub0::netpolicy_url(server_url, node), token, &etag) {
        Ok(Some(set)) => {
            runtime.set_policies(set);
            snap.netpolicy_refresh_ok = Some(true);
        }
        Ok(None) => snap.netpolicy_refresh_ok = Some(true),
        Err(e) => {
            snap.netpolicy_refresh_ok = Some(false);
            errs.push(format!("netpolicy: {e}"));
        }
    }
    snap.netpolicies = runtime.policy_view();
    if let Some(tags) = fleet_tags {
        snap.fleet_tags = tags;
    }
    if !errs.is_empty() {
        let msg = kub0::redact_secret(&errs.join("; "), token);
        if msg != *last_err {
            eprintln!("kub0d: fleet fetch failed: {msg}; keeping last-good");
            *last_err = msg;
        }
    } else {
        last_err.clear();
    }
    snap
}

/// One heartbeat thread's state between ticks.
struct Heartbeat {
    account_path: PathBuf,
    state_dir: PathBuf,
    runtime: Arc<Kub0Runtime>,
    system: bool,
    agent: ureq::Agent,
    logged_401: bool,
    logged_429: bool,
    last_fleet_err: String,
    /// The last account-file error logged, so a file that stays unreadable logs once.
    last_account_err: String,
    prior_account: Option<kub0::AccountFile>,
    enforcer: Enforcer,
    server_url: String,
    /// The deny-list stream thread for the current account, if one runs.
    stream: Option<Arc<vallumd::sse::StreamState>>,
    stream_account: Option<kub0::AccountFile>,
    /// `KUB0_DENYLIST_STREAM=0` keeps the 60 s poll as the only source.
    /// The heartbeat tests set this false: their fake API is one thread.
    stream_enabled: bool,
    /// The outcomes channel (daemon/src/outcomes.rs). `None` in user mode, whose
    /// gate frame is a mirror of the system daemon's, and under `KUB0_OUTCOMES=0`.
    outcomes: Option<vallumd::outcomes::Ledger>,
    /// The last outcomes error logged, so a server that stays down logs once.
    last_outcomes_err: String,
}

impl Heartbeat {
    fn new(
        account_path: PathBuf,
        state_dir: PathBuf,
        runtime: Arc<Kub0Runtime>,
        system: bool,
        enforcer: Enforcer,
    ) -> Self {
        let outcomes = if system && vallumd::outcomes::enabled() {
            Some(vallumd::outcomes::Ledger::new(
                Some(&state_dir),
                VERSION,
                vallumd::outcomes::interval(),
                now_ms() / 1000,
            ))
        } else {
            None
        };
        Self {
            account_path,
            state_dir,
            runtime,
            system,
            agent: http_agent(),
            logged_401: false,
            logged_429: false,
            last_fleet_err: String::new(),
            last_account_err: String::new(),
            prior_account: None,
            enforcer,
            server_url: String::new(),
            stream: None,
            stream_account: None,
            stream_enabled: vallumd::rename::env("KUB0_DENYLIST_STREAM").as_deref() != Some("0"),
            outcomes,
            last_outcomes_err: String::new(),
        }
    }

    /// Keep one deny-list stream open for the account the heartbeat runs as.
    /// A new token or server means a new stream; the old one is told to stop
    /// and notices between reads.
    fn ensure_stream(&mut self, account: &kub0::AccountFile) {
        if !self.stream_enabled {
            return;
        }
        if self.stream.is_some() && self.stream_account.as_ref() == Some(account) {
            return;
        }
        self.stop_stream();
        let state = vallumd::sse::StreamState::new();
        let url = self.server_url.clone();
        let token = account.token.clone();
        let runtime = Arc::clone(&self.runtime);
        let st = Arc::clone(&state);
        match std::thread::Builder::new()
            .name("denylist-stream".into())
            .spawn(move || vallumd::sse::run(url, token, runtime, st))
        {
            Ok(_) => {
                self.stream = Some(state);
                self.stream_account = Some(account.clone());
            }
            Err(e) => eprintln!("kub0d: deny-list stream thread did not start: {e}"),
        }
    }

    fn stop_stream(&mut self) {
        if let Some(state) = self.stream.take() {
            state.stop.store(true, std::sync::atomic::Ordering::Release);
        }
        self.stream_account = None;
        self.runtime.set_denylist_live(None);
    }

    /// One heartbeat: post, refresh the fleet and the org policy, and bring the kernel in
    /// line with it. False once the thread should stop: the account is gone and its
    /// block rules are out of the kernel.
    fn tick(&mut self) -> bool {
        let runtime = Arc::clone(&self.runtime);
        if !self.system {
            let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()));
            let _ = kub0::try_adopt_account(false, &self.account_path, &home);
        }
        let account = match kub0::load_account(&self.account_path) {
            Ok(Some(account)) => account,
            Ok(None) => return self.disconnected(),
            Err(e) => {
                // Unreadable is not absent: a connect caught mid-write, or a file this
                // process cannot read, says nothing about the org's policy. The kernel and
                // the last policy received stay as they are until it reads again.
                self.account_unreadable(e);
                runtime.set_last_ok(false);
                return true;
            }
        };
        self.last_account_err.clear();
        if self.prior_account.as_ref() != Some(&account) {
            // Policies belong to an org: a new account starts from none, not the last org's.
            runtime.set_policies(vallumd::netpolicy::PolicySet::default());
            // That empty set is not this account's answer. Until its server gives one,
            // the kernel keeps the rules it holds (a token rotation is a change too).
            self.enforcer.policy_known = false;
            if let Ok(mut plan) = runtime.system_plan.lock() {
                plan.known = false;
            }
            let _ = runtime.drain_policy_matches();
            runtime.publish_fleet(kub0::FleetSnapshot {
                connected: true,
                ..Default::default()
            });
            self.last_fleet_err.clear();
            // The lists that follow are this account's, and so is the copy the gate
            // keeps on disk. No-op for the account the gate started with.
            vallumd::execgate::set_account(&kub0::account_id(&account));
            self.prior_account = Some(account.clone());
        }
        if let Ok(mut plan) = runtime.system_plan.lock() {
            plan.account_retired = false;
        }
        runtime.set_connected(true);
        runtime.set_github_username(&account.github_username);
        let lsm_capable = kub0::read_lsm_capable();
        let node = kub0::node_name();
        let event_count = runtime.event_count();
        self.server_url = kub0::heartbeat_server_url(&account);
        self.ensure_stream(&account);
        // Read fresh each tick: the customer blocks and unblocks between heartbeats, and
        // this is the number kub0 shows as the endpoint's protection state.
        let blocks_active = kub0::read_blocks_active(&kub0::owners_path());
        // Connected is true here: we just set it. tags_for_heartbeat_dir still
        // gates on it so a future reorder cannot upload while disconnected, and
        // a missing/corrupt store yields [] rather than failing the POST.
        let tags = kub0::tags_for_heartbeat_dir(runtime.hello_account().connected, &self.state_dir);
        let policy_matches = runtime.drain_policy_matches();
        let sent = policy_matches.clone();
        let dest_networks = runtime.drain_networks();
        let sent_networks = dest_networks.clone();
        let deferred = kub0::defer_heartbeat_to_system(
            self.system,
            kub0::system_account_path().is_file(),
            kub0::system_daemon_running(),
        );
        if runtime.set_heartbeat_deferred(deferred) != deferred {
            eprintln!(
                "{}",
                if deferred {
                    "kub0d: heartbeat: the system daemon is logged in and running; it reports this host"
                } else {
                    "kub0d: heartbeat: no logged-in system daemon; reporting this host"
                }
            );
        }
        // Deferred, this daemon sends nothing: the matches and networks it drained are the
        // host's, and the system daemon reports the host from its own monitor.
        let (hb_ok, fleet_tags) = if deferred {
            (true, None)
        } else {
            match post_heartbeat(
                &self.agent,
                &self.server_url,
                &account.token,
                &node,
                lsm_capable,
                event_count,
                blocks_active,
                tags,
                policy_matches,
                dest_networks,
            ) {
                Ok((200, reports, prevalence)) => {
                    runtime.set_last_ok(true);
                    // Recorded only when sharing: a server's silence about keys we
                    // never sent says nothing about whether it answers them.
                    if runtime.sharing_destinations() {
                        runtime.apply_prevalence(prevalence);
                    }
                    (true, Some(reports))
                }
                Ok((401, ..)) => {
                    runtime.set_last_ok(false);
                    if !self.logged_401 {
                        eprintln!("kub0d: heartbeat 401 (bad key); keeping monitor");
                        self.logged_401 = true;
                    }
                    (false, None)
                }
                Ok((429, ..)) => {
                    runtime.set_last_ok(false);
                    if !self.logged_429 {
                        eprintln!("kub0d: heartbeat 429 (node limit reached); keeping monitor");
                        self.logged_429 = true;
                    }
                    (false, None)
                }
                Ok((code, ..)) => {
                    runtime.set_last_ok(false);
                    eprintln!("kub0d: heartbeat HTTP {code}; keeping monitor");
                    (false, None)
                }
                Err(e) => {
                    runtime.set_last_ok(false);
                    eprintln!(
                        "kub0d: heartbeat failed: {}; keeping monitor",
                        kub0::redact_secret(&e, &account.token)
                    );
                    (false, None)
                }
            }
        };
        if !hb_ok {
            // Undelivered counts and keys go back for the next attempt.
            runtime.restore_policy_matches(sent);
            runtime.restore_networks(sent_networks);
        }
        let ts = now_ms();
        runtime.set_last_heartbeat_ts(ts);
        self.flush_outcomes(&account.token);
        let mut snap = refresh_fleet(
            &self.agent,
            &self.server_url,
            &account.token,
            &node,
            &runtime,
            (!deferred).then_some(hb_ok),
            ts,
            &mut self.last_fleet_err,
            fleet_tags,
        );
        if deferred {
            // What kub0 shows for this host is what the system daemon sends.
            snap.last_heartbeat_ok = kub0::deferred_heartbeat_ok(&snap.self_state);
            match snap.last_heartbeat_ok {
                Some(ok) => runtime.set_last_ok(ok),
                None => runtime.clear_last_ok(),
            }
        }
        // Only a policy the server gave (a 200, or a 304 of one) makes an empty set an
        // answer; a failed fetch leaves it unknown.
        if snap.netpolicy_refresh_ok == Some(true) {
            self.enforcer.policy_known = true;
        }
        self.enforcer.sync(&runtime, self.system, &self.server_url);
        snap.netpolicies = runtime.policy_view();
        snap.netpolicy_enforcement = (*runtime.enforcement()).clone();
        // The frame is this tick's only while the file still names the account it ran as:
        // gone or replaced since, it goes out empty and the next tick starts over. One that
        // cannot be read right now (a connect caught between truncate and write) is not a
        // disconnect, and says nothing changed, so this tick's frame stands.
        match kub0::load_account(&self.account_path) {
            Ok(Some(now)) if now == account => runtime.publish_fleet(snap),
            Err(e) => {
                self.account_unreadable(e);
                runtime.publish_fleet(snap);
            }
            Ok(_) => {
                runtime.set_connected(false);
                self.enforcer.retire_diagnostics(&runtime);
                runtime.publish_fleet(kub0::FleetSnapshot::default());
            }
        }
        true
    }

    /// The outcomes channel: fold this tick's gate counters into the ledger and send
    /// what kub0 has not accepted yet, oldest window first. A system daemon whose gate
    /// is off has a frame that is not `live`, and the ledger ignores it.
    fn flush_outcomes(&mut self, token: &str) {
        use vallumd::outcomes::Delivery;
        let Some(ledger) = self.outcomes.as_mut() else { return };
        let frame = vallumd::execgate::frame();
        ledger.tick_frame(&frame, now_ms() / 1000);
        if ledger.pending() == 0 {
            return;
        }
        let url = vallumd::outcomes::outcomes_url(&self.server_url);
        let agent = &self.agent;
        let mut err = String::new();
        ledger.drain(vallumd::outcomes::DRAIN_PER_TICK, |report| {
            match post_outcomes(agent, &url, token, report) {
                Ok((code, _)) if (200..300).contains(&code) => {
                    let rows: Vec<String> = report
                        .outcomes
                        .iter()
                        .map(|r| format!("{}={}", r.result, r.count))
                        .collect();
                    eprintln!(
                        "kub0d: outcomes: kub0 accepted {}..{} ({})",
                        report.window_start,
                        report.window_end,
                        rows.join(" ")
                    );
                    Delivery::Accepted
                }
                // Our report, not the server, is wrong: drop it or it blocks every
                // window behind it. The body says which field.
                Ok((code @ (400 | 413), body)) => {
                    err = format!("HTTP {code} {body}; that window is dropped");
                    Delivery::Rejected
                }
                Ok((code, body)) => {
                    err = format!("HTTP {code} {body}; keeping the window");
                    Delivery::Retry
                }
                Err(e) => {
                    err = format!("{e}; keeping the window");
                    Delivery::Retry
                }
            }
        });
        if err != self.last_outcomes_err {
            if !err.is_empty() {
                eprintln!("kub0d: outcomes: {err}");
            }
            self.last_outcomes_err = err;
        }
    }

    /// Log an account file that exists but cannot be read, once until the error changes
    /// or it reads again. True when it logged.
    fn account_unreadable(&mut self, e: String) -> bool {
        if e == self.last_account_err {
            return false;
        }
        eprintln!("kub0d: {e}; keeping the network policy and block rules as they are");
        self.last_account_err = e;
        true
    }

    /// The account file is gone: a local disconnect. No account, no org policy, so the
    /// block rules come out. A clear that fails is reported and retried next tick
    /// rather than left behind a frame that reads as nothing enforced.
    fn disconnected(&mut self) -> bool {
        let runtime = Arc::clone(&self.runtime);
        runtime.set_connected(false);
        runtime.set_policies(vallumd::netpolicy::PolicySet::default());
        // No account, no org deny list: the exec gate drops the fleet keys and
        // goes idle (a local deny file keeps its own). The stream ends too.
        self.stop_stream();
        vallumd::execgate::clear_fleet();
        self.prior_account = None;
        self.enforcer.policy_known = true;
        if let Ok(mut plan) = runtime.system_plan.lock() {
            plan.account_retired = false;
        }
        self.enforcer.sync(&runtime, self.system, &self.server_url);
        let enforcement = (*runtime.enforcement()).clone();
        if enforcement.state == "error" {
            runtime.publish_fleet(kub0::FleetSnapshot {
                netpolicy_enforcement: enforcement,
                ..Default::default()
            });
            return true;
        }
        runtime.publish_fleet(kub0::FleetSnapshot::default());
        false
    }
}

fn heartbeat_loop(
    account_path: PathBuf,
    state_dir: PathBuf,
    runtime: Arc<Kub0Runtime>,
    system: bool,
) {
    let interval = kub0::heartbeat_interval();
    let enforcer = Enforcer::new(runtime.data_dir(), PathBuf::from(HELPER_PATH));
    let mut hb = Heartbeat::new(account_path, state_dir, Arc::clone(&runtime), system, enforcer);
    while hb.tick() {
        // Sleep in slices so a snooze reaches the kernel without waiting a heartbeat.
        let wake = Instant::now() + interval;
        while let Some(left) = wake.checked_duration_since(Instant::now()) {
            std::thread::sleep(left.min(Duration::from_millis(500)));
            serve_applier(&mut hb.enforcer, &runtime, system, &hb.server_url);
            // The deny-list stream changed the rows: refresh now so the REST
            // metadata (reason, promoted_by, created_at) catches up.
            if runtime.take_refresh_request() {
                break;
            }
        }
    }
    hb.stop_stream();
}

/// What the applier answers between heartbeats: `kub0 sync` (the org's block
/// rules, applied again now, and the outcome told) and a changed snooze (a
/// re-plan).
fn serve_applier(enforcer: &mut Enforcer, runtime: &Kub0Runtime, system: bool, server_url: &str) {
    if let Some(ticket) = runtime.take_sync_request() {
        // The re-apply plans from the same snoozes, so it covers a re-plan too.
        runtime.take_replan();
        enforcer.reapply(runtime, system, server_url);
        runtime.republish_policy_view();
        runtime.finish_sync(ticket);
    } else if runtime.take_replan() {
        enforcer.sync(runtime, system, server_url);
        runtime.republish_policy_view();
    }
}

/// How long `sync` waits for the applier. It answers within a heartbeat slice
/// unless a heartbeat is in flight, and that ends with its HTTP timeouts. The
/// CLI gives `sync` 60 s, so the daemon's own account of a wait arrives first.
const SYNC_WAIT: Duration = Duration::from_secs(45);

/// No account means no org list and no applier thread to ask.
const SYNC_LOGGED_OUT: &str =
    "sync: this daemon is not logged in, so there is no org block list to apply; run: sudo kub0 login";

/// `sync`'s worker: ask the applier for a re-apply and wait up to `wait` for
/// what it did.
fn sync_job(kub0: &Kub0Runtime, req_id: &str, wait: Duration) -> vallumd::control::Reply {
    let ticket = kub0.request_sync();
    if kub0.wait_sync(ticket, wait) {
        return sync_reply(req_id, &kub0.enforcement());
    }
    if !kub0.hello_account().connected {
        // Logged out while this waited: the applier cleared the rules and left.
        return vallumd::control::Reply::err(req_id, SYNC_LOGGED_OUT);
    }
    vallumd::control::Reply::err(
        req_id,
        format!(
            "sync: the daemon is mid-heartbeat and has not applied the block rules again after {} s;              it does when the heartbeat ends, and `kub0 policies` shows the result",
            wait.as_secs()
        ),
    )
}

/// `sync`'s reply: what the re-apply left the kernel holding, in the shape
/// `policies` reports it. Done is the org's block rules in the kernel
/// (enforcing, or held behind the panel's pause) or an org with none; anything
/// else is an error that says why.
fn sync_reply(req_id: &str, e: &vallumd::netpolicy::Enforcement) -> vallumd::control::Reply {
    use vallumd::control::Reply;
    let result = serde_json::json!({ "enforcement": e });
    match e.state.as_str() {
        "enforcing" | "none" => Reply::ok(req_id, result),
        state => {
            let why = if e.reason.is_empty() {
                format!("the block rules are not applied (state {state})")
            } else {
                e.reason.clone()
            };
            Reply { result, ..Reply::err(req_id, format!("sync: {why}")) }
        }
    }
}

/// Where the root helper lives. Only the system kub0d ever runs it directly.
const HELPER_PATH: &str = "/usr/lib/kub0/kub0-block";

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// How long a relayed exec-gate request waits for the gate thread to apply
/// it before answering with whatever the frame shows. The gate polls its
/// request file every second.
const EXECGATE_APPLY_WAIT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// `kub0` requests (daemon/src/control.rs): one reply per request, to the
// client that asked. Reads answer from the loop; a login or a helper run
// goes to a worker thread that posts its reply through `replies_tx`.
// ---------------------------------------------------------------------------
impl Server {
    fn reply_to(&mut self, client: u64, reply: vallumd::control::Reply) {
        self.send_to(client, &Event::Reply(reply).to_line());
    }

    /// Queued replies from worker threads, and cancellation of a login whose
    /// client has left.
    fn deliver_replies(&mut self) {
        while let Ok(entry) = self.activity_rx.try_recv() {
            self.push_activity(entry);
        }
        while let Ok((client, line)) = self.replies_rx.try_recv() {
            if let Some(c) = self.clients.iter_mut().find(|c| c.id == client) {
                if !c.send(&line) {
                    c.eof = true;
                }
            }
        }
        if let Some((client, cancel)) = &self.login {
            let present = self.clients.iter().any(|c| c.id == *client && !c.eof);
            if !present {
                cancel.store(true, Ordering::SeqCst);
                self.login = None;
            } else if cancel.load(Ordering::SeqCst) {
                // The worker finished and cleared itself.
                self.login = None;
            }
        }
    }

    fn take_account_changed(&self) -> bool {
        self.account_changed.swap(false, Ordering::SeqCst)
    }

    /// The client is still there to be written to: not dropped, and its read
    /// side has not closed.
    fn connected(&self, client: u64) -> bool {
        self.clients.iter().any(|c| c.id == client && !c.eof)
    }

    fn peer_of(&self, client: u64) -> Option<vallumd::control::Peer> {
        self.clients.iter().find(|c| c.id == client).map(|c| c.peer)
    }

    fn daemon(&self) -> vallumd::control::Daemon {
        vallumd::control::Daemon {
            uid: self.daemon_uid,
            system: self.mode == DaemonMode::System,
        }
    }

    /// One frame to one client, never a broadcast.
    fn send_to(&mut self, client: u64, line: &str) {
        if let Some(c) = self.clients.iter_mut().find(|c| c.id == client) {
            if !c.send(line) {
                c.eof = true;
            }
        }
    }

    fn handle_request(&mut self, from: u64, req: vallumd::control::Request, live: Option<&mut Live>) {
        use vallumd::control::{access_for, authorize, Reply};
        let Some(peer) = self.peer_of(from) else { return };
        let Some(access) = access_for(&req.cmd) else {
            self.reply_to(from, Reply::err(&req.req, format!("unknown command {}", req.cmd)));
            return;
        };
        let daemon = self.daemon();
        if let Err(e) = authorize(&req.cmd, access, peer, daemon)
            .and_then(|()| vallumd::control::authorize_args(&req, peer, daemon))
        {
            self.reply_to(from, Reply::err(&req.req, e));
            return;
        }
        // Whom a helper-backed verb acts for: the peer, or the user a root
        // caller names (`kub0` under pkexec).
        let acting = match vallumd::control::acting_uid(&req, peer) {
            Ok(uid) => uid,
            Err(e) => {
                self.reply_to(from, Reply::err(&req.req, e));
                return;
            }
        };
        match req.cmd.as_str() {
            "status" => {
                let r = self.status_result(peer);
                self.reply_to(from, Reply::ok(&req.req, r));
            }
            "whoami" => {
                let r = self.whoami_result();
                self.reply_to(from, Reply::ok(&req.req, r));
            }
            "rules" => {
                let r = rules_result(&self.kub0.fleet_snapshot());
                self.reply_to(from, Reply::ok(&req.req, r));
            }
            "endpoints" => {
                let r = endpoints_result(&self.kub0.fleet_snapshot());
                self.reply_to(from, Reply::ok(&req.req, r));
            }
            "trusts" => {
                let r = trusts_result(&vallumd::execgate::frame());
                self.reply_to(from, Reply::ok(&req.req, r));
            }
            "apps" | "conns" | "activity" | "history" | "intel" | "investigate" | "policies" | "watches" | "brief" => {
                let reply = match self.read_result(&req, acting, live.as_deref()) {
                    Ok(r) => Reply::ok(&req.req, r),
                    Err(e) => Reply::err(&req.req, e),
                };
                self.reply_to(from, reply);
            }
            "login" => self.start_login(from, req),
            "logout" => self.logout(from, req),
            "trust" | "untrust" | "allow-once" => self.execgate_request(from, req, acting),
            "blocks" | "block" | "unblock" | "block-dest" | "unblock-dest" | "pause" | "resume" | "teardown" => {
                let app = activity_app(live.as_deref(), &req.str_arg("app"));
                self.helper_request(from, req, acting, app)
            }
            "sync" => self.sync_request(from, req),
            "policy-snooze" | "policy-resume" => self.policy_request(from, req),
            "share-on" | "share-off" => self.share_request(from, req),
            "watch-set" | "watch-delete" => self.watch_request(from, req, peer, acting, live),
            "tag" => self.tag_request(from, req, live),
            other => self.reply_to(from, Reply::err(&req.req, format!("unhandled command {other}"))),
        }
    }

    fn status_result(&self, peer: vallumd::control::Peer) -> serde_json::Value {
        let hello = self.kub0.hello_account();
        let snap = self.kub0.fleet_snapshot();
        let gate = vallumd::execgate::frame();
        let server_url = kub0::read_account(&self.account_path)
            .map(|a| a.server_url)
            .unwrap_or_default();
        serde_json::json!({
            "daemon": {
                "version": VERSION,
                "pid": std::process::id(),
                "mode": self.mode,
                "uid": self.daemon_uid,
                "uptimeSeconds": self.started_at.elapsed().as_secs(),
                "socket": self.socket_path,
                "coverage": COVERAGE,
                "rdns": self.rdns,
                "stateDir": self.state_dir,
            },
            "account": {
                "connected": hello.connected,
                "githubUsername": hello.github_username,
                "nodeName": hello.node_name,
                "lastHeartbeatOk": hello.last_heartbeat_ok,
                "lastHeartbeatTs": snap.last_heartbeat_ts,
                "heartbeatDeferred": self.kub0.heartbeat_deferred(),
                "path": self.account_path,
                "serverUrl": server_url,
            },
            "fleet": {
                "orgEndpoints": snap.org_endpoints,
                "nodeLimit": snap.node_limit,
                "selfState": snap.self_state,
                "denylistVersion": snap.denylist_version,
                "denylistCount": snap.denylist.len(),
                "denylistReported": snap.denylist_reported,
                "denylistLive": self.kub0.denylist_live(),
                "endpointsCount": snap.endpoints.len(),
                "endpointsRefreshOk": snap.endpoints_refresh_ok,
                "netpolicyRefreshOk": snap.netpolicy_refresh_ok,
                "netpolicyCount": snap.netpolicies.len(),
                "enforcement": snap.netpolicy_enforcement,
                "sharingDestinations": self.kub0.sharing_destinations(),
            },
            "execGate": {
                "enabled": gate.enabled,
                "armed": gate.armed,
                "keys": gate.keys,
                "source": gate.source,
                "observedAt": gate.observed_at,
                "counters": gate.counters,
                "trustedCount": gate.trusted.len(),
                "oncePending": gate.once_pending,
                "denyCount": gate.denies.len(),
                "listReceivedAt": gate.list_received_at,
                "listRestored": gate.list_restored,
            },
            "peer": { "uid": peer.uid },
        })
    }

    fn whoami_result(&self) -> serde_json::Value {
        let hello = self.kub0.hello_account();
        let account = kub0::read_account(&self.account_path);
        serde_json::json!({
            "connected": hello.connected,
            "githubUsername": hello.github_username,
            "nodeName": hello.node_name,
            "path": self.account_path,
            "serverUrl": account.as_ref().map(|a| a.server_url.clone()).unwrap_or_default(),
            "connectedAt": account.as_ref().map(|a| a.connected_at).unwrap_or(0),
            "lastHeartbeatOk": hello.last_heartbeat_ok,
            "heartbeatDeferred": self.kub0.heartbeat_deferred(),
        })
    }

    /// The device-code login, on a worker so the loop keeps sampling. Each
    /// minted code is a partial reply; the final reply carries the account.
    fn start_login(&mut self, from: u64, req: vallumd::control::Request) {
        use vallumd::control::Reply;
        if let Some((client, cancel)) = &self.login {
            let busy = !cancel.load(Ordering::SeqCst) && self.clients.iter().any(|c| c.id == *client && !c.eof);
            if busy {
                self.reply_to(from, Reply::err(&req.req, "a login is already in progress on this daemon"));
                return;
            }
        }
        let mut server_url = req.str_arg("serverUrl");
        if server_url.is_empty() {
            server_url = kub0::DEFAULT_SERVER_URL.to_string();
        }
        let mut auth_url = req.str_arg("authUrl");
        if auth_url.is_empty() {
            auth_url = kub0::DEFAULT_AUTH_URL.to_string();
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.login = Some((from, Arc::clone(&cancel)));
        let tx = self.replies_tx.clone();
        let path = self.account_path.clone();
        let changed = Arc::clone(&self.account_changed);
        let req_id = req.req.clone();
        std::thread::spawn(move || {
            let post = |r: Reply| {
                let _ = tx.send((from, Event::Reply(r).to_line()));
            };
            let agent = vallumd::device::http_agent();
            let max = vallumd::device::MAX_CODES;
            let mut minted = 0u32;
            let outcome = loop {
                minted += 1;
                let code = match vallumd::device::device_start(&agent, &auth_url) {
                    Ok(c) => c,
                    Err(e) => break Err(e),
                };
                post(Reply::partial(
                    &req_id,
                    serde_json::json!({
                        "code": code.user_code,
                        "url": code.connect_url,
                        "expiresIn": code.expires_in,
                        "interval": code.interval,
                        "minted": minted,
                        "max": max,
                    }),
                ));
                let cancelled = || cancel.load(Ordering::SeqCst);
                match vallumd::device::device_poll(&agent, &auth_url, &code, &cancelled) {
                    Ok(vallumd::device::DevicePoll::Complete { token, github_username }) => {
                        break Ok((token, github_username))
                    }
                    Ok(vallumd::device::DevicePoll::Expired) if minted < max => {
                        post(Reply::partial(
                            &req_id,
                            serde_json::json!({ "expired": code.user_code, "minted": minted, "max": max }),
                        ));
                    }
                    Ok(vallumd::device::DevicePoll::Expired) => break Err("device login expired".into()),
                    Err(e) => break Err(e),
                }
            };
            let reply = match outcome {
                Ok((token, github_username)) => {
                    let account = AccountFile {
                        schema: 0,
                        token: token.clone(),
                        github_username: github_username.clone(),
                        connected_at: now_ms(),
                        server_url: server_url.clone(),
                    };
                    match kub0::write_account(&path, &account) {
                        Ok(()) => {
                            changed.store(true, Ordering::SeqCst);
                            Reply::ok(
                                &req_id,
                                serde_json::json!({
                                    "githubUsername": github_username,
                                    "account": path,
                                    "serverUrl": server_url,
                                }),
                            )
                        }
                        Err(e) => Reply::err(
                            &req_id,
                            kub0::redact_secret(&format!("writing {}: {e}", path.display()), &token),
                        ),
                    }
                }
                Err(e) => Reply::err(&req_id, e),
            };
            // Mark finished so the loop releases the slot.
            cancel.store(true, Ordering::SeqCst);
            post(reply);
        });
    }

    fn logout(&mut self, from: u64, req: vallumd::control::Request) {
        use vallumd::control::Reply;
        let reply = match kub0::disconnect_account(&self.account_path) {
            Ok(removed) => {
                self.account_changed.store(true, Ordering::SeqCst);
                Reply::ok(
                    &req.req,
                    serde_json::json!({ "removed": removed, "account": self.account_path }),
                )
            }
            Err(e) => Reply::err(&req.req, format!("removing {}: {e}", self.account_path.display())),
        };
        self.reply_to(from, reply);
    }

    /// `trust`, `untrust`, `allow-once`: the same request file the helper
    /// writes, then a short wait for the gate thread to show the effect.
    fn execgate_request(&mut self, from: u64, req: vallumd::control::Request, acting: Option<u32>) {
        use vallumd::control::Reply;
        if self.mode != DaemonMode::System {
            self.reply_to(
                from,
                Reply::err(&req.req, system_only(&req, "the exec gate")),
            );
            return;
        }
        let op = match req.cmd.as_str() {
            "trust" => "trust",
            "untrust" => "untrust",
            _ => "allow_once",
        };
        let Some(sha) = vallumd::trust::canonical_sha256(&req.str_arg("sha256")) else {
            self.reply_to(from, Reply::err(&req.req, "sha256 must be 64 hex characters"));
            return;
        };
        let request = vallumd::trust::Request {
            op: op.to_string(),
            sha256: sha.clone(),
            ts: now_ms(),
            uid: acting.unwrap_or(0),
            note: req.str_arg("note"),
        };
        let dir = vallumd::trust::dir();
        if let Err(e) = vallumd::trust::append_request(&dir, &request) {
            self.reply_to(from, Reply::err(&req.req, format!("queueing the request in {}: {e}", dir.display())));
            return;
        }
        let tx = self.replies_tx.clone();
        let req_id = req.req.clone();
        let before = vallumd::execgate::frame().once_pending;
        std::thread::spawn(move || {
            let deadline = Instant::now() + EXECGATE_APPLY_WAIT;
            let applied = loop {
                let frame = vallumd::execgate::frame();
                let trusted = frame.trusted.iter().any(|t| t.sha256 == sha);
                let done = match op {
                    "trust" => trusted,
                    "untrust" => !trusted,
                    _ => frame.once_pending > before,
                };
                if done || Instant::now() >= deadline {
                    break (done, frame);
                }
                std::thread::sleep(Duration::from_millis(200));
            };
            let (done, frame) = applied;
            let _ = tx.send((
                from,
                Event::Reply(Reply::ok(
                    &req_id,
                    serde_json::json!({
                        "op": op,
                        "sha256": sha,
                        "applied": done,
                        "armed": frame.armed,
                        "keys": frame.keys,
                        "trustedCount": frame.trusted.len(),
                        "oncePending": frame.once_pending,
                    }),
                ))
                .to_line(),
            ));
        });
    }

    /// The nftables verbs, through the installed helper as root, with
    /// `acting` as `PKEXEC_UID` so its ownership checks act on that user. The
    /// verb's JSON is the reply; its `ok` decides ours. A block or unblock
    /// outcome is also recorded in the activity log, as the panel's `note`
    /// line used to do after running the helper itself.
    fn helper_request(
        &mut self,
        from: u64,
        req: vallumd::control::Request,
        acting: Option<u32>,
        app: ActivityApp,
    ) {
        use vallumd::control::Reply;
        if self.mode != DaemonMode::System || self.daemon_uid != 0 {
            self.reply_to(from, Reply::err(&req.req, system_only(&req, "blocking")));
            return;
        }
        let args = match helper_argv(&req) {
            Ok(a) => a,
            Err(e) => {
                self.reply_to(from, Reply::err(&req.req, e));
                return;
            }
        };
        let helper = PathBuf::from(HELPER_PATH);
        if let Err(e) = vallumd::system_status::protected_path(&helper, false) {
            self.reply_to(from, Reply::err(&req.req, format!("{}: {e}; run: sudo kub0 install", helper.display())));
            return;
        }
        let tx = self.replies_tx.clone();
        let activity = self.activity_tx.clone();
        let req_id = req.req.clone();
        std::thread::spawn(move || {
            let reply = helper_job(&helper, &args, acting, &req_id, &app, &activity);
            let _ = tx.send((from, Event::Reply(reply).to_line()));
        });
    }

    /// `sync`: the org's block rules, applied again now. The applier (the
    /// heartbeat thread) holds the org's list and is the only caller that
    /// hands the helper one, so this asks it and waits for what it did. Run
    /// from here, `fleet-sync` would get no list and fail before planning.
    fn sync_request(&mut self, from: u64, req: vallumd::control::Request) {
        use vallumd::control::Reply;
        if self.mode != DaemonMode::System || self.daemon_uid != 0 {
            self.reply_to(from, Reply::err(&req.req, system_only(&req, "applying the org's block rules")));
            return;
        }
        if !self.kub0.hello_account().connected {
            // No account, so no applier thread: nothing would answer.
            self.reply_to(from, Reply::err(&req.req, SYNC_LOGGED_OUT));
            return;
        }
        let tx = self.replies_tx.clone();
        let kub0 = Arc::clone(&self.kub0);
        let req_id = req.req.clone();
        std::thread::spawn(move || {
            let reply = sync_job(&kub0, &req_id, SYNC_WAIT);
            let _ = tx.send((from, Event::Reply(reply).to_line()));
        });
    }

    /// `share-on` / `share-off`: destination sharing as a setting of the system
    /// daemon, the one that reports this host. It is saved first, so a daemon
    /// that could not save it does not say it changed. A user daemon is started
    /// by the panel with the flag its own switch decides, and next to a logged-in
    /// system daemon it reports nothing, so the verbs are the system daemon's.
    fn share_request(&mut self, from: u64, req: vallumd::control::Request) {
        use vallumd::control::Reply;
        if self.mode != DaemonMode::System {
            self.reply_to(from, Reply::err(&req.req, SHARE_IS_THE_SYSTEM_DAEMONS));
            return;
        }
        let on = req.cmd == "share-on";
        let reply = match kub0::save_settings(&self.state_dir, &kub0::Settings { share_destinations: on }) {
            Ok(()) => {
                self.kub0.set_sharing_destinations(on);
                eprintln!("kub0d: destination sharing {}", if on { "on" } else { "off" });
                Reply::ok(&req.req, serde_json::json!({ "sharingDestinations": on }))
            }
            Err(e) => Reply::err(&req.req, format!("{}: the setting was not saved ({e}); nothing changed", req.cmd)),
        };
        self.reply_to(from, reply);
    }

    /// `policy-snooze` (lowers: an org rule stops applying here for a while)
    /// and `policy-resume` (raises it back). The org's `user_can_snooze`
    /// still decides whether a rule may be snoozed at all.
    fn policy_request(&mut self, from: u64, req: vallumd::control::Request) {
        use vallumd::control::Reply;
        let rule = req.str_arg("rule");
        if rule.is_empty() || rule.len() > POLICY_RULE_MAX {
            self.reply_to(from, Reply::err(&req.req, format!("{} needs a rule id", req.cmd)));
            return;
        }
        let reply = if req.cmd == "policy-snooze" {
            match snooze_seconds(&req.args) {
                Err(e) => Reply::err(&req.req, e),
                Ok(seconds) => match self.kub0.snooze_rule(&rule, seconds) {
                    Ok(until) => Reply::ok(&req.req, serde_json::json!({ "rule": rule, "snoozedUntil": until })),
                    Err(e) => Reply::err(&req.req, e),
                },
            }
        } else {
            self.kub0.resume_rule(&rule);
            Reply::ok(&req.req, serde_json::json!({ "rule": rule, "resumed": true }))
        };
        self.kub0.republish_policy_view();
        self.reply_to(from, reply);
    }

    /// `watch-set` / `watch-delete`: the store the legacy `watch` line and
    /// `kub0 watch` use. On the system daemon the rules are every user's,
    /// so a non-root caller changes only the rules it set.
    fn watch_request(
        &mut self,
        from: u64,
        req: vallumd::control::Request,
        peer: vallumd::control::Peer,
        acting: Option<u32>,
        live: Option<&mut Live>,
    ) {
        use vallumd::control::Reply;
        let Some(live) = live else {
            self.reply_to(from, Reply::err(&req.req, WATCH_NEEDS_LIVE));
            return;
        };
        let actor = watch_actor(self.mode, peer);
        let new_owner = watch_new_owner(self.mode, actor, acting);
        let outcome = if req.cmd == "watch-set" {
            watch_set(live, &req.str_arg("kind"), &req.str_arg("value"), &req.str_arg("note"), actor, new_owner)
                .map(|r| serde_json::json!({ "rule": r }))
        } else {
            let id = req.str_arg("id");
            if id.is_empty() {
                Err("watch-delete needs a rule id".to_string())
            } else {
                watch_delete(live, &id, actor).map(|r| serde_json::json!({ "removed": r }))
            }
        };
        // A refused change is the caller's to hear; a change, saved or not,
        // is every client's to see.
        let reply = match outcome {
            Err(e) => Reply::err(&req.req, e),
            Ok(v) => match live.watch.save() {
                Ok(()) => {
                    publish_watchlist(live, self, String::new());
                    Reply::ok(&req.req, v)
                }
                Err(e) => {
                    let e = format!("saving watch rules: {e}");
                    publish_watchlist(live, self, e.clone());
                    Reply::err(&req.req, e)
                }
            },
        };
        self.reply_to(from, reply);
    }

    /// `tag`: the legacy `{"type":"tag"}` line as a request, same fields.
    fn tag_request(&mut self, from: u64, req: vallumd::control::Request, live: Option<&mut Live>) {
        use vallumd::control::Reply;
        let Some(live) = live else {
            self.reply_to(from, Reply::err(&req.req, "tags need the live procfs source"));
            return;
        };
        let cmd = match parse_tag_cmd(&req.args) {
            Ok(TagCmd::Set { network_key, label, kind, .. }) => {
                let peer = self.peer_of(from).unwrap_or(vallumd::control::Peer { uid: None });
                TagCmd::Set { network_key, label, kind, anchor: tag_anchor(&req.args, peer) }
            }
            Ok(c) => c,
            Err(e) => {
                self.reply_to(from, Reply::err(&req.req, format!("tag: {e}")));
                return;
            }
        };
        let result = match &cmd {
            TagCmd::Set { network_key, label, .. } => {
                serde_json::json!({ "networkKey": network_key, "label": label, "deleted": false })
            }
            TagCmd::Delete { network_key } => serde_json::json!({ "networkKey": network_key, "deleted": true }),
        };
        let reply = match apply_tag(live, self, cmd) {
            Ok(()) => Reply::ok(&req.req, result),
            Err(e) => Reply::err(&req.req, format!("tag: {e}")),
        };
        self.reply_to(from, reply);
    }
}

// ---------------------------------------------------------------------------
// `kub0` reads (#61 step 2): each answers from what this daemon already holds,
// the same data the panel's legacy reads and the retired daemon client verbs
// used, so the CLI and the panel cannot disagree about it.
// ---------------------------------------------------------------------------
impl Server {
    /// Retained history rows since `since`, flushed first so the newest
    /// sample is in them.
    fn retained(&mut self, since: u64) -> Result<Vec<vallumd::history::Entry>, String> {
        self.flush_history();
        match self.history.as_ref() {
            Some(h) if self.history_error.is_empty() => h.query("", since, vallumd::history::ROW_CAP),
            Some(_) => Err(self.history_error.clone()),
            None => Err("History unavailable".into()),
        }
    }

    /// The investigate pivot over retained history plus live rows the store has
    /// not seen yet. The legacy `investigate` line and `kub0 why` share it.
    fn investigate_pivot(&mut self, live: Option<&Live>, subject: &str, since: u64, now: u64) -> (intel::Pivot, String) {
        let subject = if subject.trim().is_empty() {
            Ok(None)
        } else {
            intel::PivotSubject::parse(subject).map(Some)
        };
        let subject = match subject {
            Err(e) => return (intel::Pivot::default(), e),
            Ok(s) => s,
        };
        let rows = self.retained(since);
        let live_rows: Vec<Connection> = live.map(|l| l.snapshot()).unwrap_or_default();
        match rows {
            Ok(entries) => {
                let truncated = entries.len() >= vallumd::history::ROW_CAP;
                // Live rows are active history rows too; only ones the
                // store has not seen yet (first sample) are added.
                let keys: HashSet<&str> = entries.iter().map(|e| e.connection.id.as_str()).collect();
                let mut observed: Vec<intel::Observed> = entries.iter().map(intel::Observed::from_entry).collect();
                observed.extend(
                    live_rows
                        .iter()
                        .filter(|c| !keys.contains(c.id.as_str()))
                        .map(|c| intel::Observed::from_live(c, now)),
                );
                (intel::pivot(subject.as_ref(), &observed, since, now, truncated), String::new())
            }
            Err(e) => {
                let observed: Vec<intel::Observed> = live_rows.iter().map(|c| intel::Observed::from_live(c, now)).collect();
                (intel::pivot(subject.as_ref(), &observed, since, now, false), format!("{e}; showing live rows only"))
            }
        }
    }

    /// When this machine talked, by app and by hour (six-hour buckets past
    /// 48 h). The legacy `timeline` line and `kub0 intel --timeline` share it.
    fn timeline_for(&mut self, live: Option<&Live>, hours: u64, now: u64) -> (intel::Timeline, String) {
        let bucket = if hours > 48 { 6 * 3_600_000 } else { 3_600_000 };
        // Aligned down to a bucket boundary, so a label reading 13:00 means
        // the hour from 13:00; the last bucket is the partial current one.
        let since = intel::align_down(now.saturating_sub(hours * 3_600_000), bucket);
        let rows = self.retained(since);
        let live_rows: Vec<Connection> = live.map(|l| l.snapshot()).unwrap_or_default();
        match rows {
            Ok(entries) => {
                let truncated = entries.len() >= vallumd::history::ROW_CAP;
                let keys: HashSet<&str> = entries.iter().map(|e| e.connection.id.as_str()).collect();
                let mut observed: Vec<intel::Observed> = entries.iter().map(intel::Observed::from_entry).collect();
                observed.extend(live_rows.iter().filter(|c| !keys.contains(c.id.as_str())).map(|c| intel::Observed::from_live(c, now)));
                (intel::timeline(&observed, since, now, bucket, intel::TIMELINE_MAX_APPS, truncated), String::new())
            }
            Err(e) => {
                let observed: Vec<intel::Observed> = live_rows.iter().map(|c| intel::Observed::from_live(c, now)).collect();
                (intel::timeline(&observed, since, now, bucket, intel::TIMELINE_MAX_APPS, false), format!("{e}; showing live rows only"))
            }
        }
    }

    /// One `Read` verb's result. `acting` is whom the caller is (for
    /// `--mine`); `live` is the procfs monitor, absent under the other sources.
    fn read_result(
        &mut self,
        req: &vallumd::control::Request,
        acting: Option<u32>,
        live: Option<&Live>,
    ) -> Result<serde_json::Value, String> {
        let now = now_ms();
        let needs_live = || live.ok_or_else(|| format!("{}: {READS_NEED_LIVE}", req.cmd));
        match req.cmd.as_str() {
            "apps" => {
                let live = needs_live()?;
                let sort = AppSort::parse(&req.str_arg("sort"))?;
                let mine = if req.args.get("mine").and_then(|v| v.as_bool()) == Some(true) {
                    Some(acting.ok_or("apps: --mine needs to know who you are, and this platform cannot say")?)
                } else {
                    None
                };
                let only_live = req.args.get("live").and_then(|v| v.as_bool()) == Some(true);
                let since = now.saturating_sub(APPS_RECENT_MS);
                let (history, error) = match self.retained(since) {
                    Ok(rows) => (rows, String::new()),
                    Err(e) => (Vec::new(), e),
                };
                let mut apps = apps_view(&live.snapshot(), &history, &live.bandwidth, mine, now);
                if only_live {
                    apps.retain(|a| a.connections > 0);
                }
                sort.apply(&mut apps);
                Ok(serde_json::json!({
                    "apps": apps,
                    "since": since,
                    "mine": mine,
                    "mode": self.mode,
                    "historyError": error,
                }))
            }
            "conns" => {
                let live = needs_live()?;
                let app = req.str_arg("app");
                let unattributed = req.args.get("unattributed").and_then(|v| v.as_bool()) == Some(true);
                let rows: Vec<Connection> = live
                    .snapshot()
                    .into_iter()
                    .filter(|c| conn_matches(c, &app, unattributed))
                    .collect();
                Ok(serde_json::json!({ "connections": rows, "count": rows.len(), "mode": self.mode }))
            }
            "activity" => {
                let seconds = req.args.get("seconds").and_then(|v| v.as_u64()).unwrap_or(3600);
                let since = now.saturating_sub(seconds.saturating_mul(1000));
                let entries: Vec<&ActivityEntryRef> = self.activity.entries().iter().filter(|e| e.ts >= since).collect();
                Ok(serde_json::json!({ "entries": entries, "since": since }))
            }
            "history" => {
                let hours = req.args.get("hours").and_then(|v| v.as_u64()).unwrap_or(24);
                if hours == 0 || hours > 168 {
                    return Err("history: hours must be 1..168".into());
                }
                let query = req.str_arg("query");
                if query.len() > 256 {
                    return Err("history: the query is longer than 256 characters".into());
                }
                let since = now.saturating_sub(hours * 3_600_000);
                self.flush_history();
                let mut rows = match self.history.as_ref() {
                    Some(h) if self.history_error.is_empty() => h.query(&query, since, CLI_HISTORY_CAP + 1)?,
                    Some(_) => return Err(self.history_error.clone()),
                    None => return Err("History unavailable".into()),
                };
                let more = rows.len() > CLI_HISTORY_CAP;
                rows.truncate(CLI_HISTORY_CAP);
                let csv = (req.str_arg("format") == "csv").then(|| vallumd::history::csv(&rows));
                Ok(serde_json::json!({ "entries": rows, "more": more, "since": since, "csv": csv }))
            }
            "intel" => {
                let live = needs_live()?;
                let rows = live.snapshot();
                let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
                let flagged: Vec<serde_json::Value> = rows
                    .iter()
                    .filter(|c| !c.indicators.is_empty())
                    .map(|c| {
                        for i in &c.indicators {
                            *counts.entry(i.severity.as_str().to_string()).or_default() += 1;
                        }
                        serde_json::json!({
                            "id": c.id,
                            "app": { "id": c.app.id, "name": c.app.name },
                            "remote": c.remote,
                            "hostname": c.hostname,
                            "country": c.country,
                            "indicators": c.indicators,
                        })
                    })
                    .collect();
                let mut out = serde_json::json!({
                    "indicators": flagged,
                    "counts": counts,
                    "listeners": listener_summaries(&self.listeners),
                    "watchRules": live.watch.rules().len(),
                });
                if let Some(hours) = req.args.get("timelineHours").and_then(|v| v.as_u64()) {
                    if hours == 0 || hours > 168 {
                        return Err("intel: the timeline's hours must be 1..168".into());
                    }
                    let (t, error) = self.timeline_for(Some(live), hours, now);
                    out["timelineText"] = serde_json::Value::String(intel::render_timeline_text(&t));
                    out["timeline"] = serde_json::to_value(&t).unwrap_or_default();
                    out["timelineError"] = serde_json::Value::String(error);
                }
                Ok(out)
            }
            "investigate" => {
                let subject = req.str_arg("subject");
                if subject.is_empty() || subject.len() > 256 {
                    return Err("investigate needs a subject: an app, an address, or kind:value".into());
                }
                let hours = req.args.get("hours").and_then(|v| v.as_u64()).unwrap_or(168);
                if hours == 0 || hours > 168 {
                    return Err("investigate: hours must be 1..168".into());
                }
                let since = now.saturating_sub(hours * 3_600_000);
                let (pivot, error) = self.investigate_pivot(live, &subject, since, now);
                if pivot.subject.is_none() && !error.is_empty() {
                    return Err(error);
                }
                Ok(serde_json::json!({ "pivot": pivot, "text": intel::render_pivot_text(&pivot), "error": error }))
            }
            "policies" => Ok(policies_result(&self.kub0)),
            "watches" => {
                let live = needs_live()?;
                Ok(serde_json::json!({ "rules": live.watch.rules(), "mode": self.mode }))
            }
            "brief" => {
                let hours = req.args.get("hours").and_then(|v| v.as_u64()).unwrap_or(24);
                if hours == 0 || hours > 168 {
                    return Err("brief: hours must be 1..168".into());
                }
                let since = now.saturating_sub(hours * 3_600_000);
                let (entries, error) = match self.retained(since) {
                    Ok(rows) => (rows, String::new()),
                    Err(e) => (Vec::new(), e),
                };
                let truncated = entries.len() >= vallumd::history::ROW_CAP;
                let observed: Vec<intel::Observed> = entries.iter().map(intel::Observed::from_entry).collect();
                let listeners = listener_summaries(&self.listeners);
                let brief = intel::brief(&kub0::node_name(), hours, now, &observed, self.activity.entries(), &listeners, truncated);
                Ok(serde_json::json!({ "markdown": intel::render_brief_markdown(&brief), "brief": brief, "historyError": error }))
            }
            other => Err(format!("unhandled read {other}")),
        }
    }
}

type ActivityEntryRef = vallumd::activity::ActivityEntry;

const READS_NEED_LIVE: &str = "this read needs the live procfs source; this daemon is replaying or reading another engine's database";

/// How far back `kub0 apps` looks for apps with no live connection now.
const APPS_RECENT_MS: u64 = 24 * 3_600_000;

/// Most history rows one `kub0 history` reply carries (the client's output
/// queue is bounded); `more` says when there were more.
const CLI_HISTORY_CAP: usize = 2000;

/// One app in `kub0 apps`: live rows now, retained rows in the last day, and
/// the last sample's traffic.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppRow {
    id: String,
    name: String,
    system: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<vallumd::event::AppOwner>,
    pids: Vec<u32>,
    /// Live connections now.
    connections: usize,
    /// Distinct retained rows in the last day, live ones included.
    seen: usize,
    last_seen: u64,
    tx_rate: Option<f64>,
    rx_rate: Option<f64>,
    tx_bytes: u64,
    rx_bytes: u64,
}

/// Group connections into apps, from live rows and the last day of retained
/// rows; `mine` keeps only rows of that uid.
fn apps_view(
    live: &[Connection],
    history: &[vallumd::history::Entry],
    bandwidth: &[vallumd::traffic::AppTraffic],
    mine: Option<u32>,
    now: u64,
) -> Vec<AppRow> {
    let keep = |c: &Connection| mine.is_none() || c.uid == mine;
    let mut apps: std::collections::BTreeMap<String, AppRow> = std::collections::BTreeMap::new();
    let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
    let row = |apps: &mut std::collections::BTreeMap<String, AppRow>, c: &Connection| {
        apps.entry(c.app.id.clone())
            .or_insert_with(|| AppRow {
                id: c.app.id.clone(),
                name: c.app.name.clone(),
                system: c.app.system,
                owner: c.app.owner.clone(),
                pids: Vec::new(),
                connections: 0,
                seen: 0,
                last_seen: 0,
                tx_rate: None,
                rx_rate: None,
                tx_bytes: 0,
                rx_bytes: 0,
            })
            .id
            .clone()
    };
    for c in live.iter().filter(|c| keep(c)) {
        let id = row(&mut apps, c);
        let a = apps.get_mut(&id).unwrap();
        a.connections += 1;
        if c.app.pid != 0 && !a.pids.contains(&c.app.pid) {
            a.pids.push(c.app.pid);
        }
        a.last_seen = now;
        seen.entry(id).or_default().insert(c.id.clone());
    }
    for e in history.iter().filter(|e| keep(&e.connection)) {
        let id = row(&mut apps, &e.connection);
        let a = apps.get_mut(&id).unwrap();
        a.last_seen = a.last_seen.max(e.last_observed);
        seen.entry(id).or_default().insert(e.connection.id.clone());
    }
    for b in bandwidth {
        if let Some(a) = apps.get_mut(&b.id) {
            a.tx_rate = b.tx_rate;
            a.rx_rate = b.rx_rate;
            a.tx_bytes = b.tx_bytes;
            a.rx_bytes = b.rx_bytes;
        }
    }
    apps.into_values()
        .map(|mut a| {
            a.seen = seen.get(&a.id).map(|s| s.len()).unwrap_or(0);
            a.pids.sort_unstable();
            a
        })
        .collect()
}

/// `kub0 apps --sort`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppSort {
    Bandwidth,
    Connections,
    Recent,
    Name,
}

impl AppSort {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "" | "connections" => Ok(Self::Connections),
            "bandwidth" => Ok(Self::Bandwidth),
            "recent" => Ok(Self::Recent),
            "name" => Ok(Self::Name),
            other => Err(format!("apps: sort by bandwidth, connections, recent or name, not {other:?}")),
        }
    }

    fn apply(self, apps: &mut [AppRow]) {
        let rate = |a: &AppRow| a.tx_rate.unwrap_or(0.0) + a.rx_rate.unwrap_or(0.0);
        let name = |a: &AppRow| a.name.to_lowercase();
        match self {
            Self::Bandwidth => apps.sort_by(|a, b| rate(b).total_cmp(&rate(a)).then_with(|| name(a).cmp(&name(b)))),
            Self::Connections => apps.sort_by(|a, b| {
                (b.connections, b.seen).cmp(&(a.connections, a.seen)).then_with(|| name(a).cmp(&name(b)))
            }),
            Self::Recent => apps.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| name(a).cmp(&name(b)))),
            Self::Name => apps.sort_by(|a, b| name(a).cmp(&name(b)).then_with(|| a.id.cmp(&b.id))),
        }
    }
}

/// `kub0 conns --app APP --unattributed`: an app by id or name (any case);
/// unattributed is a row no process could be named for.
fn conn_matches(c: &Connection, app: &str, unattributed: bool) -> bool {
    if unattributed && c.app.pid != 0 {
        return false;
    }
    app.is_empty() || c.app.id == app || c.app.name.eq_ignore_ascii_case(app)
}

/// Listening sockets as the brief and `kub0 intel` word them.
fn listener_summaries(listeners: &[Listener]) -> Vec<intel::ListenerSummary> {
    let mut out: Vec<intel::ListenerSummary> = listeners
        .iter()
        .map(|l| intel::ListenerSummary {
            proto: l.proto.clone(),
            ip: l.ip.clone(),
            port: l.port,
            app: l.app.name.clone(),
            scope: match l.scope.as_str() {
                "all" => "all interfaces".into(),
                "loopback" => "loopback only".into(),
                other => other.into(),
            },
        })
        .collect();
    out.sort_by(|a, b| (&a.proto, a.port, &a.ip).cmp(&(&b.proto, b.port, &b.ip)));
    out.dedup();
    out
}

/// The network policies as this daemon holds them, with its snoozes and its
/// enforcement: the keys of the fleet frame, so the panel reads them the same.
fn policies_result(rt: &Kub0Runtime) -> serde_json::Value {
    let snap = rt.fleet_snapshot();
    serde_json::json!({
        "connected": snap.connected,
        "netpolicies": rt.policy_view(),
        "netpolicyRefreshOk": snap.netpolicy_refresh_ok,
        "netpolicyEnforcement": *rt.enforcement(),
    })
}

fn rules_result(snap: &kub0::FleetSnapshot) -> serde_json::Value {
    serde_json::json!({
        "connected": snap.connected,
        "denylistVersion": snap.denylist_version,
        "denylistReported": snap.denylist_reported,
        "denylist": snap.denylist,
        "netpolicies": snap.netpolicies,
        "netpolicyRefreshOk": snap.netpolicy_refresh_ok,
        "enforcement": snap.netpolicy_enforcement,
    })
}

fn endpoints_result(snap: &kub0::FleetSnapshot) -> serde_json::Value {
    serde_json::json!({
        "connected": snap.connected,
        "orgEndpoints": snap.org_endpoints,
        "nodeLimit": snap.node_limit,
        "selfState": snap.self_state,
        "endpoints": snap.endpoints,
        "updatedAt": snap.endpoints_updated_at,
        "refreshOk": snap.endpoints_refresh_ok,
    })
}

fn trusts_result(frame: &vallumd::execgate::ExecGateFrame) -> serde_json::Value {
    serde_json::json!({
        "enabled": frame.enabled,
        "armed": frame.armed,
        "keys": frame.keys,
        "source": frame.source,
        "trusted": frame.trusted,
        "oncePending": frame.once_pending,
    })
}
/// The app a request names, for its activity record: the name its live rows
/// carry, else the id itself (the panel's `appById` fallback).
fn activity_app(live: Option<&Live>, id: &str) -> ActivityApp {
    let name = live
        .and_then(|l| l.live.values().find(|c| c.app.id == id).map(|c| c.app.name.clone()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| id.to_string());
    ActivityApp { id: id.to_string(), name }
}

/// One helper run for a request: its reply, and for a block or unblock the
/// activity record of the outcome, posted to the loop through `activity`.
fn helper_job(
    helper: &Path,
    args: &[String],
    acting: Option<u32>,
    req_id: &str,
    app: &ActivityApp,
    activity: &std::sync::mpsc::Sender<vallumd::activity::ActivityEntry>,
) -> vallumd::control::Reply {
    use vallumd::control::Reply;
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = run_helper_for_request(helper, &argv, acting);
    if let Some(entry) = block_outcome(args.first().map(String::as_str).unwrap_or(""), app, &result, now_ms()) {
        let _ = activity.send(entry);
    }
    match result {
        Ok(v) => {
            let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(true);
            if ok {
                Reply::ok(req_id, v)
            } else {
                let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("helper refused").to_string();
                Reply { result: v, ..Reply::err(req_id, msg) }
            }
        }
        Err(e) => Reply::err(req_id, e),
    }
}

/// The activity record for a helper verb's outcome: the one the panel's
/// legacy `note` line added after it ran the helper itself (`block`,
/// `unblock`, `block_failed`, with the mechanism and any error). A block
/// counts as done the way the panel counted it: `ok`, and a verified rule
/// (`verified` not false, or `ruleVerified`). A failed unblock was never
/// recorded and is not now; nor is anything else the helper runs.
fn block_outcome(
    helper_verb: &str,
    app: &ActivityApp,
    result: &Result<serde_json::Value, String>,
    now: u64,
) -> Option<vallumd::activity::ActivityEntry> {
    let (blocking, mechanism) = match helper_verb {
        "block-app" => (true, "cgroup"),
        "block-ips" => (true, "endpoints"),
        "block-scoped" => (true, "app-destination"),
        "unblock-app" => (false, "cgroup"),
        "unblock-ips" => (false, "endpoints"),
        "unblock-scoped" => (false, "app-destination"),
        _ => return None,
    };
    if app.id.is_empty() {
        return None;
    }
    let done = match result {
        Ok(v) => {
            v.get("ok").and_then(|b| b.as_bool()).unwrap_or(true)
                && (v.get("verified").and_then(|b| b.as_bool()) != Some(false)
                    || v.get("ruleVerified").and_then(|b| b.as_bool()) == Some(true))
        }
        Err(_) => false,
    };
    let mechanism = result
        .as_ref()
        .ok()
        .and_then(|v| v.get("mechanism").and_then(|m| m.as_str()))
        .filter(|m| !m.is_empty())
        .unwrap_or(mechanism)
        .to_string();
    let mut detail = serde_json::Map::new();
    detail.insert("mechanism".into(), serde_json::Value::String(mechanism));
    let kind = match (blocking, done) {
        (true, true) => ActivityKind::Block,
        (false, true) => ActivityKind::Unblock,
        (true, false) => {
            let error = match result {
                Ok(v) => v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .or_else(|| v.get("warning").and_then(|w| w.as_str()))
                    .unwrap_or("block incomplete")
                    .to_string(),
                Err(e) => e.clone(),
            };
            let capped: String = error.chars().take(vallumd::activity::ERROR_CAP).collect();
            detail.insert("error".into(), serde_json::Value::String(capped));
            ActivityKind::BlockFailed
        }
        (false, false) => return None,
    };
    Some(vallumd::activity::ActivityEntry::new(
        now,
        kind,
        Some(app.clone()),
        serde_json::Value::Object(detail),
    ))
}

/// Why a verb that runs only in the system daemon was refused by this one,
/// and what reaches it there: root for a request that lowers protection,
/// chooses the org or blocks addresses host-wide; for anything else, root or
/// a member of the socket's group.
fn system_only(req: &vallumd::control::Request, what: &str) -> String {
    let cmd = &req.cmd;
    match vallumd::control::root_needed(req) {
        Some((why, cli)) => format!(
            "{cmd}: {what} runs in the system daemon only, where it needs root ({why}); run: sudo kub0 {cli}"
        ),
        None => format!(
            "{cmd}: {what} runs in the system daemon only; it answers root and members of the {group} group \
             (`sudo kub0 install` installs it and adds the installing user; a new login applies the membership)",
            group = vallumd::system_status::STATUS_GROUP
        ),
    }
}

/// The timed destination block's durations, the helper's and the panel's:
/// 5 minutes, 15 minutes, 1 hour (`docs/DESTINATION-RULES.md`).
const DEST_SECONDS: [u64; 3] = [300, 900, 3600];

/// A destination for `block-dest`/`unblock-dest`: one literal unicast
/// address, canonicalised. The helper checks it again.
fn dest_ip(cmd: &str, raw: &str) -> Result<String, String> {
    let ip: std::net::IpAddr = raw
        .parse()
        .map_err(|_| format!("{cmd}: {raw:?} is not a literal IPv4 or IPv6 address"))?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("{cmd}: {ip} is not a unicast address"));
    }
    Ok(ip.to_string())
}

/// The helper's argv for one request, or why the request is malformed. No
/// helper runs on an error.
fn helper_argv(req: &vallumd::control::Request) -> Result<Vec<String>, String> {
    let app = req.str_arg("app");
    let need_app = |cmd: &str| -> Result<(), String> {
        if app.is_empty() {
            Err(format!("{cmd} needs an app id"))
        } else {
            Ok(())
        }
    };
    Ok(match req.cmd.as_str() {
        "blocks" => vec!["status".into()],
        "pause" => vec!["pause".into()],
        "resume" => vec!["resume".into()],
        "teardown" => vec!["teardown".into()],
        "block" => {
            need_app("block")?;
            let ips = req.list_arg("ips");
            if ips.is_empty() {
                let mut a = vec!["block-app".to_string(), app.clone()];
                a.extend(req.list_arg("pids"));
                a
            } else {
                let mut a = vec!["block-ips".to_string(), app.clone()];
                a.extend(ips);
                a
            }
        }
        "unblock" => {
            need_app("unblock")?;
            let verb = if req.str_arg("scope") == "ips" { "unblock-ips" } else { "unblock-app" };
            vec![verb.to_string(), app.clone()]
        }
        "block-dest" => {
            need_app("block-dest")?;
            let ip = dest_ip("block-dest", &req.str_arg("ip"))?;
            let seconds = req
                .args
                .get("seconds")
                .and_then(|v| v.as_u64())
                .filter(|s| DEST_SECONDS.contains(s))
                .ok_or("block-dest: seconds must be 300, 900 or 3600 (5 minutes, 15 minutes, 1 hour)")?;
            // The helper moves the app's verified process tree into the rule's
            // cgroup, from these seeds; it has no way to find them itself.
            let pids = req.list_arg("pids");
            if pids.is_empty() {
                return Err("block-dest needs the app's process ids (pids)".into());
            }
            if let Some(bad) = pids.iter().find(|p| p.parse::<u32>().map_or(true, |n| n == 0)) {
                return Err(format!("block-dest: {bad} is not a pid"));
            }
            let mut a = vec!["block-scoped".to_string(), app.clone(), ip, seconds.to_string()];
            a.extend(pids);
            a
        }
        "unblock-dest" => {
            need_app("unblock-dest")?;
            let ip = dest_ip("unblock-dest", &req.str_arg("ip"))?;
            vec!["unblock-scoped".to_string(), app.clone(), ip]
        }
        other => return Err(format!("unhandled helper command {other}")),
    })
}

/// Longest rule id `policy-snooze`/`policy-resume` take; the legacy line's cap.
const POLICY_RULE_MAX: usize = 100;

/// `policy-snooze`'s `seconds`: an hour when absent, else a whole number from
/// a minute to a day (the bounds `netpolicy::snooze` clamps to).
fn snooze_seconds(args: &serde_json::Value) -> Result<u64, String> {
    match args.get("seconds") {
        None | Some(serde_json::Value::Null) => Ok(3600),
        Some(v) => v
            .as_u64()
            .filter(|s| (60..=vallumd::netpolicy::MAX_SNOOZE_MS / 1000).contains(s))
            .ok_or_else(|| "policy-snooze: seconds must be a whole number from 60 to 86400".into()),
    }
}

const SHARE_IS_THE_SYSTEM_DAEMONS: &str =
    "destination sharing is a setting of the system daemon (sudo kub0 share on); this daemon is started by the panel, whose own switch decides it";

const WATCH_NEEDS_LIVE: &str =
    "Watch rules need the live procfs source; this daemon is replaying or reading another engine's database.";

/// Who is changing a watch rule, for the ownership check: `None` may change
/// any rule (root, or the owner of a user daemon, whose rules are all theirs);
/// `Some(uid)` is a group member on the system daemon, where the rules are
/// every user's, and may change only the rules it set.
fn watch_actor(mode: DaemonMode, peer: vallumd::control::Peer) -> Option<u32> {
    match (mode, peer.uid) {
        (DaemonMode::User, _) | (_, Some(0)) => None,
        // An unidentified peer never gets here (authorize keeps it to reads);
        // if it did, it owns nothing.
        (DaemonMode::System, uid) => Some(uid.unwrap_or(u32::MAX)),
    }
}

/// Whose a newly set rule is. A member's is their own. Root's is root's, unless
/// root set it for someone (`as_uid`: `sudo kub0 watch add`, and `kub0 install`
/// carrying a person's rules over from the panel's own daemon): then it is
/// theirs, so they can change it afterwards without root. Root's authority
/// over every rule is `actor`, and is not narrowed by whom it acts for.
fn watch_new_owner(mode: DaemonMode, actor: Option<u32>, acting: Option<u32>) -> Option<u32> {
    match (mode, actor) {
        (DaemonMode::System, None) => acting.filter(|uid| *uid != 0),
        _ => actor,
    }
}

fn watch_owned(rule: &vallumd::watch::Rule, actor: Option<u32>) -> Result<(), String> {
    match actor {
        None => Ok(()),
        Some(uid) if rule.owner == Some(uid) => Ok(()),
        Some(_) => Err(format!(
            "watch rule {} was set by another user; only they or root can change it",
            rule.id
        )),
    }
}

/// Add a watch rule, or update the note of one the actor may change.
fn watch_set(
    live: &mut Live,
    kind: &str,
    value: &str,
    note: &str,
    actor: Option<u32>,
    new_owner: Option<u32>,
) -> Result<vallumd::watch::Rule, String> {
    let kind = vallumd::watch::RuleKind::parse(kind).ok_or_else(|| format!("unknown watch kind {kind:?}"))?;
    let mut rule = vallumd::watch::Rule::new(kind, value, note, now_ms())?;
    if let Some(existing) = live.watch.rules().iter().find(|r| r.id == rule.id) {
        watch_owned(existing, actor)?;
        rule.owner = existing.owner;
    } else {
        rule.owner = new_owner;
    }
    live.watch.set(rule.clone())?;
    Ok(live.watch.rules().iter().find(|r| r.id == rule.id).cloned().unwrap_or(rule))
}

fn watch_delete(live: &mut Live, id: &str, actor: Option<u32>) -> Result<vallumd::watch::Rule, String> {
    let existing = live
        .watch
        .rules()
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("no watch rule {id}"))?;
    watch_owned(existing, actor)?;
    live.watch.remove(id).ok_or_else(|| format!("no watch rule {id}"))
}

/// Store a tag and send every client the retagged rows.
fn apply_tag(live: &mut Live, server: &mut Server, cmd: TagCmd) -> Result<(), String> {
    let reports = server.kub0.fleet_snapshot().fleet_tags;
    let saved = persist_tag_cmd(live, cmd, &reports);
    let snap = Event::Snapshot {
        ts: now_ms(),
        connections: live.snapshot(),
    };
    server.broadcast(&snap.to_line());
    saved
}

const PAUSED_REASON: &str = "Enforcement is paused from the panel; these rules apply when it resumes";
/// kub0-block's nftables names: its table (`TABLE`), the output chain the fleet
/// rules sit in, their comment and the panel's pause comment. Pinned to the helper's
/// source by `daemon_fleet_rule_check_matches_the_helper`.
const NFT_TABLE: &str = "vallum";
const NFT_CHAIN: &str = "out";
const FLEET_COMMENT: &str = "vallum-fleet";
const PAUSE_COMMENT: &str = "vallum-paused";
/// The PATH kub0-block pins for itself: root never finds nft through an inherited one.
const NFT_SEARCH_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// A chain listing takes milliseconds. One that takes longer is a wedged nft, and the
/// heartbeat thread must not wait on it.
const KERNEL_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Applies the org's effective block rules through kub0-block `fleet-sync`. Only the
/// system kub0d (root) enforces; a user-mode kub0d would need a password prompt for
/// every sync, so its block rules are reported as would-block and the panel says why.
struct Enforcer {
    data_dir: PathBuf,
    helper: PathBuf,
    /// The nft binary the kernel is read with. A bare name resolves on NFT_SEARCH_PATH.
    nft: PathBuf,
    read_timeout: Duration,
    ranges: Option<vallumd::netpolicy::RangeCache>,
    /// Hash of the spec the kernel holds, when we put one there.
    applied: Option<u64>,
    /// What the fleet-sync that put `applied` there reported, re-published while the
    /// kernel is seen to still hold it.
    synced: vallumd::netpolicy::Enforcement,
    /// The kernel may hold fleet rules `applied` does not describe: a previous kub0d's,
    /// left by a restart or a crash, or whatever a failed sync or clear left behind.
    /// False once a sync or a clear lands, or the kernel is seen to hold none.
    stray: bool,
    /// The policy set is an answer, not the empty set a fresh process or a new account
    /// starts from: the server's (a 200, or a 304 of one), or no account at all. Only
    /// then does an empty set take rules out; a failed fetch says nothing about them.
    policy_known: bool,
    replan_at: Option<u64>,
    last: vallumd::netpolicy::Enforcement,
    /// The last drift line logged, so rules that keep vanishing log once.
    drift: String,
}

impl Enforcer {
    fn new(data_dir: PathBuf, helper: PathBuf) -> Self {
        Self {
            data_dir,
            helper,
            nft: PathBuf::from("nft"),
            read_timeout: KERNEL_READ_TIMEOUT,
            ranges: None,
            applied: None,
            synced: Default::default(),
            stray: true,
            policy_known: false,
            replan_at: None,
            last: Default::default(),
            drift: String::new(),
        }
    }

    /// Take every fleet rule out of the kernel. Idempotent in the helper. A clear that
    /// fails marks nothing cleared, so the next empty set tries again.
    fn clear(&mut self) -> Result<(), String> {
        run_helper(&self.helper, "fleet-clear", None)?;
        self.applied = None;
        self.stray = false;
        Ok(())
    }

    /// Log a drift line once, not every heartbeat, until the kernel is seen to hold the
    /// rules again. True when it logged.
    fn note_drift(&mut self, msg: &str) -> bool {
        if self.drift == msg {
            return false;
        }
        eprintln!("kub0d: {msg}");
        self.drift = msg.into();
        true
    }

    /// Which fleet rules the kernel holds, read directly and read-only.
    fn kernel(&self) -> Result<FleetRules, String> {
        read_fleet_chain(&self.nft, self.read_timeout).map(|listing| fleet_rules_in(&listing))
    }

    /// Bring the kernel in line with the org's block rules. A plan the kernel
    /// already holds is checked there, not applied again.
    fn sync(&mut self, rt: &Kub0Runtime, system: bool, server_url: &str) {
        self.apply(rt, system, server_url, false)
    }

    /// `kub0 sync`: the same, except nothing is taken on this process's own
    /// record. A plan the kernel already holds is put there again (the check
    /// reads the chain's rules, never the sets behind them), and an org list
    /// known to be empty clears the fleet rules whether or not any were
    /// tracked here.
    fn reapply(&mut self, rt: &Kub0Runtime, system: bool, server_url: &str) {
        self.apply(rt, system, server_url, true)
    }

    fn apply(&mut self, rt: &Kub0Runtime, system: bool, server_url: &str, force: bool) {
        use vallumd::netpolicy::Enforcement;
        let set = rt.policies();
        let now = now_ms();
        if !set.has_effective_block() {
            let can_clear = system && cfg!(target_os = "linux") && self.helper.is_file();
            let held = self.applied.is_some() || ((self.stray || force) && can_clear);
            let e = if !held {
                Enforcement { state: "none".into(), ..Default::default() }
            } else if !self.policy_known {
                self.unanswered()
            } else {
                match self.clear() {
                    Ok(()) => Enforcement { state: "none".into(), ..Default::default() },
                    // Saying "none" over a drop rule that may still be live is the drift.
                    Err(e) => Enforcement {
                        state: "error".into(),
                        reason: format!("the previous block rules may still be in the kernel: {e}"),
                        ..Default::default()
                    },
                }
            };
            self.publish(rt, e);
            return;
        }
        let not_here = |reason: &str| Enforcement {
            state: "monitor".into(),
            reason: reason.into(),
            ..Default::default()
        };
        if !system {
            self.publish(rt, not_here("Block rules are enforced only when kub0d runs as the system service"));
            return;
        }
        if !cfg!(target_os = "linux") {
            self.publish(rt, not_here("Block rules need Linux nftables; this endpoint reports them"));
            return;
        }
        if !self.helper.is_file() {
            self.publish(rt, Enforcement {
                state: "error".into(),
                reason: format!("{} is not installed", self.helper.display()),
                ..Default::default()
            });
            return;
        }
        let data_dir = self.data_dir.clone();
        let ranges = self
            .ranges
            .get_or_insert_with(|| vallumd::netpolicy::RangeCache::new(&data_dir, rt.asn()));
        let shared = ranges.shared();
        if shared.is_empty() {
            // No shared-infrastructure ranges to keep, whether the ASN database is missing
            // or holds no such records: a block range that covers a CDN would cut off
            // every site behind it. Apply nothing new. Rules an earlier run put in the
            // kernel were built with a keep set, so they stay.
            self.publish(rt, Enforcement {
                state: "error".into(),
                reason: format!(
                    "no shared-infrastructure ranges from the ASN database ({}, data dir {}), so no block rules are applied; any already in the kernel were left in place (it is read once: restart kub0d after installing it)",
                    data_dir.join("geoip/dbip-asn-lite.mmdb").display(),
                    data_dir.display()
                ),
                ..Default::default()
            });
            return;
        }
        let plan = set.plan(ranges, &rt.snoozes(), now);
        if plan.no_country_db {
            // The same for a country block rule with no database to give it ranges: the
            // plan without them would take an earlier run's country blocks out. That is
            // not the org saying so, so nothing is applied and the kernel stays as it is.
            let db = ranges.country_db_path();
            self.publish(rt, Enforcement {
                state: "error".into(),
                reason: format!(
                    "the country database ({}, data dir {}) is missing or holds no countries, so country block rules have no ranges and no block rules are applied; any already in the kernel were left in place (it is read once: restart kub0d after installing it)",
                    db.display(),
                    data_dir.display()
                ),
                ..Default::default()
            });
            return;
        }
        let mut keep: Vec<String> = vallumd::netpolicy::server_addrs(server_url)
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        keep.extend(shared.iter().cloned());
        let spec = serde_json::json!({"block": plan.block, "keep": keep}).to_string();
        let hash = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            spec.hash(&mut h);
            h.finish()
        };
        let due = self.replan_at.is_some_and(|t| now >= t);
        if self.applied == Some(hash) && !due && !force {
            // The kernel held this plan when we put it there, but `kub0-block
            // teardown`, an nftables reload or a flush can take it out underneath us.
            // Look again; only the panel's pause is expected to change.
            match self.kernel() {
                Ok(FleetRules::Present { paused }) => {
                    self.drift.clear();
                    let mut e = self.synced.clone();
                    e.enforcing = !paused;
                    e.reason = if paused { PAUSED_REASON.into() } else { String::new() };
                    self.publish(rt, e);
                    return;
                }
                // Re-apply: fleet-sync checks its own rules landed, so "enforcing"
                // below is again something the kernel was seen to hold. With one family's
                // rule gone it adds back just that one.
                Ok(FleetRules::Absent | FleetRules::Partial) => {
                    self.note_drift("network-policy rules are missing from the kernel; re-applying");
                    self.applied = None;
                }
                // Not re-applied: fleet-sync runs the same nft, and a wedged one would
                // hang this thread. Report what is known and look again next heartbeat.
                Err(err) => {
                    self.publish(rt, Enforcement {
                        state: "error".into(),
                        reason: format!("cannot confirm the block rules are in the kernel ({err}); they are left as they are"),
                        ..Default::default()
                    });
                    return;
                }
            }
        }
        let e = match run_helper(&self.helper, "fleet-sync", Some(&spec)) {
            Ok(v) => {
                self.applied = Some(hash);
                self.stray = false;
                self.replan_at = plan.next_expiry;
                let paused = v.get("paused").and_then(|x| x.as_bool()).unwrap_or(false);
                let e = Enforcement {
                    state: "enforcing".into(),
                    reason: if paused {
                        PAUSED_REASON.into()
                    } else {
                        String::new()
                    },
                    enforcing: !paused,
                    rules: plan.rules,
                    skipped: plan.skipped,
                    entries: plan.block.len() as u64,
                    shared_ranges: shared.len() as u64,
                    applied_ts: now,
                };
                self.synced = e.clone();
                e
            }
            Err(err) => {
                // A transaction that failed leaves the earlier sets in place, so the
                // kernel may still hold rules: a later "none" from the server must
                // still take them out.
                self.applied = None;
                self.stray = true;
                Enforcement { state: "error".into(), reason: err, ..Default::default() }
            }
        };
        self.publish(rt, e);
    }

    /// The set is empty because nothing has been received for this account yet (a
    /// restart, an account change, a fetch that keeps failing), not because the server
    /// said none. The kernel is left alone; this says what it holds, read rather than
    /// assumed from `applied` (a teardown may have taken it out), so only a read that
    /// fails falls back on "may hold". Any fleet drop rule counts, one family's included.
    fn unanswered(&mut self) -> vallumd::netpolicy::Enforcement {
        use vallumd::netpolicy::Enforcement;
        let reason = match self.kernel() {
            Ok(FleetRules::Absent) => {
                self.stray = false;
                return Enforcement { state: "none".into(), ..Default::default() };
            }
            Ok(FleetRules::Present { .. } | FleetRules::Partial) => "no network policy has been received for this account yet; the block rules already in the kernel are left in place until one is".to_string(),
            Err(e) => format!(
                "no network policy has been received for this account yet and the kernel cannot be read ({e}); any block rules already there are left in place"
            ),
        };
        Enforcement { state: "error".into(), reason, ..Default::default() }
    }

    // Late account changes retire only diagnostics, never the enforcement clear gate.
    fn retire_diagnostics(&self, rt: &Kub0Runtime) {
        if let Ok(mut plan) = rt.system_plan.lock() {
            plan.account_retired = true;
            plan.known = false;
        }
    }

    fn publish(&mut self, rt: &Kub0Runtime, e: vallumd::netpolicy::Enforcement) {
        if let Ok(mut plan) = rt.system_plan.lock() {
            plan.known = self.policy_known && !plan.account_retired;
            // synced is the last acknowledged plan, including while refresh fails.
            plan.applied_at = self.synced.applied_ts;
        }
        if e != self.last {
            if e.state == "error" {
                eprintln!("kub0d: network-policy enforcement: {}", e.reason);
            }
            self.last = e.clone();
        }
        rt.set_enforcement(e);
    }
}

/// `nft -a list chain inet vallum out`, as kub0-block's own `fleet-sync` reads it: the
/// rules only, never the tens of thousands of set elements, with no helper, no lock and
/// no side effect. A chain or table that does not exist is an empty listing, but only on
/// nft's own word for it (`nft_says_no_such_chain`). Killed and an error after `timeout`.
fn read_fleet_chain(nft: &Path, timeout: Duration) -> Result<String, String> {
    use std::process::Stdio;
    fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<String> {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_string(&mut text);
            }
            text
        })
    }
    let mut child = Command::new(nft)
        .args(["-a", "list", "chain", "inet", NFT_TABLE, NFT_CHAIN])
        .env("PATH", NFT_SEARCH_PATH)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match other {
                    Err(e) => format!("nft: {e}"),
                    _ => format!("nft did not answer within {timeout:?}"),
                });
            }
        }
    };
    let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    if status.success() {
        return Ok(out);
    }
    if status.code() == Some(1) && nft_says_no_such_chain(&err) {
        return Ok(String::new());
    }
    Err(format!("nft list chain failed: {}", err.trim()))
}

/// nft's answer for a table or chain that is not there: it ran and exited 1, its
/// diagnostic is ENOENT, and the next line is the command it was given, the object named
/// in it. ENOENT from anything else is not that: a dynamic loader that cannot find
/// libnftables says "No such file or directory" too, and exits 127.
fn nft_says_no_such_chain(stderr: &str) -> bool {
    let mut lines = stderr.lines().map(str::trim).filter(|l| !l.is_empty());
    lines.next().is_some_and(|l| l.starts_with("Error: No such file or directory"))
        && lines.next() == Some(format!("list chain inet {NFT_TABLE} {NFT_CHAIN}").as_str())
}

/// What a chain listing says about the fleet drop rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FleetRules {
    /// Neither family's.
    Absent,
    /// One family's only: a clear or a sync cut short. Not enforcing, but not nothing:
    /// it still drops, so it still has to come out.
    Partial,
    /// Both families' (kub0-block's `fleet::rules_present`, which fleet-sync checks
    /// itself with), and whether the panel's pause rule sits ahead of them.
    Present { paused: bool },
}

/// Which fleet drop rules a chain listing holds.
fn fleet_rules_in(listing: &str) -> FleetRules {
    let fleet = |line: &str, set: &str| {
        line.contains(&format!("@{set}")) && line.contains(FLEET_COMMENT) && line.contains("drop")
    };
    let (mut v4, mut v6, mut paused) = (false, false, false);
    for line in listing.lines() {
        if fleet(line, "fleet4") {
            v4 = true;
        } else if fleet(line, "fleet6") {
            v6 = true;
        } else if !(v4 || v6)
            && line.contains(&format!("comment \"{PAUSE_COMMENT}\""))
            && line.split_whitespace().any(|t| t == "accept")
        {
            paused = true;
        }
    }
    match (v4, v6) {
        (true, true) => FleetRules::Present { paused },
        (false, false) => FleetRules::Absent,
        _ => FleetRules::Partial,
    }
}

/// Run one kub0-block verb with an optional stdin body; its JSON on success.
fn run_helper(helper: &Path, verb: &str, stdin: Option<&str>) -> Result<serde_json::Value, String> {
    run_helper_args(helper, &[verb], stdin, None)
}

/// `run_helper` with the verb's arguments and, for a request relayed from a
/// `kub0` client, that client's uid as `PKEXEC_UID`: the helper validates
/// the PIDs it is handed against the invoking user, never against root. The
/// environment is pinned the way pkexec pins it; root never resolves `nft`
/// through a PATH a client chose.
fn run_helper_args(
    helper: &Path,
    args: &[&str],
    stdin: Option<&str>,
    caller_uid: Option<u32>,
) -> Result<serde_json::Value, String> {
    let verb = args.first().copied().unwrap_or("");
    let (success, text, err) = helper_output(helper, args, stdin, caller_uid)?;
    if success {
        return serde_json::from_str(text.trim()).map_err(|e| format!("{verb}: bad reply: {e}"));
    }
    Err(format!("{verb} failed: {}", if text.trim().is_empty() { err.trim() } else { text.trim() }))
}

/// For a control request: the helper's JSON whatever its exit status, so a
/// refusal reaches the caller with its fields (`error`, `code`, `rollback`)
/// rather than flattened into a string. A non-zero exit never reads as
/// success: an object without `ok` gets `ok: false`. Output that is not a
/// JSON object is an error string, as from `run_helper_args`.
fn run_helper_for_request(helper: &Path, args: &[&str], caller_uid: Option<u32>) -> Result<serde_json::Value, String> {
    let verb = args.first().copied().unwrap_or("");
    let (success, text, err) = helper_output(helper, args, None, caller_uid)?;
    match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(serde_json::Value::Object(mut obj)) => {
            if !success && obj.get("ok").and_then(|b| b.as_bool()) != Some(false) {
                obj.insert("ok".into(), serde_json::Value::Bool(false));
            }
            Ok(serde_json::Value::Object(obj))
        }
        _ if success => Err(format!("{verb}: bad reply: {}", text.trim())),
        _ => Err(format!("{verb} failed: {}", if text.trim().is_empty() { err.trim() } else { text.trim() })),
    }
}

/// Run the helper with a pinned environment; whether it exited 0, and its
/// stdout and stderr. An error only when it could not be run at all.
fn helper_output(
    helper: &Path,
    args: &[&str],
    stdin: Option<&str>,
    caller_uid: Option<u32>,
) -> Result<(bool, String, String), String> {
    use std::io::Write;
    let verb = args.first().copied().unwrap_or("");
    let mut command = std::process::Command::new(helper);
    command
        .args(args)
        .env_clear()
        .env("PATH", NFT_SEARCH_PATH)
        .env("LC_ALL", "C");
    if let Some(uid) = caller_uid {
        command.env("PKEXEC_UID", uid.to_string());
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{verb}: {e}"))?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin.unwrap_or("").as_bytes())
            .map_err(|e| format!("{verb} stdin: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("{verb}: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}


fn run_replay(path: &Path, args: &Args) -> Result<(), String> {
    let kub0_rt = Kub0Runtime::new();
    let mut server = Server::bind(
        &args.socket,
        args.rdns,
        args.mode,
        kub0_rt,
        &args.state_dir,
    )
    .map_err(|e| format!("bind {}: {e}", args.socket.display()))?;
    eprintln!(
        "kub0d: replay {} on {}",
        path.display(),
        args.socket.display()
    );
    loop {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut snapshot: Vec<Connection> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            server.accept_new(&snapshot);
            let _ = server.drain_commands();
            if let Ok(ev) = serde_json::from_str::<Event>(line) {
                if let Event::Connect { conn, .. } = &ev {
                    snapshot.retain(|c| c.id != conn.id);
                    snapshot.push(conn.clone());
                }
                if let Event::Disconnect { id, .. } = &ev {
                    snapshot.retain(|c| c.id != *id);
                }
                if let Event::Snapshot { connections, .. } = &ev {
                    snapshot = connections.clone();
                }
            }
            let mut out = line.to_string();
            out.push('\n');
            server.broadcast(&out);
            std::thread::sleep(Duration::from_millis(80));
        }
        if !args.replay_loop {
            // Keep the socket up so the UI can reconnect and get the last snapshot.
            loop {
                server.accept_new(&snapshot);
                std::thread::sleep(Duration::from_millis(400));
            }
        }
    }
}

struct Live {
    geo: GeoDb,
    seen: SeenSet,
    apps: AppResolver,
    inode_pid: HashMap<u64, u32>,
    /// Socket inodes the last scan could not attribute to any readable
    /// process: in practice sockets owned by another uid (resolved,
    /// NetworkManager, avahi) when the daemon runs as the user. Each one used
    /// to trigger a full /proc walk of its own on every sample, and could never
    /// succeed. Cleared by the next full scan, which re-derives it.
    unowned: HashSet<u64>,
    live: HashMap<String, Connection>,
    /// (app_id, remote_ip, remote_port) → last seen ms for connected UDP aggregation
    udp_agg: HashMap<(String, String, u16), u64>,
    last_full_scan: Instant,
    /// Cost of the last full walk. A cheap delta pass must not make the next
    /// tick schedule a full walk on a busy host.
    last_full_scan_cost: Duration,
    /// True while any client has a panel open: `!panel_clients.is_empty()`.
    panel_open: bool,
    /// The clients between their own panel-open and panel-close. One panel
    /// closing must not put the daemon into passive cadence under another
    /// that is still open (the system daemon's socket admits its whole group).
    panel_clients: HashSet<u64>,
    away_new: Vec<String>,
    last_flush: Instant,
    /// Counts from the last full `scan_inodes(None)` only.
    scanned_fd_dirs: usize,
    unreadable_fd_dirs: usize,
    unknown_log: UnknownLog,
    /// uid → passwd entry, read once at startup. Names the ~5% of
    /// unattributable sockets owned by a dedicated service account with
    /// certainty, which is the only tier safe to apply without asking.
    accounts: vallumd::suggest::Accounts,
    /// The kernel routing table, refreshed each poll. It is what lets the
    /// ladder say "your router" or "a machine on your tailnet" instead of
    /// "on your LAN": a peer inside one of our own on-link routes is named
    /// by a local authority, not guessed at from its address range.
    routes: Vec<vallumd::routes::Route>,
    /// Where this host draws the system/human uid line, from
    /// `/etc/login.defs`. Human logins own most of a desktop and so name
    /// nothing; see `suggest::clue`.
    sys_uid_max: u32,
    /// Persisted names for network keys. Loaded once; user tags written
    /// through the `tag` IPC command stick across restarts.
    tags: vallumd::tags::TagStore,
    /// Reverse lookups, off the sample loop. Unattributed sockets are looked
    /// up even when `--rdns` is off (they are the only rows that need a name),
    /// and a first poll on a fresh cache can face hundreds of distinct IPs --
    /// 351 on one live desktop. These used to fork `getent` inline, with no
    /// timeout of its own, so an unresponsive resolver stalled the poll loop
    /// once per IP. Now a row is created with whatever name is already known
    /// and patched when its lookup lands; see [`apply_names`].
    resolver: vallumd::rdns::Resolver,
    /// Unattributed rows created while their name was still being looked up.
    /// Their first-seen `unknown.ndjson` record waits for the answer (or for
    /// the row to go), so the backlog keeps the PTR evidence it always had.
    unknown_pending: HashSet<String>,
    traffic: vallumd::traffic::Tracker,
    traffic_clock: Instant,
    /// What each app has done before on this machine; `baseline.json`.
    baseline: intel::BaselineStore,
    /// Arrival times per (app, destination), for the regular-cadence rung.
    cadence: intel::Cadence,
    /// Distinct networks per app in the last minute, for the fan-out rung.
    fan_out: intel::FanOut,
    /// The user's watch rules; `watchlist.json`, re-read when it changes.
    watch: vallumd::watch::WatchStore,
    /// Per-app traffic from the last sample, for `kub0 apps`.
    bandwidth: Vec<vallumd::traffic::AppTraffic>,
    /// Executable flags now, hashes later, off the sample loop.
    prober: vallumd::provenance::Prober,
    /// ASN and organisation of public peers. Shared with the policy engine;
    /// `run_live` swaps in the one `Kub0Runtime` loaded.
    asn: Arc<vallumd::geo::AsnDb>,
    /// Listening sockets as last published; compared each sample.
    listeners: Vec<Listener>,
    /// Lower bound of the kernel's ephemeral port range. A UDP socket bound
    /// below it was bound on purpose and is listed as a listener.
    ephemeral_low: u16,
    /// (indicator id, app id, remote ip) already written to the activity log
    /// this run, so a periodic app is logged once, not once per period.
    indicator_logged: HashSet<(String, String, String)>,
    /// (pid, exe) -> lineage, read once per process rather than once per
    /// connection: a browser opens dozens of sockets per sample.
    lineage_cache: HashMap<(u32, String), vallumd::lineage::Lineage>,
    /// Names this uid's software asked DNS for, from the optional collector.
    dns: vallumd::dns::Cache,
    /// The host's configured resolvers; an answer from any other server is
    /// counted as foreign and never names a row.
    resolvers: vallumd::dns::Resolvers,
    dns_foreign: u64,
    last_prune: Instant,
}

type UnknownKey = (String, Option<u32>, String, u16);

/// Why a socket has no owning pid. `orphan` wins; a scan that opened nothing
/// is blind (`unreadable`), not a perfect empty pass (`no-owner`).
pub fn missing_owner_reason(
    inode: u64,
    scanned_fd_dirs: usize,
    unreadable_fd_dirs: usize,
) -> &'static str {
    if inode == 0 {
        "orphan"
    } else if scanned_fd_dirs > 0 && unreadable_fd_dirs == 0 {
        "no-owner"
    } else {
        "unreadable"
    }
}

fn unknown_log_key(proto: &str, uid: Option<u32>, remote_ip: &str, remote_port: u16) -> UnknownKey {
    (proto.to_string(), uid, remote_ip.to_string(), remote_port)
}

fn unknown_key_from_value(v: &serde_json::Value) -> Option<UnknownKey> {
    let proto = v.get("proto")?.as_str()?.to_string();
    let uid = match v.get("uid") {
        None | Some(serde_json::Value::Null) => None,
        Some(x) => Some(x.as_u64()? as u32),
    };
    let remote = v.get("remote")?;
    let ip = remote.get("ip")?.as_str()?.to_string();
    let port = remote.get("port")?.as_u64()? as u16;
    Some((proto, uid, ip, port))
}

#[derive(serde::Serialize)]
struct UnknownRecord {
    ts: u64,
    proto: String,
    uid: Option<u32>,
    reason: String,
    inode: u64,
    state: String,
    local: Endpoint,
    remote: Endpoint,
    #[serde(rename = "networkKey")]
    network_key: String,
    country: String,
    hostname: String,
    /// The clue as it stood when the row was first written. Persisted rather
    /// than recomputed so the backlog keeps the evidence that was actually
    /// available at the time -- a PTR that has since changed, or a package
    /// manager that has since been removed, should not silently rewrite
    /// history the user may already have tagged against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clue: Option<vallumd::suggest::Clue>,
}

struct UnknownLog {
    path: PathBuf,
    keys: HashSet<UnknownKey>,
}

impl UnknownLog {
    fn load(state_dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(state_dir);
        let path = state_dir.join("unknown.ndjson");
        let mut keys = HashSet::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(k) = unknown_key_from_value(&v) {
                    keys.insert(k);
                }
            }
        }
        Self { path, keys }
    }

    fn consider(&mut self, conn: &Connection, ts: u64) -> bool {
        if conn.reason.is_empty() || conn.inode == 0 || conn.unresolved {
            return false;
        }
        let key = unknown_log_key(&conn.proto, conn.uid, &conn.remote.ip, conn.remote.port);
        if self.keys.contains(&key) {
            return false;
        }
        if self.keys.len() >= UNKNOWN_LOG_CAP {
            self.rotate();
        }
        let rec = UnknownRecord {
            ts,
            proto: conn.proto.clone(),
            uid: conn.uid,
            reason: conn.reason.clone(),
            inode: conn.inode,
            state: conn.state.clone(),
            local: conn.local.clone(),
            remote: conn.remote.clone(),
            network_key: conn.network_key.clone(),
            country: conn.country.clone(),
            hostname: conn.hostname.clone(),
            clue: conn.clue.clone(),
        };
        let Ok(mut line) = serde_json::to_string(&rec) else {
            return false;
        };
        line.push('\n');
        if self.append(&line).is_ok() {
            self.keys.insert(key);
            true
        } else {
            false
        }
    }

    fn rotate(&mut self) {
        let bak = self.path.with_file_name("unknown.ndjson.1");
        let _ = std::fs::rename(&self.path, &bak);
        self.keys.clear();
    }

    fn append(&self, line: &str) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())
    }
}

fn run_live(args: &Args) -> Result<(), String> {
    let proc_ok = Path::new("/proc/net/tcp").is_file();
    let kub0_rt = Kub0Runtime::new();
    kub0_rt.boot_netpolicy(&args.data_dir, &args.state_dir);
    kub0_rt.set_sharing_destinations(share_destinations_at_start(args.share_destinations, args.mode, &args.state_dir));
    let account_path = boot_kub0(args.mode, &args.state_dir, &kub0_rt);
    // Before the heartbeat thread, so its first refresh_fleet publishes keys.
    start_exec_gate(args.mode, &account_path);
    let _exec_gate = ExecGateGuard;
    let mut server = Server::bind(
        &args.socket,
        args.rdns,
        args.mode,
        Arc::clone(&kub0_rt),
        &args.state_dir,
    )
    .map_err(|e| format!("bind {}: {e}", args.socket.display()))?;
    let mut heartbeat = HeartbeatWatch::new(
        account_path,
        args.state_dir.clone(),
        Arc::clone(&kub0_rt),
        args.mode == DaemonMode::System,
    );
    server.emit_boot("procfs");
    let mut capture = None;
    if args.capture {
        match vallumd::capture::Capture::start() {
            Ok(mut c) => {
                server.capture_status = Some(c.poll().1);
                capture = Some(c);
            }
            Err(e) => server.capture_status = Some(vallumd::capture::Status::unavailable(e)),
        }
    }
    // KUB0_NO_PTR keeps every address off the resolver. The isolated tests
    // set it; it replaces the `getent` PATH shim they used to rely on.
    let resolver = if vallumd::rename::env_os("KUB0_NO_PTR").is_some() {
        vallumd::rdns::Resolver::disabled()
    } else {
        vallumd::rdns::Resolver::system()
    };
    let mut live = Live::new(&args.data_dir, args.mmdb.as_deref(), &args.state_dir, resolver, args.mode);
    live.asn = kub0_rt.asn();
    server.watch_rules = live.watch.rules().to_vec();
    if !proc_ok {
        eprintln!("kub0d: /proc/net/tcp not found; emitting empty snapshots (use --replay on this host)");
    }
    if !live.geo.has_mmdb() {
        eprintln!(
            "kub0d: no MMDB loaded; country/arcs will be empty until {} is present",
            args.data_dir.join("geoip/dbip-country-lite.mmdb").display()
        );
    }
    if !kub0_rt.asn().has_mmdb() {
        eprintln!(
            "kub0d: no ASN database; block rules will not be enforced until {} is present",
            args.data_dir.join("geoip/dbip-asn-lite.mmdb").display()
        );
    }
    eprintln!(
        "kub0d: listening on {} interval={}ms coverage={COVERAGE} rdns={}",
        args.socket.display(),
        args.interval.as_millis(),
        args.rdns
    );

    loop {
        if vallumd::execgate::stop_requested() {
            break;
        }
        let t0 = Instant::now();
        if let Some(capture) = capture.as_mut() {
            let (attempts, mut status) = capture.poll();
            if let Some(history) = server.history.as_mut() {
                for attempt in attempts {
                    history.record_attempt(attempt);
                }
            }
            let answers = capture.poll_dns();
            if !answers.is_empty() {
                live.resolvers.refresh(std::path::Path::new("/etc/resolv.conf"));
            }
            for answer in answers {
                if live.resolvers.accepts(&answer.server) {
                    live.dns.insert(&answer);
                } else {
                    live.dns_foreign = live.dns_foreign.saturating_add(1);
                }
            }
            status.dns_foreign = live.dns_foreign;
            server.capture_status = Some(status.clone());
            server.broadcast(
                &Event::CaptureStatus {
                    ts: now_ms(),
                    status,
                }
                .to_line(),
            );
        }
        server.accept_new(&live.snapshot());
        for (from, cmd) in server.drain_commands() {
            handle_cmd(&cmd, Some(&mut live), &mut server, from);
        }
        if proc_ok {
            sample(&mut live, &mut server, args.rdns);
        } else {
            let tick = Event::Tick {
                ts: now_ms(),
                count: 0,
                scanned_fd_dirs: 0,
                unreadable_fd_dirs: 0,
            };
            server.broadcast(&tick.to_line());
        }
        if live.last_flush.elapsed() > Duration::from_secs(5) {
            live.seen.flush();
            server.flush_history();
            if let Err(e) = live.baseline.save() {
                eprintln!("kub0d: baseline save failed: {e}");
            }
            // An edit from another daemon's client or an editor shows up here, and so do
            // the hit counts the rules collected since the last publish.
            live.watch.refresh();
            if live.watch.take_changed() {
                publish_watchlist(&live, &mut server, String::new());
            }
            live.last_flush = Instant::now();
        }
        if live.last_prune.elapsed() > Duration::from_secs(3600) {
            live.cadence.prune(now_ms().saturating_sub(7 * 24 * 3_600_000));
            let exes: HashSet<String> = live.live.values().map(|c| c.exe.clone()).collect();
            live.prober.retain(&exes);
            if live.indicator_logged.len() > 10_000 {
                live.indicator_logged.clear();
            }
            let pids: HashSet<u32> = live.live.values().map(|c| c.app.pid).collect();
            live.lineage_cache.retain(|(pid, _), _| pids.contains(pid));
            live.dns.prune(now_ms());
            live.last_prune = Instant::now();
        }
        heartbeat.tick();
        if server.take_account_changed() {
            heartbeat.tick_force();
        }
        server.poll_kub0_activity();
        server.poll_exec_gate();
        server.poll_fleet(Some(&mut live));
        let spent = t0.elapsed();
        forget_gone_panels(&mut live, &server);
        let mut want = poll_interval(on_battery(), live.panel_open, args.interval);
        // Opt-in capture has a bounded queue; drain it at the active cadence.
        if capture.as_ref().is_some_and(|c| c.running()) {
            want = want.min(Duration::from_millis(500));
        }
        if want > spent && !vallumd::execgate::stop_requested() {
            server.wait_io(want - spent);
            if vallumd::execgate::stop_requested() {
                break;
            }
            server.accept_new(&live.snapshot());
            let was_open = live.panel_open;
            for (from, cmd) in server.drain_commands() {
                handle_cmd(&cmd, Some(&mut live), &mut server, from);
            }
            // Sample at once when the panel has just opened. Any other wake
            // is floored at the active cadence, so a chatty client can never
            // drive the loop faster than it ran before passive mode existed.
            let spent = t0.elapsed();
            if !vallumd::execgate::stop_requested()
                && (was_open || !live.panel_open)
                && args.interval > spent
            {
                server.idle(args.interval - spent);
            }
        }
    }
    Ok(())
}

fn handle_cmd(cmd: &str, live: Option<&mut Live>, server: &mut Server, from: u64) {
    // A line with a `req` id is a request from one client and gets one
    // reply, to that client. Everything else is the legacy broadcast path.
    if let Some(req) = vallumd::control::Request::parse(cmd) {
        server.handle_request(from, req, live);
        return;
    }
    let v: serde_json::Value = match serde_json::from_str(cmd) {
        Ok(v) => v,
        Err(_) => return,
    };
    // A legacy line carries no access class for `authorize` to check, so on
    // the system daemon, whose socket admits its group, a mutating one is
    // root's alone; the client hears why. Reads go on as before.
    if let Some(name) = vallumd::control::legacy_mutation(&v) {
        let peer = server.peer_of(from).unwrap_or(vallumd::control::Peer { uid: None });
        if !vallumd::control::legacy_line_allowed(peer, server.daemon()) {
            let message = vallumd::control::legacy_refusal(name);
            server.send_to(from, &Event::Status { message }.to_line());
            return;
        }
    }
    let note_cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
    if note_cmd == "netpolicy-snooze" || note_cmd == "netpolicy-resume" {
        let rule = v.get("ruleId").and_then(|x| x.as_str()).unwrap_or("");
        if rule.is_empty() || rule.len() > 100 {
            return;
        }
        let outcome = if note_cmd == "netpolicy-snooze" {
            let seconds = v.get("seconds").and_then(|x| x.as_u64()).unwrap_or(3600);
            server.kub0.snooze_rule(rule, seconds).map(|_| ())
        } else {
            server.kub0.resume_rule(rule);
            Ok(())
        };
        if let Err(message) = outcome {
            server.broadcast(&Event::Status { message }.to_line());
        }
        server.kub0.republish_policy_view();
        return;
    }
    if note_cmd == "note" {
        match activity::parse_note(&v, now_ms()) {
            Ok(entry) => server.push_activity(entry),
            Err(msg) => eprintln!("kub0d: ignoring note: {msg}"),
        }
        return;
    }
    if note_cmd == "investigate" {
        let request = v.get("request").and_then(|x| x.as_str()).unwrap_or("");
        let subject = v.get("subject").and_then(|x| x.as_str()).unwrap_or("");
        if request.len() > 100 || subject.len() > 256 {
            return;
        }
        let now = now_ms();
        let since = v
            .get("since")
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
            .max(now.saturating_sub(vallumd::history::RETENTION_MS));
        let (pivot, error) = server.investigate_pivot(live.as_deref(), subject, since, now);
        // To the client that asked, like the two reads below: on the system
        // daemon every other client is another user's panel or CLI.
        server.send_to(
            from,
            &Event::Investigate {
                request: request.to_string(),
                pivot,
                error,
            }
            .to_line(),
        );
        return;
    }
    if note_cmd == "timeline" {
        let request = v.get("request").and_then(|x| x.as_str()).unwrap_or("");
        if request.len() > 100 {
            return;
        }
        let hours = v.get("hours").and_then(|x| x.as_u64()).unwrap_or(24).clamp(1, 168);
        let (timeline, error) = server.timeline_for(live.as_deref(), hours, now_ms());
        server.send_to(from, &Event::Timeline { request: request.to_string(), timeline, error }.to_line());
        return;
    }
    if note_cmd == "watch" {
        let Some(live) = live else {
            server.broadcast(
                &Event::Watchlist {
                    ts: now_ms(),
                    rules: Vec::new(),
                    error: WATCH_NEEDS_LIVE.into(),
                }
                .to_line(),
            );
            return;
        };
        let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
        // Only root's (system) or the owner's (user daemon) lines get here.
        let outcome = match action {
            "set" => {
                let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
                let value = v.get("value").and_then(|x| x.as_str()).unwrap_or("");
                let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("");
                watch_set(live, kind, value, note, None, None).map(|_| ())
            }
            "delete" => {
                let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
                watch_delete(live, id, None).map(|_| ())
            }
            _ => Err(format!("unknown watch action {action:?}")),
        };
        let error = match outcome.and_then(|()| live.watch.save().map_err(|e| e.to_string())) {
            Ok(()) => String::new(),
            Err(e) => e,
        };
        publish_watchlist(live, server, error);
        return;
    }
    if note_cmd == "history" {
        let request = v.get("request").and_then(|x| x.as_str()).unwrap_or("");
        let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("");
        if request.len() > 100 || query.len() > 256 {
            return;
        }
        let now = now_ms();
        let since = v
            .get("since")
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
            .max(now.saturating_sub(vallumd::history::RETENTION_MS));
        server.flush_history();
        let result = if server.history_error.is_empty() {
            server
                .history
                .as_ref()
                .ok_or_else(|| "History unavailable".to_string())
        } else {
            Err(server.history_error.clone())
        }
        .and_then(|h| h.query(query, since, vallumd::history::QUERY_CAP + 1));
        let (mut entries, error) = match result {
            Ok(rows) => (rows, String::new()),
            Err(e) => (Vec::new(), e),
        };
        let more = entries.len() > vallumd::history::QUERY_CAP;
        entries.truncate(vallumd::history::QUERY_CAP);
        server.send_to(from, &(serde_json::json!({ "type": "history", "request": request, "entries": entries, "more": more, "error": error, "retentionDays": 7, "rowCap": vallumd::history::ROW_CAP }).to_string() + "\n"));
        return;
    }
    let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    match ty {
        "panel-open" => {
            let Some(live) = live else { return };
            // No forced rescan needed: scan_interval() drops back to 5s now,
            // so a map passive mode left up to 60s stale is rebuilt on the
            // next sample, and one already under 5s old is not redone.
            //
            // The digest is what arrived while no panel was open. It goes to
            // the panel that opened, and only the first to open gets it: one
            // that opens beside another was not away from anything.
            let first = live.panel_clients.is_empty();
            live.panel_clients.insert(from);
            live.panel_open = true;
            let keys = if first { std::mem::take(&mut live.away_new) } else { Vec::new() };
            let ev = Event::Digest {
                ts: now_ms(),
                new_networks: keys.len(),
                keys,
            };
            server.send_to(from, &ev.to_line());
        }
        "panel-close" => {
            let Some(live) = live else { return };
            live.panel_clients.remove(&from);
            live.panel_open = !live.panel_clients.is_empty();
        }
        "ping" => {
            let ev = Event::Status {
                message: "ok".into(),
            };
            server.send_to(from, &ev.to_line());
        }
        "tag" => match parse_tag_cmd(&v) {
            Err(msg) => eprintln!("kub0d: ignoring tag: {msg}"),
            Ok(cmd) => {
                let Some(live) = live else { return };
                // persist_tag_cmd has logged a save failure already.
                let _ = apply_tag(live, server, cmd);
            }
        },
        _ => {}
    }
}

const TAG_LABEL_MAX: usize = 64;

#[derive(Debug)]
enum TagCmd {
    Set {
        network_key: String,
        label: String,
        kind: vallumd::suggest::Kind,
        /// The reverse-DNS suffix the name was given under, when root says so
        /// (`kub0 install` carrying a person's names over). Empty otherwise:
        /// the daemon uses the suffix its own live rows show.
        anchor: String,
    },
    Delete {
        network_key: String,
    },
}

fn parse_tag_cmd(v: &serde_json::Value) -> Result<TagCmd, String> {
    let key = v.get("networkKey").and_then(|x| x.as_str()).unwrap_or("");
    if key.is_empty() {
        return Err("empty networkKey".into());
    }
    let label = v.get("label").and_then(|x| x.as_str()).unwrap_or("");
    if label.chars().count() > TAG_LABEL_MAX {
        return Err("label exceeds 64 characters".into());
    }
    if label.is_empty() {
        return Ok(TagCmd::Delete {
            network_key: key.into(),
        });
    }
    let kind = match v.get("kind").and_then(|x| x.as_str()) {
        // Absent is not an error: a caller that only has a name is the normal
        // case, and Service is the honest "some product or network" default.
        None | Some("") => vallumd::suggest::Kind::Service,
        Some(s) => match serde_json::from_value(serde_json::Value::String(s.to_string())) {
            Ok(k) => k,
            // PRESENT but unmodelled is different, and it used to fall into the
            // same silent default: the caller stated a category, we stored a
            // different one, and nothing anywhere said so. Verified live
            // 2026-09-21 -- `kind: "infra"` round-tripped back as "service"
            // with no diagnostic. The tag is still worth keeping (the LABEL is
            // what the user actually typed), so this degrades rather than
            // refusing, but it degrades out loud.
            Err(_) => {
                eprintln!(
                    "kub0d: tag kind {s:?} is not one of this build's kinds -- \
                     storing the label under \"service\""
                );
                vallumd::suggest::Kind::Service
            }
        },
    };
    Ok(TagCmd::Set {
        network_key: key.into(),
        label: label.into(),
        kind,
        anchor: String::new(),
    })
}

/// A `ptrSuffix` a request names, when it is one this daemon may keep: a host
/// name suffix, from root only. The org compares a network's present reverse
/// DNS with the suffix a name was given under to tell that it has changed
/// hands, so a member must not be able to assert one the daemon never saw.
fn tag_anchor(args: &serde_json::Value, peer: vallumd::control::Peer) -> String {
    if peer.uid != Some(0) {
        return String::new();
    }
    let s = args.get("ptrSuffix").and_then(|x| x.as_str()).unwrap_or("");
    let ok = !s.is_empty() && s.len() <= 253 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if ok { s.to_string() } else { String::new() }
}

/// User tag > fleet tag > machine clue > nothing. First match wins.
fn resolve_tag(
    user: Option<&vallumd::tags::Tag>,
    fleet: Option<&vallumd::tags::Tag>,
    clue: Option<&vallumd::suggest::Clue>,
) -> Option<vallumd::tags::Tag> {
    match (user, fleet, clue) {
        (Some(tag), _, _) => Some(tag.clone()),
        (None, Some(tag), _) => Some(tag.clone()),
        (None, None, _) => None,
    }
}

/// Score org reports for this key and mint a fleet Tag, or None below quorum.
///
/// [`vallumd::tags::fleet_confidence`] never returns Certain; the match below
/// is the last line of defence so a future change to that function cannot
/// upgrade a fleet tag past Strong.
fn fleet_tag_from_reports(
    reports: &[vallumd::tags::FleetReport],
    network_key: &str,
    local_ptr: &str,
) -> Option<vallumd::tags::Tag> {
    let scored = vallumd::tags::score(reports, network_key)?;
    let sample = reports
        .iter()
        .find(|r| r.network_key == network_key && r.label == scored.label);
    let ptr_suffix = sample.map(|r| r.ptr_suffix.as_str()).unwrap_or("");
    let kind = sample
        .map(|r| r.kind)
        .unwrap_or(vallumd::suggest::Kind::Service);
    let conf = vallumd::tags::fleet_confidence(&scored, ptr_suffix, local_ptr);
    // Never Certain: that tier is a local authority. Cap so a future change
    // to fleet_confidence cannot mint Certain onto a Connection.tag.
    let _ = match conf {
        vallumd::suggest::Confidence::Certain => vallumd::suggest::Confidence::Strong,
        other => other,
    };
    Some(vallumd::tags::Tag {
        network_key: network_key.to_string(),
        label: scored.label,
        kind,
        ptr_suffix: ptr_suffix.to_string(),
        ts: 0,
        source: vallumd::tags::Source::Fleet,
    })
}

fn last_hostname_for(live: &Live, network_key: &str) -> String {
    live.live
        .values()
        .find(|c| c.network_key == network_key && !c.hostname.is_empty())
        .map(|c| c.hostname.clone())
        .unwrap_or_default()
}

/// Re-resolve tags on every unattributed live row from the local store (user)
/// and the latest scored fleet reports. Returns true when any row changed.
fn retag_unattributed(live: &mut Live, reports: &[vallumd::tags::FleetReport]) -> bool {
    let users: HashMap<String, vallumd::tags::Tag> = live
        .tags
        .iter()
        .filter(|t| t.source == vallumd::tags::Source::User)
        .map(|t| (t.network_key.clone(), t.clone()))
        .collect();
    let mut changed = false;
    for conn in live.live.values_mut() {
        if conn.app.pid != 0 {
            if conn.tag.take().is_some() {
                changed = true;
            }
            continue;
        }
        let fleet = fleet_tag_from_reports(reports, &conn.network_key, &conn.hostname);
        let new_tag = resolve_tag(
            users.get(&conn.network_key),
            fleet.as_ref(),
            conn.clue.as_ref(),
        );
        if conn.tag != new_tag {
            conn.tag = new_tag;
            changed = true;
        }
    }
    changed
}

fn persist_tag_cmd(live: &mut Live, cmd: TagCmd, reports: &[vallumd::tags::FleetReport]) -> Result<(), String> {
    let mut saved = Ok(());
    match cmd {
        TagCmd::Delete { network_key } => {
            live.tags.remove(&network_key);
            if let Err(e) = live.tags.save() {
                eprintln!("kub0d: tag save failed: {e}");
                saved = Err(format!("saving tags: {e}"));
            }
        }
        TagCmd::Set {
            network_key,
            label,
            kind,
            anchor,
        } => {
            // What a live row shows now, else what the name was given under.
            let seen = last_hostname_for(live, &network_key);
            let ptr_suffix = if seen.is_empty() { anchor } else { seen };
            live.tags.set(vallumd::tags::Tag {
                network_key: network_key.clone(),
                label,
                kind,
                ptr_suffix,
                ts: now_ms(),
                source: vallumd::tags::Source::User,
            });
            if let Err(e) = live.tags.save() {
                eprintln!("kub0d: tag save failed: {e}");
                saved = Err(format!("saving tags: {e}"));
            }
        }
    }
    retag_unattributed(live, reports);
    saved
}

impl Live {
    fn new(
        data_dir: &Path,
        mmdb: Option<&Path>,
        state_dir: &Path,
        resolver: vallumd::rdns::Resolver,
        mode: DaemonMode,
    ) -> Self {
        Live {
            geo: GeoDb::load(data_dir, mmdb),
            seen: SeenSet::load(state_dir),
            // The system daemon names every logged-in user's apps, with their
            // owner; a user daemon names only its own uid's.
            apps: AppResolver::new(mode == DaemonMode::System),
            inode_pid: HashMap::new(),
            unowned: HashSet::new(),
            live: HashMap::new(),
            udp_agg: HashMap::new(),
            last_full_scan: Instant::now() - Duration::from_secs(60),
            last_full_scan_cost: Duration::from_millis(0),
            panel_open: false,
            panel_clients: HashSet::new(),
            away_new: Vec::new(),
            last_flush: Instant::now(),
            scanned_fd_dirs: 0,
            unreadable_fd_dirs: 0,
            unknown_log: UnknownLog::load(state_dir),
            accounts: vallumd::suggest::Accounts::load(),
            routes: vallumd::routes::load(),
            sys_uid_max: vallumd::suggest::sys_uid_max(),
            tags: vallumd::tags::TagStore::load(state_dir),
            resolver,
            unknown_pending: HashSet::new(),
            traffic: vallumd::traffic::Tracker::default(),
            bandwidth: Vec::new(),
            traffic_clock: Instant::now(),
            baseline: intel::BaselineStore::load(state_dir),
            cadence: intel::Cadence::default(),
            fan_out: intel::FanOut::default(),
            watch: vallumd::watch::WatchStore::load(state_dir),
            prober: vallumd::provenance::Prober::spawn(),
            asn: Arc::new(vallumd::geo::AsnDb::empty()),
            listeners: Vec::new(),
            ephemeral_low: ephemeral_port_low(),
            indicator_logged: HashSet::new(),
            lineage_cache: HashMap::new(),
            dns: vallumd::dns::Cache::default(),
            resolvers: vallumd::dns::Resolvers::default(),
            dns_foreign: 0,
            last_prune: Instant::now(),
        }
    }

    fn snapshot(&self) -> Vec<Connection> {
        self.live.values().cloned().collect()
    }
}

/// Idle cadence. The active cadence is whatever --interval-ms was started with.
const PASSIVE: Duration = Duration::from_millis(3000);
const PASSIVE_SCAN: Duration = Duration::from_secs(60);

/// Passive only when nobody is looking AND the battery is paying for it.
/// Otherwise the daemon keeps full fidelity, since passive misses sub-3s
/// connections (most DNS lookups and quick fetches). A desktop has no
/// battery, so it never goes passive.
///
/// on_battery = a battery is discharging, see on_battery()
/// A client that disconnected without a panel-close no longer holds the
/// daemon at the active cadence.
fn forget_gone_panels(live: &mut Live, server: &Server) {
    if live.panel_clients.is_empty() {
        return;
    }
    live.panel_clients.retain(|id| server.connected(*id));
    live.panel_open = !live.panel_clients.is_empty();
}

/// panel_open = true between a panel-open and a panel-close IPC message
fn passive(on_battery: bool, panel_open: bool) -> bool {
    on_battery && !panel_open
}

/// How long to wait before the next sample. `active` is --interval-ms.
fn poll_interval(on_battery: bool, panel_open: bool, active: Duration) -> Duration {
    if passive(on_battery, panel_open) {
        PASSIVE
    } else {
        active
    }
}

/// How stale the /proc owner map may get before a full rescan.
fn scan_interval(on_battery: bool, panel_open: bool) -> Duration {
    if passive(on_battery, panel_open) {
        PASSIVE_SCAN
    } else {
        Duration::from_secs(5)
    }
}

fn should_full_scan(
    since_full: Duration,
    last_full_cost: Duration,
    on_battery: bool,
    panel_open: bool,
) -> bool {
    since_full > scan_interval(on_battery, panel_open)
        || (!passive(on_battery, panel_open) && last_full_cost < Duration::from_millis(30))
}

fn sample(live: &mut Live, server: &mut Server, rdns: bool) {
    let fleet_reports = server.kub0.fleet_snapshot().fleet_tags;
    let socks = read_all_sockets();
    let traffic = vallumd::traffic::read();
    let traffic_clock_ms = live.traffic_clock.elapsed().as_millis() as u64;
    let want_full = should_full_scan(
        live.last_full_scan.elapsed(),
        live.last_full_scan_cost,
        on_battery(),
        live.panel_open,
    );
    let scan_t0 = Instant::now();
    let current_inodes: HashSet<u64> = socks.iter().map(|s| s.inode).collect();
    if want_full {
        let (map, scanned, unreadable) = scan_inodes(None);
        live.inode_pid = map;
        // The walk records every socket, unix ones included; keep inet only.
        live.inode_pid.retain(|ino, _| current_inodes.contains(ino));
        live.scanned_fd_dirs = scanned;
        live.unreadable_fd_dirs = unreadable;
        live.last_full_scan = Instant::now();
        live.last_full_scan_cost = scan_t0.elapsed();
        live.unowned = current_inodes
            .iter()
            .filter(|i| !live.inode_pid.contains_key(i))
            .copied()
            .collect();
    } else {
        // Inodes are reused, so a cached owner is confirmed before it is
        // trusted (and later exposed for blocking). Each owner's fd table is
        // read once for all its sockets, not once per socket.
        let mut fds = FdCache::default();
        live.inode_pid
            .retain(|ino, pid| current_inodes.contains(ino) && fds.owns(*pid, *ino));
        live.unowned.retain(|ino| current_inodes.contains(ino));
        // Everything left unexplained gets ONE targeted walk between them.
        let missing: HashSet<u64> = current_inodes
            .iter()
            .filter(|i| !live.inode_pid.contains_key(i) && !live.unowned.contains(i))
            .copied()
            .collect();
        if !missing.is_empty() {
            let (extra, _, _) = scan_inodes(Some(&missing));
            for ino in &missing {
                if !extra.contains_key(ino) {
                    live.unowned.insert(*ino);
                }
            }
            live.inode_pid.extend(extra);
        }
    }
    let now = now_ms();
    apply_names(live, server, &fleet_reports, rdns, now);
    apply_dns_names(live, server, now);
    apply_provenance(live, server, now);
    let mut present: HashSet<String> = HashSet::new();
    let mut udp_seen_keys: HashSet<(String, String, u16)> = HashSet::new();
    let mut listeners: Vec<Listener> = Vec::new();
    let mut updated: Vec<String> = Vec::new();

    for sock in socks {
        if sock.proto == Protocol::Tcp {
            if sock.is_listen() {
                let (ident, exe) = resolve_app(live, sock.inode, sock.uid);
                listeners.push(listener_row(&sock, ident, exe));
                continue;
            }
            if !sock.is_active_tcp() {
                continue;
            }
        }
        let remote_ip = sock.canonical_remote();
        let local_ip = sock.canonical_local();
        let unresolved = sock.proto == Protocol::Udp && sock.remote_is_unspecified();
        let (ident, exe) = resolve_app(live, sock.inode, sock.uid);
        if unresolved && sock.local_port != 0 && sock.local_port < live.ephemeral_low {
            // Bound on purpose, below the ephemeral range: a service waiting
            // for datagrams, or a client that chose its port. Listed either
            // way; the scope says what it is reachable from.
            listeners.push(listener_row(&sock, ident.clone(), exe.clone()));
        }
        if sock.proto == Protocol::Udp && !unresolved {
            let agg_key = (ident.id.clone(), remote_ip.to_string(), sock.remote_port);
            udp_seen_keys.insert(agg_key.clone());
            if let Some(prev) = live.udp_agg.get(&agg_key) {
                if now.saturating_sub(*prev) < UDP_TTL_MS {
                    live.udp_agg.insert(agg_key, now);
                    // Keep the existing logical flow id present.
                    if let Some(existing) = live.live.values().find(|c| {
                        c.app.id == ident.id
                            && c.remote.ip == remote_ip.to_string()
                            && c.remote.port == sock.remote_port
                            && c.proto == "udp"
                    }) {
                        present.insert(existing.id.clone());
                    }
                    continue;
                }
            }
            live.udp_agg.insert(agg_key, now);
        }

        let id = connection_id(
            sock.proto.as_str(),
            sock.inode,
            &remote_ip.to_string(),
            sock.remote_port,
        );
        present.insert(id.clone());
        let bytes = traffic
            .get(&sock.inode)
            .filter(|s| {
                s.local.ip == local_ip.to_string()
                    && s.local.port == sock.local_port
                    && s.remote.ip == remote_ip.to_string()
                    && s.remote.port == sock.remote_port
            })
            .map(|s| s.bytes);
        if let Some(existing) = live.live.get_mut(&id) {
            existing.bytes = bytes;
            existing.exe = exe;
            if let Some(e) = existing.evidence.as_mut() {
                e.recorded_at = now;
            }
            // The one rung whose evidence moves while a row is open: its
            // counters. Re-evaluated from the row alone, and the row is
            // re-sent only when the answer changes.
            let who = intel::who_label(&existing.app.id, &existing.app.name, existing.app.owner_name());
            if intel::reconcile_upload(&mut existing.indicators, &who, bytes.map(|b| (b.tx, b.rx))) {
                updated.push(id.clone());
            }
            continue;
        }

        let mut country = String::new();
        let mut lat = 0.0;
        let mut lon = 0.0;
        let mut net_key = String::new();
        let mut new_net = false;
        if !unresolved && !remote_ip.is_loopback() {
            net_key = network_key(remote_ip);
            let is_dns = sock.remote_port == 53;
            let first = live.seen.observe(&net_key, now);
            new_net = first && !is_dns;
            if new_net && !live.away_new.contains(&net_key) {
                live.away_new.push(net_key.clone());
            }
            if let Some(hit) = live.geo.lookup(remote_ip) {
                country = hit.country;
                lat = hit.lat;
                lon = hit.lon;
            }
            if new_net {
                server.emit_new_network(&net_key, &country, Some(&ident));
                // For org prevalence, when the user opted in. The key is a
                // /24 or /48, never the address, and never a private, LAN,
                // link-local or tailnet range: those describe this network's
                // topology, which is nobody else's business.
                if intel::is_public_peer(remote_ip) {
                    server.kub0.note_network(&net_key);
                }
            }
        }

        // Reverse DNS is opt-in for attributed rows and always on for
        // unattributed ones. The privacy cost of `--rdns` is that every
        // destination reaches the resolver; the rows with no owning process
        // are the only ones where a PTR is the difference between a name and
        // a bare IP, and on one live desktop they were 457 of tens of
        // thousands. Scoping the lookup to them buys 68% of the naming for a
        // small fraction of the queries -- which is why this is a separate
        // condition and not a wider default for `rdns`.
        let unattributed = ident.pid == 0;
        let resolvable = resolvable(unresolved, remote_ip);
        // Whatever is known now; an unknown name is queued and patched in by
        // `apply_names` on a later pass, never waited for here.
        let mut name_pending = false;
        // The name the app asked for beats a PTR: it is what the user's
        // software meant, and a CDN address often has no PTR at all.
        let mut hostname_source = String::new();
        let hostname = if let Some(name) = (!unresolved).then(|| live.dns.lookup(remote_ip, now)).flatten() {
            hostname_source = "dns".into();
            name.to_string()
        } else if resolvable && (rdns || unattributed) {
            match live.resolver.name(remote_ip) {
                Some(name) => {
                    if !name.is_empty() {
                        hostname_source = "ptr".into();
                    }
                    name.to_string()
                }
                None => {
                    name_pending = true;
                    String::new()
                }
            }
        } else {
            String::new()
        };

        let reason = if unattributed {
            missing_owner_reason(sock.inode, live.scanned_fd_dirs, live.unreadable_fd_dirs)
                .to_string()
        } else {
            String::new()
        };

        // Only unattributed rows get a clue -- a row that already names its
        // process does not need a guess, and attaching one would invite the
        // UI to show a weaker answer beside a stronger one.
        let (clue, tag) = if unattributed {
            peer_naming(
                &live.accounts,
                live.sys_uid_max,
                &live.routes,
                &live.tags,
                &fleet_reports,
                Some(sock.uid),
                &hostname,
                remote_ip,
                sock.remote_port,
                &net_key,
            )
        } else {
            (None, None)
        };

        // Evaluated once, when the connection is first seen: an existing id returned above.
        let policy = if unresolved {
            Vec::new()
        } else {
            server
                .kub0
                .evaluate_connection(&remote_ip.to_string(), &country, &exe, now)
        };

        // Local intelligence, from evidence already on this machine.
        let public_peer = !unresolved && intel::is_public_peer(remote_ip);
        let (asn, org) = if public_peer {
            live.asn
                .lookup(remote_ip)
                .map(|(a, o)| (Some(a), o))
                .unwrap_or((None, None))
        } else {
            (None, None)
        };
        let lineage = if ident.pid != 0 && !ident.system {
            match live.lineage_cache.get(&(ident.pid, exe.clone())) {
                Some(l) => Some(l.clone()),
                None => {
                    let l = vallumd::lineage::read(ident.pid);
                    if let Some(l) = &l {
                        if live.lineage_cache.len() < 4096 {
                            live.lineage_cache.insert((ident.pid, exe.clone()), l.clone());
                        }
                    }
                    l
                }
            }
        } else {
            None
        };
        // The lineage goes to the prober too: a binary under /tmp/go-build* is
        // a dev build only when the go tool really is its parent.
        let ancestry: Vec<&str> = lineage
            .as_ref()
            .map(|l| l.ancestors.iter().map(|a| a.comm.as_str()).collect())
            .unwrap_or_default();
        let prov = live.prober.probe_with_ancestry(&exe, pid_started_ms(ident.pid), Some(sock.uid), &ancestry);
        // Behaviour is learned from public destinations only: a dev server on
        // localhost and a NAS on the LAN are not places an app "goes", and a
        // helper polled on loopback is not a beacon.
        let behaviour_peer = public_peer && ident.pid != 0 && !ident.system;
        let novelty = if !unresolved && ident.pid != 0 && !ident.system {
            Some(live.baseline.observe(
                &ident.id,
                asn,
                if public_peer { Some(country.as_str()) } else { None },
                if public_peer { Some(sock.remote_port) } else { None },
                now,
            ))
        } else {
            None
        };
        let cadence = if behaviour_peer {
            live.cadence
                .record(&ident.id, &remote_ip.to_string(), sock.remote_port, now)
        } else {
            None
        };
        let fan_out = if behaviour_peer { live.fan_out.record(&ident.id, &net_key, now) } else { 0 };
        let watch_hits = if unresolved {
            Vec::new()
        } else {
            live.watch.hits(
                &vallumd::watch::Match {
                    remote: Some(remote_ip),
                    port: sock.remote_port,
                    hostname: &hostname,
                    asn,
                    country: &country,
                    app_id: &ident.id,
                    exe: &exe,
                },
                now,
            )
        };
        let mut indicators = intel::indicators(&intel::Subject {
            app_id: &ident.id,
            app_name: &ident.name,
            owner: ident.owner_name(),
            system: ident.system,
            remote: (!unresolved).then_some(remote_ip),
            port: sock.remote_port,
            hostname: &hostname,
            // Settled only when a lookup ran and finished; with rdns off and an
            // owner known, no lookup runs and a blank name proves nothing.
            hostname_settled: !hostname.is_empty() || (resolvable && (rdns || unattributed) && !name_pending),
            asn,
            org: org.as_deref(),
            country: &country,
            novelty,
            cadence,
            bytes: bytes.map(|b| (b.tx, b.rx)),
            exe_flags: &prov.flags,
            watch_hits: &watch_hits,
            fan_out,
        });
        // The package answer for this executable may already be in: a second
        // connection of a binary the manager disowned gets the notice at birth.
        if prov.settled && prov.unpackaged {
            let who = intel::who_label(&ident.id, &ident.name, ident.owner_name());
            intel::reconcile_unpackaged(&mut indicators, &who, &exe, true);
        }
        let conn = Connection {
            id: id.clone(),
            proto: sock.proto.as_str().into(),
            inode: sock.inode,
            app: ident,
            local: Endpoint {
                ip: local_ip.to_string(),
                port: sock.local_port,
            },
            remote: Endpoint {
                ip: remote_ip.to_string(),
                port: sock.remote_port,
            },
            state: sock.state_name().into(),
            country,
            lat,
            lon,
            unresolved,
            new_network: new_net,
            network_key: net_key,
            hostname,
            hostname_source,
            uid: Some(sock.uid),
            reason,
            clue,
            tag,
            bytes,
            exe,
            evidence: Some(vallumd::event::ConnectionEvidence {
                source: vallumd::flow::SourceKind::Procfs,
                recorded_at: now,
                verdict: None,
                owner_method: "procfs socket UID and inode-to-process fd lookup".into(),
                hash: prov.hash.clone(),
                container: None,
                lineage,
                package: prov.package.clone(),
            }),
            policy,
            asn,
            org,
            indicators,
        };
        if name_pending && unattributed {
            live.unknown_pending.insert(id.clone());
        } else {
            log_unknown(&mut live.unknown_log, server, &conn, now);
        }
        log_indicators(live, server, &conn, &watch_hits, now);
        server.note_app(&conn.app);
        live.live.insert(id, conn.clone());
        server.kub0.note_connection();
        let ev = Event::Connect { ts: now, conn };
        server.broadcast(&ev.to_line());
    }

    for id in updated {
        if let Some(conn) = live.live.get(&id) {
            server.broadcast(&Event::Connect { ts: now, conn: conn.clone() }.to_line());
        }
    }
    listeners.sort_by(|a, b| {
        (&a.proto, &a.ip, a.port, &a.app.id).cmp(&(&b.proto, &b.ip, b.port, &b.app.id))
    });
    listeners.dedup();
    if listeners != live.listeners {
        live.listeners = listeners.clone();
        server.listeners = listeners.clone();
        server.broadcast(&Event::Listeners { ts: now, listeners }.to_line());
    }

    // Drop UDP aggregations that aged out and whose sockets vanished.
    live.udp_agg
        .retain(|k, last| udp_seen_keys.contains(k) || now.saturating_sub(*last) < UDP_TTL_MS);

    let gone: Vec<String> = live
        .live
        .keys()
        .filter(|k| !present.contains(*k))
        .cloned()
        .collect();
    for id in gone {
        // UDP logical flows linger until TTL.
        if let Some(c) = live.live.get(&id) {
            if c.proto == "udp" && !c.unresolved {
                let key = (c.app.id.clone(), c.remote.ip.clone(), c.remote.port);
                if let Some(last) = live.udp_agg.get(&key) {
                    if now.saturating_sub(*last) < UDP_TTL_MS {
                        continue;
                    }
                }
            }
        }
        if let Some(conn) = live.live.remove(&id) {
            // Gone before its name arrived: record what was known.
            if live.unknown_pending.remove(&id) {
                log_unknown(&mut live.unknown_log, server, &conn, now);
            }
        }
        let ev = Event::Disconnect { ts: now, id };
        server.broadcast(&ev.to_line());
    }

    let rows = live.snapshot();
    let apps = live.traffic.sample(&rows, &traffic, traffic_clock_ms);
    live.bandwidth = apps.clone();
    server.broadcast(&Event::Bandwidth { ts: now, apps }.to_line());
    if let Some(history) = server.history.as_mut() {
        history.observe(&rows, now);
    }
    let tick = Event::Tick {
        ts: now,
        count: live.live.len(),
        scanned_fd_dirs: live.scanned_fd_dirs,
        unreadable_fd_dirs: live.unreadable_fd_dirs,
    };
    server.broadcast(&tick.to_line());
}

/// Whether a remote address is worth a PTR at all: never unconnected UDP,
/// loopback or private ranges.
fn resolvable(unresolved: bool, remote: std::net::IpAddr) -> bool {
    !unresolved && !remote.is_loopback() && !vallumd::geo::is_private(remote)
}

/// The machine's guess at who an unattributed peer is, and the name a human or
/// the fleet gave its network. Both read the PTR name, so a row whose name
/// arrives late is re-derived here rather than left with the evidence it had
/// without one.
#[allow(clippy::too_many_arguments)]
fn peer_naming(
    accounts: &vallumd::suggest::Accounts,
    sys_uid_max: u32,
    routes: &[vallumd::routes::Route],
    tags: &vallumd::tags::TagStore,
    fleet_reports: &[vallumd::tags::FleetReport],
    uid: Option<u32>,
    hostname: &str,
    remote: std::net::IpAddr,
    port: u16,
    net_key: &str,
) -> (Option<vallumd::suggest::Clue>, Option<vallumd::tags::Tag>) {
    let clue = vallumd::suggest::clue(&vallumd::suggest::Evidence {
        uid,
        sys_uid_max,
        account: uid.and_then(|u| accounts.get(u)),
        hostname,
        remote,
        port,
        routes,
    });
    let stored = tags.get(net_key).cloned();
    let fleet = fleet_tag_from_reports(fleet_reports, net_key, hostname);
    let tag = resolve_tag(
        stored
            .as_ref()
            .filter(|t| t.source == vallumd::tags::Source::User),
        fleet.as_ref(),
        clue.as_ref(),
    );
    (clue, tag)
}

fn log_unknown(log: &mut UnknownLog, server: &mut Server, conn: &Connection, now: u64) {
    if log.consider(conn, now) {
        server.emit_kind(
            ActivityKind::UnknownOwner,
            None,
            serde_json::json!({ "uid": conn.uid, "reason": conn.reason }),
        );
    }
}

/// Settle the reverse lookups that finished since the last pass: write each
/// name into the live rows that were waiting for it, re-derive the evidence
/// that reads a name, and re-send those rows. A `connect` for a known id
/// replaces the row in the panel (`ConnectionModel.putConnection`), and only a
/// new id can pulse, so a late name is an update, not a second arrival.
///
/// Also asks again for any row whose request a full queue dropped.
fn apply_names(
    live: &mut Live,
    server: &mut Server,
    fleet_reports: &[vallumd::tags::FleetReport],
    rdns: bool,
    now: u64,
) {
    live.resolver.collect();
    let mut changed = Vec::new();
    let mut settled = Vec::new();
    let mut named = Vec::new();
    for conn in live.live.values_mut() {
        if !conn.hostname.is_empty() {
            continue;
        }
        let Ok(ip) = conn.remote.ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        let unattributed = conn.app.pid == 0;
        if !resolvable(conn.unresolved, ip) || !(rdns || unattributed) {
            continue;
        }
        let Some(name) = live.resolver.name(ip) else {
            continue;
        };
        if !name.is_empty() {
            conn.hostname = name.to_string();
            conn.hostname_source = "ptr".into();
            named.push(conn.id.clone());
            if unattributed {
                let (clue, tag) = peer_naming(
                    &live.accounts,
                    live.sys_uid_max,
                    &live.routes,
                    &live.tags,
                    fleet_reports,
                    conn.uid,
                    &conn.hostname,
                    ip,
                    conn.remote.port,
                    &conn.network_key,
                );
                conn.clue = clue;
                conn.tag = tag;
            }
            changed.push(conn.id.clone());
        }
        if live.unknown_pending.contains(&conn.id) {
            settled.push(conn.id.clone());
        }
    }
    for id in settled {
        live.unknown_pending.remove(&id);
        if let Some(conn) = live.live.get(&id) {
            log_unknown(&mut live.unknown_log, server, conn, now);
        }
    }
    on_names_landed(live, server, &named, now);
    for id in changed {
        if let Some(conn) = live.live.get(&id) {
            server.broadcast(
                &Event::Connect {
                    ts: now,
                    conn: conn.clone(),
                }
                .to_line(),
            );
        }
    }
}

/// Name rows the collector's DNS answers can now name, and re-send them.
/// Runs only when an answer arrived since the last pass.
fn apply_dns_names(live: &mut Live, server: &mut Server, now: u64) {
    if !live.dns.take_fresh() {
        return;
    }
    let mut named = Vec::new();
    for conn in live.live.values_mut() {
        // The name the app asked for beats a PTR, so a PTR-named row is
        // renamed when the answer lands; a row already named by DNS is left.
        if conn.unresolved || (!conn.hostname.is_empty() && conn.hostname_source != "ptr") {
            continue;
        }
        let Ok(ip) = conn.remote.ip.parse::<std::net::IpAddr>() else { continue };
        if let Some(name) = live.dns.lookup(ip, now) {
            if conn.hostname == name {
                continue;
            }
            conn.hostname = name.to_string();
            conn.hostname_source = "dns".into();
            named.push(conn.id.clone());
        }
    }
    on_names_landed(live, server, &named, now);
    for id in named {
        if let Some(conn) = live.live.get(&id) {
            server.broadcast(&Event::Connect { ts: now, conn: conn.clone() }.to_line());
        }
    }
}

/// A name is evidence a row was built without: the host-suffix watch rules
/// and the PTR rungs are evaluated now, the way they would have been had the
/// name been known at first sight. Other rule kinds were already counted.
fn on_names_landed(live: &mut Live, server: &mut Server, named: &[String], now: u64) {
    for id in named {
        let Some(conn) = live.live.get(id) else { continue };
        let remote = conn.remote.ip.parse::<std::net::IpAddr>().ok();
        let hits = live.watch.host_hits(
            &vallumd::watch::Match {
                remote,
                port: conn.remote.port,
                hostname: &conn.hostname,
                asn: conn.asn,
                country: &conn.country,
                app_id: &conn.app.id,
                exe: &conn.exe,
            },
            now,
        );
        let Some(conn) = live.live.get_mut(id) else { continue };
        let public = remote.is_some_and(intel::is_public_peer);
        let from_ptr = conn.hostname_source == "ptr";
        let system = conn.app.system;
        let mut moved = intel::reconcile_hostname(&mut conn.indicators, &conn.hostname.clone(), from_ptr, public, system);
        if intel::add_watch_hits(&mut conn.indicators, &hits) {
            moved = true;
        }
        if moved || !hits.is_empty() {
            let snapshot = conn.clone();
            log_indicators(live, server, &snapshot, &hits, now);
        }
    }
}

/// A listening or bound socket as the panel sees it.
fn listener_row(sock: &ParsedSocket, app: AppIdentity, exe: String) -> Listener {
    let ip = sock.canonical_local();
    let scope = if ip.is_unspecified() {
        "all"
    } else if ip.is_loopback() {
        "loopback"
    } else {
        "address"
    };
    Listener {
        proto: sock.proto.as_str().into(),
        ip: ip.to_string(),
        port: sock.local_port,
        app,
        exe,
        uid: Some(sock.uid),
        scope: scope.into(),
    }
}

/// Lower bound of `net.ipv4.ip_local_port_range`; the kernel default when it
/// cannot be read.
fn ephemeral_port_low() -> u16 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|t| t.split_whitespace().next().and_then(|n| n.parse().ok()))
        .unwrap_or(32768)
}

/// When a process started, in milliseconds since the epoch: field 22 of
/// `/proc/<pid>/stat` (clock ticks since boot) plus `btime` from `/proc/stat`.
/// `None` off Linux, for pid 0, or when either file cannot be read.
fn pid_started_ms(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    // Boot time and the tick rate do not change while the daemon runs; read
    // them once rather than parsing the whole of /proc/stat per connection.
    // A read that fails once (fd pressure at startup) is retried next call,
    // never remembered as "no boot time".
    static BOOT: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();
    let (btime, hz) = match BOOT.get() {
        Some(v) => *v,
        None => {
            let btime: u64 = std::fs::read_to_string("/proc/stat")
                .ok()?
                .lines()
                .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))?;
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            if hz <= 0 {
                return None;
            }
            let _ = BOOT.set((btime, hz as u64));
            (btime, hz as u64)
        }
    };
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field is parenthesised and may contain spaces; split after it.
    let after = stat.get(stat.rfind(')')? + 1..)?;
    let start_ticks: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    Some(btime * 1000 + start_ticks * 1000 / hz)
}

/// Write watch hits and notice-or-worse indicators to the local activity log,
/// once per (indicator, app, peer) per run. Info indicators stay on the row.
fn log_indicators(live: &mut Live, server: &mut Server, conn: &Connection, hits: &[(String, String)], now: u64) {
    let _ = now;
    let app = Some(ActivityApp {
        id: conn.app.id.clone(),
        name: conn.app.name.clone(),
    });
    for (rule, what) in hits {
        // One line per (rule, app, peer) per run: a rule on port 443 would
        // otherwise write, and notify, once per connection while browsing.
        if !live.indicator_logged.insert((format!("watch:{rule}"), conn.app.id.clone(), conn.remote.ip.clone())) {
            continue;
        }
        server.emit_kind(
            ActivityKind::WatchHit,
            app.clone(),
            serde_json::json!({
                "rule": rule, "match": what,
                "remote": conn.remote.ip, "port": conn.remote.port, "hostname": conn.hostname
            }),
        );
    }
    for i in conn.indicators.iter().filter(|i| i.severity >= Severity::Notice && i.id != "watchlist") {
        let key = (i.id.clone(), conn.app.id.clone(), conn.remote.ip.clone());
        if !live.indicator_logged.insert(key) {
            continue;
        }
        server.emit_kind(
            ActivityKind::Indicator,
            app.clone(),
            serde_json::json!({
                "indicator": i.id, "severity": i.severity.as_str(), "basis": i.basis,
                "attack": i.attack.as_ref().map(|a| a.id.clone()),
                "remote": conn.remote.ip, "port": conn.remote.port, "hostname": conn.hostname
            }),
        );
    }
}

/// Patch executable hashes that finished since the last pass into the rows
/// that were waiting for them, and re-send those rows (see `apply_names`).
fn apply_provenance(live: &mut Live, server: &mut Server, now: u64) {
    let settled = live.prober.collect();
    if settled.is_empty() {
        return;
    }
    let mut changed = Vec::new();
    let mut late: Vec<(String, Connection)> = Vec::new();
    for conn in live.live.values_mut() {
        if !settled.contains(&conn.exe) {
            continue;
        }
        let Some(prov) = live.prober.settled(&conn.exe) else { continue };
        let mut moved = false;
        if let Some(ev) = conn.evidence.as_mut() {
            if prov.hash.is_some() && ev.hash != prov.hash {
                ev.hash = prov.hash.clone();
                moved = true;
            }
            if prov.package.is_some() && ev.package != prov.package {
                ev.package = prov.package.clone();
                moved = true;
            }
        }
        let who = intel::who_label(&conn.app.id, &conn.app.name, conn.app.owner_name());
        if intel::reconcile_unpackaged(&mut conn.indicators, &who, &conn.exe, prov.unpackaged) {
            moved = true;
            if prov.unpackaged {
                // A notice that arrived after the row did still belongs in the
                // log, once per (indicator, app, peer) like the ones at creation.
                late.push(("exe-unpackaged".to_string(), conn.clone()));
            }
        }
        // A binary replaced under the process: the package manager's answer
        // decides between exe-changed (an upgrade) and exe-deleted.
        if prov.replacement_packaged.is_some() {
            let (m, added) = intel::reconcile_replaced(&mut conn.indicators, &who, &prov.flags);
            moved |= m;
            for id in added {
                late.push((id.to_string(), conn.clone()));
            }
        }
        if moved {
            changed.push(conn.id.clone());
        }
    }
    for (id, conn) in late {
        let key = (id.clone(), conn.app.id.clone(), conn.remote.ip.clone());
        if !live.indicator_logged.insert(key) {
            continue;
        }
        let Some(i) = conn.indicators.iter().find(|i| i.id == id) else { continue };
        server.emit_kind(
            ActivityKind::Indicator,
            Some(ActivityApp { id: conn.app.id.clone(), name: conn.app.name.clone() }),
            serde_json::json!({
                "indicator": i.id, "severity": i.severity.as_str(), "basis": i.basis,
                "attack": i.attack.as_ref().map(|a| a.id.clone()),
                "remote": conn.remote.ip, "port": conn.remote.port, "hostname": conn.hostname
            }),
        );
    }
    for id in changed {
        if let Some(conn) = live.live.get(&id) {
            server.broadcast(&Event::Connect { ts: now, conn: conn.clone() }.to_line());
        }
    }
}

fn publish_watchlist(live: &Live, server: &mut Server, error: String) {
    server.watch_rules = live.watch.rules().to_vec();
    server.broadcast(
        &Event::Watchlist {
            ts: now_ms(),
            rules: live.watch.rules().to_vec(),
            error,
        }
        .to_line(),
    );
}

fn resolve_app(live: &mut Live, inode: u64, uid: u32) -> (AppIdentity, String) {
    let pid = resolve_inode_pid(live, inode);
    if pid == 0 {
        if uid != live.apps.our_uid() && uid != 0 {
            return (vallumd::identity::system_identity(0), String::new());
        }
        return (unknown_identity(0), String::new());
    }
    let exe = read_exe(pid);
    let comm = read_comm(pid);
    let real_uid = read_status_uid(pid).unwrap_or(uid);
    (live.apps.resolve(pid, real_uid, &exe, &comm), exe)
}

/// True while a battery is actually draining, which includes running on a
/// charger too small for the load (a 30 W USB-C brick under a 44 W draw
/// drains with Mains online=1). Only type=Battery counts: empty USB-C ports
/// also report status=Discharging.
fn on_battery() -> bool {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else {
        return false;
    };
    dir.flatten().any(|ent| {
        let p = ent.path();
        let read = |f: &str| std::fs::read_to_string(p.join(f)).unwrap_or_default();
        read("type").trim() == "Battery" && read("status").trim() == "Discharging"
    })
}

/// The owner sample() established for this inode. sample() confirms every
/// cached owner against its fd table, and walks /proc once for whatever is
/// new, before any socket is resolved, so this only reads the result.
fn resolve_inode_pid(live: &mut Live, inode: u64) -> u32 {
    live.inode_pid.get(&inode).copied().unwrap_or(0)
}

/// Each process's socket inodes, read from /proc/<pid>/fd at most once per
/// sample. Confirming ownership used to re-walk the owner's whole fd table
/// for every one of its sockets: a browser holding 100 sockets among 2000
/// fds cost 200k readlinks a sample for the browser alone.
#[derive(Default)]
struct FdCache {
    by_pid: HashMap<u32, HashSet<u64>>,
}

impl FdCache {
    fn owns(&mut self, pid: u32, inode: u64) -> bool {
        if pid < 2 {
            return false;
        }
        self.by_pid
            .entry(pid)
            .or_insert_with(|| socket_inodes_of(pid))
            .contains(&inode)
    }
}

fn socket_inodes_of(pid: u32) -> HashSet<u64> {
    let mut out = HashSet::new();
    let Ok(fd_dir) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };
    for fd in fd_dir.flatten() {
        if let Ok(target) = std::fs::read_link(fd.path()) {
            if let Some(inode) = parse_socket_link(&target.to_string_lossy()) {
                out.insert(inode);
            }
        }
    }
    out
}

fn read_all_sockets() -> Vec<ParsedSocket> {
    let mut out = Vec::new();
    for (path, proto, v6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            out.extend(parse_proc_net(&text, proto, v6));
        }
    }
    out
}

/// Walk `/proc/<pid>/fd` looking for `socket:[inode]`. When `only` is set,
/// stop a pid early once remaining targets are gone (delta scan).
///
/// The fd-dir counts are only meaningful for a full scan (`only == None`).
/// Delta and single-inode callers must not store them: those walks early-exit.
fn scan_inodes(only: Option<&HashSet<u64>>) -> (HashMap<u64, u32>, usize, usize) {
    let mut map = HashMap::new();
    let proc = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        // Blind: scanned nothing. A zero/zero pair would look like a perfect
        // empty pass, so mark the attempt unreadable.
        Err(_) => return (map, 0, 1),
    };
    let mut scanned_fd_dirs = 0usize;
    let mut unreadable_fd_dirs = 0usize;
    let mut remaining: Option<HashSet<u64>> = only.cloned();
    for ent in proc.flatten() {
        if remaining.as_ref().is_some_and(|s| s.is_empty()) {
            break;
        }
        let name = ent.file_name();
        let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fd_dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(_) => {
                unreadable_fd_dirs += 1;
                continue;
            }
        };
        scanned_fd_dirs += 1;
        for fd in fd_dir.flatten() {
            let target = match std::fs::read_link(fd.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let s = target.to_string_lossy();
            if let Some(inode) = parse_socket_link(&s) {
                if let Some(rem) = remaining.as_mut() {
                    if rem.remove(&inode) {
                        map.insert(inode, pid);
                    }
                } else {
                    map.insert(inode, pid);
                }
            }
        }
    }
    (map, scanned_fd_dirs, unreadable_fd_dirs)
}

fn parse_socket_link(s: &str) -> Option<u64> {
    let rest = s.strip_prefix("socket:[")?.strip_suffix(']')?;
    rest.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_only_when_closed_and_on_battery() {
        let active = Duration::from_millis(500);
        let fast = Duration::from_secs(5);
        // (on_battery, panel_open) -> (poll, scan)
        for (bat, open, poll, scan) in [
            (false, true, active, fast),
            (false, false, active, fast),
            (true, true, active, fast),
            (true, false, PASSIVE, PASSIVE_SCAN),
        ] {
            assert_eq!(poll_interval(bat, open, active), poll, "poll bat={bat} open={open}");
            assert_eq!(scan_interval(bat, open), scan, "scan bat={bat} open={open}");
        }
    }

    #[test]
    fn full_scan_cadence_uses_the_previous_full_walk_cost() {
        let expensive = Duration::from_millis(50);
        let cheap = Duration::from_millis(5);
        // A cheap delta pass does not replace `expensive`; an active desktop
        // waits five seconds before walking all of /proc again.
        assert!(!should_full_scan(Duration::from_secs(1), expensive, false, false));
        assert!(should_full_scan(Duration::from_secs(6), expensive, false, false));
        // A genuinely cheap full walk may be repeated at active cadence.
        assert!(should_full_scan(Duration::from_millis(500), cheap, false, false));
        // Battery passive always keeps its 60-second bound, even if a prior
        // full walk was cheap. Opening the panel restores active cadence.
        assert!(!should_full_scan(Duration::from_secs(10), cheap, true, false));
        assert!(should_full_scan(Duration::from_secs(61), cheap, true, false));
        assert!(should_full_scan(Duration::from_secs(10), cheap, true, true));
    }

    #[test]
    fn command_wakes_io_wait_before_the_passive_interval() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut clients = vec![Client {
            id: 1,
            peer: vallumd::control::Peer { uid: None },
            stream,
            buf: Vec::new(),
            eof: false,
            out: vallumd::outq::OutQueue::new(vallumd::outq::DEFAULT_CAP),
        }];
        peer.write_all(b"{\"type\":\"panel-open\"}\n").unwrap();
        let started = Instant::now();
        Server::wait_io_clients(-1, &mut clients, PASSIVE);
        assert!(started.elapsed() < Duration::from_secs(1));
        let mut buf = [0u8; 128];
        let n = clients[0].stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"{\"type\":\"panel-open\"}\n");
    }

    #[test]
    fn socket_link_parse() {
        assert_eq!(parse_socket_link("socket:[54321]"), Some(54321));
        assert_eq!(parse_socket_link("/dev/pts/0"), None);
    }

    #[test]
    fn ndjson_split_frame_is_held() {
        let mut buf = Vec::new();
        buf.extend_from_slice(br#"{ "type": "pan"#);
        assert!(take_complete_lines(&mut buf).is_empty());
        buf.extend_from_slice(br#"el-open" }"#);
        buf.push(b'\n');
        assert_eq!(
            take_complete_lines(&mut buf),
            vec![r#"{ "type": "panel-open" }"#]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn ndjson_two_lines_one_read() {
        let mut buf = b"{\"type\":\"ping\"}\n{\"type\":\"panel-open\"}\npartial".to_vec();
        let lines = take_complete_lines(&mut buf);
        assert_eq!(
            lines,
            vec![r#"{"type":"ping"}"#, r#"{"type":"panel-open"}"#]
        );
        assert_eq!(buf, b"partial");
    }

    #[test]
    fn owner_reason_table() {
        let cases: &[(u64, usize, usize, &str)] = &[
            (0, 0, 0, "orphan"),
            (0, 100, 0, "orphan"),
            (0, 100, 5, "orphan"),
            (1, 0, 0, "unreadable"),
            (1, 0, 1, "unreadable"),
            (42, 0, 99, "unreadable"),
            (1, 1, 0, "no-owner"),
            (9, 50, 0, "no-owner"),
            (1, 10, 1, "unreadable"),
            (1, 1, 1, "unreadable"),
        ];
        for (inode, scanned, unread, want) in cases {
            assert_eq!(
                missing_owner_reason(*inode, *scanned, *unread),
                *want,
                "inode={inode} scanned={scanned} unread={unread}"
            );
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum-unk-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn test_conn(inode: u64, reason: &str, unresolved: bool) -> Connection {
        Connection {
            id: format!("tcp:{inode}:1.2.3.4:443"),
            proto: "tcp".into(),
            inode,
            app: AppIdentity {
                id: "unknown".into(),
                name: "unknown".into(),
                icon: "unknown".into(),
                desktop: String::new(),
                pid: 0,
                system: false,
                exe: String::new(),
                owner: None,
            },
            local: Endpoint {
                ip: "10.0.0.1".into(),
                port: 1234,
            },
            remote: Endpoint {
                ip: "1.2.3.4".into(),
                port: 443,
            },
            state: "ESTABLISHED".into(),
            country: "US".into(),
            lat: 0.0,
            lon: 0.0,
            unresolved,
            new_network: false,
            network_key: "1.2.3.0/24".into(),
            hostname: String::new(),
            hostname_source: String::new(),
            clue: None,
            tag: None,
            bytes: None,
            exe: String::new(),
            evidence: None,
            policy: Vec::new(),
            uid: Some(1000),
            reason: reason.into(),
            asn: None,
            org: None,
            indicators: Vec::new(),
        }
    }

    fn data_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data")
    }

    /// A row created while its PTR was still being looked up gets the name,
    /// the evidence that reads it, a client update and its deferred backlog
    /// record once the lookup lands. The pass that finds it pending returns
    /// at once.
    #[test]
    fn a_late_ptr_name_patches_the_row_and_reaches_clients() {
        use std::io::Read;
        let dir = tmpdir("late-ptr");
        let sock = dir.join("s.sock");
        let mut server =
            Server::bind(&sock, false, DaemonMode::User, Kub0Runtime::new(), &dir).unwrap();
        let resolver = vallumd::rdns::Resolver::spawn(
            1,
            8,
            Arc::new(|_| {
                std::thread::sleep(Duration::from_millis(300));
                Ok(Some("derp15c.tailscale.com".into()))
            }),
        );
        let mut live = Live::new(&data_dir(), None, &dir, resolver, DaemonMode::User);
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        server.accept_new(&[]);

        let mut conn = test_conn(9, "unreadable", false);
        conn.uid = Some(0);
        let id = conn.id.clone();
        let ip: std::net::IpAddr = conn.remote.ip.parse().unwrap();
        assert_eq!(live.resolver.name(ip), None, "lookup should be pending");
        live.live.insert(id.clone(), conn);
        live.unknown_pending.insert(id.clone());

        let t0 = Instant::now();
        apply_names(&mut live, &mut server, &[], false, 1);
        assert!(t0.elapsed() < Duration::from_millis(100), "a pending lookup held the pass");
        assert_eq!(live.live[&id].hostname, "");
        assert!(live.unknown_pending.contains(&id));

        let deadline = Instant::now() + Duration::from_secs(5);
        while live.live[&id].hostname.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            apply_names(&mut live, &mut server, &[], false, 2);
        }
        let row = &live.live[&id];
        assert_eq!(row.hostname, "derp15c.tailscale.com");
        assert_eq!(row.clue.as_ref().map(|c| c.label.as_str()), Some("Tailscale relay"));
        assert!(!live.unknown_pending.contains(&id));
        let backlog = std::fs::read_to_string(dir.join("unknown.ndjson")).unwrap();
        assert!(backlog.contains("derp15c.tailscale.com"), "{backlog}");

        server.idle(Duration::from_millis(50));
        let mut got = Vec::new();
        let mut buf = [0u8; 65536];
        let read_until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < read_until {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => {
                    if !got.is_empty() {
                        break;
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&got);
        let update = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["type"] == "connect" && v["id"] == id.as_str())
            .unwrap_or_else(|| panic!("no connect update for {id}: {text}"));
        assert_eq!(update["hostname"], "derp15c.tailscale.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Attributed rows are only looked up under `--rdns`, as before.
    #[test]
    fn an_attributed_row_is_not_looked_up_without_rdns() {
        let dir = tmpdir("no-rdns");
        let sock = dir.join("s.sock");
        let mut server =
            Server::bind(&sock, false, DaemonMode::User, Kub0Runtime::new(), &dir).unwrap();
        let resolver =
            vallumd::rdns::Resolver::spawn(1, 8, Arc::new(|_| Ok(Some("x.example".into()))));
        let mut live = Live::new(&data_dir(), None, &dir, resolver, DaemonMode::User);
        let mut conn = test_conn(10, "", false);
        conn.app.pid = 4242;
        live.live.insert(conn.id.clone(), conn.clone());
        apply_names(&mut live, &mut server, &[], false, 1);
        assert_eq!(live.resolver.inflight(), 0);
        apply_names(&mut live, &mut server, &[], true, 1);
        assert_eq!(live.resolver.inflight(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_log_key_ignores_reason() {
        let a = serde_json::json!({
            "proto": "tcp",
            "uid": 1000,
            "reason": "no-owner",
            "remote": {"ip": "1.2.3.4", "port": 443}
        });
        let b = serde_json::json!({
            "proto": "tcp",
            "uid": 1000,
            "reason": "unreadable",
            "remote": {"ip": "1.2.3.4", "port": 443}
        });
        assert_eq!(unknown_key_from_value(&a), unknown_key_from_value(&b));
        assert_eq!(
            unknown_log_key("tcp", Some(1000), "1.2.3.4", 443),
            unknown_key_from_value(&a).unwrap()
        );

        let dir = tmpdir("key");
        let mut log = UnknownLog::load(&dir);
        let mut conn = test_conn(10, "no-owner", false);
        log.consider(&conn, 1);
        conn.reason = "unreadable".into();
        conn.inode = 11;
        log.consider(&conn, 2);
        let text = std::fs::read_to_string(dir.join("unknown.ndjson")).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("no-owner"), "{text}");
        assert!(!text.contains("unreadable"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphan_and_unresolved_never_logged() {
        let dir = tmpdir("skip");
        let mut log = UnknownLog::load(&dir);
        log.consider(&test_conn(0, "orphan", false), 1);
        log.consider(&test_conn(5, "unreadable", true), 2);
        log.consider(&test_conn(5, "", false), 3);
        assert!(!dir.join("unknown.ndjson").exists());
        assert!(log.keys.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_defaults_and_explicit_overrides() {
        let default = try_parse_args(Vec::<String>::new()).unwrap();
        #[cfg(target_os = "macos")]
        assert!(default.source == SourceSel::Libproc);
        #[cfg(not(target_os = "macos"))]
        assert!(default.source == SourceSel::Procfs);
        assert!(try_parse_args(["--source", "procfs"]).unwrap().source == SourceSel::Procfs);
        assert!(try_parse_args(["--source", "opensnitch"]).unwrap().source == SourceSel::Opensnitch);
        #[cfg(target_os = "macos")]
        assert!(try_parse_args(["--source", "libproc"]).unwrap().source == SourceSel::Libproc);
    }

    #[test]
    fn path_defaults_user_vs_system() {
        assert_eq!(
            default_socket_for(DaemonMode::System),
            PathBuf::from("/run/kub0/kub0.sock")
        );
        assert_eq!(
            default_state_dir_for(DaemonMode::System),
            PathBuf::from("/var/lib/kub0/daemon")
        );
        let user_sock = default_socket_for(DaemonMode::User);
        let user_state = default_state_dir_for(DaemonMode::User);
        assert_ne!(user_sock, PathBuf::from("/run/kub0/kub0.sock"));
        assert_ne!(user_state, PathBuf::from("/var/lib/kub0/daemon"));
        assert_eq!(user_sock, default_socket());
        assert_eq!(user_state, default_state_dir());
        assert_eq!(socket_mode_bits(DaemonMode::User), 0o600);
        assert_eq!(socket_mode_bits(DaemonMode::System), 0o660);
        assert_eq!(default_data_dir_for(DaemonMode::System), PathBuf::from("/usr/share/kub0"));
        assert_eq!(default_data_dir_for(DaemonMode::User), PathBuf::from("data"));
    }

    #[test]
    fn system_flag_parses_and_sets_mode() {
        let args = try_parse_args(["--system"]).expect("parse --system");
        assert_eq!(args.mode, DaemonMode::System);
        assert_eq!(args.socket, PathBuf::from("/run/kub0/kub0.sock"));
        assert_eq!(args.state_dir, PathBuf::from("/var/lib/kub0/daemon"));
        // systemd starts the system kub0d in `/`: a relative data dir finds no databases.
        assert_eq!(args.data_dir, PathBuf::from("/usr/share/kub0"));
        assert!(args.data_dir.is_absolute());

        let user = try_parse_args(Vec::<&str>::new()).expect("parse empty");
        assert_eq!(user.mode, DaemonMode::User);
        assert_ne!(user.socket, PathBuf::from("/run/kub0/kub0.sock"));
        assert_ne!(user.state_dir, PathBuf::from("/var/lib/kub0/daemon"));
        assert_eq!(user.data_dir, PathBuf::from("data"));

        let over = try_parse_args([
            "--system",
            "--socket",
            "/tmp/explicit.sock",
            "--state-dir",
            "/srv/vallum-explicit",
            "--data-dir",
            "/srv/vallum-data",
        ])
        .expect("parse overrides");
        assert_eq!(over.mode, DaemonMode::System);
        assert_eq!(over.socket, PathBuf::from("/tmp/explicit.sock"));
        assert_eq!(over.state_dir, PathBuf::from("/srv/vallum-explicit"));
        assert_eq!(over.data_dir, PathBuf::from("/srv/vallum-data"));
        let user_over = try_parse_args(["--data-dir", "/opt/plugin/data"]).expect("user data dir");
        assert_eq!(user_over.data_dir, PathBuf::from("/opt/plugin/data"));
        for bad in [vec!["--system", "--data-dir"], vec!["--data-dir", ""], vec!["--data-dir", "--system"]] {
            assert_eq!(try_parse_args(bad.clone()).err(), Some(ParseError::MissingDataDir), "{bad:?}");
        }

        let over_first = try_parse_args(["--socket", "/tmp/a.sock", "--system"]).expect("order");
        assert_eq!(over_first.socket, PathBuf::from("/tmp/a.sock"));
        assert_eq!(over_first.mode, DaemonMode::System);
    }

    #[test]
    fn unknown_log_rotates_at_cap() {
        let dir = tmpdir("rot");
        let path = dir.join("unknown.ndjson");
        std::fs::write(
            &path,
            "{\"proto\":\"tcp\",\"uid\":1,\"remote\":{\"ip\":\"0.0.0.0\",\"port\":1}}\n",
        )
        .unwrap();
        let mut log = UnknownLog::load(&dir);
        while log.keys.len() < UNKNOWN_LOG_CAP {
            log.keys.insert((
                "pad".into(),
                Some(log.keys.len() as u32),
                "0.0.0.0".into(),
                0,
            ));
        }
        assert_eq!(log.keys.len(), UNKNOWN_LOG_CAP);
        log.consider(&test_conn(99, "no-owner", false), 42);
        assert!(dir.join("unknown.ndjson.1").exists());
        let rotated = std::fs::read_to_string(dir.join("unknown.ndjson.1")).unwrap();
        assert!(rotated.contains("0.0.0.0"));
        let new = std::fs::read_to_string(dir.join("unknown.ndjson")).unwrap();
        assert_eq!(new.lines().filter(|l| !l.is_empty()).count(), 1);
        assert!(new.contains("no-owner"), "{new}");
        assert_eq!(log.keys.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A start never moves system state; only `kub0d migrate-state` and
    /// `kub0 install` do. Pinned by text: the system arm of `prepare_state`
    /// moves nothing, and the system move has one caller.
    #[test]
    fn only_migrate_state_moves_system_state() {
        let src = include_str!("main.rs");
        let body = &src[src.find("fn prepare_state(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let system = &body[body.find("DaemonMode::System =>").unwrap()..body.find("DaemonMode::User =>").unwrap()];
        assert!(!system.contains("move_state"), "a start moved system state:\n{system}");
        let migrate = &src[src.find("fn migrate_state_command(").unwrap()..];
        let migrate = &migrate[..migrate.find("\n}\n").unwrap()];
        assert!(migrate.contains("move_state_logged(old, new)"));
        assert!(matches!(
            try_parse_args(["--system", "--migrate-state"]),
            Err(ParseError::UnknownArgument(_))
        ));
        assert!(try_parse_args(["--migrate-state"]).unwrap().migrate_state);
        assert!(!try_parse_args::<[&str; 0], &str>([]).unwrap().migrate_state, "a bare start moves nothing");
    }

    /// A live 0.4.x daemon is a listening socket at the old path; a link
    /// there (what 0.4.5 and 0.4.6 left) or a dead socket is not one.
    #[test]
    fn a_running_old_daemon_is_a_live_socket_not_a_link() {
        let dir = std::env::temp_dir().join(format!("kub0d-old-daemon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("vallum.sock");
        assert!(!old_daemon_running(&old), "nothing there");
        let listener = std::os::unix::net::UnixListener::bind(dir.join("kub0.sock")).unwrap();
        std::os::unix::fs::symlink(dir.join("kub0.sock"), &old).unwrap();
        assert!(!old_daemon_running(&old), "the link 0.4.5 and 0.4.6 left is not a 0.4.x daemon");
        std::fs::remove_file(&old).unwrap();
        let live = std::os::unix::net::UnixListener::bind(&old).unwrap();
        assert!(old_daemon_running(&old), "a listening 0.4.x socket");
        drop(live);
        // Another test in this binary may be spawning a child at this moment.
        // Until that child execs it holds a copy of every descriptor, this
        // listener among them, and a connect is still accepted (measured:
        // under a millisecond). Wait that out before asserting.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while old_daemon_running(&old) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(!old_daemon_running(&old), "a socket nobody answers on any more");
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserved_command_path_aliases_are_rejected() {
        use std::os::unix::fs::symlink;
        for path in ["/run/kub0/../kub0/kub0-status.sock", "/run/./kub0/kub0-status.sock"] {
            assert!(validate_command_path(Path::new(path)).is_err());
        }
        let cwd = std::env::current_dir().unwrap();
        let relative = cwd.components().skip(1).fold(PathBuf::new(), |p, _| p.join(".."))
            .join("run/kub0/kub0-status.sock");
        assert!(validate_command_path(&relative).is_err());
        let dir = enforcer_dir("reserved-alias");
        symlink("/run", dir.join("run-alias")).unwrap();
        assert!(validate_command_path(&dir.join("run-alias/kub0/kub0-status.sock")).is_err());
        assert!(validate_command_path(&dir.join("command.sock")).is_ok());
        assert!(validate_command_path(Path::new("/run/kub0/kub0.sock")).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reserved_command_path_is_rejected_before_bind_or_setup() {
        let rt = Kub0Runtime::new();
        let result = Server::bind_with_diagnostics(
            Path::new(vallumd::system_status::SYSTEM_STATUS_SOCKET),
            false,
            DaemonMode::System,
            rt,
            Path::new("/tmp"),
            || panic!("must not resolve the group"),
            |_| panic!("must not start diagnostics"),
        );
        assert!(matches!(result, Err(e) if e.kind() == std::io::ErrorKind::InvalidInput));
    }

    #[test]
    fn diagnostics_snapshot_and_user_gate() {
        let rt = Kub0Runtime::new();
        setup_system_diagnostics(DaemonMode::User, &rt, |_| panic!("user producer"));
        setup_system_diagnostics(DaemonMode::System, &rt, |producer| {
            assert!(!producer().policy_known);
            {
                let mut plan = rt.system_plan.lock().unwrap();
                plan.known = true;
                plan.applied_at = 123;
            }
            let status = producer();
            assert!(status.policy_known);
            assert_eq!(status.reported_last_applied_at, 123);
            assert_eq!(status.current_kernel_verification, "unknown");
            Err(std::io::Error::other("optional setup failure"))
        });
    }

    #[test]
    #[ignore = "requires namespace root and a Unix bind, which a build sandbox may refuse"]
    fn common_live_server_starts_one_diagnostics_producer() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let egid = unsafe { libc::getegid() };
        for flags in [vec!["--system"], vec!["--system", "--source", "opensnitch"]] {
            let args = try_parse_args(flags).unwrap();
            let dir = tmpdir("live-diagnostics");
            let path = dir.join("command.sock");
            let rt = Kub0Runtime::new();
            let mut starts = 0;
            let server = Server::bind_with_diagnostics(
                &path,
                false,
                args.mode,
                Arc::clone(&rt),
                &dir,
                || Err(std::io::Error::other("missing/invalid group simulation")),
                |producer| {
                    starts += 1;
                    assert_eq!(producer().mode, "system");
                    assert!(!producer().policy_known);
                    rt.system_plan.lock().unwrap().applied_at = 321;
                    assert_eq!(producer().reported_last_applied_at, 321);
                    Err(std::io::Error::other("missing/invalid group simulation"))
                },
            )
            .unwrap();
            assert_eq!(starts, 1);
            vallumd::system_status::verify_command(&path, 0).unwrap();
            assert_eq!(unsafe { libc::getegid() }, egid);
            drop(server);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn heartbeat_thread_not_started_when_account_file_absent() {
        let dir = tmpdir("no-acct");
        let path = dir.join("account.json");
        let rt = Kub0Runtime::new();
        assert!(
            spawn_heartbeat_thread(path, dir.clone(), Arc::clone(&rt), true).is_none(),
            "must not spawn when account.json is missing"
        );
        assert!(!rt.system_plan.lock().unwrap().known);
        assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_temp_state_dir_is_refused_by_the_daemon() {
        let tmpdir = std::env::temp_dir();
        let tmpdir_child = tmpdir.join("vallum-state");
        let mut refused = vec![
            "/tmp/vallum-state",
            "/tmp",
            "/var/tmp/vallum",
            "/private/tmp/vallum-state",
            "/dev/shm/vallum",
        ];
        // Empty/root TMPDIR is intentionally ignored by the guard.
        if !tmpdir.as_os_str().is_empty()
            && normalize_absolute_path(&std::path::absolute(&tmpdir).unwrap()).parent().is_some()
        {
            refused.push(tmpdir_child.to_str().unwrap());
        }
        for dir in refused {
            match try_parse_args(["--state-dir", dir]) {
                Err(ParseError::TempStateDir(got, _root)) => assert_eq!(got, PathBuf::from(dir)),
                Err(e) => panic!("{dir}: wrong error {e:?}"),
                Ok(_) => panic!("daemon accepted temp --state-dir {dir}"),
            }
        }
        // --system does not exempt it: the account file is just as mortal there.
        assert!(matches!(
            try_parse_args(["--system", "--state-dir", "/tmp/vallum-state"]),
            Err(ParseError::TempStateDir(..))
        ));
    }

    #[test]
    fn durable_state_dirs_and_near_misses_are_accepted() {
        // Component-wise match: "/tmpfoo" is not under "/tmp".
        for dir in [
            "/srv/vallum",
            "/home/u/.local/state/kub0",
            "/tmpfoo/vallum",
            "/var/tmpx",
        ] {
            let a = try_parse_args(["--state-dir", dir]).unwrap_or_else(|e| panic!("{dir}: {e:?}"));
            assert_eq!(a.state_dir, PathBuf::from(dir));
        }
        // The default is never checked, so a mktemp XDG_STATE_HOME (the runtime tests) still boots.
        assert!(try_parse_args(Vec::<&str>::new()).is_ok());
    }

    #[test]
    fn temp_state_paths_normalize_parent_components() {
        assert!(temp_root_of_with(Path::new("/srv/../tmp/vallum"), Path::new("/")).is_some());
        assert!(temp_root_of_with(Path::new("/tmp/../srv/vallum"), Path::new("/")).is_none());
        assert!(temp_root_of_with(Path::new("/srv/vallum"), Path::new("")).is_none());
        assert!(temp_root_of_with(Path::new("/srv/vallum"), Path::new("/srv/..")).is_none());
        assert!(temp_root_of_with(
            Path::new("/opt/custom-temp/vallum"),
            Path::new("/opt/custom-temp")
        )
        .is_some());
        assert!(temp_root_of_with(
            Path::new("/opt/custom-temporary/vallum"),
            Path::new("/opt/custom-temp")
        )
        .is_none());
    }

    #[test]
    fn explicit_state_dir_needs_a_nonempty_path() {
        for argv in [
            vec!["--state-dir"],
            vec!["--state-dir", ""],
            vec!["--state-dir", "--system"],
            vec!["--state-dir", "-h"],
        ] {
            assert!(matches!(
                try_parse_args(&argv),
                Err(ParseError::MissingStateDir)
            ));
        }
    }

    fn sample_tag(source: vallumd::tags::Source, label: &str) -> vallumd::tags::Tag {
        vallumd::tags::Tag {
            network_key: "1.2.3.0/24".into(),
            label: label.into(),
            kind: vallumd::suggest::Kind::Service,
            ptr_suffix: String::new(),
            ts: 1,
            source,
        }
    }

    fn sample_clue(label: &str) -> vallumd::suggest::Clue {
        vallumd::suggest::Clue {
            label: label.into(),
            basis: "test".into(),
            confidence: vallumd::suggest::Confidence::Weak,
            kind: vallumd::suggest::Kind::Service,
        }
    }

    #[test]
    fn user_tag_outranks_machine_clue() {
        let user = sample_tag(vallumd::tags::Source::User, "Plex");
        let clue = sample_clue("Tailscale relay");
        let got = resolve_tag(Some(&user), None, Some(&clue)).expect("user tag wins");
        assert_eq!(got.label, "Plex");
        assert_eq!(got.source, vallumd::tags::Source::User);
    }

    #[test]
    fn user_tag_outranks_fleet_tag() {
        let user = sample_tag(vallumd::tags::Source::User, "Plex");
        let fleet = sample_tag(vallumd::tags::Source::Fleet, "Jellyfin");
        let clue = sample_clue("machine");
        let got = resolve_tag(Some(&user), Some(&fleet), Some(&clue)).expect("user tag wins");
        assert_eq!(got.label, "Plex");
        assert_eq!(got.source, vallumd::tags::Source::User);
    }

    #[test]
    fn fleet_tag_outranks_machine_clue() {
        let fleet = sample_tag(vallumd::tags::Source::Fleet, "Jellyfin");
        let clue = sample_clue("Tailscale relay");
        let got = resolve_tag(None, Some(&fleet), Some(&clue)).expect("fleet tag wins");
        assert_eq!(got.label, "Jellyfin");
        assert_eq!(got.source, vallumd::tags::Source::Fleet);
    }

    #[test]
    fn machine_clue_is_not_promoted_to_tag() {
        let clue = sample_clue("Tailscale relay");
        assert!(
            resolve_tag(None, None, Some(&clue)).is_none(),
            "a machine guess stays on Connection.clue, never overwrites a tag"
        );
    }

    #[test]
    fn nothing_resolves_to_none() {
        assert!(resolve_tag(None, None, None).is_none());
    }

    fn fleet_report(key: &str, label: &str, node: &str, ptr: &str) -> vallumd::tags::FleetReport {
        vallumd::tags::FleetReport {
            network_key: key.into(),
            label: label.into(),
            node: node.into(),
            kind: vallumd::suggest::Kind::Service,
            ptr_suffix: ptr.into(),
        }
    }

    #[test]
    fn scored_fleet_tag_reaches_resolve_order() {
        let reports = [
            fleet_report("1.2.3.0/24", "Plex", "node-a", "plex.example"),
            fleet_report("1.2.3.0/24", "Plex", "node-b", "plex.example"),
        ];
        let fleet = fleet_tag_from_reports(&reports, "1.2.3.0/24", "host.plex.example")
            .expect("two agreeing nodes are a quorum");
        assert_eq!(fleet.label, "Plex");
        assert_eq!(fleet.source, vallumd::tags::Source::Fleet);
        assert_eq!(fleet.ptr_suffix, "plex.example");
        let clue = sample_clue("machine");
        let got = resolve_tag(None, Some(&fleet), Some(&clue)).expect("fleet outranks clue");
        assert_eq!(got.source, vallumd::tags::Source::Fleet);
        let user = sample_tag(vallumd::tags::Source::User, "Mine");
        let got = resolve_tag(Some(&user), Some(&fleet), Some(&clue)).expect("user wins");
        assert_eq!(got.source, vallumd::tags::Source::User);
        assert_eq!(got.label, "Mine");
    }

    #[test]
    fn one_reporter_is_not_a_scored_fleet_tag() {
        let reports = [fleet_report("1.2.3.0/24", "Plex", "node-a", "")];
        assert!(
            fleet_tag_from_reports(&reports, "1.2.3.0/24", "").is_none(),
            "one node is hearsay; score() must not mint a tag"
        );
    }

    #[test]
    fn scored_fleet_tag_is_never_user_source() {
        let reports = [
            fleet_report("1.2.3.0/24", "Plex", "a", "old.example"),
            fleet_report("1.2.3.0/24", "Plex", "b", "old.example"),
        ];
        // PTR no longer matches: confidence is Weak, source must still be Fleet
        // so this label cannot be re-uploaded as a user tag.
        let fleet = fleet_tag_from_reports(&reports, "1.2.3.0/24", "new.example.net")
            .expect("quorum still holds when PTR disagrees");
        assert_eq!(fleet.source, vallumd::tags::Source::Fleet);
        let conf = vallumd::tags::fleet_confidence(
            &vallumd::tags::FleetTag {
                label: fleet.label.clone(),
                agreeing: 2,
                reporters: 2,
            },
            &fleet.ptr_suffix,
            "new.example.net",
        );
        assert_ne!(conf, vallumd::suggest::Confidence::Certain);
        assert_eq!(conf, vallumd::suggest::Confidence::Weak);
    }

    #[test]
    fn tag_cmd_rejects_empty_network_key() {
        let v = serde_json::json!({"type":"tag","networkKey":"","label":"Plex","kind":"service"});
        let err = parse_tag_cmd(&v).unwrap_err();
        assert!(err.contains("empty networkKey"), "{err}");
    }

    #[test]
    fn tag_cmd_keeps_the_label_when_the_kind_is_unmodelled() {
        // Found by driving the live socket 2026-09-21: `kind: "infra"` came back
        // as "service" with no diagnostic anywhere. The LABEL is what the user
        // actually typed, so it must survive -- but the substitution is now
        // logged rather than silent. Both branches, because a kind this build
        // DOES model must not be quietly downgraded by the same path.
        let v = serde_json::json!({
            "type":"tag","networkKey":"1.2.3.0/24","label":"Home router","kind":"infra"
        });
        match parse_tag_cmd(&v).expect("an unknown kind degrades, it does not refuse") {
            TagCmd::Set { label, kind, .. } => {
                assert_eq!(label, "Home router");
                assert_eq!(kind, vallumd::suggest::Kind::Service);
            }
            other => panic!("expected Set, got {other:?}"),
        }
        let known = serde_json::json!({
            "type":"tag","networkKey":"1.2.3.0/24","label":"My tailnet","kind":"tailnet"
        });
        match parse_tag_cmd(&known).expect("a modelled kind parses") {
            TagCmd::Set { kind, .. } => assert_eq!(kind, vallumd::suggest::Kind::Tailnet),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn tag_cmd_rejects_label_over_64_chars() {
        let label = "a".repeat(65);
        let v = serde_json::json!({
            "type":"tag",
            "networkKey":"1.2.3.0/24",
            "label":label,
            "kind":"service"
        });
        let err = parse_tag_cmd(&v).unwrap_err();
        assert!(err.contains("64"), "{err}");
        let ok = serde_json::json!({
            "type":"tag",
            "networkKey":"1.2.3.0/24",
            "label":"a".repeat(64),
            "kind":"service"
        });
        assert!(matches!(parse_tag_cmd(&ok), Ok(TagCmd::Set { .. })));
    }

    #[test]
    fn tag_cmd_empty_label_deletes() {
        let v = serde_json::json!({
            "type":"tag",
            "networkKey":"1.2.3.0/24",
            "label":"",
            "kind":"service"
        });
        match parse_tag_cmd(&v).unwrap() {
            TagCmd::Delete { network_key } => assert_eq!(network_key, "1.2.3.0/24"),
            TagCmd::Set { .. } => panic!("empty label must delete"),
        }
    }

    #[test]
    fn tag_cmd_set_keeps_label_and_kind() {
        let v = serde_json::json!({
            "type":"tag",
            "networkKey":"1.2.3.0/24",
            "label":"Plex",
            "kind":"service"
        });
        match parse_tag_cmd(&v).unwrap() {
            TagCmd::Set {
                network_key,
                label,
                kind,
                anchor,
            } => {
                assert_eq!(anchor, "", "a parsed line names no anchor");
                assert_eq!(network_key, "1.2.3.0/24");
                assert_eq!(label, "Plex");
                assert_eq!(kind, vallumd::suggest::Kind::Service);
            }
            TagCmd::Delete { .. } => panic!("non-empty label must set"),
        }
    }

    /// One HTTP request off `c`: the head, then as much body as Content-Length says, so
    /// a reply never lands on a client that is still sending.
    fn read_request(c: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        c.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
        loop {
            let n = c.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// One-shot HTTP server: answers each accepted request with the next canned reply
    /// and records the request head, so a test can assert what kub0d sent.
    fn canned_http(replies: Vec<String>) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for reply in replies {
                let (mut c, _) = l.accept().unwrap();
                tx.send(read_request(&mut c)).ok();
                c.write_all(reply.as_bytes()).ok();
            }
        });
        (url, rx)
    }

    fn http_reply(status: &str, content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn json_reply(body: &str) -> String {
        http_reply("200 OK", "application/json", body)
    }

    #[test]
    fn netpolicy_fetch_honours_etag_and_only_a_policies_array_replaces_the_set() {
        let body = r#"{"policies":[{"id":"p","name":"n","mode":"monitor","version":2,"rules":[{"id":"r","kind":"ip","action":"monitor","match":{"cidr":"198.51.100.0/24"}}]}]}"#;
        let ok = format!(
            "HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let not_modified = "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nConnection: close\r\n\r\n".to_string();
        let missing = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
        let gone = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
        let (base, heads) = canned_http(vec![
            ok,
            not_modified.clone(),
            not_modified,
            missing,
            gone,
            json_reply("{}"),
            json_reply(r#"{"policies":null}"#),
            json_reply(r#"{"policies":{}}"#),
            json_reply(r#"{"policies":"x"}"#),
            http_reply("200 OK", "text/html", "<html>not found</html>"),
            http_reply("401 Unauthorized", "application/json", r#"{"error":"invalid token"}"#),
            http_reply("403 Forbidden", "text/plain", ""),
            http_reply("410 Gone", "text/plain", ""),
            json_reply(r#"{"policies":[]}"#),
        ]);
        let agent = http_agent();
        let url = kub0::netpolicy_url(&base, "lap 1");

        let set = fetch_netpolicy(&agent, &url, "tok", "").unwrap().expect("200 is a new set");
        assert_eq!(set.etag, "\"abc\"");
        assert_eq!(set.policies[0].rules[0].id, "r");
        let head = heads.recv().unwrap();
        assert!(head.starts_with("GET /detonate/api/enforce/netpolicy?node=lap%201 "), "{head}");
        assert!(head.to_ascii_lowercase().contains("authorization: bearer tok"), "{head}");
        assert!(!head.to_ascii_lowercase().contains("if-none-match"), "{head}");

        assert!(fetch_netpolicy(&agent, &url, "tok", &set.etag).unwrap().is_none(), "304 = unchanged");
        let head = heads.recv().unwrap();
        assert!(head.to_ascii_lowercase().contains("if-none-match: \"abc\""), "{head}");
        // A 304 to a request that named no ETag is not "unchanged" from anything.
        assert!(fetch_netpolicy(&agent, &url, "tok", "").unwrap_err().contains("304"));

        // A 404 is a route that was not reached, never "no policies": an older server and a
        // deleted ingress Middleware both answer it, and treating it as empty cleared the kernel.
        assert_eq!(fetch_netpolicy(&agent, &url, "tok", "").unwrap_err(), "HTTP 404");
        assert_eq!(fetch_netpolicy(&agent, &url, "tok", "").unwrap_err(), "HTTP 500");
        for what in ["{}", "policies: null", "policies: {}", "policies: \"x\"", "an HTML page"] {
            assert!(fetch_netpolicy(&agent, &url, "tok", "").is_err(), "{what} is not a policy set");
        }
        for code in ["HTTP 401", "HTTP 403", "HTTP 410"] {
            assert_eq!(fetch_netpolicy(&agent, &url, "tok", "").unwrap_err(), code);
        }
        let empty = fetch_netpolicy(&agent, &url, "tok", "").unwrap().expect("[] is the server saying none");
        assert!(empty.policies.is_empty());
    }

    /// Write an executable stand-in and wait until it can run. A child another test thread
    /// forks while the file is open for writing holds it until that child execs, and
    /// running it meanwhile fails with ETXTBSY. Once one exec succeeds nothing can hold
    /// it open again; one that never does is a broken fixture, not a pass.
    fn install_script(bin: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(bin, body).unwrap();
        std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        for attempt in 1.. {
            match Command::new(bin).arg("probe").stdin(std::process::Stdio::null()).status() {
                Ok(_) => return,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 200 => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("{} never became runnable after {attempt} tries: {e}", bin.display()),
            }
        }
    }

    /// A kub0-block stand-in that logs each verb and its stdin to `calls.log`, and keeps
    /// the fake kernel `fake_nft` reads: `fleet-sync` puts the fleet rules there and
    /// `fleet-clear` takes them out. `fail-<verb>` in `dir` makes that verb fail, and
    /// `reply-paused` makes it answer that the panel's pause is on.
    fn fake_helper(dir: &Path, exit: i32) -> (PathBuf, PathBuf) {
        let log = dir.join("calls.log");
        let bin = dir.join("kub0-block");
        let d = dir.display();
        std::fs::write(dir.join("chain.synced"), fleet_chain(false)).unwrap();
        install_script(
            &bin,
            &format!(
                "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\nprintf '%s\\t' \"$1\" >> '{d}/calls.log'\ncat >> '{d}/calls.log'\nprintf '\\n' >> '{d}/calls.log'\n\
                 [ -f '{d}/fail-'\"$1\" ] && exit 1\n\
                 [ {exit} -eq 0 ] || exit {exit}\n\
                 case \"$1\" in fleet-sync) cp '{d}/chain.synced' '{d}/chain.txt';; fleet-clear) rm -f '{d}/chain.txt';; esac\n\
                 if [ -f '{d}/reply-paused' ]; then echo '{{\"ok\":true,\"paused\":true}}'; else echo '{{\"ok\":true,\"paused\":false}}'; fi\n"
            ),
        );
        (bin, log)
    }

    /// An nft stand-in for the read-only kernel check: logs its arguments to `nft.log` and
    /// prints `chain.txt`, or nft's own error for a missing table when there is none.
    /// `nft-fail` makes it fail; `nft-hang` makes it hang.
    fn fake_nft(dir: &Path) -> PathBuf {
        let bin = dir.join("nft");
        let d = dir.display();
        install_script(
            &bin,
            &format!(
                "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\necho \"$*\" >> '{d}/nft.log'\n\
                 [ -f '{d}/nft-hang' ] && exec sleep 30\n\
                 [ -f '{d}/nft-fail' ] && {{ echo 'Error: Could not receive tables from kernel: Operation not permitted' >&2; exit 1; }}\n\
                 [ -f '{d}/chain.txt' ] || {{ printf 'Error: No such file or directory\\nlist chain inet vallum out\\n' >&2; exit 1; }}\n\
                 cat '{d}/chain.txt'\n"
            ),
        );
        bin
    }

    /// `nft -a list chain inet vallum out` with both fleet rules, as a real nft prints it
    /// (taken from one in a throwaway namespace), with the panel's pause rule or without.
    fn fleet_chain(paused: bool) -> String {
        format!(
            "table inet vallum {{\n\tchain out {{ # handle 1\n\t\ttype filter hook output priority filter; policy accept;\n{}\
             \t\tip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 drop comment \"vallum-fleet\" # handle 6\n\
             \t\tip6 daddr @fleet6 ip6 daddr != @fleetkeep6 counter packets 0 bytes 0 drop comment \"vallum-fleet\" # handle 7\n\t}}\n}}\n",
            if paused { "\t\taccept comment \"vallum-paused\" # handle 8\n" } else { "" }
        )
    }

    #[derive(Clone, Copy)]
    enum Kernel {
        Empty,
        Holds,
        Paused,
    }

    /// Set what the fake nft reads back, as a teardown, an earlier run or the panel would.
    fn fake_kernel(dir: &Path, k: Kernel) {
        let chain = dir.join("chain.txt");
        match k {
            Kernel::Empty => drop(std::fs::remove_file(chain)),
            Kernel::Holds => std::fs::write(chain, fleet_chain(false)).unwrap(),
            Kernel::Paused => std::fs::write(chain, fleet_chain(true)).unwrap(),
        }
    }

    /// The system kub0d's enforcer, wired to a fake helper and a fake nft in `dir`.
    fn test_enforcer(dir: &Path, data: PathBuf) -> Enforcer {
        let (bin, _) = fake_helper(dir, 0);
        let mut e = Enforcer::new(data, bin);
        e.nft = fake_nft(dir);
        e
    }

    fn helper_calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    fn nft_calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("nft.log")).unwrap_or_default()
    }

    fn bundled_data() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data")
    }

    /// A runtime with the bundled ASN database, as `boot_netpolicy` gives a packaged one.
    fn runtime_with_asn() -> Arc<Kub0Runtime> {
        let rt = Kub0Runtime::new();
        rt.set_asn(Arc::new(vallumd::geo::AsnDb::load(&bundled_data())));
        rt
    }

    fn block_policies(mode: &str) -> vallumd::netpolicy::PolicySet {
        vallumd::netpolicy::parse(
            &serde_json::json!({"policies":[{"id":"p","name":"Block C2","mode":mode,"version":1,"rules":[
                {"id":"r","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}),
            "",
        )
        .unwrap()
    }

    fn enforcer_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vallum-enforcer-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn enforcer_only_syncs_as_system_and_only_on_change() {
        let dir = enforcer_dir("change");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        let calls = || helper_calls(&dir);

        e.sync(&rt, false, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "monitor");
        assert!(rt.enforcement().reason.contains("system service"));
        assert!(calls().is_empty() && nft_calls(&dir).is_empty(), "a user-mode kub0d never touches the kernel");

        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing, enf.entries), ("enforcing", true, 1));
        assert!(enf.rules.contains("r"));
        let first = calls();
        assert!(first.starts_with("fleet-sync\t"), "{first}");
        let spec: serde_json::Value = serde_json::from_str(first.trim_start_matches("fleet-sync\t").trim()).unwrap();
        assert_eq!(spec["block"], serde_json::json!(["198.51.100.0/24"]));
        let keep = spec["keep"].as_array().unwrap();
        assert!(keep.iter().any(|k| k == "127.0.0.1"), "the kub0 server is kept");
        assert!(
            keep.iter().filter_map(|k| k.as_str()).any(|k| k == "1.1.1.0/24" || k.starts_with("1.1.1.")),
            "Cloudflare is shared infrastructure and is kept"
        );
        assert_eq!(enf.shared_ranges as usize, keep.len() - 1);

        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(calls(), first, "an unchanged plan is checked, not re-synced, and never through the root helper");
        assert_eq!(nft_calls(&dir), "-a list chain inet vallum out\n", "one read-only chain listing");
        assert_eq!(*rt.enforcement(), *enf, "the kernel holds what was applied");

        // The policy flips to monitor: the enforcer takes the rules back out.
        e.policy_known = true;
        rt.set_policies(block_policies("monitor"));
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert!(calls().ends_with("fleet-clear\t\n"), "{}", calls());
        assert_eq!(rt.enforcement().state, "none");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforcer_reports_a_failing_helper() {
        let dir = enforcer_dir("fail");
        let (bin, _) = fake_helper(&dir, 1);
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = Enforcer::new(bundled_data(), bin);
        e.nft = fake_nft(&dir);
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!(enf.state, "error");
        assert!(enf.reason.starts_with("fleet-sync failed"), "{}", enf.reason);
        assert!(!enf.enforcing);
        // Not enforcing ⇒ a matching connection would block but is never counted blocked.
        let shown = rt.evaluate_connection("198.51.100.7", "", "", 1);
        assert_eq!(shown.len(), 1);
        let r = rt.drain_policy_matches();
        assert_eq!((r[0].would_block, r[0].blocked), (1, 0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforcer_without_helper_is_an_error_not_a_silent_monitor() {
        let rt = Kub0Runtime::new();
        rt.set_policies(block_policies("block"));
        let mut e = Enforcer::new(PathBuf::from("data"), PathBuf::from("/nonexistent/kub0-block"));
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "error");
        assert!(rt.enforcement().reason.contains("not installed"));

        // With no helper there is nothing to clear with, and an empty policy is not an
        // error on a host that never had one.
        rt.set_policies(vallumd::netpolicy::PolicySet::default());
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none", "{}", rt.enforcement().reason);
    }

    #[test]
    fn enforcer_applies_nothing_without_shared_infrastructure_and_leaves_the_kernel_alone() {
        let dir = enforcer_dir("noasn");
        let mut e = test_enforcer(&dir, PathBuf::from("/nonexistent/data"));
        // An earlier run, built with its keep set, left its rules in the kernel.
        fake_kernel(&dir, Kernel::Holds);
        let rt = Kub0Runtime::new(); // what boot_netpolicy leaves when the ASN file is missing
        rt.set_policies(block_policies("block"));
        e.policy_known = true;
        for _ in 0..2 {
            e.sync(&rt, true, "http://127.0.0.1:9");
            let enf = rt.enforcement();
            assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
            for want in ["ASN", "/nonexistent/data/geoip/dbip-asn-lite.mmdb", "data dir /nonexistent/data", "left in place", "restart kub0d"] {
                assert!(enf.reason.contains(want), "{want}: {}", enf.reason);
            }
            assert_eq!(helper_calls(&dir), "", "no new block set without CDNs to keep, and no clear");
            assert!(dir.join("chain.txt").exists(), "the earlier run's rules stay");
        }
        rt.evaluate_connection("198.51.100.7", "", "", 1);
        let r = rt.drain_policy_matches();
        assert_eq!((r[0].would_block, r[0].blocked), (1, 0));

        // An mmdb that opens but holds no autonomous-system records keeps nothing either:
        // the gate is on the keep set itself, not on a file having opened. The same file
        // with an ASN record is the near miss that does sync.
        let country = b"\xE1\x47country\xE1\x48iso_code\x42KP".to_vec();
        let cloudflare = [b"\xE1\x58autonomous_system_number\xC2".as_slice(), &13335u16.to_be_bytes()].concat();
        for (data, syncs) in [(country, false), (cloudflare, true)] {
            let tiny = enforcer_dir(if syncs { "noasn-near-miss" } else { "noasn-wrong-type" });
            std::fs::create_dir_all(tiny.join("geoip")).unwrap();
            tiny_mmdb(&tiny.join("geoip/dbip-asn-lite.mmdb"), &data);
            let asn = Arc::new(vallumd::geo::AsnDb::load(&tiny));
            assert!(asn.has_mmdb(), "the file opens as an mmdb");
            let rt = Kub0Runtime::new();
            rt.set_asn(asn);
            rt.set_policies(block_policies("block"));
            let mut e = test_enforcer(&tiny, tiny.clone());
            e.sync(&rt, true, "http://127.0.0.1:9");
            assert_eq!(helper_calls(&tiny).contains("fleet-sync"), syncs, "{}", helper_calls(&tiny));
            assert_eq!(rt.enforcement().state, if syncs { "enforcing" } else { "error" }, "{}", rt.enforcement().reason);
            std::fs::remove_dir_all(&tiny).ok();
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A MaxMind DB whose two IPv4 halves, `0.0.0.0/1` and `128.0.0.0/1`, hold `data` (one
    /// MaxMind-encoded map): small enough to build in a test, where walking a real database
    /// takes seconds. Two networks because a country's ranges are told apart by looking up
    /// each one's first address, and `0.0.0.0` never looks up.
    fn tiny_mmdb(path: &Path, data: &[u8]) {
        fn text(s: &str) -> Vec<u8> {
            [&[0x40 | s.len() as u8][..], s.as_bytes()].concat()
        }
        // An IPv6 tree, as DB-IP ships: 96 nodes down the zero bits to where IPv4 starts,
        // then one node whose halves both point at data offset 0. 24-bit records; a record
        // equal to the node count is "no data", one past it by 16 + n is data offset n.
        const NODES: u32 = 97;
        let record = |v: u32| v.to_be_bytes()[1..].to_vec();
        let mut db = Vec::new();
        for i in 1..NODES {
            db.extend(record(i));
            db.extend(record(NODES));
        }
        db.extend(record(NODES + 16));
        db.extend(record(NODES + 16));
        db.extend([0u8; 16]);
        db.extend(data);
        db.extend(b"\xAB\xCD\xEFMaxMind.com\xE9");
        for (key, value) in [
            ("binary_format_major_version", vec![0xA1, 2]),
            ("binary_format_minor_version", vec![0xA0]),
            ("build_epoch", vec![0x00, 0x02]),
            ("database_type", text("Test")),
            ("description", vec![0xE0]),
            ("ip_version", vec![0xA1, 6]),
            ("languages", vec![0x00, 0x04]),
            ("node_count", vec![0xC1, NODES as u8]),
            ("record_size", vec![0xA1, 24]),
        ] {
            db.extend(text(key));
            db.extend(value);
        }
        std::fs::write(path, db).unwrap();
    }

    #[test]
    fn enforcer_keeps_last_good_when_netpolicy_fetch_fails() {
        let dir = enforcer_dir("lastgood");
        let calls = || helper_calls(&dir);
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert!(calls().starts_with("fleet-sync\t"), "{}", calls());

        let applied_ts = rt.enforcement().applied_ts;
        assert!(applied_ts > 0);
        let agent = http_agent();
        let mut last_err = String::new();
        let down = || http_reply("500 Internal Server Error", "text/plain", "");
        let unreachable = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let replies = [
            http_reply("404 Not Found", "text/plain", "404 page not found"),
            down(),
            json_reply("{}"),
        ];
        for netpolicy in replies.into_iter().map(Some).chain([None]) {
            let base = match netpolicy {
                Some(reply) => canned_http(vec![down(), down(), reply]).0,
                None => unreachable.clone(),
            };
            let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
            assert_eq!(snap.netpolicy_refresh_ok, Some(false), "{base}: {last_err}");
            e.sync(&rt, true, &base);
            assert_eq!(rt.enforcement().applied_ts, applied_ts, "failed refresh must not advance apply time");
            let plan = rt.system_plan.lock().unwrap();
            assert!(plan.known);
            assert_eq!(plan.applied_at, applied_ts);
            assert_eq!(plan.refresh_ok, None); // refresh_fleet alone does not publish a heartbeat
            drop(plan);
            assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
            assert!(rt.policies().has_effective_block(), "the last policy received still stands");
            assert_eq!((rt.enforcement().state.as_str(), rt.enforcement().enforcing), ("enforcing", true));
        }
        assert!(!calls().contains("fleet-clear"), "{}", calls());
        assert_eq!(calls().matches("fleet-sync").count(), 1, "{}", calls());

        // Only the server saying "none" takes the rules out.
        let (base, _) = canned_http(vec![down(), down(), json_reply(r#"{"policies":[]}"#)]);
        let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
        assert_eq!(snap.netpolicy_refresh_ok, Some(true));
        e.sync(&rt, true, &base);
        assert!(calls().ends_with("fleet-clear\t\n"), "{}", calls());
        assert_eq!(rt.enforcement().state, "none");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// #86. After a restart the snapshot holds no rows. A refresh whose deny-list fetch
    /// failed used to hand the exec gate that empty list all the same, which takes out
    /// the keys the gate loaded from disk at start. Only a list the API returned goes
    /// to the gate, and an empty one the API returned is such a list.
    #[test]
    fn a_failed_deny_list_fetch_hands_the_exec_gate_nothing() {
        let rt = Kub0Runtime::new();
        let agent = http_agent();
        let mut last_err = String::new();
        let down = || http_reply("500 Internal Server Error", "text/plain", "");
        let handed = vallumd::execgate::handed_on_this_thread;
        let before = handed();

        // The three requests are nodes, deny list, network policy, in that order.
        let unreachable = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        for base in [canned_http(vec![down(), down(), down()]).0, unreachable] {
            let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
            assert!(snap.denylist.is_empty());
            assert!(last_err.contains("denylist: "), "{last_err}");
            assert_eq!(handed(), before, "{base}: a failed fetch is not a list");
        }

        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let list = format!(
            r#"{{"version":7,"entries":[{{"comm":"sample","path":"/workspace/{digest}","action":"block"}}]}}"#
        );
        let (base, _) = canned_http(vec![down(), json_reply(&list), down()]);
        let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
        assert_eq!((snap.denylist.len(), snap.denylist_version), (1, 7));
        assert_eq!(handed(), before + 1, "the list the API returned goes to the gate");

        // A 200 with no `entries` is not a list: it must not read as an empty one.
        for body in ["{}", r#"{"detail":"not found"}"#] {
            let (base, _) = canned_http(vec![down(), json_reply(body), down()]);
            let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
            assert!(last_err.contains("without an entries field"), "{body}: {last_err}");
            assert!(snap.denylist.is_empty());
            assert_eq!(handed(), before + 1, "{body} is not the org's list");
        }

        for (n, empty) in [r#"{"version":8,"entries":[]}"#, r#"{"version":9,"entries":null}"#].into_iter().enumerate() {
            let (base, _) = canned_http(vec![down(), json_reply(empty), down()]);
            let snap = refresh_fleet(&agent, &base, "tok", "n", &rt, None, 0, &mut last_err, None);
            assert!(snap.denylist.is_empty());
            assert_eq!(handed(), before + 2 + n as u64, "{empty}: the org's list going to zero is an answer");
        }
    }

    #[test]
    fn enforcer_reapplies_when_the_kernel_lost_its_rules() {
        let dir = enforcer_dir("drift");
        let syncs = || helper_calls(&dir).matches("fleet-sync").count();
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.sync(&rt, true, "http://127.0.0.1:9");
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(syncs(), 1, "the kernel holds the plan");

        // `kub0-block teardown` (or an nftables reload) took the table out underneath.
        fake_kernel(&dir, Kernel::Empty);
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(syncs(), 2, "missing rules are re-applied: {}", helper_calls(&dir));
        assert_eq!((rt.enforcement().state.as_str(), rt.enforcement().enforcing), ("enforcing", true));
        assert!(e.drift.contains("missing"), "{}", e.drift);
        assert!(!e.note_drift(&e.drift.clone()), "rules that keep vanishing log once");
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(syncs(), 2);
        assert!(e.drift.is_empty(), "seen again, so a later loss logs again");
        assert!(e.note_drift("network-policy rules are missing from the kernel; re-applying"));
        e.drift.clear();

        // A kernel that cannot be read is not taken on trust, and not re-applied blind
        // through the same nft either: "cannot confirm", until it can be read again.
        std::fs::write(dir.join("nft-fail"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
        assert!(enf.reason.contains("cannot confirm") && enf.reason.contains("Operation not permitted"), "{}", enf.reason);
        assert_eq!(syncs(), 2);
        std::fs::remove_file(dir.join("nft-fail")).unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!((rt.enforcement().state.as_str(), rt.enforcement().enforcing), ("enforcing", true));
        assert_eq!(syncs(), 2, "the rules were there all along");

        // A wedged nft is killed, never waited on.
        std::fs::write(dir.join("nft-hang"), "").unwrap();
        e.read_timeout = Duration::from_millis(300);
        let started = Instant::now();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
        assert!(enf.reason.contains("did not answer within 300ms"), "{}", enf.reason);
        assert_eq!(syncs(), 2);
        std::fs::remove_file(dir.join("nft-hang")).unwrap();

        // Gone again, and re-applying fails: not enforcing, so nothing counts as blocked.
        fake_kernel(&dir, Kernel::Empty);
        std::fs::write(dir.join("fail-fleet-sync"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
        assert!(enf.rules.is_empty());
        rt.evaluate_connection("198.51.100.7", "", "", 1);
        let r = rt.drain_policy_matches();
        assert_eq!((r[0].would_block, r[0].blocked), (1, 0));

        // Every kernel read was the read-only chain listing; the root helper never read.
        assert!(nft_calls(&dir).lines().all(|l| l == "-a list chain inet vallum out"), "{}", nft_calls(&dir));
        assert!(!helper_calls(&dir).contains("status"), "{}", helper_calls(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforcer_reads_the_pause_from_the_kernel() {
        let dir = enforcer_dir("pause");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.sync(&rt, true, "http://127.0.0.1:9");
        let applied = (*rt.enforcement()).clone();
        assert!(applied.enforcing);

        // The panel paused vallum: its accept sits ahead of the fleet drops.
        fake_kernel(&dir, Kernel::Paused);
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing, enf.reason.as_str()), ("enforcing", false, PAUSED_REASON));
        assert_eq!((enf.rules.clone(), enf.entries), (applied.rules.clone(), applied.entries));

        fake_kernel(&dir, Kernel::Holds);
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(*rt.enforcement(), applied, "resumed");
        assert_eq!(helper_calls(&dir).matches("fleet-sync").count(), 1, "pausing is not a new plan");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforcer_clears_inherited_rules_once_the_policy_is_known() {
        let dir = enforcer_dir("inherited");
        let calls = || helper_calls(&dir);
        let rt = Kub0Runtime::new(); // a restarted kub0d: no policy fetched yet
        let mut e = test_enforcer(&dir, bundled_data());
        fake_kernel(&dir, Kernel::Holds);

        // The first fetch failed: an empty set here says nothing, and the previous
        // process's rules must stay rather than be cleared on a fetch error. Nor is that
        // "none": the kernel was read, and it holds them.
        for _ in 0..2 {
            e.sync(&rt, true, "http://127.0.0.1:9");
            assert!(calls().is_empty(), "{}", calls());
            assert_eq!(rt.enforcement().state, "error");
            assert!(rt.enforcement().reason.contains("left in place"), "{}", rt.enforcement().reason);
        }

        // The server answered with no block rules: the previous process's rules come out.
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(calls(), "fleet-clear\t\n");
        assert_eq!(rt.enforcement().state, "none");
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(calls(), "fleet-clear\t\n", "once");

        // A restart over a kernel that holds nothing is plainly "none", with nothing to clear.
        let mut fresh = test_enforcer(&dir, bundled_data());
        fresh.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none");
        fresh.policy_known = true;
        fresh.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(calls(), "fleet-clear\t\n", "nothing was there to clear");

        let reads = nft_calls(&dir);
        let mut user = test_enforcer(&dir, bundled_data());
        fake_kernel(&dir, Kernel::Holds);
        user.sync(&rt, false, "http://127.0.0.1:9");
        user.policy_known = true;
        user.sync(&rt, false, "http://127.0.0.1:9");
        assert_eq!(calls(), "fleet-clear\t\n", "a user-mode kub0d never runs the helper");
        assert_eq!(nft_calls(&dir), reads, "nor reads the kernel");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn diagnostics_retirement_does_not_change_failed_clear_replan() {
        for policies in [block_policies("monitor"), vallumd::netpolicy::PolicySet::default()] {
            let dir = enforcer_dir("retired-clear");
            let rt = runtime_with_asn();
            let mut e = test_enforcer(&dir, bundled_data());
            e.policy_known = true;
            rt.set_policies(block_policies("block"));
            e.sync(&rt, true, "http://127.0.0.1:9");
            let applied = rt.system_plan.lock().unwrap().applied_at;
            std::fs::write(dir.join("fail-fleet-clear"), "").unwrap();
            rt.set_policies(policies);
            e.sync(&rt, true, "http://127.0.0.1:9");
            e.retire_diagnostics(&rt);
            e.sync(&rt, true, "http://127.0.0.1:9");
            assert!(e.policy_known);
            assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 2);
            assert_eq!(rt.enforcement().state, "error");
            assert!(!rt.system_plan.lock().unwrap().known);
            assert_eq!(rt.system_plan.lock().unwrap().applied_at, applied);
            assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
            std::fs::remove_file(dir.join("fail-fleet-clear")).unwrap();
            e.sync(&rt, true, "http://127.0.0.1:9");
            assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 3);
            assert!(!rt.system_plan.lock().unwrap().known);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn enforcer_reports_a_failed_clear_as_an_error_not_none() {
        let dir = enforcer_dir("clearfail");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "enforcing");
        std::fs::write(dir.join("fail-fleet-clear"), "").unwrap();
        rt.set_policies(block_policies("monitor"));
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
        assert!(enf.reason.contains("may still be in the kernel"), "{}", enf.reason);
        // And it is tried again.
        std::fs::remove_file(dir.join("fail-fleet-clear")).unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none");
        assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failed_sync_still_lets_a_known_empty_policy_clear() {
        let dir = enforcer_dir("syncfail");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "enforcing");

        // The org changes its block list and the new transaction fails: nft keeps the
        // earlier sets, so the kernel still drops what the first sync put there.
        rt.set_policies(vallumd::netpolicy::parse(
            &serde_json::json!({"policies":[{"id":"p","name":"","mode":"block","version":2,"rules":[
                {"id":"r2","kind":"ip","action":"block","match":{"cidr":"203.0.113.0/24"}}]}]}),
            "",
        )
        .unwrap());
        std::fs::write(dir.join("fail-fleet-sync"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "error");
        assert!(dir.join("chain.txt").exists());

        // Then the server says there are none: those rules must still come out.
        rt.set_policies(vallumd::netpolicy::parse(&serde_json::json!({"policies":[]}), "").unwrap());
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert!(helper_calls(&dir).ends_with("fleet-clear\t\n"), "{}", helper_calls(&dir));
        assert!(!dir.join("chain.txt").exists());
        assert_eq!(rt.enforcement().state, "none");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// What the fake API does once, mid-request, before it answers the next netpolicy GET.
    type DuringGet = Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

    /// A kub0 API stand-in for whole heartbeat ticks: the heartbeat and the fleet reads
    /// answer 200, the netpolicy GET answers with whatever `netpolicy` holds at the time,
    /// and every netpolicy request is sent to `heads`.
    struct FakeKub0 {
        url: String,
        netpolicy: Arc<std::sync::Mutex<String>>,
        during: DuringGet,
        heads: std::sync::mpsc::Receiver<String>,
    }

    impl FakeKub0 {
        fn start() -> Self {
            use std::io::Write;
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            let netpolicy = Arc::new(std::sync::Mutex::new(String::new()));
            let during: DuringGet = Arc::default();
            let (np, hook, (tx, heads)) = (Arc::clone(&netpolicy), Arc::clone(&during), std::sync::mpsc::channel());
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let Ok(mut c) = c else { continue };
                    let req = read_request(&mut c);
                    let path = req.split_whitespace().nth(1).unwrap_or_default().to_string();
                    let reply = if path.starts_with("/detonate/api/enforce/netpolicy") {
                        tx.send(req).ok();
                        if let Some(f) = hook.lock().unwrap().take() {
                            f();
                        }
                        np.lock().unwrap().clone()
                    } else if path == "/api/nodes" {
                        json_reply(r#"{"nodes":[],"count":0,"node_limit":10}"#)
                    } else if path.starts_with("/detonate/api/enforce/denylist") {
                        json_reply(r#"{"version":1,"entries":[]}"#)
                    } else {
                        json_reply(r#"{"status":"ok"}"#)
                    };
                    c.write_all(reply.as_bytes()).ok();
                }
            });
            Self { url, netpolicy, during, heads }
        }

        fn netpolicy(&self, reply: String) {
            *self.netpolicy.lock().unwrap() = reply;
        }

        /// Run `f` while the next netpolicy GET is in flight.
        fn during_next_get(&self, f: impl FnOnce() + Send + 'static) {
            *self.during.lock().unwrap() = Some(Box::new(f));
        }

        fn last_head(&self) -> String {
            self.heads.try_iter().last().expect("no netpolicy request")
        }
    }

    fn set_account(path: &Path, server_url: &str, token: &str) {
        let account = kub0::AccountFile {
            schema: 1,
            token: token.into(),
            github_username: "fixture".into(),
            connected_at: 1,
            server_url: server_url.into(),
        };
        kub0::write_account(path, &account).unwrap();
    }

    /// A system kub0d's heartbeat thread, connected to a fake kub0, before its first tick.
    fn heartbeat_fixture(dir: &Path) -> (FakeKub0, Heartbeat, Arc<Kub0Runtime>) {
        // The override would send this test's heartbeats to a real server.
        assert!(std::env::var_os("KUB0_SERVER_URL").is_none(), "unset KUB0_SERVER_URL to run this test");
        let api = FakeKub0::start();
        api.netpolicy(http_reply("500 Internal Server Error", "text/plain", ""));
        let rt = runtime_with_asn();
        let account = dir.join("account.json");
        set_account(&account, &api.url, "tok-a");
        let mut hb = Heartbeat::new(account, dir.join("state"), Arc::clone(&rt), true, test_enforcer(dir, bundled_data()));
        // FakeKub0 answers one connection at a time; a long-lived stream would
        // sit in front of the netpolicy GETs these tests count.
        hb.stream_enabled = false;
        (api, hb, rt)
    }

    fn block_policy_reply() -> String {
        format!(
            "HTTP/1.1 200 OK\r\nETag: \"b1\"\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            body = BLOCK_POLICY_BODY,
            len = BLOCK_POLICY_BODY.len()
        )
    }

    const BLOCK_POLICY_BODY: &str = r#"{"policies":[{"id":"p","name":"Block C2","mode":"block","version":1,"rules":[{"id":"r","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}"#;

    #[test]
    fn heartbeat_only_a_policy_the_server_gave_clears_an_earlier_runs_rules() {
        let dir = enforcer_dir("tick-known");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        fake_kernel(&dir, Kernel::Holds); // an earlier run's rules

        // A fetch that fails says nothing about those rules, and neither does a 304 to a
        // request that had no ETag to be unchanged from.
        for reply in [
            http_reply("500 Internal Server Error", "text/plain", ""),
            http_reply("404 Not Found", "text/plain", ""),
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
        ] {
            api.netpolicy(reply);
            assert!(hb.tick());
            assert_eq!(rt.fleet_snapshot().netpolicy_refresh_ok, Some(false));
            assert_eq!(helper_calls(&dir), "", "nothing is cleared on a failed fetch");
            let enf = rt.fleet_snapshot().netpolicy_enforcement;
            assert_eq!(enf.state, "error");
            assert!(enf.reason.contains("left in place"), "{}", enf.reason);
        }
        assert!(dir.join("chain.txt").exists());

        // The server says there are none: now they come out.
        api.netpolicy(json_reply(r#"{"policies":[]}"#));
        assert!(hb.tick());
        assert_eq!(rt.fleet_snapshot().netpolicy_refresh_ok, Some(true));
        assert_eq!(helper_calls(&dir), "fleet-clear\t\n");
        assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "none");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn heartbeat_counts_a_304_of_a_received_set_as_an_answer() {
        let dir = enforcer_dir("tick-304");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        fake_kernel(&dir, Kernel::Holds);
        // This account's empty set, already received with its ETag, and nothing yet known
        // to the enforcer: only the wiring from the 304 can make it an answer.
        hb.prior_account = kub0::read_account(&hb.account_path);
        rt.set_policies(vallumd::netpolicy::parse(&serde_json::json!({"policies":[]}), "\"e1\"").unwrap());
        api.netpolicy("HTTP/1.1 304 Not Modified\r\nETag: \"e1\"\r\nConnection: close\r\n\r\n".into());
        assert!(hb.tick());
        assert!(api.last_head().to_ascii_lowercase().contains("if-none-match: \"e1\""));
        assert_eq!(rt.fleet_snapshot().netpolicy_refresh_ok, Some(true));
        assert_eq!(helper_calls(&dir), "fleet-clear\t\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn heartbeat_account_change_keeps_the_kernel_until_the_new_account_is_answered() {
        let dir = enforcer_dir("tick-account");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        api.netpolicy(block_policy_reply());
        assert!(hb.tick());
        assert!(helper_calls(&dir).starts_with("fleet-sync\t"));
        assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "enforcing");

        let applied = rt.system_plan.lock().unwrap().applied_at;
        assert!(applied > 0);
        assert!(rt.system_plan.lock().unwrap().known);
        // Same-account refresh failure keeps the known plan and acknowledgement.
        api.netpolicy(http_reply("503 Service Unavailable", "text/plain", ""));
        assert!(hb.tick());
        {
            let plan = rt.system_plan.lock().unwrap();
            assert!(plan.known);
            assert_eq!(plan.applied_at, applied);
            assert_eq!(plan.refresh_ok, Some(false));
        }

        // The token rotates and the new account's first fetch fails.
        set_account(&hb.account_path, &api.url, "tok-b");
        let during_rt = Arc::clone(&rt);
        api.during_next_get(move || {
            let plan = during_rt.system_plan.lock().unwrap();
            assert!(
                !plan.known,
                "account adoption must become unknown before the response"
            );
            assert_eq!(plan.applied_at, applied);
        });
        api.netpolicy(http_reply("503 Service Unavailable", "text/plain", ""));
        assert!(hb.tick());
        assert!(!api.last_head().to_ascii_lowercase().contains("if-none-match"), "the old org's ETag is not reused");
        assert!(!helper_calls(&dir).contains("fleet-clear"), "{}", helper_calls(&dir));
        assert!(dir.join("chain.txt").exists(), "the rules stay in the kernel");
        let snap = rt.fleet_snapshot();
        assert_eq!(snap.netpolicy_refresh_ok, Some(false));
        assert!(snap.netpolicies.is_empty());
        {
            let plan = rt.system_plan.lock().unwrap();
            assert!(!plan.known);
            assert_eq!(plan.applied_at, applied);
            assert_eq!(plan.refresh_ok, Some(false));
        }
        assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
        assert_eq!((snap.netpolicy_enforcement.state.as_str(), snap.netpolicy_enforcement.enforcing), ("error", false));
        assert!(snap.netpolicy_enforcement.reason.contains("left in place"), "{}", snap.netpolicy_enforcement.reason);

        // The new account's server says there are none.
        api.netpolicy(json_reply(r#"{"policies":[]}"#));
        assert!(hb.tick());
        assert!(helper_calls(&dir).ends_with("fleet-clear\t\n"), "{}", helper_calls(&dir));
        assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "none");
        { let plan = rt.system_plan.lock().unwrap();
          assert!(plan.known); assert_eq!(plan.applied_at, applied);
          assert_eq!(plan.refresh_ok, Some(true)); }
        assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn heartbeat_unreadable_account_keeps_the_kernel_and_a_missing_one_clears_it() {
        let dir = enforcer_dir("tick-unreadable");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        api.netpolicy(block_policy_reply());
        assert!(hb.tick());
        let enforcing = (*rt.enforcement()).clone();
        assert_eq!(enforcing.state, "enforcing");

        // Caught between connect's truncate and its write, then unreadable outright.
        std::fs::write(&hb.account_path, "").unwrap();
        assert!(hb.tick());
        assert!(hb.last_account_err.contains("cannot parse"), "{}", hb.last_account_err);
        std::fs::remove_file(&hb.account_path).unwrap();
        std::fs::create_dir(&hb.account_path).unwrap();
        assert!(hb.tick());
        assert!(hb.last_account_err.contains("cannot read"), "{}", hb.last_account_err);
        assert!(!helper_calls(&dir).contains("fleet-clear"), "{}", helper_calls(&dir));
        assert!(rt.policies().has_effective_block(), "the last policy received still stands");
        assert_eq!(*rt.enforcement(), enforcing);

        // Absent is a local disconnect: the rules come out and the thread ends.
        std::fs::remove_dir(&hb.account_path).unwrap();
        assert!(!hb.tick());
        assert!(helper_calls(&dir).ends_with("fleet-clear\t\n"), "{}", helper_calls(&dir));
        assert!(!rt.fleet_snapshot().connected);
        {
            let plan = rt.system_plan.lock().unwrap();
            assert!(plan.known);
            assert_eq!(plan.applied_at, enforcing.applied_ts);
            assert_eq!(plan.refresh_ok, None);
        }
        assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn diagnostics_late_account_change_preserves_clear_retry_and_resets() {
        for removal in [false, true] {
            let dir = enforcer_dir(if removal { "late-remove" } else { "late-replace" });
            let (api, mut hb, rt) = heartbeat_fixture(&dir);
            api.netpolicy(block_policy_reply());
            assert!(hb.tick());
            let applied = rt.system_plan.lock().unwrap().applied_at;
            std::fs::write(dir.join("fail-fleet-clear"), "").unwrap();
            api.netpolicy(json_reply(r#"{"policies":[]}"#));
            let (path, url) = (hb.account_path.clone(), api.url.clone());
            api.during_next_get(move || {
                if removal { std::fs::remove_file(&path).unwrap(); }
                else { set_account(&path, &url, "tok-b"); }
            });
            assert!(hb.tick());
            assert!(hb.enforcer.policy_known, "late check must preserve the clear gate");
            assert!(!rt.system_plan.lock().unwrap().known);
            // The same sync used by a between-heartbeat resume/replan retries clear.
            hb.enforcer.sync(&rt, true, &api.url);
            assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 2);
            assert_eq!(rt.enforcement().state, "error");
            assert_eq!(rt.system_plan.lock().unwrap().applied_at, applied);
            assert!(!rt.system_plan.lock().unwrap().known);
            assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
            std::fs::remove_file(dir.join("fail-fleet-clear")).unwrap();
            api.netpolicy(http_reply("503 Service Unavailable", "text/plain", ""));
            assert_eq!(hb.tick(), !removal);
            let plan = rt.system_plan.lock().unwrap();
            assert!(!plan.account_retired);
            assert_eq!(plan.known, removal, "new account pending is unknown; disconnect is known");
            drop(plan);
            if !removal {
                api.netpolicy(json_reply(r#"{"policies":[]}"#));
                assert!(hb.tick());
                assert!(rt.system_plan.lock().unwrap().known);
            }
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn heartbeat_disconnect_retries_a_failed_clear_and_says_so() {
        let dir = enforcer_dir("tick-disconnect");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        api.netpolicy(block_policy_reply());
        assert!(hb.tick());
        let applied = rt.system_plan.lock().unwrap().applied_at;
        std::fs::write(dir.join("fail-fleet-clear"), "").unwrap();
        kub0::disconnect_account(&hb.account_path).unwrap();
        assert!(hb.tick(), "the thread stays to try again");
        {
            let plan = rt.system_plan.lock().unwrap();
            assert!(plan.known);
            assert_eq!(plan.applied_at, applied);
            assert_eq!(plan.refresh_ok, None);
        }
        assert_eq!(system_snapshot(&rt).current_kernel_verification, "unknown");
        let snap = rt.fleet_snapshot();
        assert!(!snap.connected);
        assert_eq!(snap.netpolicy_enforcement.state, "error");
        assert!(snap.netpolicy_enforcement.reason.contains("may still be in the kernel"), "{}", snap.netpolicy_enforcement.reason);

        std::fs::remove_file(dir.join("fail-fleet-clear")).unwrap();
        assert!(!hb.tick(), "done once the rules are out");
        assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 2);
        assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn daemon_fleet_rule_check_matches_the_helper() {
        let helper = include_str!("../../helper/src/main.rs");
        let fleet = include_str!("../../helper/src/fleet.rs");
        let pause = include_str!("../../helper/src/pause.rs");
        for (src, decl) in [
            (helper, format!("const TABLE: &str = \"{NFT_TABLE}\";")),
            (helper, format!(".args([\"-a\", \"list\", \"chain\", \"inet\", TABLE, \"{NFT_CHAIN}\"])")),
            (helper, format!("const SAFE_PATH: &str = \"{NFT_SEARCH_PATH}\";")),
            (fleet, format!("pub const FLEET_COMMENT: &str = \"{FLEET_COMMENT}\";")),
            (fleet, r#"pub const SET4: &str = "fleet4";"#.to_string()),
            (fleet, r#"pub const SET6: &str = "fleet6";"#.to_string()),
            (pause, format!("pub const PAUSE_COMMENT: &str = \"{PAUSE_COMMENT}\";")),
        ] {
            assert!(src.contains(&decl), "kub0-block's fleet rule changed: {decl}");
        }
        let present = |paused| FleetRules::Present { paused };
        assert_eq!(fleet_rules_in(&fleet_chain(false)), present(false));
        assert_eq!(fleet_rules_in(&fleet_chain(true)), present(true));
        // fleet-sync's own `rules_present` listing (no table header).
        let chain = "chain out { # handle 1\n\t\tip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 drop comment \"vallum-fleet\" # handle 12\n\t\tip6 daddr @fleet6 ip6 daddr != @fleetkeep6 counter packets 0 bytes 0 drop comment \"vallum-fleet\" # handle 13\n}";
        assert_eq!(fleet_rules_in(chain), present(false));
        let listing = fleet_chain(false);
        let v4 = "ip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 drop comment \"vallum-fleet\"";
        let v6 = "ip6 daddr @fleet6 ip6 daddr != @fleetkeep6 counter packets 0 bytes 0 drop comment \"vallum-fleet\"";
        // Not a v4 fleet drop, so only the v6 one is there: still a rule that drops.
        for (near, why) in [
            (String::new(), "one family's rule is gone"),
            ("ip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 drop".to_string(), "not vallum's rule"),
            ("ip daddr @fleet4 ip daddr != @fleetkeep4 counter packets 0 bytes 0 accept comment \"vallum-fleet\"".to_string(), "not a drop"),
            ("ip daddr @fleetkeep4 counter packets 0 bytes 0 drop comment \"vallum-fleet\"".to_string(), "the keep set is not the block set"),
        ] {
            assert_eq!(fleet_rules_in(&listing.replace(v4, &near)), FleetRules::Partial, "{why}");
        }
        assert_eq!(fleet_rules_in(&listing.replace(v6, "")), FleetRules::Partial, "the v4 one alone");
        assert_eq!(fleet_rules_in(&fleet_chain(true).replace(v6, "")), FleetRules::Partial, "paused or not");
        assert_eq!(fleet_rules_in(&listing.replace(v4, "").replace(v6, "")), FleetRules::Absent);
        // A pause rule below the fleet drops does not pause them, and only an accept pauses.
        let below = listing.replace("\t}\n}", "\t\taccept comment \"vallum-paused\" # handle 9\n\t}\n}");
        assert_eq!(fleet_rules_in(&below), present(false));
        let drop_ahead = listing.replace("policy accept;\n", "policy accept;\n\t\tdrop comment \"vallum-paused\" # handle 9\n");
        assert_eq!(fleet_rules_in(&drop_ahead), present(false));
        assert_eq!(fleet_rules_in(""), FleetRules::Absent);
    }

    /// The chain with one family's fleet drop rule and not the other's: a clear or a sync
    /// cut short between the two.
    fn one_family_chain(keep: &str) -> String {
        let gone = if keep == "fleet6" { "@fleet4 " } else { "@fleet6 " };
        fleet_chain(false).lines().filter(|l| !l.contains(gone)).map(|l| format!("{l}\n")).collect()
    }

    /// A policy set this build cannot read in full is a failed fetch, never fewer block
    /// rules: read loosely, a mode word it did not know was a monitor policy, and a
    /// policy with no id was skipped, and either one cleared every block.
    #[test]
    fn heartbeat_refuses_a_policy_set_it_cannot_read_and_a_monitor_only_one_clears() {
        let dir = enforcer_dir("tick-unread-set");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        api.netpolicy(block_policy_reply());
        assert!(hb.tick());
        assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "enforcing");
        let synced = helper_calls(&dir);
        // A new block list, readable on its own: had it been taken, it would have synced.
        let other = r#"{"id":"p","name":"","mode":"block","version":2,"rules":[{"id":"r2","kind":"ip","action":"block","match":{"cidr":"203.0.113.0/24"}}]}"#;
        let rule = |action: &str, kind: &str| {
            format!(r#"{{"policies":[{{"id":"p","name":"","mode":"block","version":2,"rules":[{{"id":"r2","kind":"{kind}","action":"{action}","match":{{"cidr":"203.0.113.0/24"}}}}]}}]}}"#)
        };
        for (body, want) in [
            (r#"{"policies":[{"id":"p","name":"","mode":"enforce","version":2,"rules":[{"id":"r","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}"#.to_string(), r#"netpolicy: policy 0 ("p") has a mode this kub0d does not know"#),
            (r#"{"policies":[{"policy_id":"p","name":"","mode":"block","version":2,"rules":[]}]}"#.to_string(), "netpolicy: policy 0 has no id"),
            (format!(r#"{{"policies":[{other},{{"id":"q","name":"","mode":"enforce","version":1,"rules":[]}}]}}"#), r#"policy 1 ("q") has a mode"#),
            (format!(r#"{{"policies":[{other},{{"name":"","mode":"monitor","version":1,"rules":[]}}]}}"#), "policy 1 has no id"),
            (rule("deny", "ip"), r#"rule 0 ("r2") has an action this kub0d does not know"#),
            (rule("block", "cidr"), r#"rule 0 ("r2") blocks with a match this kub0d cannot read"#),
        ] {
            api.netpolicy(json_reply(&body));
            assert!(hb.tick());
            let snap = rt.fleet_snapshot();
            assert_eq!(snap.netpolicy_refresh_ok, Some(false), "{body}");
            assert!(hb.last_fleet_err.contains(want), "{want}: {}", hb.last_fleet_err);
            for value in ["enforce\"", "deny", "cidr", "203.0.113", "tok-a"] {
                assert!(!hb.last_fleet_err.contains(value), "the log names where, never what: {}", hb.last_fleet_err);
            }
            assert_eq!(helper_calls(&dir), synced, "neither cleared nor replaced: {body}");
            assert!(dir.join("chain.txt").exists());
            let kept = rt.policies();
            assert_eq!((kept.policies.len(), kept.policies[0].rules[0].id.as_str()), (1, "r"), "the last set received stands");
            assert_eq!(snap.netpolicies.len(), 1);
            assert_eq!((snap.netpolicy_enforcement.state.as_str(), snap.netpolicy_enforcement.enforcing), ("enforcing", true));
        }

        // Read in full and blocking nothing: the org switched to monitor, so they come out.
        api.netpolicy(json_reply(
            r#"{"policies":[{"id":"p","name":"","mode":"monitor","version":3,"rules":[{"id":"r","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}},{"id":"r3","kind":"domain","action":"monitor","match":{"name":"x"}}]}]}"#,
        ));
        assert!(hb.tick());
        let snap = rt.fleet_snapshot();
        assert_eq!(snap.netpolicy_refresh_ok, Some(true));
        assert_eq!(snap.netpolicies[0].rules.len(), 2);
        assert!(helper_calls(&dir).ends_with("fleet-clear\t\n"), "{}", helper_calls(&dir));
        assert_eq!(snap.netpolicy_enforcement.state, "none");
        assert!(!dir.join("chain.txt").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The country analog of the ASN gate. A country block rule with no database to give
    /// it ranges makes a plan short of the one applied, and syncing it would take the
    /// country's blocks out of the kernel on a local fault, not on the org's word.
    #[test]
    fn enforcer_applies_nothing_without_the_country_database_and_leaves_the_kernel_alone() {
        let country_policy = || {
            vallumd::netpolicy::parse(
                &serde_json::json!({"policies":[{"id":"p","name":"","mode":"block","user_can_snooze":"all","version":1,"rules":[
                    {"id":"r-kp","kind":"country","action":"block","match":{"countries":["KP"]}},
                    {"id":"r","kind":"ip","action":"block","match":{"cidr":"198.51.100.0/24"}}]}]}),
                "",
            )
            .unwrap()
        };
        // Country databases small enough to build here (walking the bundled one takes half
        // a minute in a debug build): one that places all of IPv4 in KP, and the same file
        // holding an ASN record instead, which opens fine and knows no country.
        let country = b"\xE1\x47country\xE1\x48iso_code\x42KP".to_vec();
        let asn_record = [b"\xE1\x58autonomous_system_number\xC2".as_slice(), &13335u16.to_be_bytes()].concat();
        let data_dir = |name: &str, record: &[u8]| {
            let d = enforcer_dir(name);
            std::fs::create_dir_all(d.join("geoip")).unwrap();
            tiny_mmdb(&d.join("geoip/dbip-country-lite.mmdb"), record);
            d
        };
        let dir = enforcer_dir("nocountry");
        let data = data_dir("nocountry-data", &country);
        let rt = runtime_with_asn();
        rt.set_policies(country_policy());
        let mut e = test_enforcer(&dir, data.clone());
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing, enf.entries), ("enforcing", true, 2), "{enf:?}");
        assert!(enf.rules.contains("r-kp"));
        let synced = helper_calls(&dir);
        assert!(synced.contains("128.0.0.0/1"), "the country's range went in: {synced}");

        // Restarted with no database in its data dir (the ASN one was loaded at boot), or
        // with one of the wrong kind there.
        let wrong = data_dir("nocountry-wrong", &asn_record);
        for data in [PathBuf::from("/nonexistent"), wrong.clone()] {
            let mut restarted = test_enforcer(&dir, data.clone());
            restarted.policy_known = true;
            for _ in 0..2 {
                restarted.sync(&rt, true, "http://127.0.0.1:9");
                let enf = rt.enforcement();
                assert_eq!((enf.state.as_str(), enf.enforcing), ("error", false));
                let db = format!("{}/geoip/dbip-country-lite.mmdb", data.display());
                let at = format!("data dir {}", data.display());
                for want in ["country database", &db, &at, "missing or holds no countries", "left in place", "restart kub0d"] {
                    assert!(enf.reason.contains(want), "{want}: {}", enf.reason);
                }
                assert_eq!(helper_calls(&dir), synced, "no new block set without the country's ranges, and no clear");
                assert!(dir.join("chain.txt").exists());
            }
            // Snoozed, the country rule is out of the plan on the user's word: the rest syncs.
            rt.snooze_rule("r-kp", 3600).unwrap();
            restarted.sync(&rt, true, "http://127.0.0.1:9");
            assert_eq!(rt.enforcement().state, "enforcing", "{}", rt.enforcement().reason);
            assert_eq!(helper_calls(&dir).matches("fleet-sync").count(), 2, "{}", helper_calls(&dir));
            rt.resume_rule("r-kp");
            std::fs::write(dir.join("calls.log"), &synced).unwrap();
        }
        for d in [dir, data, wrong] {
            std::fs::remove_dir_all(d).ok();
        }
    }

    /// One family's drop rule left behind still drops: it is held, not "none", and it
    /// comes out once the server says there are none. Before, only both families counted,
    /// so a remnant read as "none" and nothing ever cleared it.
    #[test]
    fn heartbeat_clears_a_one_family_remnant_once_the_server_says_none() {
        for keep in ["fleet6", "fleet4"] {
            let dir = enforcer_dir(&format!("tick-remnant-{keep}"));
            let (api, mut hb, rt) = heartbeat_fixture(&dir);
            std::fs::write(dir.join("chain.txt"), one_family_chain(keep)).unwrap();
            assert!(hb.tick(), "the first fetch fails");
            assert_eq!(helper_calls(&dir), "");
            let enf = rt.fleet_snapshot().netpolicy_enforcement;
            assert_eq!(enf.state, "error", "{keep}");
            assert!(enf.reason.contains("left in place"), "{}", enf.reason);
            assert!(hb.enforcer.stray);

            api.netpolicy(json_reply(r#"{"policies":[]}"#));
            assert!(hb.tick());
            assert_eq!(helper_calls(&dir), "fleet-clear\t\n", "{keep}");
            assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "none");
            assert!(!dir.join("chain.txt").exists());
            std::fs::remove_dir_all(&dir).ok();
        }

        // Over rules it applied, a family gone missing is re-applied like both.
        let dir = enforcer_dir("remnant-drift");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.sync(&rt, true, "http://127.0.0.1:9");
        std::fs::write(dir.join("chain.txt"), one_family_chain("fleet4")).unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(helper_calls(&dir).matches("fleet-sync").count(), 2, "{}", helper_calls(&dir));
        assert_eq!((rt.enforcement().state.as_str(), rt.enforcement().enforcing), ("enforcing", true));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Only nft's own "no such table or chain" reads as an empty kernel. A loader that
    /// cannot find libnftables says "No such file or directory" too.
    #[test]
    fn kernel_read_takes_absent_only_on_nfts_word() {
        let dir = enforcer_dir("nft-enoent");
        let diag = "Error: No such file or directory\\nlist chain inet vallum out\\n                ^^^^^^";
        let loader = "nft: error while loading shared libraries: libnftables.so.1: cannot open shared object file: No such file or directory";
        for (name, body, absent) in [
            ("nft-gone", format!("printf '{diag}\\n' >&2; exit 1"), true),
            ("nft-loader", format!("echo '{loader}' >&2; exit 127"), false),
            ("nft-127", format!("printf '{diag}\\n' >&2; exit 127"), false),
            ("nft-signal", format!("printf '{diag}\\n' >&2; kill -9 $$"), false),
            ("nft-other", "printf 'Error: No such file or directory\\nlist table inet other\\n' >&2; exit 1".to_string(), false),
            ("nft-eperm", "echo 'Error: Could not receive tables from kernel: Operation not permitted' >&2; exit 1".to_string(), false),
        ] {
            let bin = dir.join(name);
            install_script(&bin, &format!("#!/bin/sh\n[ \"$1\" = probe ] && exit 0\n{body}\n"));
            let read = read_fleet_chain(&bin, Duration::from_secs(5));
            if absent {
                assert_eq!(read, Ok(String::new()), "{name}");
            } else {
                assert!(read.is_err(), "{name}: {read:?}");
            }
        }
        assert!(read_fleet_chain(&dir.join("no-such-nft"), Duration::from_secs(5)).unwrap_err().starts_with("nft: "));

        // A restart whose nft cannot load: what the kernel holds is unknown, so it is not
        // "none", and the rules stay to be cleared later.
        let rt = Kub0Runtime::new();
        let mut e = test_enforcer(&dir, bundled_data());
        e.nft = dir.join("nft-loader");
        fake_kernel(&dir, Kernel::Holds);
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "error");
        assert!(rt.enforcement().reason.contains("loading shared libraries"), "{}", rt.enforcement().reason);
        assert!(e.stray);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An account file caught mid-write at the end of a tick is not a disconnect: the
    /// frame stays this tick's, the kernel stays, and a tick that cannot read it at the
    /// start says the heartbeat did not go.
    #[test]
    fn heartbeat_account_unreadable_mid_tick_is_not_a_disconnect() {
        let dir = enforcer_dir("tick-midwrite");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        api.netpolicy(block_policy_reply());
        assert!(hb.tick());
        assert_eq!(rt.hello_account().last_heartbeat_ok, Some(true));
        let synced = helper_calls(&dir);

        // connect truncates the file while this tick's netpolicy GET is in flight, and
        // the server has a new list.
        let path = hb.account_path.clone();
        api.during_next_get(move || std::fs::write(&path, "").unwrap());
        let body = r#"{"policies":[{"id":"p","name":"","mode":"block","version":2,"rules":[{"id":"r2","kind":"ip","action":"block","match":{"cidr":"203.0.113.0/24"}}]}]}"#;
        api.netpolicy(json_reply(body));
        assert!(hb.tick());
        let snap = rt.fleet_snapshot();
        assert!(snap.connected, "an unreadable file is not a disconnect");
        assert_eq!(snap.netpolicy_refresh_ok, Some(true));
        assert_eq!(snap.netpolicies[0].rules[0].id, "r2", "this tick's frame");
        assert_eq!((snap.netpolicy_enforcement.state.as_str(), snap.netpolicy_enforcement.enforcing), ("enforcing", true));
        assert!(hb.last_account_err.contains("cannot parse"), "{}", hb.last_account_err);
        assert!(!hb.account_unreadable(hb.last_account_err.clone()), "the same error logs once");
        assert!(!helper_calls(&dir).contains("fleet-clear"), "{}", helper_calls(&dir));
        assert!(helper_calls(&dir).len() > synced.len(), "the new list was applied");

        // Still unreadable at the next tick's start: no heartbeat goes, and the panel's
        // hello frame says so, still connected.
        assert!(hb.tick());
        let hello = rt.hello_account();
        assert_eq!((hello.connected, hello.last_heartbeat_ok), (true, Some(false)));
        assert!(rt.fleet_snapshot().connected);
        assert!(dir.join("chain.txt").exists());

        // Readable again; then replaced by another account mid-tick: that frame is not
        // the new account's, so it goes out empty, and the new account starts unanswered.
        set_account(&hb.account_path, &api.url, "tok-a");
        assert!(hb.tick());
        assert_eq!(rt.hello_account().last_heartbeat_ok, Some(true));
        assert!(hb.last_account_err.is_empty(), "read again, so the next failure logs again");
        let (path, url) = (hb.account_path.clone(), api.url.clone());
        api.during_next_get(move || set_account(&path, &url, "tok-b"));
        assert!(hb.tick());
        assert!(!rt.fleet_snapshot().connected);
        assert!(!helper_calls(&dir).contains("fleet-clear"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The documented way out for a revoked host is a local disconnect, and it works
    /// before any policy has arrived: every fetch refused since a restart, rules an earlier
    /// run left in the kernel, and the account file removed.
    #[test]
    fn heartbeat_disconnect_clears_rules_no_policy_has_vouched_for() {
        let dir = enforcer_dir("tick-revoked");
        let (api, mut hb, rt) = heartbeat_fixture(&dir);
        fake_kernel(&dir, Kernel::Holds);
        api.netpolicy(http_reply("401 Unauthorized", "application/json", r#"{"error":"revoked"}"#));
        for _ in 0..2 {
            assert!(hb.tick());
            assert_eq!(helper_calls(&dir), "");
            assert_eq!(rt.fleet_snapshot().netpolicy_enforcement.state, "error");
        }
        assert!(!hb.enforcer.policy_known);
        kub0::disconnect_account(&hb.account_path).unwrap();
        assert!(!hb.tick(), "a local disconnect ends the thread once the rules are out");
        assert_eq!(helper_calls(&dir), "fleet-clear\t\n");
        assert!(!dir.join("chain.txt").exists());
        assert!(!rt.fleet_snapshot().connected);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A kernel that cannot be read is not an empty one: before a policy arrives the
    /// rules there may still be live, so the state is an error, they stay marked as
    /// possibly held, and a later "none" from the server still takes them out.
    #[test]
    fn enforcer_an_unreadable_kernel_is_not_an_empty_one() {
        let dir = enforcer_dir("unreadable-kernel");
        let rt = Kub0Runtime::new();
        let mut e = test_enforcer(&dir, bundled_data());
        fake_kernel(&dir, Kernel::Holds);
        std::fs::write(dir.join("nft-fail"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!(enf.state, "error");
        assert!(enf.reason.contains("cannot be read") && enf.reason.contains("Operation not permitted"), "{}", enf.reason);
        assert!(e.stray);
        std::fs::remove_file(dir.join("nft-fail")).unwrap();
        std::fs::write(dir.join("nft-hang"), "").unwrap();
        e.read_timeout = Duration::from_millis(300);
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert!(rt.enforcement().reason.contains("did not answer"), "{}", rt.enforcement().reason);
        assert!(e.stray);
        std::fs::remove_file(dir.join("nft-hang")).unwrap();
        assert_eq!(helper_calls(&dir), "");

        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(helper_calls(&dir), "fleet-clear\t\n");
        assert_eq!(rt.enforcement().state, "none");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Until an account's policy arrives the state says what the kernel holds now, read,
    /// not what this kub0d once put there; only a read that fails falls back on that.
    #[test]
    fn enforcer_reads_the_kernel_before_saying_what_an_unanswered_account_holds() {
        let dir = enforcer_dir("unanswered-read");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "enforcing");

        // A new account, nothing received for it yet.
        rt.set_policies(vallumd::netpolicy::PolicySet::default());
        e.policy_known = false;
        let reads = nft_calls(&dir).lines().count();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(nft_calls(&dir).lines().count(), reads + 1, "read, not assumed");
        assert_eq!(rt.enforcement().state, "error");
        assert!(rt.enforcement().reason.contains("left in place"), "{}", rt.enforcement().reason);

        // A teardown took them out: that is what the state says.
        fake_kernel(&dir, Kernel::Empty);
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none", "{}", rt.enforcement().reason);

        // Unreadable: what it put there is assumed still there.
        std::fs::write(dir.join("nft-fail"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "error");
        assert!(rt.enforcement().reason.contains("cannot be read"), "{}", rt.enforcement().reason);
        assert!(!helper_calls(&dir).contains("fleet-clear"), "{}", helper_calls(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// fleet-sync says whether the panel's pause was on when it applied: paused rules are
    /// not enforcing, and nothing they match counts as blocked.
    #[test]
    fn enforcer_reports_the_pause_fleet_sync_found() {
        let dir = enforcer_dir("sync-paused");
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        std::fs::write(dir.join("reply-paused"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!((enf.state.as_str(), enf.enforcing, enf.reason.as_str()), ("enforcing", false, PAUSED_REASON));
        assert!(enf.rules.contains("r"));
        rt.evaluate_connection("198.51.100.7", "", "", 1);
        let r = rt.drain_policy_matches();
        assert_eq!((r[0].would_block, r[0].blocked), (1, 0));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A fleet-sync that fails may have replaced the sets before it failed (the pause
    /// reconcile or the re-list after the transaction), so what the kernel holds is not
    /// the earlier plan any more: going back to that plan syncs it again.
    #[test]
    fn a_failed_sync_leaves_the_sets_unknown_so_a_revert_resyncs() {
        let dir = enforcer_dir("revert");
        let syncs = || helper_calls(&dir).matches("fleet-sync").count();
        let rt = runtime_with_asn();
        rt.set_policies(block_policies("block"));
        let mut e = test_enforcer(&dir, bundled_data());
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(syncs(), 1);
        rt.set_policies(vallumd::netpolicy::parse(
            &serde_json::json!({"policies":[{"id":"p","name":"","mode":"block","version":2,"rules":[
                {"id":"r2","kind":"ip","action":"block","match":{"cidr":"203.0.113.0/24"}}]}]}),
            "",
        )
        .unwrap());
        std::fs::write(dir.join("fail-fleet-sync"), "").unwrap();
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!((syncs(), rt.enforcement().state.as_str()), (2, "error"));
        std::fs::remove_file(dir.join("fail-fleet-sync")).unwrap();
        rt.set_policies(block_policies("block"));
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(syncs(), 3, "re-synced, not taken as unchanged");
        assert_eq!(rt.enforcement().state, "enforcing");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The kernel read runs nft on kub0-block's PATH with a C locale (the absent check
    /// reads nft's English), and a wedged one is killed and reaped: not one zombie per
    /// heartbeat. The bound is well inside the shortest heartbeat.
    #[test]
    fn kernel_read_pins_its_environment_and_reaps_a_wedged_nft() {
        let dir = enforcer_dir("nft-env");
        let d = dir.display();
        let bin = dir.join("nft");
        install_script(&bin, &format!("#!/bin/sh\n[ \"$1\" = probe ] && exit 0\necho \"PATH=$PATH LC_ALL=$LC_ALL\" > '{d}/env.log'\n"));
        assert_eq!(read_fleet_chain(&bin, Duration::from_secs(5)), Ok(String::new()));
        let env = std::fs::read_to_string(dir.join("env.log")).unwrap();
        assert_eq!(env.trim(), format!("PATH={NFT_SEARCH_PATH} LC_ALL=C"));

        let wedged = dir.join("nft-wedged");
        install_script(&wedged, &format!("#!/bin/sh\n[ \"$1\" = probe ] && exit 0\necho $$ > '{d}/pid'\nexec sleep 30\n"));
        let err = read_fleet_chain(&wedged, Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("did not answer within 1s"), "{err}");
        let pid = std::fs::read_to_string(dir.join("pid")).expect("the wedged nft ran");
        let proc_dir = PathBuf::from(format!("/proc/{}", pid.trim()));
        let stat = std::fs::read_to_string(proc_dir.join("stat")).unwrap_or_default();
        assert!(!proc_dir.exists(), "killed and reaped, not left a zombie: {stat}");

        assert_eq!(KERNEL_READ_TIMEOUT, Duration::from_secs(10));
        assert!(KERNEL_READ_TIMEOUT < Duration::from_secs(kub0::HEARTBEAT_INTERVAL_MIN_SECS));
        assert_eq!(Enforcer::new(bundled_data(), PathBuf::from(HELPER_PATH)).read_timeout, KERNEL_READ_TIMEOUT);
        std::fs::remove_dir_all(&dir).ok();
    }

    // -- step 1a: the group raises, root lowers ---------------------------

    #[test]
    fn the_system_command_socket_is_group_owned_when_the_status_group_resolves() {
        assert_eq!(command_socket_gid(DaemonMode::System, || Ok(981)), (981, None));
        let (gid, why) = command_socket_gid(DaemonMode::System, || Err(std::io::Error::other("no kub0")));
        assert_eq!(gid, 0, "a missing or invalid group keeps root:root");
        let why = why.expect("the fallback is logged");
        assert!(why.contains("root:root 0660") && why.contains("no kub0"), "{why}");
        let (gid, why) = command_socket_gid(DaemonMode::System, || Ok(0));
        assert_eq!(gid, 0);
        assert!(why.is_some());
        assert_eq!(
            command_socket_gid(DaemonMode::User, || panic!("the user socket has no group")),
            (0, None)
        );
    }

    fn dest_req(v: serde_json::Value) -> vallumd::control::Request {
        let mut v = v;
        v["req"] = "1".into();
        vallumd::control::Request::parse(&v.to_string()).unwrap()
    }

    #[test]
    fn block_dest_runs_the_helpers_block_scoped_with_its_durations_only() {
        let ok = dest_req(serde_json::json!({"cmd":"block-dest","app":"firefox","ip":"203.0.113.9","seconds":900,"pids":["4242","4243"]}));
        assert_eq!(
            helper_argv(&ok).unwrap(),
            ["block-scoped", "firefox", "203.0.113.9", "900", "4242", "4243"]
        );
        let v6 = dest_req(serde_json::json!({"cmd":"block-dest","app":"firefox","ip":"2001:DB8:0::1","seconds":300,"pids":["7"]}));
        assert_eq!(helper_argv(&v6).unwrap()[2], "2001:db8::1", "canonical address");
        for seconds in [300, 900, 3600] {
            let r = dest_req(serde_json::json!({"cmd":"block-dest","app":"a","ip":"192.0.2.1","seconds":seconds,"pids":["7"]}));
            assert!(helper_argv(&r).is_ok(), "{seconds}");
        }
        for (bad, needle) in [
            (serde_json::json!({"app":"a","ip":"192.0.2.1","pids":["7"]}), "seconds must be"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":60,"pids":["7"]}), "seconds must be"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":301,"pids":["7"]}), "seconds must be"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":86400,"pids":["7"]}), "seconds must be"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":"300","pids":["7"]}), "seconds must be"),
            (serde_json::json!({"app":"a","ip":"example.com","seconds":300,"pids":["7"]}), "not a literal"),
            (serde_json::json!({"app":"a","ip":"192.0.2.0/24","seconds":300,"pids":["7"]}), "not a literal"),
            (serde_json::json!({"app":"a","ip":"","seconds":300,"pids":["7"]}), "not a literal"),
            (serde_json::json!({"app":"a","ip":"0.0.0.0","seconds":300,"pids":["7"]}), "not a unicast"),
            (serde_json::json!({"app":"a","ip":"ff02::1","seconds":300,"pids":["7"]}), "not a unicast"),
            (serde_json::json!({"app":"a","ip":"224.0.0.1","seconds":300,"pids":["7"]}), "not a unicast"),
            (serde_json::json!({"ip":"192.0.2.1","seconds":300,"pids":["7"]}), "needs an app id"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":300}), "process ids"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":300,"pids":["x"]}), "not a pid"),
            (serde_json::json!({"app":"a","ip":"192.0.2.1","seconds":300,"pids":["0"]}), "not a pid"),
        ] {
            let mut line = bad.clone();
            line["cmd"] = "block-dest".into();
            let e = helper_argv(&dest_req(line)).unwrap_err();
            assert!(e.contains(needle), "{bad}: {e}");
        }
    }

    #[test]
    fn unblock_dest_runs_the_helpers_unblock_scoped() {
        let ok = dest_req(serde_json::json!({"cmd":"unblock-dest","app":"firefox","ip":"203.0.113.9"}));
        assert_eq!(helper_argv(&ok).unwrap(), ["unblock-scoped", "firefox", "203.0.113.9"]);
        assert!(helper_argv(&dest_req(serde_json::json!({"cmd":"unblock-dest","app":"firefox","ip":"x"})))
            .unwrap_err()
            .contains("not a literal"));
        assert!(helper_argv(&dest_req(serde_json::json!({"cmd":"unblock-dest","ip":"203.0.113.9"})))
            .unwrap_err()
            .contains("needs an app id"));
        // The existing verbs build the same argv as before.
        let b = dest_req(serde_json::json!({"cmd":"block","app":"firefox","pids":["12"]}));
        assert_eq!(helper_argv(&b).unwrap(), ["block-app", "firefox", "12"]);
        let b = dest_req(serde_json::json!({"cmd":"block","app":"firefox","ips":["192.0.2.1"]}));
        assert_eq!(helper_argv(&b).unwrap(), ["block-ips", "firefox", "192.0.2.1"]);
        let u = dest_req(serde_json::json!({"cmd":"unblock","app":"firefox","scope":"ips"}));
        assert_eq!(helper_argv(&u).unwrap(), ["unblock-ips", "firefox"]);
        assert_eq!(helper_argv(&dest_req(serde_json::json!({"cmd":"blocks"}))).unwrap(), ["status"]);
        assert!(helper_argv(&dest_req(serde_json::json!({"cmd":"block"}))).is_err());
    }

    #[test]
    fn policy_snooze_seconds_default_to_an_hour_and_stay_within_a_day() {
        assert_eq!(snooze_seconds(&serde_json::json!({})), Ok(3600));
        assert_eq!(snooze_seconds(&serde_json::json!({"seconds": null})), Ok(3600));
        assert_eq!(snooze_seconds(&serde_json::json!({"seconds": 60})), Ok(60));
        assert_eq!(snooze_seconds(&serde_json::json!({"seconds": 86400})), Ok(86400));
        for bad in [serde_json::json!(0), serde_json::json!(59), serde_json::json!(86401), serde_json::json!(-1), serde_json::json!("3600"), serde_json::json!(1.5)] {
            assert!(snooze_seconds(&serde_json::json!({"seconds": bad})).is_err(), "{bad}");
        }
    }

    /// A user-mode server on a private socket, then turned into what the test
    /// needs: a system daemon a group member (`peer_uid`) is connected to, or
    /// the user's own. The daemon's uid stays the test's, so no helper runs.
    struct Rig {
        dir: PathBuf,
        server: Server,
        live: Live,
        client: std::os::unix::net::UnixStream,
        id: u64,
        /// Every frame this client has read, and where the last send began.
        log: Vec<serde_json::Value>,
        mark: usize,
    }

    fn rig(tag: &str, mode: DaemonMode, peer_uid: u32) -> Rig {
        let dir = tmpdir(tag);
        let sock = dir.join("s.sock");
        let mut server = Server::bind(&sock, false, DaemonMode::User, Kub0Runtime::new(), &dir).unwrap();
        let resolver = vallumd::rdns::Resolver::spawn(1, 8, Arc::new(|_| Ok(None)));
        let live = Live::new(&data_dir(), None, &dir, resolver, DaemonMode::User);
        let client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        client.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        server.accept_new(&[]);
        server.mode = mode;
        // The user daemon's owner is the peer's uid, and never root, so no
        // helper runs even when the suite does.
        server.daemon_uid = 1000;
        let id = server.clients[0].id;
        server.clients[0].peer = vallumd::control::Peer { uid: Some(peer_uid) };
        Rig { dir, server, live, client, id, log: Vec::new(), mark: 0 }
    }

    impl Rig {
        fn send(&mut self, line: serde_json::Value) {
            self.drain();
            self.mark = self.log.len();
            handle_cmd(&line.to_string(), Some(&mut self.live), &mut self.server, self.id);
            self.server.flush_pending();
        }

        /// Read whatever has arrived into the log (the greeting, at first).
        fn drain(&mut self) {
            use std::io::Read;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            let quiet = Instant::now() + Duration::from_millis(200);
            loop {
                self.server.flush_pending();
                match self.client.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) if buf.last() == Some(&b'\n') || Instant::now() > quiet => break,
                    Err(_) => {}
                }
            }
            self.push_lines(&mut buf);
        }

        fn push_lines(&mut self, buf: &mut Vec<u8>) {
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&line) {
                    self.log.push(v);
                }
            }
        }

        /// The first frame since the last send that matches `want`, reading
        /// for up to 3 s.
        fn until(&mut self, want: impl Fn(&serde_json::Value) -> bool) -> Option<serde_json::Value> {
            use std::io::Read;
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            loop {
                if let Some(v) = self.log[self.mark..].iter().find(|v| want(v)) {
                    return Some(v.clone());
                }
                if Instant::now() >= deadline {
                    return None;
                }
                self.server.flush_pending();
                match self.client.read(&mut chunk) {
                    Ok(0) => return None,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => {}
                }
                self.push_lines(&mut buf);
            }
        }

        fn reply(&mut self, req: &str) -> serde_json::Value {
            self.until(|v| v["type"] == "reply" && v["req"] == req)
                .unwrap_or_else(|| panic!("no reply to {req}"))
        }

        fn request(&mut self, req: &str, mut line: serde_json::Value) -> serde_json::Value {
            line["req"] = req.into();
            self.send(line);
            self.reply(req)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Everything `stream` has been sent and not yet read, as frames.
    fn frames_waiting(server: &mut Server, stream: &mut std::os::unix::net::UnixStream) -> Vec<serde_json::Value> {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 65536];
        let quiet = Instant::now() + Duration::from_millis(200);
        loop {
            server.flush_pending();
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) if buf.last() == Some(&b'\n') || Instant::now() > quiet => break,
                Err(_) => {}
            }
        }
        buf.split(|&b| b == b'\n')
            .filter_map(|line| serde_json::from_slice(line).ok())
            .collect()
    }

    /// One daemon serves every panel and CLI of a host (#61, whole host). What one
    /// client asks is answered to it: the replies used to go to every client, which on
    /// a system daemon is another user's panel. And one panel closing does not put the
    /// daemon into passive cadence under a panel that is still open.
    #[test]
    fn a_read_is_answered_to_the_client_that_asked_and_panels_are_counted_per_client() {
        let mut r = rig("one-client", DaemonMode::System, 1000);
        let mut other = std::os::unix::net::UnixStream::connect(r.dir.join("s.sock")).unwrap();
        other.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        r.server.accept_new(&[]);
        let other_id = r.server.clients[1].id;
        r.server.clients[1].peer = vallumd::control::Peer { uid: Some(1001) };
        let _greeting = frames_waiting(&mut r.server, &mut other);

        for (line, ty) in [
            (serde_json::json!({"cmd": "history", "request": "h1"}), "history"),
            (serde_json::json!({"cmd": "investigate", "request": "i1", "subject": "1.1.1.1"}), "investigate"),
            (serde_json::json!({"cmd": "timeline", "request": "t1"}), "timeline"),
            (serde_json::json!({"type": "ping"}), "status"),
        ] {
            r.send(line);
            assert!(r.until(|v| v["type"] == ty).is_some(), "{ty}: no answer for the client that asked");
            let seen = frames_waiting(&mut r.server, &mut other);
            assert!(!seen.iter().any(|v| v["type"] == ty), "{ty} went to a client that did not ask: {seen:?}");
        }

        // The digest of what arrived while no panel was open goes to the panel that
        // opens, once. One that opens beside it was not away from anything.
        r.live.away_new.push("asn:64500".into());
        r.send(serde_json::json!({"type": "panel-open"}));
        let digest = r.until(|v| v["type"] == "digest").expect("the opening panel gets the digest");
        assert_eq!(digest["newNetworks"], 1);
        assert!(!frames_waiting(&mut r.server, &mut other).iter().any(|v| v["type"] == "digest"));
        let open = serde_json::json!({"type": "panel-open"}).to_string();
        let close = serde_json::json!({"type": "panel-close"}).to_string();
        handle_cmd(&open, Some(&mut r.live), &mut r.server, other_id);
        let second: Vec<_> = frames_waiting(&mut r.server, &mut other).into_iter().filter(|v| v["type"] == "digest").collect();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0]["newNetworks"], 0);

        // One closes: the other still holds the daemon at the active cadence.
        r.send(serde_json::json!({"type": "panel-close"}));
        assert!(r.live.panel_open, "the other client's panel is still open");
        handle_cmd(&close, Some(&mut r.live), &mut r.server, other_id);
        assert!(!r.live.panel_open);

        // A client that goes away without closing its panel does not hold it either.
        // Its end of the socket is not always closed by the time it has let go: a
        // process another thread is starting holds a copy of every descriptor from
        // its clone until its exec, and until then the daemon reads "nothing yet",
        // not end of file. `held` is that copy, kept on purpose. The daemon forgets
        // the panel when the end of file does arrive, on whichever pass that is.
        // (This asserted on the first read after the drop, and failed in CI when
        // another test was starting its fake nft at that moment.)
        handle_cmd(&open, Some(&mut r.live), &mut r.server, other_id);
        assert!(r.live.panel_open);
        let held = other.try_clone().unwrap();
        drop(other);
        let _ = r.server.drain_commands();
        forget_gone_panels(&mut r.live, &r.server);
        assert!(r.live.panel_open, "the client's socket is still open somewhere: it has not gone yet");
        drop(held);
        let deadline = Instant::now() + Duration::from_secs(3);
        while r.live.panel_open && Instant::now() < deadline {
            let _ = r.server.drain_commands();
            forget_gone_panels(&mut r.live, &r.server);
            if r.live.panel_open {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(!r.live.panel_open, "a client that is gone does not hold the daemon at the active cadence");
    }

    /// One daemon (#61): destination sharing was a start-up flag only the panel's own
    /// daemon was ever given, and next to a logged-in system daemon that daemon reports
    /// nothing, so the panel's switch did nothing. It is a setting of the system daemon:
    /// root turns it on, a member may turn it off, and it holds across a restart.
    #[test]
    fn destination_sharing_is_a_saved_setting_of_the_system_daemon() {
        let mut r = rig("share", DaemonMode::System, 0);
        r.server.state_dir = r.dir.clone();
        assert!(!r.server.kub0.sharing_destinations());
        assert!(!share_destinations_at_start(false, DaemonMode::System, &r.dir));

        let on = r.request("s1", serde_json::json!({"cmd": "share-on"}));
        assert_eq!((on["ok"].as_bool(), on["result"]["sharingDestinations"].as_bool()), (Some(true), Some(true)), "{on}");
        assert!(r.server.kub0.sharing_destinations());
        // Every client sees it: the fleet frame carries the setting.
        r.server.poll_fleet(None);
        let fleet = r.until(|v| v["type"] == "fleet").expect("a fleet frame after the change");
        assert_eq!(fleet["sharingDestinations"], true);
        // And `status` says it.
        let status = r.request("s2", serde_json::json!({"cmd": "status"}));
        assert_eq!(status["result"]["fleet"]["sharingDestinations"], true);
        // It is what the next start reads; a user daemon reads no such file.
        assert!(share_destinations_at_start(false, DaemonMode::System, &r.dir));
        assert!(!share_destinations_at_start(false, DaemonMode::User, &r.dir));
        assert!(share_destinations_at_start(true, DaemonMode::User, &r.dir));

        // A member may stop it, and may not start it.
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1000) };
        let refused = r.request("s3", serde_json::json!({"cmd": "share-on"}));
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["error"], "share-on: sends the networks this host reaches to your org; needs root: sudo kub0 share on");
        let off = r.request("s4", serde_json::json!({"cmd": "share-off"}));
        assert_eq!((off["ok"].as_bool(), off["result"]["sharingDestinations"].as_bool()), (Some(true), Some(false)), "{off}");
        assert!(!r.server.kub0.sharing_destinations());
        assert!(!share_destinations_at_start(false, DaemonMode::System, &r.dir));

        // No file, or one that does not parse, is off; the flag turns it on for a
        // run whatever is saved.
        let empty = tmpdir("share-none");
        assert!(!share_destinations_at_start(false, DaemonMode::System, &empty));
        std::fs::write(kub0::settings_path(&empty), "{not json").unwrap();
        assert!(!share_destinations_at_start(false, DaemonMode::System, &empty));
        assert!(share_destinations_at_start(true, DaemonMode::System, &r.dir), "the flag, over a saved off");
        let _ = std::fs::remove_dir_all(&empty);

        // The panel's own daemon is started with the flag its switch decides.
        let mut u = rig("share-user", DaemonMode::User, 1000);
        u.server.state_dir = u.dir.clone();
        let no = u.request("u1", serde_json::json!({"cmd": "share-on"}));
        assert_eq!(no["ok"], false);
        assert!(no["error"].as_str().unwrap().contains("setting of the system daemon"), "{no}");
        assert!(!u.server.kub0.sharing_destinations());
        assert!(!kub0::settings_path(&u.dir).exists());
    }

    fn snoozed_until(server: &Server, rule: &str) -> u64 {
        server
            .kub0
            .policy_view()
            .iter()
            .flat_map(|p| p.rules.iter())
            .find(|r| r.id == rule)
            .map(|r| r.snoozed_until)
            .unwrap_or(0)
    }

    #[test]
    fn a_mutating_legacy_line_from_a_group_member_is_refused_on_the_system_daemon() {
        let mut r = rig("legacy-sys", DaemonMode::System, 1000);
        r.server.kub0.set_policies(block_policies("monitor"));
        r.send(serde_json::json!({"cmd":"netpolicy-snooze","ruleId":"r","seconds":600}));
        let st = r.until(|v| v["type"] == "status").expect("the client is told");
        let msg = st["message"].as_str().unwrap();
        assert!(msg.starts_with("netpolicy-snooze:") && msg.contains("update the panel"), "{msg}");
        assert_eq!(snoozed_until(&r.server, "r"), 0, "nothing snoozed");

        r.send(serde_json::json!({"cmd":"watch","action":"set","kind":"country","value":"KP"}));
        r.until(|v| v["type"] == "status" && v["message"].as_str().unwrap_or("").starts_with("watch:"))
            .expect("watch refused");
        assert!(r.live.watch.is_empty(), "no rule written");

        r.send(serde_json::json!({"type":"tag","networkKey":"203.0.113.0/24","label":"lab"}));
        r.until(|v| v["type"] == "status" && v["message"].as_str().unwrap_or("").starts_with("tag:"))
            .expect("tag refused");
        assert!(r.live.tags.get("203.0.113.0/24").is_none(), "no tag written");

        let before = r.server.activity.replay_newest(10).len();
        r.send(serde_json::json!({"cmd":"note","kind":"block","app":{"id":"firefox","name":"Firefox"},"detail":{}}));
        r.until(|v| v["type"] == "status" && v["message"].as_str().unwrap_or("").starts_with("note:"))
            .expect("note refused");
        assert_eq!(r.server.activity.replay_newest(10).len(), before, "no activity injected");

        r.send(serde_json::json!({"cmd":"netpolicy-resume","ruleId":"r"}));
        r.until(|v| v["type"] == "status" && v["message"].as_str().unwrap_or("").starts_with("netpolicy-resume:"))
            .expect("resume refused too");

        // Reads keep working for the panel that sends them.
        r.send(serde_json::json!({"type":"ping"}));
        r.until(|v| v["type"] == "status" && v["message"] == "ok").expect("ping answered");
        r.send(serde_json::json!({"cmd":"timeline","request":"t1","hours":1}));
        r.until(|v| v["type"] == "timeline" && v["request"] == "t1").expect("timeline answered");
    }

    #[test]
    fn root_and_the_user_daemon_still_take_mutating_legacy_lines() {
        for (mode, uid) in [(DaemonMode::System, 0), (DaemonMode::User, 1000)] {
            let mut r = rig("legacy-ok", mode, uid);
            r.server.kub0.set_policies(block_policies("monitor"));
            r.send(serde_json::json!({"cmd":"netpolicy-snooze","ruleId":"r","seconds":600}));
            let deadline = Instant::now() + Duration::from_secs(2);
            while snoozed_until(&r.server, "r") == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(snoozed_until(&r.server, "r") > 0, "{mode:?} uid {uid}: snoozed");
            r.send(serde_json::json!({"cmd":"watch","action":"set","kind":"country","value":"KP"}));
            assert_eq!(r.live.watch.len(), 1, "{mode:?}");
            r.send(serde_json::json!({"type":"tag","networkKey":"203.0.113.0/24","label":"lab"}));
            assert_eq!(r.live.tags.get("203.0.113.0/24").map(|t| t.label.as_str()), Some("lab"), "{mode:?}");
            r.send(serde_json::json!({"cmd":"note","kind":"block","app":{"id":"firefox","name":"Firefox"},"detail":{}}));
            let newest = r.server.activity.replay_newest(1);
            assert_eq!(newest.last().and_then(|e| e.app.as_ref()).map(|a| a.id.as_str()), Some("firefox"), "{mode:?}");
        }
    }

    #[test]
    fn policy_snooze_lowers_and_policy_resume_raises_on_the_system_daemon() {
        let mut r = rig("policy-verbs", DaemonMode::System, 1000);
        r.server.kub0.set_policies(block_policies("monitor"));
        let rep = r.request("s1", serde_json::json!({"cmd":"policy-snooze","rule":"r","seconds":600}));
        assert_eq!(rep["ok"], false);
        assert_eq!(rep["error"], "policy-snooze: lowers protection; needs root: sudo kub0 policy snooze <rule>");
        assert_eq!(snoozed_until(&r.server, "r"), 0);

        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(0) };
        let gen = r.server.kub0.fleet_generation();
        let rep = r.request("s2", serde_json::json!({"cmd":"policy-snooze","rule":"r","seconds":600}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert!(rep["result"]["snoozedUntil"].as_u64().unwrap() > now_ms());
        assert_eq!(snoozed_until(&r.server, "r"), rep["result"]["snoozedUntil"].as_u64().unwrap());
        assert!(r.server.kub0.fleet_generation() > gen, "the policy view is republished");

        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1000) };
        let rep = r.request("s3", serde_json::json!({"cmd":"policy-resume","rule":"r"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(snoozed_until(&r.server, "r"), 0, "a group member may resume");

        let rep = r.request("s4", serde_json::json!({"cmd":"policy-resume"}));
        assert_eq!(rep["error"], "policy-resume needs a rule id");
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(0) };
        let rep = r.request("s5", serde_json::json!({"cmd":"policy-snooze","rule":""}));
        assert_eq!(rep["error"], "policy-snooze needs a rule id");
        let rep = r.request("s6", serde_json::json!({"cmd":"policy-snooze","rule":"r","seconds":5}));
        assert!(rep["error"].as_str().unwrap().contains("from 60 to 86400"), "{rep}");
        let rep = r.request("s7", serde_json::json!({"cmd":"policy-snooze","rule":"nope"}));
        assert_eq!(rep["error"], "no such rule");

        // The org decides what may be snoozed, and its refusal reaches the caller.
        r.server.kub0.set_policies(block_policies("block"));
        let rep = r.request("s8", serde_json::json!({"cmd":"policy-snooze","rule":"r"}));
        assert_eq!(rep["ok"], false);
        assert_eq!(rep["error"], "your organization does not allow snoozing this rule");
    }

    #[test]
    fn a_group_member_changes_only_the_watch_rules_it_set() {
        let mut r = rig("watch-verbs", DaemonMode::System, 1000);
        let rep = r.request("w1", serde_json::json!({"cmd":"watch-set","kind":"country","value":"kp","note":"mine"}));
        assert_eq!(rep["ok"], true, "{rep}");
        let id = rep["result"]["rule"]["id"].as_str().unwrap().to_string();
        assert_eq!(rep["result"]["rule"]["owner"], 1000);
        assert_eq!(rep["result"]["rule"]["value"], "KP");
        assert_eq!(r.live.watch.rules()[0].owner, Some(1000));
        r.until(|v| v["type"] == "watchlist" && v["rules"].as_array().is_some_and(|a| a.len() == 1))
            .expect("every client sees the new rule");

        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1001) };
        let rep = r.request("w2", serde_json::json!({"cmd":"watch-delete","id":id}));
        assert_eq!(rep["ok"], false);
        assert!(rep["error"].as_str().unwrap().contains("another user"), "{rep}");
        let rep = r.request("w3", serde_json::json!({"cmd":"watch-set","kind":"country","value":"KP","note":"theirs"}));
        assert!(rep["error"].as_str().unwrap().contains("another user"), "{rep}");
        assert_eq!(r.live.watch.rules()[0].note, "mine", "untouched");

        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1000) };
        let rep = r.request("w4", serde_json::json!({"cmd":"watch-set","kind":"country","value":"KP","note":"renamed"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(r.live.watch.rules()[0].note, "renamed");
        let rep = r.request("w5", serde_json::json!({"cmd":"watch-delete","id":id}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert!(r.live.watch.is_empty());

        // Root changes anyone's; a rule with no owner is root's alone.
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(0) };
        let rep = r.request("w6", serde_json::json!({"cmd":"watch-set","kind":"port","value":"4444"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert!(rep["result"]["rule"].get("owner").is_none(), "root's rules carry no owner: {rep}");
        let root_id = rep["result"]["rule"]["id"].as_str().unwrap().to_string();
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1000) };
        let rep = r.request("w7", serde_json::json!({"cmd":"watch-delete","id":root_id}));
        assert!(rep["error"].as_str().unwrap().contains("another user"), "{rep}");

        // One daemon (#61): a rule root sets FOR someone is theirs. `kub0 install`
        // carries a person's rules over from the panel's own daemon this way, and
        // `sudo kub0 watch add` acts for the sudo caller. (It used to be root's:
        // the person could then neither rename nor remove their own rule.)
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(0) };
        let rep = r.request("o1", serde_json::json!({"cmd":"watch-set","kind":"asn","value":"64500","note":"carried","as_uid":1000}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(rep["result"]["rule"]["owner"], 1000);
        let carried_id = rep["result"]["rule"]["id"].as_str().unwrap().to_string();
        // Root's authority is not narrowed by whom it acts for: it still changes
        // another person's rule while acting for this one.
        let rep = r.request("o2", serde_json::json!({"cmd":"watch-set","kind":"asn","value":"64501","as_uid":1001}));
        let others_id = rep["result"]["rule"]["id"].as_str().unwrap().to_string();
        let rep = r.request("o3", serde_json::json!({"cmd":"watch-delete","id":others_id,"as_uid":1000}));
        assert_eq!(rep["ok"], true, "{rep}");
        // And the person changes the carried rule without root.
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(1000) };
        let rep = r.request("o4", serde_json::json!({"cmd":"watch-delete","id":carried_id}));
        assert_eq!(rep["ok"], true, "{rep}");

        let rep = r.request("w8", serde_json::json!({"cmd":"watch-set","kind":"planet","value":"mars"}));
        assert_eq!(rep["error"], "unknown watch kind \"planet\"");
        let rep = r.request("w9", serde_json::json!({"cmd":"watch-set","kind":"country","value":"Korea"}));
        assert!(rep["error"].as_str().unwrap().contains("not a two-letter country code"), "{rep}");
        let rep = r.request("w10", serde_json::json!({"cmd":"watch-delete"}));
        assert_eq!(rep["error"], "watch-delete needs a rule id");
        let rep = r.request("w11", serde_json::json!({"cmd":"watch-delete","id":"w-00000000"}));
        assert_eq!(rep["error"], "no watch rule w-00000000");
    }

    #[test]
    fn the_user_daemon_owner_changes_every_watch_rule() {
        let mut r = rig("watch-user", DaemonMode::User, 1000);
        r.send(serde_json::json!({"cmd":"watch","action":"set","kind":"port","value":"4444"}));
        let id = r.live.watch.rules()[0].id.clone();
        assert_eq!(r.live.watch.rules()[0].owner, None);
        let rep = r.request("u1", serde_json::json!({"cmd":"watch-delete","id":id}));
        assert_eq!(rep["ok"], true, "{rep}");
    }

    #[test]
    /// A name carried over by `kub0 install` keeps the reverse-DNS suffix it was
    /// given under, so the org can still tell when the network changed hands.
    /// Only root may say so, and only where no live row shows one.
    fn a_names_ptr_anchor_is_roots_to_give() {
        let peer = |uid| vallumd::control::Peer { uid: Some(uid) };
        let args = serde_json::json!({"ptrSuffix": "edge.example.net"});
        assert_eq!(tag_anchor(&args, peer(0)), "edge.example.net");
        assert_eq!(tag_anchor(&args, peer(1000)), "", "a member cannot assert an anchor");
        assert_eq!(tag_anchor(&serde_json::json!({}), peer(0)), "");
        for bad in ["a b", "x/../y", "é.example", &"a".repeat(254)] {
            assert_eq!(tag_anchor(&serde_json::json!({"ptrSuffix": bad}), peer(0)), "", "{bad:?}");
        }

        let mut r = rig("tag-anchor", DaemonMode::System, 0);
        let rep = r.request("a1", serde_json::json!({"cmd":"tag","networkKey":"203.0.113.0/24","label":"Office VPN","ptrSuffix":"edge.example.net"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(r.live.tags.get("203.0.113.0/24").map(|t| t.ptr_suffix.clone()), Some("edge.example.net".to_string()));
        r.server.clients[0].peer = peer(1000);
        let rep = r.request("a2", serde_json::json!({"cmd":"tag","networkKey":"198.51.100.0/24","label":"Lab","ptrSuffix":"edge.example.net"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(r.live.tags.get("198.51.100.0/24").map(|t| t.ptr_suffix.clone()), Some(String::new()));
    }

    #[test]
    fn tag_requests_behave_like_the_legacy_line() {
        let mut r = rig("tag-req", DaemonMode::System, 1000);
        let rep = r.request("t1", serde_json::json!({"cmd":"tag","networkKey":"203.0.113.0/24","label":"lab","kind":"infra"}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert_eq!(rep["result"]["deleted"], false);
        assert_eq!(r.live.tags.get("203.0.113.0/24").map(|t| t.label.as_str()), Some("lab"));
        r.until(|v| v["type"] == "snapshot").expect("retagged rows go out");
        let rep = r.request("t2", serde_json::json!({"cmd":"tag","networkKey":"203.0.113.0/24","label":""}));
        assert_eq!(rep["result"]["deleted"], true, "{rep}");
        assert!(r.live.tags.get("203.0.113.0/24").is_none());
        let rep = r.request("t3", serde_json::json!({"cmd":"tag","label":"x"}));
        assert_eq!(rep["error"], "tag: empty networkKey");
        let rep = r.request("t4", serde_json::json!({"cmd":"tag","networkKey":"k","label":"x".repeat(65)}));
        assert!(rep["error"].as_str().unwrap().contains("64"), "{rep}");
    }

    /// The panel's record of a block outcome stays a legacy line: as a request
    /// it is no verb at all, so no member can forge an activity row with it.
    #[test]
    fn a_note_request_is_an_unknown_command() {
        let mut r = rig("note-req", DaemonMode::System, 1000);
        let before = r.server.activity.replay_newest(10).len();
        let rep = r.request("n1", serde_json::json!({"cmd":"note","kind":"block","app":{"id":"firefox","name":"Firefox"},"detail":{}}));
        assert_eq!(rep["ok"], false);
        assert_eq!(rep["error"], "unknown command note");
        assert_eq!(r.server.activity.replay_newest(10).len(), before, "no activity row");
    }

    #[test]
    fn destination_verbs_are_classed_and_refused_off_the_system_daemon() {
        let mut r = rig("dest-user", DaemonMode::User, 1000);
        let rep = r.request("d1", serde_json::json!({"cmd":"block-dest","app":"a","ip":"192.0.2.1","seconds":300,"pids":["7"]}));
        let e = rep["error"].as_str().unwrap();
        assert!(e.contains("system daemon only") && e.contains("kub0") && !e.contains("needs root"), "a raise: {e}");
        let rep = r.request("d2", serde_json::json!({"cmd":"unblock-dest","app":"a","ip":"192.0.2.1"}));
        let e = rep["error"].as_str().unwrap();
        assert!(e.contains("system daemon only") && e.contains("needs root") && e.contains("sudo kub0 unblock <app> --to <ip>"), "a lower: {e}");

        let mut r = rig("dest-sys", DaemonMode::System, 1000);
        let rep = r.request("d3", serde_json::json!({"cmd":"unblock-dest","app":"a","ip":"192.0.2.1"}));
        assert_eq!(rep["error"], "unblock-dest: lowers protection; needs root: sudo kub0 unblock <app> --to <ip>");
    }

    #[test]
    fn a_group_member_cannot_log_the_system_daemon_in() {
        let mut r = rig("login-member", DaemonMode::System, 1000);
        // A closed local port: were login a raise, it would fail here instead
        // of reaching a real auth server.
        let rep = r.request(
            "l1",
            serde_json::json!({"cmd":"login","authUrl":"http://127.0.0.1:9","serverUrl":"http://127.0.0.1:9"}),
        );
        assert_eq!(rep["ok"], false);
        assert_eq!(rep["error"], "login: chooses the org whose rules this host enforces; needs root: sudo kub0 login");
        assert!(r.server.login.is_none(), "no login was started");
        assert!(!r.server.account_path.exists());
    }

    #[test]
    fn a_group_member_may_block_an_app_but_not_addresses() {
        let mut r = rig("block-ips", DaemonMode::System, 1000);
        let rep = r.request("b1", serde_json::json!({"cmd":"block","app":"firefox","ips":["192.0.2.1"]}));
        assert_eq!(rep["error"], vallumd::control::ADDRESS_BLOCK_NEEDS_ROOT);
        // An app block passes authorization and reaches the helper path,
        // which this test daemon (not root) declines without running it.
        let rep = r.request("b2", serde_json::json!({"cmd":"block","app":"firefox","pids":["12"]}));
        let e = rep["error"].as_str().unwrap();
        assert!(e.contains("system daemon only") && !e.contains("needs root"), "{e}");
        // Off the system daemon, the hint for an address block names root.
        let mut r = rig("block-ips-user", DaemonMode::User, 1000);
        let rep = r.request("b3", serde_json::json!({"cmd":"block","app":"firefox","ips":["192.0.2.1"]}));
        let e = rep["error"].as_str().unwrap();
        assert!(e.contains("needs root") && e.contains("sudo kub0 block <app> --ip"), "{e}");
    }

    // -- step 1b: as_uid and the daemon's own block records ---------------

    #[test]
    fn the_hello_says_this_daemon_honours_as_uid() {
        let mut r = rig("hello-as-uid", DaemonMode::System, 1000);
        r.drain();
        let hello = r.log.iter().find(|v| v["type"] == "hello").cloned().expect("a greeting");
        assert_eq!(hello["requests"], true);
        assert_eq!(hello["as_uid"], true, "kub0 sends as_uid only to a daemon that says so");
    }

    #[test]
    fn as_uid_from_a_group_member_is_refused_not_ignored() {
        let mut r = rig("as-uid", DaemonMode::System, 1000);
        let rep = r.request("a1", serde_json::json!({"cmd":"block","app":"firefox","pids":["12"],"as_uid":1001}));
        assert_eq!(rep["ok"], false);
        assert_eq!(rep["error"], "block: as_uid is honoured only from root");
        let rep = r.request("a2", serde_json::json!({"cmd":"status","as_uid":1001}));
        assert_eq!(rep["error"], "status: as_uid is honoured only from root");
        // From root it passes authorization and reaches the helper path, which
        // this test daemon (not root) declines without running anything.
        r.server.clients[0].peer = vallumd::control::Peer { uid: Some(0) };
        let rep = r.request("a3", serde_json::json!({"cmd":"block","app":"firefox","pids":["12"],"as_uid":1001}));
        assert!(rep["error"].as_str().unwrap().contains("system daemon only"), "{rep}");
        let rep = r.request("a4", serde_json::json!({"cmd":"status","as_uid":1001}));
        assert_eq!(rep["ok"], true, "{rep}");
    }

    fn app(id: &str, name: &str) -> ActivityApp {
        ActivityApp { id: id.into(), name: name.into() }
    }

    #[test]
    fn a_block_outcome_is_the_record_the_panel_noted() {
        let a = app("firefox", "Firefox");
        let rec = |verb: &str, v: serde_json::Value| block_outcome(verb, &a, &Ok(v), 7);
        let e = rec("block-app", serde_json::json!({"ok":true,"verified":true})).unwrap();
        assert_eq!((e.kind, e.ts), (ActivityKind::Block, 7));
        assert_eq!(e.app, Some(a.clone()));
        assert_eq!(e.detail, serde_json::json!({"mechanism":"cgroup"}));
        let e = rec("block-ips", serde_json::json!({"ok":true})).unwrap();
        assert_eq!((e.kind, e.detail["mechanism"].as_str()), (ActivityKind::Block, Some("endpoints")));
        let e = rec("block-app", serde_json::json!({"ok":true,"mechanism":"endpoints"})).unwrap();
        assert_eq!(e.detail["mechanism"], "endpoints", "the helper's own mechanism wins");
        // A rule that landed with a warning is still a block, as the panel had it.
        let e = rec("block-app", serde_json::json!({"ok":true,"verified":false,"ruleVerified":true,"warning":"w"})).unwrap();
        assert_eq!(e.kind, ActivityKind::Block);
        let e = rec("block-app", serde_json::json!({"ok":true,"verified":false,"warning":"sockets escaped"})).unwrap();
        assert_eq!(e.kind, ActivityKind::BlockFailed);
        assert_eq!(e.detail, serde_json::json!({"mechanism":"cgroup","error":"sockets escaped"}));
        let e = rec("block-app", serde_json::json!({"ok":false,"error":"no live processes","code":"empty-forest"})).unwrap();
        assert_eq!(e.detail, serde_json::json!({"mechanism":"cgroup","error":"no live processes"}));
        let e = block_outcome("block-ips", &a, &Err("block-ips: No such file".into()), 7).unwrap();
        assert_eq!(e.detail, serde_json::json!({"mechanism":"endpoints","error":"block-ips: No such file"}));
        let long = "x".repeat(500);
        let e = rec("block-app", serde_json::json!({"ok":false,"error":long})).unwrap();
        assert_eq!(e.detail["error"].as_str().unwrap().chars().count(), vallumd::activity::ERROR_CAP);
        let e = rec("block-scoped", serde_json::json!({"ok":true,"mechanism":"app-destination"})).unwrap();
        assert_eq!((e.kind, e.detail["mechanism"].as_str()), (ActivityKind::Block, Some("app-destination")));
        for verb in ["unblock-app", "unblock-ips", "unblock-scoped"] {
            assert_eq!(rec(verb, serde_json::json!({"ok":true})).unwrap().kind, ActivityKind::Unblock, "{verb}");
            assert!(rec(verb, serde_json::json!({"ok":false,"error":"x"})).is_none(), "a failed unblock was never noted");
        }
        assert_eq!(rec("unblock-ips", serde_json::json!({"ok":true})).unwrap().detail["mechanism"], "endpoints");
        for verb in ["status", "pause", "resume", "fleet-sync", "teardown", ""] {
            assert!(rec(verb, serde_json::json!({"ok":true})).is_none(), "{verb}");
        }
        assert!(block_outcome("block-app", &app("", ""), &Ok(serde_json::json!({"ok":true})), 7).is_none());
        // Every record is one the panel's note line could have sent.
        let e = rec("block-app", serde_json::json!({"ok":false,"error":"boom"})).unwrap();
        let line = serde_json::json!({"cmd":"note","kind":e.kind.as_str(),"app":e.app,"detail":e.detail});
        assert_eq!(activity::parse_note(&line, 7).unwrap(), e);
    }

    #[test]
    fn a_helper_job_acts_for_the_named_user_and_keeps_the_helpers_fields() {
        let dir = enforcer_dir("helper-job");
        let bin = dir.join("kub0-block");
        install_script(
            &bin,
            "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\n\
             if [ \"$1\" = block-app ] && [ \"$3\" = fail ]; then echo '{\"ok\":false,\"error\":\"no live processes\",\"code\":\"empty-forest\",\"rollback\":true}'; exit 1; fi\n\
             if [ \"$1\" = block-app ] && [ \"$3\" = bare ]; then echo '{\"error\":\"bare\"}'; exit 1; fi\n\
             if [ \"$1\" = block-app ] && [ \"$3\" = text ]; then echo 'not json' >&2; exit 1; fi\n\
             printf '{\"ok\":true,\"verified\":true,\"uid\":\"%s\"}\\n' \"$PKEXEC_UID\"\n",
        );
        let a = app("firefox", "Firefox");
        let argv = |third: &str| vec!["block-app".to_string(), "firefox".to_string(), third.to_string()];
        let (tx, rx) = std::sync::mpsc::channel();
        let job = |args: &[String], uid, id: &str, a: &ActivityApp| {
            let reply = helper_job(&bin, args, uid, id, a, &tx);
            (reply, rx.try_recv().ok())
        };
        let (reply, entry) = job(&argv("12"), Some(1000), "j1", &a);
        assert!(reply.ok, "{reply:?}");
        assert_eq!(reply.result["uid"], "1000", "PKEXEC_UID is the acting user");
        assert_eq!(entry.unwrap().kind, ActivityKind::Block);

        let (reply, entry) = job(&argv("fail"), Some(1000), "j2", &a);
        assert!(!reply.ok);
        assert_eq!(reply.error, "no live processes");
        assert_eq!(reply.result["code"], "empty-forest", "the caller can tell a rolled-back block");
        assert_eq!(reply.result["rollback"], true);
        let entry = entry.unwrap();
        assert_eq!(entry.kind, ActivityKind::BlockFailed);
        assert_eq!(entry.detail["error"], "no live processes");

        let (reply, _) = job(&argv("bare"), Some(1000), "j3", &a);
        assert!(!reply.ok, "a non-zero exit never reads as success");
        assert_eq!(reply.result["ok"], false);
        let (reply, entry) = job(&argv("text"), Some(1000), "j4", &a);
        assert!(!reply.ok && reply.error.contains("not json"), "{reply:?}");
        assert_eq!(entry.unwrap().kind, ActivityKind::BlockFailed);

        let (reply, entry) = job(&["pause".to_string()], Some(0), "j5", &app("", ""));
        assert!(reply.ok);
        assert!(entry.is_none(), "a pause has no activity kind");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_block_record_from_a_worker_reaches_the_log_and_the_clients() {
        let mut r = rig("block-record", DaemonMode::System, 1000);
        let entry = block_outcome("block-app", &app("firefox", "Firefox"), &Ok(serde_json::json!({"ok":true})), now_ms()).unwrap();
        r.server.activity_tx.send(entry).unwrap();
        r.send(serde_json::json!({"type":"ping"}));
        r.server.deliver_replies();
        let newest = r.server.activity.replay_newest(1);
        assert_eq!(newest.last().map(|e| e.kind), Some(ActivityKind::Block));
        r.until(|v| v["type"] == "activity" && v["entries"][0]["kind"] == "block").expect("clients see the record");
    }

    #[test]
    fn a_request_names_the_app_by_its_live_rows() {
        let dir = tmpdir("activity-app");
        let resolver = vallumd::rdns::Resolver::spawn(1, 8, Arc::new(|_| Ok(None)));
        let mut live = Live::new(&data_dir(), None, &dir, resolver, DaemonMode::User);
        let mut conn = test_conn(5, "", false);
        conn.app.id = "firefox".into();
        conn.app.name = "Firefox".into();
        live.live.insert(conn.id.clone(), conn);
        assert_eq!(activity_app(Some(&live), "firefox"), app("firefox", "Firefox"));
        assert_eq!(activity_app(Some(&live), "curl"), app("curl", "curl"));
        assert_eq!(activity_app(None, "curl"), app("curl", "curl"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- #63: `sync` asks the applier ----------------------------------------

    /// The applier between heartbeats, as `heartbeat_loop` runs it, over a fake
    /// helper and a fake kernel in `dir`, until `stop` is set.
    fn test_applier(rt: Arc<Kub0Runtime>, dir: PathBuf, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut enforcer = test_enforcer(&dir, bundled_data());
            enforcer.policy_known = true;
            while !stop.load(Ordering::SeqCst) {
                serve_applier(&mut enforcer, &rt, true, "http://127.0.0.1:9");
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    }

    impl Rig {
        /// The reply to `req` from a worker thread, which reaches the client
        /// only through `deliver_replies`.
        fn worker_reply(&mut self, req: &str) -> serde_json::Value {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                self.server.deliver_replies();
                self.drain();
                if let Some(v) = self.log[self.mark..].iter().find(|v| v["type"] == "reply" && v["req"] == req) {
                    return v.clone();
                }
                assert!(Instant::now() < deadline, "no reply to {req}");
            }
        }
    }

    /// #63: `sync` ran the helper's `fleet-sync` itself, with no rule list on
    /// its stdin, so it failed before planning anything. The applier is the one
    /// caller that has the org's list.
    #[test]
    fn sync_hands_the_org_list_to_the_helper_through_the_applier() {
        let mut r = rig("sync-verb", DaemonMode::System, 1000);
        r.server.daemon_uid = 0; // the system daemon; `sync` itself runs no helper
        let rt = Arc::clone(&r.server.kub0);
        rt.set_asn(Arc::new(vallumd::geo::AsnDb::load(&bundled_data())));
        rt.set_policies(block_policies("block"));
        rt.set_connected(true);
        let dir = enforcer_dir("sync-verb");
        let stop = Arc::new(AtomicBool::new(false));
        let applier = test_applier(Arc::clone(&rt), dir.clone(), Arc::clone(&stop));

        r.send(serde_json::json!({"cmd":"sync","req":"y1"}));
        let rep = r.worker_reply("y1");
        assert_eq!(rep["ok"], true, "{rep}");
        let enf = &rep["result"]["enforcement"];
        assert_eq!(
            (enf["state"].as_str(), enf["enforcing"].as_bool(), enf["entries"].as_u64()),
            (Some("enforcing"), Some(true), Some(1)),
            "{rep}"
        );
        assert_eq!(enf["rules"], serde_json::json!(["r"]));
        let calls = helper_calls(&dir);
        let spec: serde_json::Value = serde_json::from_str(calls.trim_start_matches("fleet-sync\t").trim())
            .unwrap_or_else(|e| panic!("the helper got no rule list ({e}): {calls:?}"));
        assert_eq!(spec["block"], serde_json::json!(["198.51.100.0/24"]), "{calls}");
        assert!(
            std::fs::read_to_string(dir.join("chain.txt")).unwrap_or_default().contains("vallum-fleet"),
            "the fleet rules are in the kernel"
        );

        // Asked again with nothing changed, it applies again; the heartbeat's
        // own pass over an unchanged plan only looks.
        r.send(serde_json::json!({"cmd":"sync","req":"y2"}));
        assert_eq!(r.worker_reply("y2")["ok"], true);
        assert_eq!(helper_calls(&dir).matches("fleet-sync").count(), 2, "{}", helper_calls(&dir));

        stop.store(true, Ordering::SeqCst);
        applier.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sync_with_no_org_block_rules_clears_what_the_kernel_holds() {
        let dir = enforcer_dir("sync-clear");
        let rt = runtime_with_asn();
        let mut e = test_enforcer(&dir, bundled_data());
        // Fleet rules this process did not put there and does not count as strays.
        fake_kernel(&dir, Kernel::Holds);
        e.stray = false;
        e.policy_known = true;
        e.sync(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none");
        assert!(helper_calls(&dir).is_empty(), "the heartbeat's pass goes by its own record");

        e.reapply(&rt, true, "http://127.0.0.1:9");
        assert_eq!(rt.enforcement().state, "none");
        assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 1, "{}", helper_calls(&dir));
        assert!(!dir.join("chain.txt").exists(), "the rules are out of the kernel");

        // An empty set that is not the org's answer clears nothing, asked or not.
        fake_kernel(&dir, Kernel::Holds);
        e.policy_known = false;
        e.reapply(&rt, true, "http://127.0.0.1:9");
        let enf = rt.enforcement();
        assert_eq!(enf.state, "error");
        assert!(enf.reason.contains("left in place"), "{}", enf.reason);
        assert_eq!(helper_calls(&dir).matches("fleet-clear").count(), 1, "nothing more was cleared");
        assert!(dir.join("chain.txt").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sync_the_applier_cannot_serve_in_time_says_so_and_stays_queued() {
        let rt = Kub0Runtime::new();
        rt.set_connected(true);
        let rep = sync_job(&rt, "t1", Duration::from_millis(50));
        assert!(!rep.ok);
        assert!(rep.error.starts_with("sync: the daemon is mid-heartbeat"), "{}", rep.error);
        // Logged out while it waited, it is told that, not to keep waiting.
        rt.set_connected(false);
        let rep = sync_job(&rt, "t2", Duration::from_millis(50));
        assert!(!rep.ok && rep.error.contains("not logged in"), "{}", rep.error);
        let ticket = rt.take_sync_request().expect("still asked for");
        rt.finish_sync(ticket);
        assert!(rt.take_sync_request().is_none(), "served once, late");
        // One re-apply answers everyone who asked before it.
        let (a, b) = (rt.request_sync(), rt.request_sync());
        assert_eq!(rt.take_sync_request(), Some(b));
        rt.finish_sync(b);
        assert!(rt.wait_sync(a, Duration::ZERO) && rt.wait_sync(b, Duration::ZERO));
    }

    #[test]
    fn a_sync_is_done_only_when_the_kernel_matches_the_org() {
        use vallumd::netpolicy::Enforcement;
        let state = |state: &str, reason: &str| Enforcement {
            state: state.into(),
            reason: reason.into(),
            ..Default::default()
        };
        for ok in ["enforcing", "none"] {
            let rep = sync_reply("q", &state(ok, ""));
            assert!(rep.ok, "{ok}");
            assert_eq!(rep.result["enforcement"]["state"], ok);
        }
        // Held behind the panel's pause is applied; the reason travels with it.
        let rep = sync_reply("q", &state("enforcing", PAUSED_REASON));
        assert!(rep.ok);
        assert_eq!(rep.result["enforcement"]["reason"], PAUSED_REASON);
        let rep = sync_reply("q", &state("error", "fleet-sync failed: boom"));
        assert!(!rep.ok);
        assert_eq!(rep.error, "sync: fleet-sync failed: boom");
        assert_eq!(rep.result["enforcement"]["state"], "error", "the caller still gets the state");
        let rep = sync_reply("q", &state("monitor", ""));
        assert!(!rep.ok && rep.error.contains("not applied"), "{}", rep.error);
    }

    #[test]
    fn sync_is_refused_where_nothing_would_apply_it() {
        // A user daemon enforces nothing: the verb is the group's, on the system daemon.
        let mut r = rig("sync-user", DaemonMode::User, 1000);
        let rep = r.request("u1", serde_json::json!({"cmd":"sync"}));
        let err = rep["error"].as_str().unwrap().to_string();
        assert_eq!(rep["ok"], false);
        assert!(err.starts_with("sync: applying the org's block rules runs in the system daemon only"), "{err}");
        assert!(err.contains("kub0 group") && !err.contains("needs root"), "{err}");

        // Logged out, the system daemon has no org list and no applier to ask.
        let mut r = rig("sync-loggedout", DaemonMode::System, 1000);
        r.server.daemon_uid = 0;
        let rep = r.request("u2", serde_json::json!({"cmd":"sync"}));
        assert_eq!(rep["ok"], false);
        assert!(rep["error"].as_str().unwrap().contains("not logged in"), "{rep}");
        assert!(r.server.kub0.take_sync_request().is_none(), "nothing is left queued");

        // And `sync` is not a bare helper verb again.
        assert_eq!(
            helper_argv(&dest_req(serde_json::json!({"cmd":"sync"}))).unwrap_err(),
            "unhandled helper command sync"
        );
    }

    // -- #61 step 2: the reads and the retired client verbs ---------------

    #[test]
    fn the_old_client_verbs_name_their_kub0_command() {
        for (verb, want) in [
            ("connect", "kub0 login"),
            ("disconnect", "kub0 logout"),
            ("status", "kub0 whoami"),
            ("history", "kub0 history"),
            ("brief", "kub0 brief"),
            ("investigate", "kub0 why <app|ip|kind:value>"),
            ("timeline", "kub0 intel --timeline"),
            ("watch", "kub0 watches, kub0 watch add|rm"),
        ] {
            assert_eq!(retired_client_verb(verb), Some(want), "{verb}");
        }
        for verb in ["system-status", "--system", "selftest", ""] {
            assert_eq!(retired_client_verb(verb), None, "{verb}");
        }
    }

    fn owned_conn(inode: u64, app: &str, pid: u32, uid: u32) -> Connection {
        let mut c = test_conn(inode, "", false);
        c.id = format!("tcp:{inode}:203.0.113.9:443");
        c.app.id = app.into();
        c.app.name = app.to_uppercase();
        c.app.pid = pid;
        c.uid = Some(uid);
        c.remote.ip = "203.0.113.9".into();
        c
    }

    #[test]
    fn apps_group_live_and_retained_rows_and_mine_keeps_one_uid() {
        let live = vec![owned_conn(1, "firefox", 10, 1000), owned_conn(2, "firefox", 11, 1000), owned_conn(3, "curl", 12, 1001)];
        let gone = owned_conn(4, "git", 13, 1000);
        let mut store = vallumd::history::History::open(&tmpdir("apps-history"), 1).unwrap();
        store.observe(&[gone.clone()], 500);
        store.observe(&[], 600);
        store.flush(700).unwrap();
        let retained = store.query("", 0, 100).unwrap();
        let bandwidth: Vec<vallumd::traffic::AppTraffic> = serde_json::from_value(serde_json::json!([
            {"id": "curl", "txBytes": 9, "rxBytes": 900, "txRate": 1.0, "rxRate": 5000.0, "measured": 1, "tcp": 1}
        ])).unwrap();
        let all = apps_view(&live, &retained, &bandwidth, None, 10_000);
        let by = |id: &str| all.iter().find(|a| a.id == id).cloned().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!((by("firefox").connections, by("firefox").pids.clone()), (2, vec![10, 11]));
        assert_eq!(by("firefox").last_seen, 10_000, "live now");
        assert_eq!((by("git").connections, by("git").seen), (0, 1), "seen in the last day, not live");
        assert_eq!(by("curl").rx_rate, Some(5000.0));
        let mine = apps_view(&live, &retained, &bandwidth, Some(1000), 10_000);
        assert_eq!(mine.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), ["firefox", "git"], "uid 1001's curl is not mine");
        let mut sorted = all.clone();
        AppSort::Bandwidth.apply(&mut sorted);
        assert_eq!(sorted[0].id, "curl");
        AppSort::Connections.apply(&mut sorted);
        assert_eq!(sorted[0].id, "firefox");
        AppSort::Name.apply(&mut sorted);
        assert_eq!(sorted.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), ["curl", "firefox", "git"]);
        AppSort::Recent.apply(&mut sorted);
        assert_eq!(sorted.last().unwrap().id, "git");
        assert!(AppSort::parse("size").is_err());
        assert_eq!(AppSort::parse(""), Ok(AppSort::Connections));
    }

    #[test]
    fn conns_filter_by_app_and_unattributed() {
        let a = owned_conn(1, "firefox", 10, 1000);
        let orphan = owned_conn(2, "unknown", 0, 1000);
        assert!(conn_matches(&a, "", false));
        assert!(conn_matches(&a, "firefox", false));
        assert!(conn_matches(&a, "FIREFOX", false), "by name, any case");
        assert!(!conn_matches(&a, "curl", false));
        assert!(!conn_matches(&a, "", true));
        assert!(conn_matches(&orphan, "", true));
    }

    #[test]
    fn the_reads_answer_from_the_daemons_own_state() {
        let mut r = rig("reads", DaemonMode::System, 1000);
        let mut flagged = owned_conn(1, "firefox", 10, 1000);
        flagged.indicators.push(vallumd::intel::Indicator {
            id: "exe-temp-dir".into(),
            severity: vallumd::intel::Severity::Warning,
            attack: None,
            basis: "runs from /tmp".into(),
        });
        r.live.live.insert(flagged.id.clone(), flagged.clone());
        r.live.live.insert("tcp:2:x".into(), owned_conn(2, "curl", 12, 1001));
        r.server.history.as_mut().unwrap().observe(&r.live.snapshot(), now_ms());

        let rep = r.request("a1", serde_json::json!({"cmd":"apps","sort":"name"}));
        assert_eq!(rep["ok"], true, "{rep}");
        let ids: Vec<&str> = rep["result"]["apps"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["curl", "firefox"]);
        let rep = r.request("a2", serde_json::json!({"cmd":"apps","mine":true}));
        assert_eq!(rep["result"]["mine"], 1000, "the caller's own uid");
        assert_eq!(rep["result"]["apps"].as_array().unwrap().len(), 1);
        let rep = r.request("a3", serde_json::json!({"cmd":"apps","sort":"size"}));
        assert!(rep["error"].as_str().unwrap().contains("sort by"), "{rep}");

        let rep = r.request("c1", serde_json::json!({"cmd":"conns","app":"curl"}));
        assert_eq!(rep["result"]["count"], 1, "{rep}");

        r.server.push_activity(vallumd::activity::ActivityEntry::new(now_ms(), ActivityKind::Block, None, serde_json::json!({})));
        r.server.push_activity(vallumd::activity::ActivityEntry::new(now_ms() - 7_200_000, ActivityKind::Unblock, None, serde_json::json!({})));
        let rep = r.request("v1", serde_json::json!({"cmd":"activity","seconds":3600}));
        let kinds: Vec<&str> = rep["result"]["entries"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"block") && !kinds.contains(&"unblock"), "{kinds:?}");

        let rep = r.request("h1", serde_json::json!({"cmd":"history","hours":1,"query":"curl","format":"csv"}));
        assert_eq!(rep["result"]["entries"].as_array().unwrap().len(), 1, "{rep}");
        assert!(rep["result"]["csv"].as_str().unwrap().lines().count() >= 2, "a header and a row");
        let rep = r.request("h2", serde_json::json!({"cmd":"history","hours":0}));
        assert_eq!(rep["error"], "history: hours must be 1..168");

        r.server.listeners = vec![Listener {
            proto: "tcp".into(),
            ip: "127.0.0.1".into(),
            port: 631,
            app: owned_conn(9, "cupsd", 1, 0).app,
            exe: String::new(),
            uid: Some(0),
            scope: "loopback".into(),
        }];
        let rep = r.request("i1", serde_json::json!({"cmd":"intel","timelineHours":1}));
        assert_eq!(rep["result"]["counts"]["warning"], 1, "{rep}");
        assert_eq!(rep["result"]["indicators"][0]["app"]["id"], "firefox");
        assert_eq!(rep["result"]["listeners"][0]["scope"], "loopback only");
        assert!(rep["result"]["timelineText"].as_str().is_some());

        let rep = r.request("w1", serde_json::json!({"cmd":"investigate","subject":"ip:203.0.113.9","hours":1}));
        assert_eq!(rep["ok"], true, "{rep}");
        assert!(!rep["result"]["text"].as_str().unwrap().is_empty());
        let rep = r.request("w2", serde_json::json!({"cmd":"investigate","subject":"   "}));
        assert!(rep["error"].as_str().unwrap().contains("needs a subject"));

        r.server.kub0.set_policies(block_policies("monitor"));
        let rep = r.request("p1", serde_json::json!({"cmd":"policies"}));
        assert_eq!(rep["result"]["netpolicies"][0]["rules"][0]["id"], "r", "{rep}");
        assert!(rep["result"].get("netpolicyEnforcement").is_some(), "the fleet frame's keys");

        r.live.watch.set(vallumd::watch::Rule::new(vallumd::watch::RuleKind::Port, "4444", "lab", 1).unwrap()).unwrap();
        let rep = r.request("r1", serde_json::json!({"cmd":"watches"}));
        assert_eq!(rep["result"]["rules"][0]["value"], "4444");

        let rep = r.request("b1", serde_json::json!({"cmd":"brief","hours":1}));
        assert!(rep["result"]["markdown"].as_str().unwrap().contains('#'), "{rep}");

        // Without the procfs monitor the reads that need it say so.
        let req = vallumd::control::Request::parse(r#"{"req":"x","cmd":"apps"}"#).unwrap();
        assert!(r.server.read_result(&req, Some(1000), None).unwrap_err().contains("live procfs source"));
        let req = vallumd::control::Request::parse(r#"{"req":"x","cmd":"policies"}"#).unwrap();
        assert!(r.server.read_result(&req, Some(1000), None).is_ok(), "the policy list needs no monitor");
    }
}
