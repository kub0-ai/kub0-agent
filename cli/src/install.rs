//! `kub0 install`: the root half of a server or desktop install
//! (`scripts/install-privileged.sh` runs it for the Omarchy plugin).
//! Idempotent: every file is compared before it is written, and the unit is
//! restarted only when something it runs changed.
//!
//! On a 0.4.x host it also carries out the rename (#61 step 3), in an order
//! that never leaves two state directories or two daemons: refuse first if
//! the groups cannot be renamed cleanly; stop and remove the old units; move
//! `/var/lib/vallum` to `/var/lib/kub0`; install the renamed binaries; swap
//! the polkit policy; rename the group in place; start `kub0d.service`; and
//! only then remove the old binary paths. A host that went through 0.4.5 or
//! 0.4.6 loses what those kept for compatibility: the links at the old
//! binary paths and the unit's `vallumd` alias.

use crate::args::InstallOpts;
use crate::paths;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const UNIT_KUB0D: &str = include_str!("../../packaging/systemd/kub0d.service");
const UNIT_EXPIRY: &str = include_str!("../../packaging/systemd/kub0-expiry.service");
const TIMER_EXPIRY: &str = include_str!("../../packaging/systemd/kub0-expiry.timer");
const POLKIT_POLICY: &str = include_str!("../../polkit/ai.kub0.agent.policy");
const GEO_FILES: &[&str] = &["dbip-country-lite.mmdb", "dbip-asn-lite.mmdb", "ATTRIBUTION.txt"];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Written {
    Changed,
    Same,
}

/// Write `bytes` to `dst` with `mode` only when they differ, through a
/// temporary file in the same directory so a reader never sees a half file.
fn put(dst: &Path, bytes: &[u8], mode: u32, did: &mut Vec<String>) -> Result<Written, String> {
    if let Ok(existing) = std::fs::read(dst) {
        let same_mode = dst
            .metadata()
            .map(|m| m.permissions().mode() & 0o7777 == mode)
            .unwrap_or(false);
        if existing == bytes && same_mode {
            did.push(format!("unchanged {}", dst.display()));
            return Ok(Written::Same);
        }
    }
    let dir = dst.parent().ok_or_else(|| format!("{}: no parent", dst.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.kub0-install", dst.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dst).map_err(|e| format!("installing {}: {e}", dst.display()))?;
    did.push(format!("installed {}", dst.display()));
    Ok(Written::Changed)
}

fn put_file(src: &Path, dst: &Path, mode: u32, did: &mut Vec<String>) -> Result<Written, String> {
    let bytes = std::fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    put(dst, &bytes, mode, did)
}

fn systemctl(args: &[&str], did: &mut Vec<String>) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("systemctl {}: {e}", args.join(" ")))?;
    if !status.success() {
        return Err(format!("systemctl {} failed ({status})", args.join(" ")));
    }
    did.push(format!("systemctl {}", args.join(" ")));
    Ok(())
}

/// The GID of `group` when it exists (`getent`, so a group only a directory
/// service knows counts as taken).
fn group_gid(group: &str) -> Result<Option<u32>, String> {
    let out = Command::new("getent")
        .args(["group", group])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("getent group {group}: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&out.stdout);
    line.split(':').nth(2).and_then(|g| g.trim().parse().ok()).map(Some).ok_or_else(|| format!("getent group {group}: no GID in {line:?}"))
}

/// What happens to the status group.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupPlan {
    Keep,
    Create,
    /// `groupmod -n`: the 0.4.x group takes the new name and keeps its GID
    /// and its members.
    Rename,
}

/// The status group (`docs/system-status.md`) given which names exist and
/// their GIDs, refused before anything changes when it cannot be ours: two
/// groups are never merged, and an existing group is kept (or renamed) only
/// when it is a system group that is no account's primary group
/// (`rename::status_group_refusal`, the rule kub0d applies too). A `kub0`
/// group that was there first, a user's private group say, would otherwise be
/// handed the command socket and the installing user.
fn plan_group(new: Option<u32>, old: Option<u32>, passwd: &str, login_defs: &str) -> Result<GroupPlan, String> {
    let (new_name, old_name) = (paths::STATUS_GROUP, paths::old::STATUS_GROUP);
    let refuse = |why: String| {
        Err(format!(
            "{why}. kub0d hands its sockets only to a system group that is nobody's primary group, and kub0 install \
             never takes over a group it did not make: remove or rename that group (or move its account to another \
             primary group), then run kub0 install again. Nothing was changed."
        ))
    };
    match (new, old) {
        (Some(_), Some(_)) => Err(format!(
            "both a {new_name} group and the 0.4.x {old_name} group exist. kub0 install renames {old_name} to {new_name} in place \
             (keeping its GID and members) and never merges two groups: check who belongs in each, remove one \
             (groupdel), and run kub0 install again. Nothing was changed."
        )),
        (Some(gid), None) => match paths::rename::status_group_refusal(new_name, gid, passwd, login_defs) {
            Some(why) => refuse(why),
            None => Ok(GroupPlan::Keep),
        },
        (None, Some(gid)) => match paths::rename::status_group_refusal(old_name, gid, passwd, login_defs) {
            Some(why) => refuse(why),
            None => Ok(GroupPlan::Rename),
        },
        (None, None) => Ok(GroupPlan::Create),
    }
}

/// The system daemon resolves the status group from `/etc/group` once, at
/// start: it owns the read-only status socket and the command socket
/// (members read and raise; root lowers), and without it both stay root's.
/// The installing user is added separately (`add_installing_user`).
fn apply_group(plan: &GroupPlan, did: &mut Vec<String>) -> Result<Written, String> {
    let (new, old) = (paths::STATUS_GROUP, paths::old::STATUS_GROUP);
    let (program, args, what): (&str, Vec<&str>, String) = match plan {
        GroupPlan::Keep => {
            did.push(format!("unchanged group {new}"));
            return Ok(Written::Same);
        }
        GroupPlan::Create => ("groupadd", vec!["--system", new], format!("created group {new}")),
        GroupPlan::Rename => (
            "groupmod",
            vec!["-n", new, old],
            format!("renamed group {old} to {new} in place (same GID, same members)"),
        ),
    };
    let status = Command::new(program)
        .args(&args)
        .status()
        .map_err(|e| format!("{program} {}: {e}", args.join(" ")))?;
    if !status.success() {
        return Err(format!("{program} {} failed ({status})", args.join(" ")));
    }
    did.push(what);
    Ok(Written::Changed)
}

/// The 0.4.x unit files in `unit_dir` that must go before kub0d's: a regular
/// `vallumd.service` is a second daemon over the same state, and the old
/// expiry pair would run a second timer over the old directory. A symlink
/// named `vallumd.service` is not a unit to stop: it is the alias 0.4.5 and
/// 0.4.6 gave kub0d (`remove_old_alias` takes it out once kub0d runs).
fn old_unit_files(unit_dir: &Path) -> Vec<&'static str> {
    [paths::old::EXPIRY_TIMER, paths::old::EXPIRY_SERVICE, paths::old::UNIT]
        .into_iter()
        .filter(|u| std::fs::symlink_metadata(unit_dir.join(u)).is_ok_and(|m| !m.file_type().is_symlink()))
        .collect()
}

/// Stop, disable and remove the 0.4.x units. It runs only once everything
/// kub0d needs is staged and the group is renamed, right before the state
/// moves and kub0d starts; their files are returned so a failure after this
/// point can put them back.
fn retire_old_units(unit_dir: &Path, did: &mut Vec<String>) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let old = old_unit_files(unit_dir);
    let mut saved = Vec::new();
    for unit in &old {
        let p = unit_dir.join(unit);
        saved.push((*unit, std::fs::read(&p).map_err(|e| format!("reading {}: {e}", p.display()))?));
    }
    // `disable --now` stops it too. A unit systemd never loaded fails here,
    // which is fine as long as nothing by that name is left running.
    for unit in &old {
        let _ = Command::new("systemctl").args(["disable", "--now", unit]).stdin(Stdio::null()).status();
        if unit_active(unit) {
            return Err(format!("{unit} is still running after systemctl disable --now; stop it and run kub0 install again"));
        }
    }
    for unit in &old {
        let p = unit_dir.join(unit);
        std::fs::remove_file(&p).map_err(|e| format!("removing {}: {e}", p.display()))?;
        did.push(format!("stopped, disabled and removed the 0.4.x {}", p.display()));
    }
    Ok(saved)
}

/// The 0.4.x binary paths. 0.4.5 and 0.4.6 kept links at the first three for
/// an installed panel that still ran them, and `scripts/install-capture.sh`
/// kept the collector's. Nothing runs them now.
const OLD_BINARIES: &[&str] =
    &[paths::old::DAEMON, paths::old::HELPER, paths::old::INSTALLED_CLI, paths::old::COLLECTOR];

/// Remove what is left at the 0.4.x binary paths (a 0.4.x install's files,
/// or the links 0.4.5 and 0.4.6 made), then their directory when that
/// leaves it empty. Anything else in it is not kub0's to remove: it stays
/// and is named. Run only once kub0d is up, so a rollback still finds the
/// 0.4.x binaries.
fn remove_old_binaries(root: &Path, did: &mut Vec<String>) -> Result<(), String> {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let dir = at(paths::old::LIB_DIR);
    if std::fs::symlink_metadata(&dir).is_err() {
        return Ok(());
    }
    for old in OLD_BINARIES {
        let p = at(old);
        match std::fs::symlink_metadata(&p) {
            Err(_) => {}
            Ok(m) if m.is_dir() => did.push(format!("left {old}: a directory, not a 0.4.x binary")),
            Ok(_) => {
                std::fs::remove_file(&p).map_err(|e| format!("removing {}: {e}", p.display()))?;
                did.push(if *old == paths::old::COLLECTOR {
                    format!("removed the 0.4.x {old} (to use capture again: scripts/install-capture.sh)")
                } else {
                    format!("removed the 0.4.x {old}")
                });
            }
        }
    }
    if std::fs::remove_dir(&dir).is_ok() {
        did.push(format!("removed the empty {}", paths::old::LIB_DIR));
    } else {
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        left.sort();
        did.push(format!("left {}: it still holds {}", paths::old::LIB_DIR, left.join(", ")));
    }
    Ok(())
}

/// The 0.4.x runtime directory, which 0.4.5 and 0.4.6 made for a link to the
/// command socket. systemd removed it with the unit that listed it; the
/// unit no longer does, so after the first restart into this release it
/// would sit there until the next boot. Only the link and the directory it
/// leaves empty go: a real socket there is a 0.4.x daemon, and stays.
fn remove_old_runtime_dir(root: &Path, did: &mut Vec<String>) {
    let sock = root.join(paths::rename::OLD_SYSTEM_SOCKET.trim_start_matches('/'));
    if std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_symlink()) {
        let _ = std::fs::remove_file(&sock);
    }
    if let Some(dir) = sock.parent() {
        if std::fs::remove_dir(dir).is_ok() {
            did.push("removed the 0.4.x runtime directory and its socket link".into());
        }
    }
}

/// The `vallumd.service` alias 0.4.5 and 0.4.6 gave kub0d: a symlink in the
/// unit directory. A regular file by that name is a 0.4.x unit, which
/// `RetireOld` stops and removes first. True when it removed the alias.
fn remove_old_alias(unit_dir: &Path, did: &mut Vec<String>) -> bool {
    let alias = unit_dir.join(paths::old::UNIT);
    let is_link = std::fs::symlink_metadata(&alias).is_ok_and(|m| m.file_type().is_symlink());
    if is_link && std::fs::remove_file(&alias).is_ok() {
        did.push(format!("removed the {} alias: `systemctl status kub0d` is the name now", paths::old::UNIT));
        return true;
    }
    false
}

/// Where `kub0 install` gets the geo databases.
#[derive(Debug, PartialEq, Eq)]
enum GeoSource {
    /// Shipped beside these binaries: install or refresh them.
    Beside(PathBuf),
    /// None shipped, and kub0d's directory already holds a set: keep it.
    Installed,
    /// None shipped and none installed, but a 0.4.x install left a set in its
    /// own data directory (`paths::old::DATA_DIR`), which kub0d does not read:
    /// carry it over. A release download ships no databases, so without this
    /// an upgraded host would lose its country and ASN lookups.
    Old(PathBuf),
    Nowhere,
}

fn has_geo(dir: &Path) -> bool {
    dir.join(GEO_FILES[0]).is_file() && dir.join(GEO_FILES[1]).is_file()
}

fn geo_source(src: &Path, installed: &Path, old_data: &Path) -> GeoSource {
    if let Some(dir) = [src.join("geoip"), src.join("data/geoip"), src.join("../data/geoip")].into_iter().find(|d| has_geo(d)) {
        return GeoSource::Beside(dir);
    }
    if has_geo(installed) {
        return GeoSource::Installed;
    }
    let old = old_data.join("geoip");
    if has_geo(&old) {
        return GeoSource::Old(old);
    }
    GeoSource::Nowhere
}

/// Copy the geo files `from` holds into `to`; whether any file changed.
fn install_geo(from: &Path, to: &Path, did: &mut Vec<String>) -> Result<Written, String> {
    let mut any = Written::Same;
    for f in GEO_FILES {
        let s = from.join(f);
        if s.is_file() && put_file(&s, &to.join(f), 0o644, did)? == Written::Changed {
            any = Written::Changed;
        }
    }
    Ok(any)
}

/// Remove what an earlier install put under `/usr/share/vallum` (the geo
/// databases kub0d now reads from `/usr/share/kub0`), and the directories
/// if that leaves them empty. Nothing else there is touched.
fn remove_old_data(old_dir: &Path, did: &mut Vec<String>) {
    let geo = old_dir.join("geoip");
    for f in GEO_FILES {
        let p = geo.join(f);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) && std::fs::remove_file(&p).is_ok() {
            did.push(format!("removed {}", p.display()));
        }
    }
    for d in [&geo, old_dir] {
        if std::fs::remove_dir(d).is_ok() {
            did.push(format!("removed {}", d.display()));
        }
    }
}

/// The person running `sudo kub0 install`, from `SUDO_USER`: a non-root
/// login name, as `useradd` would take it. `None` for a root shell, an empty
/// or odd value, or a plain `kub0 install` as root with no sudo.
fn installing_user(sudo_user: Option<&str>) -> Option<String> {
    let u = sudo_user?.trim();
    if u.is_empty()
        || u == "root"
        || u.len() > 64
        || u.starts_with('-')
        || u.chars().any(|c| matches!(c, ':' | ',' | '/') || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    Some(u.to_string())
}

fn member_of(user: &str, group: &str) -> bool {
    Command::new("id")
        .args(["-nG", user])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).split_whitespace().any(|g| g == group))
        .unwrap_or(false)
}

fn quiet_success(program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} failed ({}): {}", args.join(" "), out.status, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Make the installing user a member of the status group, which owns the
/// system daemon's command socket: their `kub0` then reaches it without sudo
/// to read and to raise protection (lowering stays `sudo kub0`). `gpasswd -a`,
/// else `usermod -aG`. Not fatal: the daemon is installed either way, and the
/// step says what to do by hand.
fn add_installing_user(user: &str, did: &mut Vec<String>) {
    let group = paths::STATUS_GROUP;
    if member_of(user, group) {
        did.push(format!("unchanged: {user} in group {group}"));
        return;
    }
    let added = quiet_success("gpasswd", &["-a", user, group]).or_else(|first| {
        quiet_success("usermod", &["-aG", group, user]).map_err(|second| format!("{first}; {second}"))
    });
    match added {
        Ok(()) => did.push(format!(
            "added {user} to group {group}: kub0 reaches the system daemon without sudo to read and raise protection \
             (lowering stays `sudo kub0`); log in again for the membership to take effect"
        )),
        Err(e) => did.push(format!("could not add {user} to group {group} ({e}); run: gpasswd -a {user} {group}")),
    }
}

fn unit_active(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Where the binaries come from: `--from`, else the directory this `kub0`
/// runs from (a release tarball unpacked anywhere, or a checkout's `bin/`).
fn source_dir(opts: &InstallOpts) -> Result<PathBuf, String> {
    if let Some(d) = &opts.from {
        return Ok(d.clone());
    }
    let me = std::env::current_exe().map_err(|e| format!("current executable: {e}"))?;
    let me = std::fs::canonicalize(&me).unwrap_or(me);
    me.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot tell where this kub0 binary lives; pass --from DIR".into())
}

/// A binary from the source directory, accepting the release artifact's
/// target-suffixed name too (`kub0d-x86_64-unknown-linux-musl`). The part
/// after `name-` must be a target triple, whose architecture always holds a
/// digit (x86_64, aarch64, armv7, i686, riscv64): `kub0` must never take
/// `kub0-block-x86_64-unknown-linux-musl`, which shares its prefix.
fn find_binary(dir: &Path, name: &str) -> Option<PathBuf> {
    let plain = dir.join(name);
    if plain.is_file() {
        return Some(plain);
    }
    let prefix = format!("{name}-");
    let triple = |rest: &str| {
        rest.contains("linux")
            && !rest.ends_with(".sha256")
            && rest.split('-').next().is_some_and(|arch| arch.bytes().any(|b| b.is_ascii_digit()))
    };
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix(&prefix))
                    .is_some_and(triple)
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

const RELEASES: &str = "https://github.com/kub0-ai/kub0-agent/releases";

/// The error when the source directory lacks a binary. The installed copy
/// (`/usr/bin/kub0`) run with no `--from` looks beside itself in `/usr/bin`,
/// where only the CLI lives, and `--from` there would only reinstall this same
/// version: say how to upgrade instead.
fn missing_binary(name: &str, src: &Path, from_given: bool) -> String {
    if !from_given && Some(src) == Path::new(paths::CLI_LINK).parent() {
        return format!(
            "this is the installed kub0 {}, which installs only the files beside it ({} has no {name}). \
             To upgrade, unpack a newer release and run its kub0: sudo ./kub0 install. Releases: {RELEASES}",
            env!("CARGO_PKG_VERSION"),
            src.display()
        );
    }
    format!("no {name} in {}; pass --from DIR", src.display())
}

pub fn run(opts: &InstallOpts) -> i32 {
    match install(opts) {
        Ok(did) => {
            println!("done. {} step(s):", did.len());
            for d in &did {
                println!("  - {d}");
            }
            0
        }
        Err(e) => {
            eprintln!("kub0 install: {e}");
            1
        }
    }
}

/// One step of an install, in the order `plan` gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// kub0d, kub0-block and kub0 under /usr/lib/kub0, and /usr/bin/kub0.
    Binaries,
    /// ai.kub0.agent.policy (the 0.4.x policy stays until kub0d runs).
    Polkit,
    Geo,
    /// The exec gate's directory, under the state directory in use.
    Execgate,
    /// kub0d.service and kub0-expiry.*, written but not enabled.
    Units,
    DaemonReload,
    /// groupadd, or groupmod -n: the running 0.4.x daemon read its group at
    /// start, so a rename does not reach it.
    Group,
    AddUser,
    /// Stop, disable and remove vallumd.service and vallum-expiry.*; their
    /// files are kept for a rollback.
    RetireOld,
    /// /var/lib/vallum to /var/lib/kub0, never while a 0.4.x daemon runs.
    MoveState,
    /// enable --now kub0-expiry.timer and kub0d.service (or restart it).
    Start,
    /// The 0.4.x binary paths, their directory and the unit alias go, only
    /// once kub0d runs: a rollback has to find the 0.4.x binaries.
    DropOldBinaries,
    /// The 0.4.x policy and geo data.
    DropOld,
    /// No systemd: how to start kub0d.
    StartLine,
    /// --no-start on a host vallumd.service still runs: nothing switches.
    NotSwitched,
}

/// What `plan` needs to know about the host.
#[derive(Debug, Clone, Copy)]
struct Host {
    systemd: bool,
    start: bool,
    /// vallumd.service or vallum-expiry.* are installed (regular files).
    old_units: bool,
}

/// The order of an install. Everything kub0d needs is staged at new paths
/// first, the group after that; only then does the 0.4.x daemon stop, its
/// state move and kub0d start, so a failure in any staging step leaves the
/// 0.4.x daemon running and enabled. `--no-start` on a host whose
/// vallumd.service is installed stages and stops there: it never retires the
/// running daemon, renames its group or moves its state, and says so.
fn plan(host: Host) -> Vec<Step> {
    use Step::*;
    let mut steps = vec![Binaries, Polkit, Geo, Execgate];
    if !host.systemd {
        steps.extend([Group, AddUser, MoveState, DropOldBinaries, DropOld, StartLine]);
        return steps;
    }
    steps.extend([Units, DaemonReload]);
    if !host.start && host.old_units {
        steps.push(NotSwitched);
        return steps;
    }
    steps.extend([Group, AddUser]);
    if host.old_units {
        steps.push(RetireOld);
    }
    steps.push(MoveState);
    if host.start {
        steps.push(Start);
    }
    steps.extend([DropOldBinaries, DropOld]);
    steps
}

/// Carries out one step; `rollback` undoes a switch that failed part way.
trait Exec {
    fn step(&mut self, step: Step) -> Result<(), String>;
    /// After `RetireOld` succeeded and `MoveState` or `Start` failed: put the
    /// 0.4.x daemon back as it was. What it did, for the error.
    fn rollback(&mut self) -> Vec<String>;
}

/// Run `steps` in order and stop at the first error. One that fails after
/// the 0.4.x units were retired and before kub0d runs rolls the switch back,
/// so the host is never left with neither daemon enabled.
fn execute(steps: &[Step], exec: &mut dyn Exec) -> Result<(), String> {
    let mut retired = false;
    let mut started = false;
    for &step in steps {
        if let Err(e) = exec.step(step) {
            if retired && !started {
                let undone = exec.rollback();
                return Err(format!("{e}; rolled back: {}", undone.join("; ")));
            }
            return Err(e);
        }
        retired |= step == Step::RetireOld;
        started |= step == Step::Start;
    }
    Ok(())
}

/// A 0.4.x system daemon is running (its process, or its socket answering).
fn old_system_daemon_running() -> Option<String> {
    use std::os::unix::fs::FileTypeExt;
    if paths::rename::old_daemon_running_in(Path::new("/proc"), 0, paths::rename::OldDaemon::System) {
        return Some("a 0.4.x vallumd --system is running".into());
    }
    let sock = Path::new(paths::rename::OLD_SYSTEM_SOCKET);
    let live = std::fs::symlink_metadata(sock).is_ok_and(|m| m.file_type().is_socket())
        && std::os::unix::net::UnixStream::connect(sock).is_ok();
    live.then(|| format!("a 0.4.x daemon answers on {}", sock.display()))
}

/// Without systemd nothing can stop a running 0.4.x daemon, so the install
/// refuses before it changes anything: moving its state would leave it
/// writing to a vanished directory, and kub0d started beside it would be a
/// second exec gate. With systemd, `RetireOld` stops it first.
fn refuse_beside_a_running_old_daemon(host: Host, running: impl FnOnce() -> Option<String>) -> Result<(), String> {
    if host.systemd {
        return Ok(());
    }
    match running() {
        Some(why) => Err(format!(
            "{why}. Without systemd kub0 install cannot stop it, and kub0d beside it would be a second exec gate \
             over a state directory still in use: stop vallumd from your init first, then run kub0 install again. \
             Nothing was changed."
        )),
        None => Ok(()),
    }
}

/// The real install, step by step.
struct Installer<'a> {
    opts: &'a InstallOpts,
    src: PathBuf,
    daemon_src: PathBuf,
    helper_src: PathBuf,
    cli_src: PathBuf,
    group_plan: GroupPlan,
    did: Vec<String>,
    changed: bool,
    units_changed: bool,
    saved_units: Vec<(&'static str, Vec<u8>)>,
    moved: bool,
}

impl Installer<'_> {
    fn mark(&mut self, w: Written) {
        self.changed |= w == Written::Changed;
    }
}

impl Exec for Installer<'_> {
    fn step(&mut self, step: Step) -> Result<(), String> {
        let unit_dir = Path::new(paths::UNIT_DIR);
        match step {
            Step::Binaries => {
                std::fs::create_dir_all(paths::LIB_DIR).map_err(|e| format!("creating {}: {e}", paths::LIB_DIR))?;
                let w = put_file(&self.daemon_src, Path::new(paths::DAEMON), 0o755, &mut self.did)?;
                self.mark(w);
                put_file(&self.helper_src, Path::new(paths::HELPER), 0o755, &mut self.did)?;
                put_file(&self.cli_src, Path::new(paths::INSTALLED_CLI), 0o755, &mut self.did)?;
                // /usr/bin/kub0 is a copy, not a symlink: the daemon's protected-path
                // rules refuse symlinks, and a copy keeps working if /usr/lib/kub0 is
                // ever reinstalled while a shell has the old one open.
                put_file(&self.cli_src, Path::new(paths::CLI_LINK), 0o755, &mut self.did)?;
            }
            Step::Polkit => {
                if self.opts.polkit && Path::new(paths::POLKIT_DIR).is_dir() {
                    put(Path::new(paths::POLKIT_POLICY), POLKIT_POLICY.as_bytes(), 0o644, &mut self.did)?;
                } else if self.opts.polkit {
                    self.did.push(format!("no {} on this host; polkit policy skipped (servers do not need it)", paths::POLKIT_DIR));
                }
            }
            Step::Geo => {
                if !self.opts.geo {
                    return Ok(());
                }
                let geo_dir = Path::new(paths::GEO_DIR);
                // The daemon reads the geo databases once, at start.
                match geo_source(&self.src, geo_dir, Path::new(paths::old::DATA_DIR)) {
                    GeoSource::Beside(dir) => {
                        let w = install_geo(&dir, geo_dir, &mut self.did)?;
                        self.mark(w);
                    }
                    GeoSource::Installed => {
                        self.did.push(format!("no geo databases beside the binaries; keeping the ones in {}", paths::GEO_DIR));
                    }
                    GeoSource::Old(dir) => {
                        self.did.push(format!("no geo databases beside the binaries; carrying over the ones a 0.4.x install left in {}", dir.display()));
                        let w = install_geo(&dir, geo_dir, &mut self.did)?;
                        self.mark(w);
                    }
                    GeoSource::Nowhere => self.did.push("no geo databases beside the binaries; the system daemon applies no country rules without them".into()),
                }
            }
            Step::Execgate => {
                // The directory in use: /var/lib/vallum's until it moves, so this
                // never starts a second state directory.
                let execgate = paths::execgate_dir();
                if !execgate.is_dir() {
                    // The state root is made 0755 on the way (the helper's
                    // `status` runs as any user); the gate's own directory
                    // starts root's alone, and the daemon gives it to the
                    // kub0 group when it starts.
                    paths::rename::create_state_dir(&execgate, 0o755).map_err(|e| format!("creating {}: {e}", execgate.display()))?;
                    std::fs::set_permissions(&execgate, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
                        .map_err(|e| format!("closing {}: {e}", execgate.display()))?;
                    self.did.push(format!("created {}", execgate.display()));
                }
            }
            Step::Units => {
                let mut w = put(&unit_dir.join(paths::UNIT), UNIT_KUB0D.as_bytes(), 0o644, &mut self.did)?;
                for (name, text) in [(paths::EXPIRY_SERVICE, UNIT_EXPIRY), (paths::EXPIRY_TIMER, TIMER_EXPIRY)] {
                    if put(&unit_dir.join(name), text.as_bytes(), 0o644, &mut self.did)? == Written::Changed {
                        w = Written::Changed;
                    }
                }
                self.units_changed = w == Written::Changed;
                self.mark(w);
            }
            Step::DaemonReload => {
                if self.units_changed {
                    systemctl(&["daemon-reload"], &mut self.did)?;
                }
            }
            Step::Group => {
                let w = apply_group(&self.group_plan, &mut self.did)?;
                self.mark(w);
            }
            Step::AddUser => {
                if let Some(user) = installing_user(std::env::var("SUDO_USER").ok().as_deref()) {
                    add_installing_user(&user, &mut self.did);
                }
            }
            Step::RetireOld => {
                self.saved_units = retire_old_units(unit_dir, &mut self.did)?;
                systemctl(&["daemon-reload"], &mut self.did)?;
            }
            Step::MoveState => {
                if let Some(why) = old_system_daemon_running() {
                    return Err(format!("{why}; {} stays where it is: stop it first", paths::rename::OLD_STATE_ROOT));
                }
                let (old, new) = (paths::rename::OLD_STATE_ROOT, paths::rename::STATE_ROOT);
                match paths::rename::move_system_state() {
                    Ok(paths::rename::Moved::Moved) => {
                        self.moved = true;
                        self.changed = true;
                        self.did.push(format!("moved {old} to {new} (account, exec-gate trusts, scoped and block records)"));
                    }
                    Ok(paths::rename::Moved::NothingToMove) => {}
                    Ok(paths::rename::Moved::BothExist) => self.did.push(format!(
                        "{new} and {old} both hold state: {new} is the one in use, and {old} was left untouched (check it, then remove it)"
                    )),
                    Err(e) => self.did.push(format!(
                        "could not move {old} to {new} ({e}); kub0d keeps using {old} until it can, and `kub0 doctor` fails until then"
                    )),
                }
            }
            Step::Start => {
                systemctl(&["enable", "--now", paths::EXPIRY_TIMER], &mut self.did)?;
                if unit_active(paths::UNIT) {
                    // A group created or renamed now is one the running daemon looked
                    // for at start and did not find under that name: its sockets need
                    // the restart as much as a new binary does.
                    if self.changed {
                        systemctl(&["restart", paths::UNIT], &mut self.did)?;
                    } else {
                        self.did.push("kub0d already running; nothing to restart".into());
                    }
                } else {
                    systemctl(&["enable", "--now", paths::UNIT], &mut self.did)?;
                }
            }
            Step::DropOldBinaries => {
                remove_old_binaries(Path::new("/"), &mut self.did)?;
                remove_old_runtime_dir(Path::new("/"), &mut self.did);
                if remove_old_alias(Path::new(paths::UNIT_DIR), &mut self.did) {
                    let _ = Command::new("systemctl").arg("daemon-reload").stdin(Stdio::null()).status();
                }
            }
            Step::DropOld => {
                // The 0.4.x policies declare actions for paths that are gone.
                if Path::new(paths::POLKIT_POLICY).is_file() {
                    for old in [paths::old::POLKIT_POLICY, paths::old::CAPTURE_POLICY] {
                        if std::fs::remove_file(old).is_ok() {
                            self.did.push(format!("removed the 0.4.x {old}"));
                        }
                    }
                }
                if Path::new(paths::GEO_DIR).join(GEO_FILES[0]).is_file() {
                    remove_old_data(Path::new(paths::old::DATA_DIR), &mut self.did);
                }
            }
            Step::StartLine => self.did.push(format!(
                "no systemd on this host: start `{} --system --interval-ms 500` as root from your init (KUB0_EXEC_GATE=1 for the exec gate)",
                paths::DAEMON
            )),
            Step::NotSwitched => self.did.push(
                "not started (--no-start), and nothing switched: vallumd.service still runs and owns /var/lib/vallum; \
                 run `sudo kub0 install` without --no-start to switch to kub0d"
                    .into(),
            ),
        }
        Ok(())
    }

    fn rollback(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let unit_dir = Path::new(paths::UNIT_DIR);
        // An alias link from 0.4.5 or 0.4.6 would sit where vallumd.service goes back.
        let _ = Command::new("systemctl").args(["disable", "--now", paths::UNIT, paths::EXPIRY_TIMER]).stdin(Stdio::null()).status();
        out.push(format!("disabled {} and {}", paths::UNIT, paths::EXPIRY_TIMER));
        if self.moved {
            let (old, new) = (Path::new(paths::rename::OLD_STATE_ROOT), Path::new(paths::rename::STATE_ROOT));
            out.push(match paths::rename::move_state(new, old) {
                Ok(paths::rename::Moved::Moved) => format!("moved {} back to {}", new.display(), old.display()),
                other => format!("left {} where it is ({other:?})", new.display()),
            });
        }
        for (unit, bytes) in &self.saved_units {
            let p = unit_dir.join(unit);
            out.push(match std::fs::write(&p, bytes) {
                Ok(()) => format!("restored {}", p.display()),
                Err(e) => format!("could not restore {} ({e})", p.display()),
            });
        }
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let back: Vec<&str> = self.saved_units.iter().map(|(u, _)| *u).filter(|u| *u != paths::old::EXPIRY_SERVICE).collect();
        if !back.is_empty() {
            let ok = Command::new("systemctl").args(["enable", "--now"]).args(&back).status().is_ok_and(|s| s.success());
            out.push(format!("{} {}", if ok { "re-enabled and started" } else { "could not re-enable" }, back.join(", ")));
        }
        out
    }
}

fn install(opts: &InstallOpts) -> Result<Vec<String>, String> {
    if paths::euid() != 0 {
        return Err("needs root: sudo kub0 install".into());
    }
    let src = source_dir(opts)?;
    let from_given = opts.from.is_some();
    let daemon_src = find_binary(&src, "kub0d").ok_or_else(|| missing_binary("kub0d", &src, from_given))?;
    let helper_src = find_binary(&src, "kub0-block").ok_or_else(|| missing_binary("kub0-block", &src, from_given))?;
    let cli_src = find_binary(&src, "kub0")
        .or_else(|| std::env::current_exe().ok())
        .ok_or("no kub0 binary to install")?;
    // Refused here, before anything changes, rather than half way through.
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let login_defs = std::fs::read_to_string("/etc/login.defs").unwrap_or_default();
    let group_plan = plan_group(group_gid(paths::STATUS_GROUP)?, group_gid(paths::old::STATUS_GROUP)?, &passwd, &login_defs)?;
    let host = Host {
        systemd: Path::new("/run/systemd/system").is_dir(),
        start: opts.start,
        old_units: !old_unit_files(Path::new(paths::UNIT_DIR)).is_empty(),
    };
    refuse_beside_a_running_old_daemon(host, old_system_daemon_running)?;
    let mut installer = Installer {
        opts,
        src,
        daemon_src,
        helper_src,
        cli_src,
        group_plan,
        did: Vec::new(),
        changed: false,
        units_changed: false,
        saved_units: Vec::new(),
        moved: false,
    };
    let steps = plan(host);
    match execute(&steps, &mut installer) {
        Ok(()) => {
            // One daemon (#61): the panel reads this daemon from now on, so what the
            // person installing it set in the panel's own daemon comes along.
            if steps.contains(&Step::Start) {
                if let Some(user) = installing_user(std::env::var("SUDO_USER").ok().as_deref()) {
                    installer.did.extend(crate::carry::after_install(&user, &paths::system_socket(), &paths::daemon_state()));
                }
            }
            if steps.contains(&Step::Start) || steps.contains(&Step::StartLine) {
                // Accounts are not open to the public yet, so logging in is not
                // everyone's next step.
                installer.did.push("next: `kub0 doctor`. With a kub0 account, `sudo kub0 login` joins your org".into());
            } else if !steps.contains(&Step::NotSwitched) {
                installer.did.push("not started (--no-start)".into());
            }
            Ok(installer.did)
        }
        Err(e) => {
            for d in &installer.did {
                eprintln!("  - {d}");
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_units_are_the_packaged_ones() {
        assert!(UNIT_KUB0D.contains("ExecStart=/usr/lib/kub0/kub0d --system"));
        assert!(
            UNIT_KUB0D.contains("After=network-online.target") && UNIT_KUB0D.contains("Wants=network-online.target"),
            "without both, the daemon starts before the network and its first syncs fail DNS"
        );
        assert!(UNIT_EXPIRY.contains("expire-scoped"));
        assert!(TIMER_EXPIRY.contains("kub0-expiry.service"));
        assert!(POLKIT_POLICY.contains("execgate-trust"), "a policy without the exec-gate actions cannot authorize them");
        // `kub0` re-runs itself through pkexec at the copy it installs on PATH.
        assert!(
            POLKIT_POLICY.contains(&format!(">{}<", paths::CLI_LINK)) && POLKIT_POLICY.contains(&format!(">{}<", paths::INSTALLED_CLI)),
            "the policy must name every kub0 path install writes"
        );
        assert_eq!(crate::elevate::pkexec_argv(&[])[0], paths::CLI_LINK);
    }

    /// The unit still moves a 0.4.x host's state outside its sandbox before
    /// the daemon starts and does not let systemd create /var/lib/kub0 ahead
    /// of the move. What 0.4.5 and 0.4.6 added beside that is gone: it does
    /// not answer to the old name and makes no old socket directory.
    #[test]
    fn the_unit_moves_old_state_and_answers_to_one_name() {
        let install = UNIT_KUB0D.split("[Install]").nth(1).unwrap();
        assert!(!install.lines().any(|l| l.starts_with("Alias=")), "kub0d.service is the only name:\n{install}");
        let service = UNIT_KUB0D.split("[Service]").nth(1).unwrap().split("[Install]").next().unwrap();
        let line = |k: &str| service.lines().find(|l| l.starts_with(k)).unwrap_or_else(|| panic!("no {k}"));
        assert_eq!(line("ExecStartPre="), "ExecStartPre=+/usr/lib/kub0/kub0d migrate-state", "outside the sandbox ('+')");
        assert_eq!(line("RuntimeDirectory="), "RuntimeDirectory=kub0", "no /run directory under the old name");
        assert_eq!(line("ReadWritePaths="), "ReadWritePaths=-/var/lib/kub0 -/var/lib/vallum");
        assert_eq!(line("Environment="), "Environment=KUB0_EXEC_GATE=1");
        assert!(!service.lines().any(|l| l.starts_with("StateDirectory=")), "systemd would create /var/lib/kub0 before the move");
        assert!(UNIT_EXPIRY.contains("ConditionPathIsDirectory=|/var/lib/kub0/scoped"));
        assert!(UNIT_EXPIRY.contains("ConditionPathIsDirectory=|/var/lib/vallum/scoped"), "expiry runs wherever the records are");
        assert!(UNIT_EXPIRY.contains("ExecStart=/usr/lib/kub0/kub0-block expire-scoped"));
    }

    #[test]
    fn the_groups_are_renamed_in_place_and_never_merged() {
        assert_eq!(plan_group(Some(975), None, "", "").unwrap(), GroupPlan::Keep);
        assert_eq!(plan_group(None, None, "", "").unwrap(), GroupPlan::Create);
        assert_eq!(plan_group(None, Some(975), "", "").unwrap(), GroupPlan::Rename, "groupmod -n keeps the GID and the members");
        let e = plan_group(Some(975), Some(976), "", "").unwrap_err();
        assert!(e.contains("never merges") && e.contains("Nothing was changed"), "{e}");
    }

    /// A `kub0` group that was there first is never taken over: not a
    /// user's private group, not any account's primary group, not a group
    /// outside the system range. The same rule kub0d applies.
    #[test]
    fn an_existing_group_is_kept_only_when_it_is_a_system_group_nobody_has_as_primary() {
        let passwd = "root:x:0:0::/root:/bin/sh\nkub0:x:1001:1001::/home/kub0:/bin/sh\nsvc:x:950:975::/:/bin/false\n";
        let upg = plan_group(Some(1001), None, passwd, "").unwrap_err();
        assert!(upg.contains("outside this host's system GIDs") && upg.contains("Nothing was changed"), "{upg}");
        let primary = plan_group(Some(975), None, passwd, "").unwrap_err();
        assert!(primary.contains("primary group of the account svc"), "{primary}");
        assert_eq!(plan_group(Some(980), None, passwd, "").unwrap(), GroupPlan::Keep);
        let ranged = plan_group(Some(980), None, passwd, "SYS_GID_MIN 101\nSYS_GID_MAX 499\n").unwrap_err();
        assert!(ranged.contains("101-499"), "{ranged}");
        // The 0.4.x group is renamed only under the same rule.
        assert!(plan_group(None, Some(1001), passwd, "").is_err());
    }

    use std::cell::RefCell;

    /// Records the steps it ran, and fails at one of them.
    struct Mock {
        ran: RefCell<Vec<Step>>,
        fail_at: Option<Step>,
        rolled_back: usize,
    }

    impl Exec for Mock {
        fn step(&mut self, step: Step) -> Result<(), String> {
            self.ran.borrow_mut().push(step);
            if self.fail_at == Some(step) {
                Err(format!("{step:?} failed"))
            } else {
                Ok(())
            }
        }
        fn rollback(&mut self) -> Vec<String> {
            self.rolled_back += 1;
            vec!["put vallumd back".into()]
        }
    }

    fn mock(fail_at: Option<Step>) -> Mock {
        Mock { ran: RefCell::new(Vec::new()), fail_at, rolled_back: 0 }
    }

    const UPGRADE: Host = Host { systemd: true, start: true, old_units: true };

    /// Everything kub0d needs is staged, and the group renamed, before the
    /// 0.4.x daemon is retired; its state moves and kub0d starts after that,
    /// and the old binary paths become links only once kub0d runs.
    #[test]
    fn the_old_daemon_is_retired_only_after_everything_is_staged() {
        let steps = plan(UPGRADE);
        let at = |s: Step| steps.iter().position(|x| *x == s).unwrap_or_else(|| panic!("{s:?} missing from {steps:?}"));
        for staged in [Step::Binaries, Step::Polkit, Step::Geo, Step::Execgate, Step::Units, Step::DaemonReload, Step::Group, Step::AddUser] {
            assert!(at(staged) < at(Step::RetireOld), "{staged:?} after RetireOld: {steps:?}");
        }
        assert!(at(Step::RetireOld) < at(Step::MoveState) && at(Step::MoveState) < at(Step::Start));
        assert!(at(Step::Start) < at(Step::DropOldBinaries) && at(Step::Start) < at(Step::DropOld));
    }

    /// A failure anywhere before the switch leaves vallumd.service in place,
    /// running and enabled; one between retiring it and kub0d running puts it
    /// back; one after kub0d runs leaves kub0d.
    #[test]
    fn a_failure_after_staging_leaves_the_old_units_in_place() {
        let steps = plan(UPGRADE);
        for fail in [Step::Binaries, Step::Polkit, Step::Geo, Step::Execgate, Step::Units, Step::DaemonReload, Step::Group, Step::AddUser] {
            let mut m = mock(Some(fail));
            assert!(execute(&steps, &mut m).is_err());
            assert!(!m.ran.borrow().contains(&Step::RetireOld), "{fail:?} failed and vallumd was retired anyway");
            assert_eq!(m.rolled_back, 0);
        }
        for fail in [Step::MoveState, Step::Start] {
            let mut m = mock(Some(fail));
            let e = execute(&steps, &mut m).unwrap_err();
            assert_eq!(m.rolled_back, 1, "{fail:?}: the switch is undone");
            assert!(e.contains("rolled back: put vallumd back"), "{e}");
        }
        let mut m = mock(Some(Step::DropOldBinaries));
        assert!(execute(&steps, &mut m).is_err());
        assert_eq!(m.rolled_back, 0, "kub0d already runs");
        let mut m = mock(None);
        execute(&steps, &mut m).unwrap();
        assert_eq!(*m.ran.borrow(), steps);
    }

    #[test]
    fn without_systemd_a_running_old_daemon_stops_the_install_before_anything_changes() {
        let init = Host { systemd: false, start: true, old_units: false };
        let e = refuse_beside_a_running_old_daemon(init, || Some("a 0.4.x vallumd --system is running".into())).unwrap_err();
        assert!(e.contains("stop vallumd from your init first") && e.contains("Nothing was changed"), "{e}");
        assert!(refuse_beside_a_running_old_daemon(init, || None).is_ok());
        assert!(refuse_beside_a_running_old_daemon(UPGRADE, || panic!("systemd stops it in RetireOld")).is_ok());
    }

    /// `--no-start` on a host vallumd.service still runs stages and stops:
    /// no retire, no group rename, no move.
    #[test]
    fn no_start_on_an_old_host_switches_nothing() {
        let steps = plan(Host { start: false, ..UPGRADE });
        assert_eq!(steps.last(), Some(&Step::NotSwitched));
        for never in [Step::RetireOld, Step::MoveState, Step::Group, Step::Start, Step::DropOldBinaries] {
            assert!(!steps.contains(&never), "{never:?} in {steps:?}");
        }
        let fresh = plan(Host { start: false, old_units: false, ..UPGRADE });
        assert!(fresh.contains(&Step::MoveState) && !fresh.contains(&Step::Start) && !fresh.contains(&Step::NotSwitched));
        let init = plan(Host { systemd: false, start: true, old_units: false });
        assert!(init.contains(&Step::MoveState) && init.contains(&Step::StartLine));
        assert!(!init.contains(&Step::RetireOld) && !init.contains(&Step::Units));
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kub0-install-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_old_units_are_regular_files_and_the_alias_is_not_one() {
        let d = scratch("units");
        assert!(old_unit_files(&d).is_empty());
        for u in ["vallumd.service", "vallum-expiry.service", "vallum-expiry.timer"] {
            std::fs::write(d.join(u), b"[Unit]").unwrap();
        }
        assert_eq!(old_unit_files(&d), ["vallum-expiry.timer", "vallum-expiry.service", "vallumd.service"], "the timer stops first");
        std::fs::remove_file(d.join("vallumd.service")).unwrap();
        std::os::unix::fs::symlink(d.join("kub0d.service"), d.join("vallumd.service")).unwrap();
        assert!(!old_unit_files(&d).contains(&"vallumd.service"), "the alias is not a unit to stop");
        // ...and it goes once kub0d runs. A regular file by that name is not it.
        let mut did = Vec::new();
        assert!(remove_old_alias(&d, &mut did));
        assert!(std::fs::symlink_metadata(d.join("vallumd.service")).is_err(), "the alias is gone");
        assert_eq!(did, ["removed the vallumd.service alias: `systemctl status kub0d` is the name now"]);
        assert!(!remove_old_alias(&d, &mut did), "nothing to remove the second time");
        std::fs::write(d.join("vallumd.service"), b"[Unit]").unwrap();
        assert!(!remove_old_alias(&d, &mut did), "a 0.4.x unit file is RetireOld's, not this");
        assert!(d.join("vallumd.service").is_file());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 0.4.5 and 0.4.6 left links at the 0.4.x binary paths. Now whatever is
    /// there goes (a 0.4.x install's own files, or those links), and the
    /// directory with it unless it holds something that is not kub0's.
    #[test]
    fn the_old_binary_paths_and_their_directory_are_removed() {
        let root = scratch("old-binaries");
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        let mut did = Vec::new();
        std::fs::create_dir_all(at(paths::LIB_DIR)).unwrap();
        std::fs::write(at(paths::HELPER), b"renamed").unwrap();
        remove_old_binaries(&root, &mut did).unwrap();
        assert!(did.is_empty(), "a fresh host has nothing to remove: {did:?}");

        // An upgraded host: a hard link, two symlinks and the old collector.
        std::fs::create_dir_all(at(paths::old::LIB_DIR)).unwrap();
        std::fs::write(at(paths::old::DAEMON), b"0.4.x").unwrap();
        std::os::unix::fs::symlink(at(paths::HELPER), at(paths::old::HELPER)).unwrap();
        std::os::unix::fs::symlink("/nowhere/kub0", at(paths::old::INSTALLED_CLI)).unwrap();
        std::fs::write(at(paths::old::COLLECTOR), b"collector").unwrap();
        remove_old_binaries(&root, &mut did).unwrap();
        assert!(std::fs::symlink_metadata(at(paths::old::LIB_DIR)).is_err(), "the directory is gone: {did:?}");
        assert!(at(paths::HELPER).is_file(), "a link was removed, never what it pointed at");
        assert_eq!(did.len(), 5, "{did:?}");
        assert!(did[3].contains("vallum-capture") && did[3].contains("scripts/install-capture.sh"), "{did:?}");
        assert_eq!(did[4], "removed the empty /usr/lib/vallum");

        // Something there that kub0 did not put: it stays, named, with its directory.
        did.clear();
        std::fs::create_dir_all(at(paths::old::LIB_DIR)).unwrap();
        std::fs::write(at(paths::old::DAEMON), b"0.4.x").unwrap();
        std::fs::write(at(paths::old::LIB_DIR).join("notes.txt"), b"mine").unwrap();
        remove_old_binaries(&root, &mut did).unwrap();
        assert!(std::fs::symlink_metadata(at(paths::old::DAEMON)).is_err());
        assert!(at(paths::old::LIB_DIR).join("notes.txt").is_file());
        assert_eq!(did.last().map(String::as_str), Some("left /usr/lib/vallum: it still holds notes.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The unit no longer lists the 0.4.x runtime directory, so systemd no
    /// longer removes it: the install does, when all it holds is the link.
    #[test]
    fn the_old_runtime_directory_goes_with_its_link_and_never_with_a_socket() {
        let root = scratch("old-run");
        let sock = root.join(paths::rename::OLD_SYSTEM_SOCKET.trim_start_matches('/'));
        let dir = sock.parent().unwrap().to_path_buf();
        let mut did = Vec::new();
        remove_old_runtime_dir(&root, &mut did);
        assert!(did.is_empty(), "nothing there: {did:?}");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/run/kub0/kub0.sock", &sock).unwrap();
        remove_old_runtime_dir(&root, &mut did);
        assert!(std::fs::symlink_metadata(&dir).is_err(), "the directory is gone");
        assert_eq!(did, ["removed the 0.4.x runtime directory and its socket link"]);
        // A 0.4.x daemon's own socket: not a link, so nothing is touched.
        did.clear();
        std::fs::create_dir_all(&dir).unwrap();
        let live = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        remove_old_runtime_dir(&root, &mut did);
        assert!(std::fs::symlink_metadata(&sock).is_ok() && did.is_empty(), "{did:?}");
        drop(live);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_the_installed_geo_files_leave_the_old_data_dir() {
        let d = scratch("data");
        let mut did = Vec::new();
        std::fs::create_dir_all(d.join("geoip")).unwrap();
        for f in GEO_FILES {
            std::fs::write(d.join("geoip").join(f), b"x").unwrap();
        }
        std::fs::write(d.join("geoip/mine.mmdb"), b"someone else's").unwrap();
        remove_old_data(&d, &mut did);
        assert!(d.join("geoip/mine.mmdb").exists(), "a file install did not put there stays");
        assert!(GEO_FILES.iter().all(|f| !d.join("geoip").join(f).exists()));
        std::fs::remove_file(d.join("geoip/mine.mmdb")).unwrap();
        remove_old_data(&d, &mut did);
        assert!(!d.exists(), "empty directories go");
    }

    // 0.4.5 moved the daemon's data directory; a release download ships no
    // databases, so an upgraded host's set has to come from the old directory.
    #[test]
    fn an_upgrade_from_a_release_carries_the_geo_databases_over() {
        let root = scratch("geo-carry");
        let (release, new, old) = (root.join("release"), root.join("usr/share/kub0/geoip"), root.join("usr/share/vallum"));
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(old.join("geoip")).unwrap();
        for f in GEO_FILES {
            std::fs::write(old.join("geoip").join(f), f.as_bytes()).unwrap();
        }
        let source = geo_source(&release, &new, &old);
        assert_eq!(source, GeoSource::Old(old.join("geoip")));
        let mut did = Vec::new();
        assert_eq!(install_geo(&old.join("geoip"), &new, &mut did).unwrap(), Written::Changed);
        for f in GEO_FILES {
            assert_eq!(std::fs::read(new.join(f)).unwrap(), f.as_bytes(), "{f} is where kub0d reads it");
        }
        // What DropOld does once the new directory holds a set.
        remove_old_data(&old, &mut did);
        assert!(!old.exists(), "the old copy goes only after the new one is in place");
        // The next install from a release keeps them, and says so.
        assert_eq!(geo_source(&release, &new, &old), GeoSource::Installed);
        assert_eq!(install_geo(&new, &new, &mut did).unwrap(), Written::Same);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn geo_databases_beside_the_binaries_win_and_none_anywhere_is_said() {
        let root = scratch("geo-source");
        let (src, new, old) = (root.join("src"), root.join("new"), root.join("old"));
        std::fs::create_dir_all(&src).unwrap();
        assert_eq!(geo_source(&src, &new, &old), GeoSource::Nowhere);
        // One file of the pair is not a set.
        std::fs::create_dir_all(old.join("geoip")).unwrap();
        std::fs::write(old.join("geoip").join(GEO_FILES[0]), b"x").unwrap();
        assert_eq!(geo_source(&src, &new, &old), GeoSource::Nowhere);
        std::fs::write(old.join("geoip").join(GEO_FILES[1]), b"x").unwrap();
        for dir in [&new, &src.join("data/geoip")] {
            std::fs::create_dir_all(dir).unwrap();
            for f in GEO_FILES {
                std::fs::write(dir.join(f), b"x").unwrap();
            }
        }
        assert_eq!(geo_source(&src, &new, &old), GeoSource::Beside(src.join("data/geoip")), "a shipped set refreshes the installed one");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn put_is_idempotent_and_atomic() {
        let dir = std::env::temp_dir().join(format!("kub0-install-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dst = dir.join("unit");
        let mut did = Vec::new();
        assert_eq!(put(&dst, b"one", 0o644, &mut did).unwrap(), Written::Changed);
        assert_eq!(put(&dst, b"one", 0o644, &mut did).unwrap(), Written::Same);
        assert_eq!(put(&dst, b"one", 0o755, &mut did).unwrap(), Written::Changed, "a mode change is a change");
        assert_eq!(put(&dst, b"two", 0o755, &mut did).unwrap(), Written::Changed);
        assert_eq!(std::fs::read(&dst).unwrap(), b"two");
        assert_eq!(dst.metadata().unwrap().permissions().mode() & 0o7777, 0o755);
        assert!(!dir.join(".unit.kub0-install").exists(), "no temp file left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_installing_user_is_sudo_user_when_it_is_a_person() {
        assert_eq!(installing_user(Some("alice")), Some("alice".into()));
        assert_eq!(installing_user(Some(" alice ")), Some("alice".into()));
        assert_eq!(installing_user(Some("ad.user_1-x$")), Some("ad.user_1-x$".into()), "a samba machine-style name");
        for none in [None, Some(""), Some("root"), Some("-G"), Some("a:b"), Some("a,b"), Some("a b"), Some("../x"), Some("a\nb")] {
            assert_eq!(installing_user(none), None, "{none:?}");
        }
        assert_eq!(installing_user(Some(&"x".repeat(65))), None);
    }

    #[test]
    fn the_installed_copy_says_how_to_upgrade() {
        // `sudo kub0 install` from /usr/bin/kub0 said "no <daemon> in /usr/bin;
        // pass --from DIR" (operator, 2026-11-05 and 11-11).
        let usr_bin = Path::new(paths::CLI_LINK).parent().unwrap();
        let m = missing_binary("kub0d", usr_bin, false);
        assert!(m.starts_with("this is the installed kub0 "), "{m}");
        assert!(m.contains("sudo ./kub0 install") && m.contains(RELEASES), "{m}");
        assert!(!m.contains("--from"), "--from would only reinstall this version: {m}");
        // An explicit --from, or any other directory, keeps the plain message.
        assert_eq!(missing_binary("kub0d", usr_bin, true), "no kub0d in /usr/bin; pass --from DIR");
        assert_eq!(missing_binary("kub0-block", Path::new("/opt/x"), false), "no kub0-block in /opt/x; pass --from DIR");
    }

    #[test]
    fn find_binary_accepts_release_names() {
        let dir = std::env::temp_dir().join(format!("kub0-find-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(find_binary(&dir, "kub0d").is_none());
        std::fs::write(dir.join("kub0d-x86_64-unknown-linux-musl"), b"x").unwrap();
        std::fs::write(dir.join("kub0d-x86_64-unknown-linux-musl.sha256"), b"x").unwrap();
        assert_eq!(find_binary(&dir, "kub0d").unwrap().file_name().unwrap(), "kub0d-x86_64-unknown-linux-musl");
        std::fs::write(dir.join("kub0d"), b"x").unwrap();
        assert_eq!(find_binary(&dir, "kub0d").unwrap().file_name().unwrap(), "kub0d", "a plain name wins");
        // The release's three artifacts, side by side: `kub0` is not `kub0-block`.
        for f in ["kub0-block-x86_64-unknown-linux-musl", "kub0-x86_64-unknown-linux-musl"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        assert_eq!(find_binary(&dir, "kub0").unwrap().file_name().unwrap(), "kub0-x86_64-unknown-linux-musl");
        assert_eq!(find_binary(&dir, "kub0-block").unwrap().file_name().unwrap(), "kub0-block-x86_64-unknown-linux-musl");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
