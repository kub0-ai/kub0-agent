//! Privileged helper for Vallum. Installed root-owned at
//! `/usr/lib/kub0/kub0-block` and invoked with `pkexec`.
//!
//! Verbs: block-app, unblock-app, block-ips, unblock-ips, pause, resume,
//! teardown, status.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use vallum_block::block_state;
use vallum_block::caller;
use vallum_block::deps::BlockingCaps;
use vallum_block::endpoints;
use vallum_block::execgate;
use vallum_block::fleet;
use vallum_block::forest::{self, ProcIdentity};
use vallum_block::ids::sanitize_app;
use vallum_block::nft_verify;
use vallum_block::owners::{self, OwnerMap};
use vallum_block::pause::{self, PAUSE_COMMENT};
use vallum_block::restore::{self, RestoreFile};
use vallum_block::sockets::{self, Flow, Proto};
use vallum_block::temporary::{self, Rule as ScopedRule};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SLICE: &str = "vallum.slice";
const TABLE: &str = "vallum";
const CANONICAL_HELPER: &str = "/usr/lib/kub0/kub0-block";
/// pkexec's root PATH minus its `/root/bin` tail. Under sudo without `secure_path` the
/// invoking user's PATH survives instead, with their own writable directories
/// ahead of /usr/bin, and `nft`, `conntrack` and `ss` are all run by name.
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Root never resolves a tool through a PATH the caller chose. LC_ALL=C because
/// conntrack_delete reads success out of conntrack's English messages.
fn pin_environment() {
    std::env::set_var("PATH", SAFE_PATH);
    std::env::set_var("LC_ALL", "C");
}

fn main() {
    pin_environment();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        fail(
            2,
            "usage: kub0-block <block-app|unblock-app|block-ips|unblock-ips|fleet-sync|fleet-clear|fleet-render|execgate-trust|execgate-untrust|execgate-allow-once|pause|resume|teardown|status> ...",
        );
    }
    // fleet-render only prints text; status only reads.
    let _lock = if args[1] != "status" && args[1] != "fleet-render" {
        Some(temporary::Lock::acquire().unwrap_or_else(|e| fail(1, &e)))
    } else {
        None
    };
    let result = match args[1].as_str() {
        "block-scoped" => {
            if args.len() < 6 {
                fail(2, "block-scoped <app-id> <ip> <seconds> <pid...>");
            }
            block_scoped(&args[2], &args[3], &args[4], &args[5..])
        }
        "unblock-scoped" => {
            if args.len() != 4 {
                fail(2, "unblock-scoped <app-id> <ip>");
            }
            unblock_scoped(&args[2], &args[3])
        }
        "expire-scoped" => expire_scoped(),
        "block-app" => {
            if args.len() < 3 {
                fail(2, "block-app <app-id> [pid...]");
            }
            block_app(&args[2], &args[3..])
        }
        "unblock-app" => {
            if args.len() < 3 {
                fail(2, "unblock-app <app-id>");
            }
            unblock_app(&args[2])
        }
        "block-ips" => {
            if args.len() < 4 {
                fail(2, "block-ips <app-id> <ip> [ip...]");
            }
            block_ips(&args[2], &args[3..])
        }
        "unblock-ips" => {
            if args.len() < 3 {
                fail(2, "unblock-ips <app-id>");
            }
            unblock_ips(&args[2])
        }
        "fleet-sync" => fleet_sync(),
        "fleet-clear" => fleet_clear(),
        "fleet-render" => fleet_render(args.get(2).map(String::as_str) == Some("--rules-present")),
        // One arm per verb: the policy test reads the first quoted word per line.
        "execgate-trust" => execgate_request(&args),
        "execgate-untrust" => execgate_request(&args),
        "execgate-allow-once" => execgate_request(&args),
        "pause" => pause_enforcement(),
        "resume" => resume_enforcement(),
        "teardown" => teardown(),
        "status" => status(),
        other => fail(2, &format!("unknown verb {other}")),
    };
    let result = match args[1].as_str() {
        "block-app" | "block-ips" | "block-scoped" => result.map(note_paused),
        _ => result,
    };
    match result {
        Ok(v) => println!("{v}"),
        Err(e) => {
            if e.trim_start().starts_with('{') {
                println!("{e}");
            } else {
                println!("{}", json!({"ok": false, "error": e, "rollback": false}));
            }
            std::process::exit(1);
        }
    }
}

fn fail_block(code: &str, error: String, rollback: bool) -> Result<Value, String> {
    Err(json!({"ok": false, "error": error, "code": code, "rollback": rollback}).to_string())
}

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    println!("{}", json!({"ok": false, "error": msg}));
    std::process::exit(code);
}

fn parse_pid(s: &str) -> Result<u32, String> {
    s.parse::<u32>().map_err(|_| format!("bad pid {s}"))
}

fn cgroup_slice() -> PathBuf {
    Path::new(CGROUP_ROOT).join(SLICE)
}

fn cgroup_app(app: &str) -> PathBuf {
    cgroup_slice().join(format!("vallum-{app}"))
}

fn cgroup_match_path(app: &str) -> String {
    format!("{SLICE}/vallum-{app}")
}

fn owners_path() -> PathBuf {
    vallum_block::rename::state_path("endpoint-owners.json")
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn scoped_present(rule: &ScopedRule) -> Result<bool, String> {
    let out = Command::new("nft")
        .args(["list", "set", "inet", TABLE, &rule.set()])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("No such file or directory") {
            return Ok(false);
        }
        return Err(format!("scoped set unreadable: {}", err.trim()));
    }
    let set = String::from_utf8_lossy(&out.stdout);
    let present = nft_verify::set_elements_in_text(&set)
        .iter()
        .any(|s| s.parse::<IpAddr>().is_ok_and(|ip| ip == rule.ip));
    if !present {
        return Ok(false);
    }
    let listing = list_out_chain()?;
    Ok(listing.lines().any(|line| {
        line.contains(&format!("@{}", rule.set()))
            && line.contains(&rule.path())
            && line.contains(temporary::COMMENT)
            && line.split_whitespace().any(|s| s == "drop")
    }))
}

fn add_scoped_rule(rule: &ScopedRule) -> Result<(), String> {
    let seconds = rule.expires_at.saturating_sub(epoch_ms()).div_ceil(1000);
    if seconds == 0 {
        return Err("rule expired before installation".into());
    }
    let set = rule.set();
    let kind = if rule.ip.is_ipv4() {
        "ipv4_addr"
    } else {
        "ipv6_addr"
    };
    nft(&[
        "add",
        "set",
        "inet",
        TABLE,
        &set,
        &format!("{{ type {kind}; flags timeout; }}"),
    ])?;
    let added = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            TABLE,
            &set,
            &format!("{{ {} timeout {seconds}s }}", rule.ip),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !added.status.success() {
        return Err(format!(
            "timed element: {}",
            String::from_utf8_lossy(&added.stderr).trim()
        ));
    }
    let path = rule.path();
    if !list_out_chain()?.contains(&format!("@{set}")) {
        nft(&[
            "add",
            "rule",
            "inet",
            TABLE,
            "out",
            "socket",
            "cgroupv2",
            "level",
            "2",
            &format!("\"{path}\""),
            rule.family(),
            "daddr",
            &format!("@{set}"),
            "drop",
            "comment",
            &format!("\"{}\"", temporary::COMMENT),
        ])?;
    }
    if !scoped_present(rule)? {
        return Err("scoped rule or timed element did not land".into());
    }
    Ok(())
}

fn cleanup_scoped(rule: &ScopedRule) -> Result<(), String> {
    let set = rule.set();
    if scoped_present(rule)? {
        nft(&[
            "delete",
            "element",
            "inet",
            TABLE,
            &set,
            &format!("{{ {} }}", rule.ip),
        ])?;
    }
    if scoped_present(rule)? {
        return Err("scoped destination is still blocked".into());
    }
    delete_rules_containing(&rule.path())?;
    // A now-empty set may be absent if a reboot or teardown removed the table.
    let out = Command::new("nft")
        .args(["delete", "set", "inet", TABLE, &set])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success()
        && !String::from_utf8_lossy(&out.stderr).contains("No such file or directory")
    {
        return Err(format!(
            "scoped set cleanup: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    restore_memberships(&rule.group)?;
    let dest = cgroup_app(&rule.group);
    if dest.exists() {
        let (_, errors) = drain_stragglers(&dest);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        fs::remove_dir(&dest).map_err(|e| format!("scoped group cleanup: {e}"))?;
    }
    let _ = fs::remove_file(restore::path_for(&rule.group));
    Ok(())
}

fn expire_for_uid(uid: u32) -> Result<Vec<ScopedRule>, String> {
    let mut kept = Vec::new();
    let mut errors = Vec::new();
    for r in temporary::load(uid)? {
        if r.expires_at <= epoch_ms() {
            if let Err(e) = cleanup_scoped(&r) {
                errors.push(e);
                kept.push(r);
            }
        } else {
            kept.push(r);
        }
    }
    temporary::save(uid, &kept)?;
    if errors.is_empty() {
        Ok(kept)
    } else {
        Err(errors.join("; "))
    }
}

fn block_scoped(app: &str, ip: &str, seconds: &str, pids: &[String]) -> Result<Value, String> {
    let uid = caller::invoking_uid()?;
    let rule = ScopedRule::new(
        app,
        uid,
        ip,
        seconds.parse().map_err(|_| "invalid duration")?,
        epoch_ms(),
    )?;
    let mut rules = expire_for_uid(uid)?;
    if let Some(prior) = rules.iter().find(|r| r.same_target(&rule)) {
        if !scoped_present(prior)? {
            return Err(
                "stored scoped rule is missing from the kernel; cancel it and retry".into(),
            );
        }
        return Ok(
            json!({"ok":true,"verified":false,"ruleVerified":true,"warning":"Timed rule already present; existing sockets and process membership were not reverified.","rule":prior,"temporaryRules":rules}),
        );
    }
    if rules.len() >= temporary::MAX_RULES {
        return Err("temporary rule limit reached".into());
    }
    if rules.iter().any(|r| r.app == rule.app) {
        return Err("cancel the app's previous destination rule first".into());
    }
    let listing = nft_table_listing()?;
    if listing
        .is_some_and(|s| nft_verify::cgroup_drop_in_text(&s, &cgroup_match_path(&rule.app), 2))
    {
        return Err("unblock the whole app before adding a destination rule".into());
    }
    let mut out = block_app_with_rule(&rule.app, pids, Some(&rule))?;
    rules.push(rule.clone());
    if let Err(e) = temporary::save(uid, &rules) {
        let rollback = cleanup_scoped(&rule).is_ok();
        return fail_block(
            "scoped-state",
            format!("{e}; rule rollback={rollback}"),
            rollback,
        );
    }
    out["mechanism"] = json!("app-destination");
    out["app"] = json!(rule.app);
    out["rule"] = json!(rule);
    out["temporaryRules"] = json!(rules);
    Ok(out)
}

fn unblock_scoped(app: &str, ip: &str) -> Result<Value, String> {
    let uid = caller::invoking_uid()?;
    let target = ScopedRule::new(app, uid, ip, 1, epoch_ms())?;
    let mut rules = temporary::load(uid)?;
    if let Some(r) = rules.iter().find(|r| r.same_target(&target)) {
        cleanup_scoped(r)?;
    }
    rules.retain(|r| !r.same_target(&target));
    temporary::save(uid, &rules)?;
    Ok(
        json!({"ok":true,"verified":true,"app":target.app,"mechanism":"app-destination","temporaryRules":rules}),
    )
}

fn expire_scoped() -> Result<Value, String> {
    if caller::current_euid() != 0 {
        return Err("expiry housekeeping requires root".into());
    }
    let mut errors = Vec::new();
    for entry in fs::read_dir(temporary::directory())
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let uid: u32 = match path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
        {
            Some(u) if u != 0 => u,
            _ => continue,
        };
        // Root-owned, validated state authorizes housekeeping for that owner;
        // restore still checks the recorded UID, PID start time and membership.
        std::env::set_var("PKEXEC_UID", uid.to_string());
        if let Err(e) = expire_for_uid(uid) {
            errors.push(e);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(json!({"ok":true,"verified":true,"expiredRulesReconciled":true}))
}

fn block_app(app_raw: &str, pids: &[String]) -> Result<Value, String> {
    let uid = caller::invoking_uid()?;
    let app = sanitize_app(app_raw)?;
    if temporary::load(uid)?.iter().any(|r| r.app == app) {
        return Err("cancel the app's destination rule before applying a whole-app block".into());
    }
    block_app_with_rule(app_raw, pids, None)
}

fn block_app_with_rule(
    app_raw: &str,
    pids: &[String],
    scoped: Option<&ScopedRule>,
) -> Result<Value, String> {
    let app = match scoped {
        Some(r) => r.group.clone(),
        None => sanitize_app(app_raw)?,
    };
    let caller_uid = match caller::invoking_uid() {
        Ok(u) => u,
        Err(e) => return fail_block("pid-owner", e, false),
    };
    if scoped.is_some_and(|r| r.uid != caller_uid) {
        return Err("scoped owner mismatch".into());
    }
    let seeds_raw: Vec<u32> = pids
        .iter()
        .map(|s| parse_pid(s))
        .collect::<Result<Vec<u32>, String>>()?;
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
        return Err("cgroup v2 not mounted at /sys/fs/cgroup".into());
    }
    let procs = snapshot_proc();
    let seeds = match caller::authorize_seed_pids(&seeds_raw, caller_uid, &procs) {
        Ok(s) => s,
        Err(e) => {
            return fail_block("pid-owner", e, false);
        }
    };
    let forest = forest::collect_forest(&seeds, &procs);
    let live = match caller::authorize_seed_pids(&forest, caller_uid, &procs) {
        Ok(s) => s,
        Err(e) => {
            return fail_block("pid-owner", e, false);
        }
    };
    if live.is_empty() {
        return fail_block(
            "empty-forest",
            "no live processes in the application forest".into(),
            true,
        );
    }

    // Merge with what an earlier block recorded rather than starting over. The
    // panel forgets cgroup blocks across a shell restart, so re-blocking an app
    // that is already blocked is an ordinary path, and every process it finds
    // is then already inside vallum.slice. Recording that as the "original"
    // cgroup would make unblock put them straight back where they are, and the
    // real originals would be gone for good.
    let prior = restore::load(&restore::path_for(&app));
    let mut restore_file = RestoreFile::default();
    for pid in &live {
        let Some(p) = procs.get(pid) else {
            return fail_block(
                "pid-owner",
                format!("pid {pid} has no recorded membership — refusing cgroup block"),
                false,
            );
        };
        let Some(now) = read_identity(*pid) else {
            return fail_block(
                "pid-owner",
                format!("pid {pid} vanished before migrate — refusing cgroup block"),
                false,
            );
        };
        if !caller::identity_still_caller(p, &now, caller_uid) {
            return fail_block(
                "pid-owner",
                format!("pid {pid} is not the invoking user's process (uid/starttime mismatch)"),
                false,
            );
        }
        if restore::is_root_cgroup(&p.cgroup) {
            return fail_block(
                "root-cgroup",
                format!(
                    "pid {pid} is in the root cgroup; cgroup-block refused (use endpoint fallback)"
                ),
                true,
            );
        }
        if restore::in_slice(&p.cgroup, SLICE) {
            // Already blocked. Keep its earlier record if it is the same
            // process; otherwise it was forked while blocked and unblock will
            // rehome it by ancestry (drain_stragglers), so record nothing.
            if let Some(rec) = prior.pids.get(&pid.to_string()) {
                if rec.uid == p.uid && rec.starttime == p.starttime {
                    restore_file.pids.insert(pid.to_string(), rec.clone());
                }
            }
            continue;
        }
        restore_file.pids.insert(
            pid.to_string(),
            restore::RestorePid {
                cgroup: p.cgroup.clone(),
                uid: p.uid,
                starttime: p.starttime,
            },
        );
    }
    // Records of processes this block did not see (exited, or outside this
    // forest) are kept too: dropping them cannot help and may strand one.
    for (k, rec) in prior.pids {
        restore_file.pids.entry(k).or_insert(rec);
    }
    restore::save(&restore::path_for(&app), &restore_file)?;

    ensure_table_and_output_chain()?;
    let slice = cgroup_slice();
    fs::create_dir_all(&slice).map_err(|e| format!("mkdir slice: {e}"))?;
    let _ = fs::write(slice.join("cgroup.subtree_control"), "+pids\n");
    let dest = cgroup_app(&app);
    fs::create_dir_all(&dest).map_err(|e| format!("mkdir app cgroup: {e}"))?;
    let dest_rel = cgroup_match_path(&app);

    let mut moved = Vec::new();
    for pid in &live {
        let Some(snap) = procs.get(pid) else {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} dropped from snapshot"),
                "pid-owner",
            );
        };
        let Some(now) = read_identity(*pid) else {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} vanished during migrate"),
                "pid-owner",
            );
        };
        if !caller::identity_still_caller(snap, &now, caller_uid) {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} uid/starttime changed — refusing migrate"),
                "pid-owner",
            );
        }
        if write_proc(&dest, *pid).is_err() {
            return rollback_block(&app, &dest_rel, format!("migrate {pid} failed"), "migrate");
        }
        let cur = read_proc_cgroup(*pid).unwrap_or_default();
        if !restore::membership_matches(&cur, &format!("/{dest_rel}"))
            && !restore::membership_matches(&cur, &dest_rel)
        {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} cgroup is {cur}, expected {dest_rel}"),
                "migrate",
            );
        }
        moved.push(*pid);
    }
    if moved.len() != live.len() {
        return rollback_block(
            &app,
            &dest_rel,
            format!(
                "partial migration {}/{} — refusing verified:true",
                moved.len(),
                live.len()
            ),
            "migrate",
        );
    }

    let install = match scoped {
        Some(r) => add_scoped_rule(r),
        None => add_cgroup_drop_rule(&dest_rel),
    };
    if let Err(e) = install {
        return rollback_block(&app, &dest_rel, e, "nft");
    }
    let verified = match scoped {
        Some(r) => scoped_present(r).unwrap_or(false),
        None => verify_cgroup_rule(&dest_rel),
    };
    if !verified {
        return rollback_block(
            &app,
            &dest_rel,
            "nft rule did not land (nft list check failed)".into(),
            "nft",
        );
    }

    // Read before anything is closed: a destroyed socket loses its peer.
    let mut flows = app_flows(&moved);
    let unconnected_udp = sockets::unconnected_udp_count(&flows);
    if let Some(rule) = scoped {
        flows.retain(|f| f.remote.ip() == rule.ip);
    }
    // Scoped rules must not flush another app's conntrack entries to this IP.
    let (nameservers, gateways) = host_critical();
    let remotes = if scoped.is_some() {
        Vec::new()
    } else {
        remotes_of(&flows, &nameservers, &gateways)
    };
    let flush = match flush_conntrack(&remotes) {
        Ok(f) => f,
        Err(e) => return rollback_block(&app, &dest_rel, e, "conntrack"),
    };
    if !flush.ok {
        return rollback_block(
            &app,
            &dest_rel,
            format!("conntrack flush failed ({})", flush.summary()),
            "conntrack",
        );
    }

    // The panel cannot read nftables as an ordinary user. Persist a separate
    // marker only after the rule and conntrack work are verified. One marker
    // per app avoids concurrent helpers overwriting one shared status file.
    if let Err(e) = if scoped.is_none() {
        block_state::mark(&app)
    } else {
        Ok(())
    } {
        return rollback_block(&app, &dest_rel, e, "block-state");
    }

    // The rule only catches sockets opened from here on (see sockets.rs), so
    // close the ones the app already had. A socket that will not close is not
    // a reason to undo a rule that is working for everything else: the block
    // stands, and the warning says exactly what it does not cover yet.
    let closed = close_existing(&flows);
    // An unconnected UDP socket can sendto() a new peer after migration while
    // retaining the cgroup where the socket was created. We cannot destroy it
    // by local port alone without risking a different app's SO_REUSEPORT socket.
    let closure_complete = closed.still_open.is_empty() && unconnected_udp == 0;
    let mut out = json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": dest_rel,
        "level": restore::cgroup_match_level(&dest_rel),
        "moved": moved,
        "forest": live,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "closed": closed.closed,
        "stillOpen": closed.still_open,
        "unconnectedUdp": unconnected_udp,
        "ruleVerified": true,
        "enforcementComplete": closure_complete,
        "verified": closure_complete,
        "helper": CANONICAL_HELPER
    });
    let mut warnings = Vec::new();
    if let Some(w) = closed.warning() {
        warnings.push(w);
    }
    if unconnected_udp > 0 {
        warnings.push(format!(
            "{unconnected_udp} pre-existing unconnected UDP socket(s) can still send to new peers; the cgroup rule blocks newly opened sockets"
        ));
    }
    if !warnings.is_empty() {
        out["warning"] = json!(warnings.join("; "));
    }
    Ok(out)
}

fn rollback_block(app: &str, path: &str, why: String, code: &str) -> Result<Value, String> {
    let _ = delete_rules_containing(path);
    // A failed nft read is not proof the rule was removed. Keep the marker if
    // the kernel state is unknown, so an active rule does not vanish from UI.
    let rule_absent = match nft_table_listing() {
        Ok(listing) => !listing.as_ref().is_some_and(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .any(|token| token.trim_matches('"') == path)
            })
        }),
        Err(_) => false,
    };
    if rule_absent {
        let _ = block_state::unmark(app);
        if app.starts_with("__vallum_scoped_") {
            for family in [4, 6] {
                let _ = nft(&["delete", "set", "inet", TABLE, &format!("t{family}_{app}")]);
            }
        }
    }
    let restore = restore_memberships(app);
    match (rule_absent, restore) {
        (true, Ok(_)) => fail_block(code, format!("{why} — rolled back"), true),
        (false, Ok(_)) => fail_block(
            "rollback-failed",
            format!("{why}; could not confirm the cgroup drop rule was removed"),
            false,
        ),
        (_, Err(e)) => fail_block(
            "rollback-failed",
            format!("{why}; restore failed ({e}) — processes may still be in vallum.slice"),
            false,
        ),
    }
}

fn read_proc_cgroup(pid: u32) -> Option<String> {
    let t = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    restore::parse_unified_cgroup(&t)
}

fn snapshot_proc() -> HashMap<u32, ProcIdentity> {
    let mut map = HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return map;
    };
    for e in rd.flatten() {
        let pid: u32 = match e.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) if p >= 1 => p,
            _ => continue,
        };
        // PID 1 is snapshotted so authorize can refuse it explicitly.
        if let Some(id) = read_identity(pid) {
            map.insert(pid, id);
        }
    }
    map
}

fn read_identity(pid: u32) -> Option<ProcIdentity> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut ppid = 0u32;
    let mut uid = 0u32;
    for line in status.lines() {
        if let Some(r) = line.strip_prefix("PPid:") {
            ppid = r.split_whitespace().next()?.parse().ok()?;
        }
        if let Some(r) = line.strip_prefix("Uid:") {
            uid = r.split_whitespace().next()?.parse().ok()?;
        }
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (flags, starttime) = caller::parse_stat_fields(&stat)?;
    let kthread = caller::is_kernel_thread(flags);
    let exe_base = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| forest::exe_basename(&p))
        .unwrap_or_default();
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|t| restore::parse_unified_cgroup(&t))
        .unwrap_or_default();
    Some(ProcIdentity {
        pid,
        ppid,
        uid,
        exe_base,
        comm,
        cgroup,
        starttime,
        kthread,
    })
}

fn restore_memberships(app: &str) -> Result<Vec<u32>, String> {
    let file = restore::load(&restore::path_for(app));
    let mut restored = Vec::new();
    let mut errors = Vec::new();
    for (pid_s, rec) in &file.pids {
        let pid: u32 = match pid_s.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let orig = &rec.cgroup;
        if !Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let Some(now) = read_identity(pid) else {
            continue;
        };
        if now.uid != rec.uid || now.starttime != rec.starttime {
            errors.push(format!(
                "{pid}: uid/starttime mismatch — refusing restore (PID reuse)"
            ));
            continue;
        }
        // Never move a process that has since joined a different block or
        // been deliberately moved elsewhere by its owner.
        if !restore::membership_matches(&now.cgroup, &cgroup_match_path(app)) {
            continue;
        }
        if restore::is_root_cgroup(orig) {
            errors.push(format!("{pid}: refusing to write cgroup root"));
            continue;
        }
        let recorded = restore::sys_path(Path::new(CGROUP_ROOT), orig);

        // The recorded cgroup is frequently gone by the time we try to go back
        // to it, and blocking is what destroyed it. A systemd transient scope
        // (app-*-transient-<pid>.scope) is garbage collected the moment it goes
        // empty, and moving its only process into vallum's cgroup is precisely
        // what empties it. Writing to a directory that no longer exists fails,
        // and the old behaviour then gave up—stranding the process inside
        // vallum.slice, which also keeps teardown from ever removing it.
        //
        // Fall back to the nearest surviving ancestor. Putting a process back
        // as close to where it lived as still exists is a real restore; leaving
        // it in the firewall's own cgroup is not. Never unwind to the cgroup
        // root, which is what is_root_cgroup refuses above.
        let mut dest = recorded.clone();
        let mut fell_back = false;
        if !dest.is_dir() {
            let root = Path::new(CGROUP_ROOT);
            let mut up = dest.clone();
            while !up.is_dir() && up != root {
                match up.parent() {
                    Some(p) if p.starts_with(root) => up = p.to_path_buf(),
                    _ => break,
                }
            }
            if up.is_dir() && up != root {
                // Existing is not the same as able to hold a process. cgroup v2
                // forbids internal processes: once a cgroup lists controllers in
                // cgroup.subtree_control, only its leaves may contain PIDs. Every
                // surviving ancestor here is by definition an interior node —
                // app.slice carries "memory pids" and 23 children and holds zero
                // processes itself — so writing to the ancestor is rejected by the
                // kernel, not by permissions.
                //
                // Land on a leaf we make ourselves, as a sibling of the scope that
                // was collected. It inherits the parent's controllers, it is a
                // legal home for a process, and it frees vallum.slice so teardown
                // can finally remove it.
                let leaf = up.join("vallum-restored");
                if !leaf.is_dir() {
                    let _ = fs::create_dir(&leaf);
                }
                dest = if leaf.is_dir() { leaf } else { up };
                fell_back = true;
            }
        }

        if write_proc(&dest, pid).is_err() {
            errors.push(format!("{pid}: restore to {} failed", dest.display()));
            continue;
        }
        let current = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|t| restore::parse_unified_cgroup(&t))
            .unwrap_or_default();
        // Verify against where we actually aimed. Checking against `orig` after
        // a deliberate fallback would report failure for a restore that did the
        // right thing.
        // sys_path() is the forward direction (rel -> absolute); invert it the
        // same way it builds, by stripping the root and restoring the leading
        // slash that /proc/<pid>/cgroup reports.
        let wanted = if fell_back {
            match dest.strip_prefix(CGROUP_ROOT) {
                Ok(rel) => format!("/{}", rel.display()),
                Err(_) => orig.clone(),
            }
        } else {
            orig.clone()
        };
        if !restore::membership_matches(&current, &wanted) {
            errors.push(format!("{pid}: still in {current}, wanted {wanted}"));
            continue;
        }
        restored.push(pid);
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(restored)
}

fn write_proc(dest: &Path, pid: u32) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(dest.join("cgroup.procs"))
        .map_err(|e| format!("open cgroup.procs: {e}"))?;
    write!(f, "{pid}").map_err(|e| format!("migrate {pid}: {e}"))
}

fn socket_inodes(pids: &[u32]) -> std::collections::HashSet<u64> {
    let mut inodes = std::collections::HashSet::new();
    for pid in pids {
        if let Ok(fd) = fs::read_dir(format!("/proc/{pid}/fd")) {
            for e in fd.flatten() {
                if let Ok(t) = fs::read_link(e.path()) {
                    let s = t.to_string_lossy();
                    if let Some(rest) = s.strip_prefix("socket:[") {
                        if let Some(n) = rest.strip_suffix(']').and_then(|x| x.parse::<u64>().ok())
                        {
                            inodes.insert(n);
                        }
                    }
                }
            }
        }
    }
    inodes
}

fn read_all_flows() -> Vec<Flow> {
    let mut out = Vec::new();
    for (path, proto, v6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            out.extend(sockets::parse_table(&text, proto, v6));
        }
    }
    out
}

/// Every socket the given processes hold, connected or not.
fn app_flows(pids: &[u32]) -> Vec<Flow> {
    let inodes = socket_inodes(pids);
    read_all_flows()
        .into_iter()
        .filter(|f| f.inode != 0 && inodes.contains(&f.inode))
        .collect()
}

/// Remote addresses whose conntrack entries to flush.
///
/// `conntrack -D -d` is host-wide: it drops every app's entries to that
/// address, not just the blocked app's. So the same addresses an endpoint
/// block refuses are skipped here. The seed pids are only checked for uid,
/// so a same-user process that joined the row could otherwise make one
/// confirmed block flush the gateway, the nameservers or tailnet peers. The
/// app's own sockets to them are still closed by close_existing.
fn remotes_of(flows: &[Flow], nameservers: &[IpAddr], gateways: &[IpAddr]) -> Vec<IpAddr> {
    let mut remotes: Vec<IpAddr> = flows
        .iter()
        .map(|f| f.remote.ip())
        .filter(|ip| {
            endpoints::refusal(ip, nameservers).is_none()
                && endpoints::gateway_refusal(ip, gateways).is_none()
        })
        .collect();
    remotes.sort_by_key(|i| i.to_string());
    remotes.dedup();
    remotes
}

struct CloseReport {
    closed: usize,
    still_open: Vec<String>,
    missing_tool: bool,
}

impl CloseReport {
    fn warning(&self) -> Option<String> {
        if self.missing_tool {
            return Some(format!(
                "ss (iproute2) is not installed, so {} connection(s) the app already had stay open until it closes them; new ones are blocked",
                self.still_open.len()
            ));
        }
        if self.still_open.is_empty() {
            return None;
        }
        Some(format!(
            "{} existing connection(s) could not be closed and stay open until the app closes them ({}); new ones are blocked",
            self.still_open.len(),
            self.still_open.join(", ")
        ))
    }
}

fn close_existing(flows: &[Flow]) -> CloseReport {
    let targets: Vec<Flow> = flows.iter().filter(|f| f.is_connected()).cloned().collect();
    let describe = |f: &Flow| format!("{:?} {}", f.proto, f.remote).to_lowercase();
    if targets.is_empty() {
        return CloseReport {
            closed: 0,
            still_open: vec![],
            missing_tool: false,
        };
    }
    let Some(ss) = which("ss") else {
        return CloseReport {
            closed: 0,
            still_open: targets.iter().map(describe).collect(),
            missing_tool: true,
        };
    };
    for f in &targets {
        // Exit status is deliberately ignored: ss reports success whether or
        // not the kernel destroyed anything. The re-read below is the verdict.
        let _ = Command::new(&ss)
            .args(f.ss_kill_args())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let left = sockets::survivors(&targets, &read_all_flows());
    CloseReport {
        closed: targets.len() - left.len(),
        still_open: left.iter().map(describe).collect(),
        missing_tool: false,
    }
}

struct FlushReport {
    flushed: Vec<String>,
    failed: Vec<String>,
    ok: bool,
    missing_tool: bool,
}

impl FlushReport {
    fn summary(&self) -> String {
        if self.missing_tool {
            "conntrack not installed".into()
        } else if self.failed.is_empty() {
            format!("{} flushed", self.flushed.len())
        } else {
            format!(
                "{} flushed, {} failed ({})",
                self.flushed.len(),
                self.failed.len(),
                self.failed.join(", ")
            )
        }
    }
}

fn flush_conntrack(remotes: &[IpAddr]) -> Result<FlushReport, String> {
    if remotes.is_empty() {
        return Ok(FlushReport {
            flushed: vec![],
            failed: vec![],
            ok: true,
            missing_tool: false,
        });
    }
    if which("conntrack").is_none() {
        return Ok(FlushReport {
            flushed: vec![],
            failed: remotes.iter().map(|i| i.to_string()).collect(),
            ok: false,
            missing_tool: true,
        });
    }
    let mut flushed = Vec::new();
    let mut failed = Vec::new();
    for ip in remotes {
        match conntrack_delete(ip) {
            Ok(()) => flushed.push(ip.to_string()),
            Err(e) => failed.push(format!("{ip}: {e}")),
        }
    }
    Ok(FlushReport {
        ok: failed.is_empty(),
        flushed,
        failed,
        missing_tool: false,
    })
}

fn which(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(
            path.split(':')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
    }
    for extra in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        if !dirs.iter().any(|d| d == extra) {
            dirs.push(extra.to_string());
        }
    }
    for dir in dirs {
        let p = Path::new(&dir).join(name);
        if is_executable(&p) {
            return Some(p);
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn cgroup_v2_present() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
        || Path::new("/sys/fs/cgroup/unified/cgroup.controllers").is_file()
}

fn probe_blocking_caps() -> BlockingCaps {
    BlockingCaps::from_presence(
        which("nft").is_some(),
        which("conntrack").is_some(),
        cgroup_v2_present(),
    )
}

/// Treat "deleted N" and "0 flow entries have been deleted" as success.
/// Anything else (missing binary already handled, permission, bad syntax) is failure.
fn conntrack_delete(ip: &IpAddr) -> Result<(), String> {
    let mut cmd = Command::new("conntrack");
    match ip {
        IpAddr::V4(_) => {
            cmd.args(["-D", "-d", &ip.to_string()]);
        }
        IpAddr::V6(_) => {
            cmd.args(["-f", "ipv6", "-D", "-d", &ip.to_string()]);
        }
    }
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("conntrack exec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_lowercase();
    if text.contains("0 flow entries")
        || text.contains("has been deleted")
        || text.contains("have been deleted")
    {
        return Ok(());
    }
    Err(text.trim().to_string())
}

fn ensure_table_and_output_chain() -> Result<(), String> {
    nft(&["add", "table", "inet", TABLE])?;
    nft(&[
        "add",
        "chain",
        "inet",
        TABLE,
        "out",
        "{ type filter hook output priority 0; policy accept; }",
    ])?;
    reconcile_pause()
}

fn is_paused() -> bool {
    pause::marker_path().exists()
}

/// The chain listing, or an error when nft could not produce one. A missing
/// table or chain is a real, empty answer; any other failure must not read as
/// "no pause rule", or resume would drop the marker with the rule still live.
fn list_out_chain() -> Result<String, String> {
    let out = Command::new("nft")
        .args(["-a", "list", "chain", "inet", TABLE, "out"])
        .output()
        .map_err(|e| format!("nft exec: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("No such file or directory") {
        return Ok(String::new());
    }
    Err(format!("nft list chain failed: {}", err.trim()))
}

/// True only when nft positively reports the table absent.
fn table_gone() -> bool {
    match Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
    {
        Ok(o) => {
            !o.status.success()
                && String::from_utf8_lossy(&o.stderr).contains("No such file or directory")
        }
        Err(_) => false,
    }
}

/// Bring the kernel in line with the marker. Every block path runs this, so a
/// block added while paused lands paused, and a pause rule left without its
/// marker (the panel would read "on" while nothing is enforced) is removed.
fn reconcile_pause() -> Result<(), String> {
    let listing = list_out_chain()?;
    let handles = pause::pause_rule_handles(&listing);
    if is_paused() {
        if pause::pause_rule_is_first(&listing) {
            return Ok(());
        }
        for h in &handles {
            nft(&["delete", "rule", "inet", TABLE, "out", "handle", h])?;
        }
        let comment = format!("\"{PAUSE_COMMENT}\"");
        nft(&[
            "insert", "rule", "inet", TABLE, "out", "accept", "comment", &comment,
        ])?;
        if !pause::pause_rule_is_first(&list_out_chain()?) {
            return Err("pause rule did not land at the head of the chain".into());
        }
    } else {
        for h in &handles {
            nft(&["delete", "rule", "inet", TABLE, "out", "handle", h])?;
        }
        if !pause::pause_rule_handles(&list_out_chain()?).is_empty() {
            return Err("pause rule still present after delete".into());
        }
    }
    Ok(())
}

fn pause_enforcement() -> Result<Value, String> {
    // Marker first. If the rule then fails to land, the marker comes back off
    // and the error says so: the panel must never read "off" while vallum is
    // still dropping, nor "on" while it is not.
    let marker = pause::marker_path();
    if let Some(dir) = marker.parent() {
        vallum_block::rename::create_state_dir(dir, 0o755).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(&marker, "").map_err(|e| format!("write {}: {e}", marker.display()))?;
    if let Err(e) = ensure_table_and_output_chain() {
        let _ = fs::remove_file(&marker);
        if let Err(undo) = reconcile_pause() {
            // Could not confirm the rule is gone. Keep reading "off": saying
            // "on" over a live pause rule is the one lie this must not tell.
            let _ = fs::write(&marker, "");
            return Err(format!(
                "{e}; could not confirm the pause rule was removed ({undo}) — enforcement stays marked off"
            ));
        }
        return Err(format!("{e} — enforcement left on"));
    }
    Ok(json!({"ok": true, "paused": true, "verified": true}))
}

fn resume_enforcement() -> Result<Value, String> {
    // Kernel first, marker last: until the rule is verifiably gone the panel
    // keeps reading "off", which is what is true.
    let listing = list_out_chain()?;
    for h in pause::pause_rule_handles(&listing) {
        nft(&["delete", "rule", "inet", TABLE, "out", "handle", &h])?;
    }
    if !pause::pause_rule_handles(&list_out_chain()?).is_empty() {
        return Err("pause rule still present after delete — enforcement still off".into());
    }
    let marker = pause::marker_path();
    if let Err(e) = fs::remove_file(&marker) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("remove {}: {e}", marker.display()));
        }
    }
    Ok(json!({"ok": true, "paused": false, "verified": true}))
}

/// A block made while paused is recorded and in the kernel, but it does not
/// drop anything until resume. Say so on the result rather than let
/// `verified: true` read as "enforced".
fn note_paused(mut v: Value) -> Value {
    if !is_paused() {
        return v;
    }
    let note = "Enforcement is off: this block takes effect when you turn it back on";
    let warning = match v.get("warning").and_then(Value::as_str) {
        Some(w) => format!("{note}. {w}"),
        None => note.to_string(),
    };
    v["paused"] = json!(true);
    v["warning"] = json!(warning);
    v
}

fn add_cgroup_drop_rule(path: &str) -> Result<(), String> {
    if verify_cgroup_rule(path) {
        return Ok(());
    }
    let level = restore::cgroup_match_level(path).to_string();
    nft(&[
        "add", "rule", "inet", TABLE, "out", "socket", "cgroupv2", "level", &level, path, "drop",
    ])
}

fn verify_cgroup_rule(path: &str) -> bool {
    let level = restore::cgroup_match_level(path);
    if let Some(js) = nft_list_table_json() {
        if nft_verify::cgroup_drop_in_json(&js, path, level) {
            return true;
        }
    }
    nft_verify::cgroup_drop_in_text(&nft_list_table(), path, level)
}

fn unblock_app(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let path = cgroup_match_path(&app);
    delete_rules_containing(&path)?;
    let listed = nft_table_listing()?;
    if listed.as_ref().is_some_and(|text| {
        nft_verify::cgroup_drop_in_text(text, &path, restore::cgroup_match_level(&path))
    }) {
        return Err("cgroup drop rule still present after delete".into());
    }
    // From here on the rule is gone and the app has its network back. What
    // is left is housekeeping, and failing the call over it would tell the
    // panel the app is still blocked when it is not. So it is reported as a
    // warning, and the restore record is kept for teardown to retry.
    let mut warnings: Vec<String> = Vec::new();
    if let Err(e) = block_state::unmark(&app) {
        warnings.push(format!("block marker: {e}"));
    }
    let restored = match restore_memberships(&app) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!("restore: {e}"));
            Vec::new()
        }
    };
    let dest = cgroup_app(&app);
    let mut adopted = Vec::new();
    if dest.exists() {
        let (moved, errs) = drain_stragglers(&dest);
        adopted = moved;
        warnings.extend(errs);
        if let Err(e) = fs::remove_dir(&dest) {
            warnings.push(format!("rmdir {}: {e}", dest.display()));
        }
    }
    if !dest.exists() {
        let _ = fs::remove_file(restore::path_for(&app));
    }
    let mut out = json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "restored": restored,
        "adopted": adopted,
        "verified": true
    });
    if !warnings.is_empty() {
        out["warning"] = json!(format!(
            "unblocked, but cleanup was incomplete: {}",
            warnings.join("; ")
        ));
    }
    Ok(out)
}

/// Move the processes the app forked while blocked (see
/// restore::straggler_home) out of its cgroup, so the cgroup can be removed.
/// Only the invoking user's own processes are moved: a setuid child in there
/// is reported and left, since putting a root process in a user-delegated
/// cgroup would hand that user control over it.
fn drain_stragglers(dest: &Path) -> (Vec<u32>, Vec<String>) {
    let mut moved = Vec::new();
    let mut errors = Vec::new();
    let members: Vec<u32> = fs::read_to_string(dest.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    if members.is_empty() {
        return (moved, errors);
    }
    let caller_uid = match caller::invoking_uid() {
        Ok(u) => u,
        Err(e) => {
            errors.push(format!(
                "{} process(es) left in {}: {e}",
                members.len(),
                dest.display()
            ));
            return (moved, errors);
        }
    };
    let procs = snapshot_proc();
    let ppid: HashMap<u32, u32> = procs.iter().map(|(p, id)| (*p, id.ppid)).collect();
    let cgroup: HashMap<u32, String> = procs
        .iter()
        .map(|(p, id)| (*p, id.cgroup.clone()))
        .collect();
    for pid in members {
        let Some(id) = procs.get(&pid) else { continue };
        if id.uid != caller_uid {
            errors.push(format!(
                "{pid}: not the invoking user's process, left in place"
            ));
            continue;
        }
        let Some(home) = restore::straggler_home(pid, &ppid, &cgroup, SLICE) else {
            errors.push(format!("{pid}: no ancestor outside {SLICE} to rejoin"));
            continue;
        };
        let target = restore::sys_path(Path::new(CGROUP_ROOT), &home);
        match write_proc(&target, pid) {
            Ok(()) => moved.push(pid),
            Err(e) => errors.push(format!("{pid}: {e}")),
        }
    }
    (moved, errors)
}

fn delete_rules_containing(needle: &str) -> Result<(), String> {
    let level = restore::cgroup_match_level(needle);
    let out = Command::new("nft")
        .args(["-a", "list", "chain", "inet", TABLE, "out"])
        .output()
        .map_err(|e| format!("nft list: {e}"))?;
    if !out.status.success() {
        if matches!(nft_table_listing(), Ok(None)) {
            return Ok(());
        }
        return Err(format!(
            "nft list chain: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !nft_verify::cgroup_drop_any_in_text(line, needle, level) {
            continue;
        }
        if let Some(handle) = line.rsplit("handle").nth(0).map(str::trim) {
            if handle.chars().all(|c| c.is_ascii_digit()) {
                nft(&["delete", "rule", "inet", TABLE, "out", "handle", handle])?;
            }
        }
    }
    Ok(())
}

fn ensure_ip_sets_and_rules() -> Result<(), String> {
    ensure_table_and_output_chain()?;
    nft(&[
        "add",
        "set",
        "inet",
        TABLE,
        "blocked4",
        "{ type ipv4_addr; }",
    ])?;
    nft(&[
        "add",
        "set",
        "inet",
        TABLE,
        "blocked6",
        "{ type ipv6_addr; }",
    ])?;
    let listed = nft_list_table();
    if !listed.contains("ip daddr @blocked4") {
        nft(&[
            "add",
            "rule",
            "inet",
            TABLE,
            "out",
            "ip",
            "daddr",
            "@blocked4",
            "drop",
        ])?;
    }
    if !listed.contains("ip6 daddr @blocked6") {
        nft(&[
            "add",
            "rule",
            "inet",
            TABLE,
            "out",
            "ip6",
            "daddr",
            "@blocked6",
            "drop",
        ])?;
    }
    let listed = nft_list_table();
    if !listed.contains("ip daddr @blocked4") || !listed.contains("ip6 daddr @blocked6") {
        return Err("host-wide drop rules for blocked4/blocked6 did not land".into());
    }
    Ok(())
}

fn set_name(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "blocked4",
        IpAddr::V6(_) => "blocked6",
    }
}

fn delete_element(ip: &IpAddr) -> Result<(), String> {
    nft(&[
        "delete",
        "element",
        "inet",
        TABLE,
        set_name(ip),
        &format!("{{ {ip} }}"),
    ])
}

fn set_contains(ip: &IpAddr) -> bool {
    // Compare as addresses, not strings: nft may print an IPv6 element in a
    // different (but equal) spelling from the one we added.
    nft_verify::set_elements_in_text(&nft_list_set(set_name(ip)))
        .iter()
        .any(|e| e.parse::<IpAddr>().map(|x| x == *ip).unwrap_or(false))
}

fn verify_element_absent(ip: &IpAddr) -> bool {
    !set_contains(ip)
}

fn nft_list_set(name: &str) -> String {
    Command::new("nft")
        .args(["list", "set", "inet", TABLE, name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

trait EndpointSet {
    fn contains(&mut self, ip: &IpAddr) -> Result<bool, String>;
    fn add(&mut self, ip: &IpAddr) -> Result<(), String>;
    fn delete(&mut self, ip: &IpAddr) -> Result<(), String>;
}

struct NftEndpointSet;

impl EndpointSet for NftEndpointSet {
    fn contains(&mut self, ip: &IpAddr) -> Result<bool, String> {
        let out = Command::new("nft")
            .args(["list", "set", "inet", TABLE, set_name(ip)])
            .output()
            .map_err(|e| format!("nft list set {}: {e}", set_name(ip)))?;
        if !out.status.success() {
            return Err(format!(
                "nft list set {}: {}",
                set_name(ip),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let listed = String::from_utf8_lossy(&out.stdout);
        Ok(nft_verify::set_elements_in_text(&listed)
            .iter()
            .any(|e| e.parse::<IpAddr>().is_ok_and(|found| found == *ip)))
    }

    fn add(&mut self, ip: &IpAddr) -> Result<(), String> {
        // The general nft wrapper deliberately treats "File exists" as
        // success for idempotent setup. Here that would falsely classify an
        // out-of-band insertion after contains() as ours, and rollback could
        // delete another actor's block. Require an actual successful add.
        let out = Command::new("nft")
            .args([
                "add",
                "element",
                "inet",
                TABLE,
                set_name(ip),
                &format!("{{ {ip} }}"),
            ])
            .output()
            .map_err(|e| format!("nft add element {ip}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "nft add element {ip}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn delete(&mut self, ip: &IpAddr) -> Result<(), String> {
        delete_element(ip)
    }
}

/// Roll back only nft members this invocation inserted. An address already
/// present may belong to another app, even if this app has not yet been added
/// to the owner map.
fn rollback_inserted<S: EndpointSet>(set: &mut S, inserted: &[IpAddr], why: String) -> String {
    let mut failed = Vec::new();
    for ip in inserted.iter().rev() {
        if let Err(e) = set.delete(ip) {
            failed.push(format!("{ip}: {e}"));
            continue;
        }
        match set.contains(ip) {
            Ok(false) => {}
            Ok(true) => failed.push(format!("{ip} remains in nft set")),
            Err(e) => failed.push(format!("{ip}: cannot verify removal ({e})")),
        }
    }
    if failed.is_empty() {
        format!("{why} — newly inserted nft elements rolled back")
    } else {
        format!(
            "{why}; endpoint rollback incomplete ({})",
            failed.join("; ")
        )
    }
}

fn insert_missing_endpoints<S: EndpointSet>(
    set: &mut S,
    requested: &[IpAddr],
) -> Result<Vec<IpAddr>, String> {
    let mut inserted = Vec::new();
    for ip in requested {
        match set.contains(ip) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => return Err(rollback_inserted(set, &inserted, e)),
        }
        if let Err(e) = set.add(ip) {
            return Err(rollback_inserted(set, &inserted, e));
        }
        inserted.push(*ip);
        match set.contains(ip) {
            Ok(true) => {}
            Ok(false) => {
                return Err(rollback_inserted(
                    set,
                    &inserted,
                    format!("{ip} not present in nft set after add"),
                ))
            }
            Err(e) => return Err(rollback_inserted(set, &inserted, e)),
        }
    }
    Ok(inserted)
}

/// The org's network-policy spec on stdin: `{"block":[cidr...],"keep":[cidr...]}`.
fn read_fleet_spec() -> Result<fleet::FleetSpec, String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .take(64 << 20)
        .read_to_string(&mut buf)
        .map_err(|e| format!("read spec: {e}"))?;
    serde_json::from_str(&buf).map_err(|e| format!("bad fleet spec: {e}"))
}

/// The floor the helper adds on its own authority: this host's resolvers and
/// default gateways, read root-side so no caller can talk its way past them.
fn fleet_host_keep() -> Vec<IpAddr> {
    let (nameservers, gateways) = host_critical();
    nameservers.into_iter().chain(gateways).collect()
}

/// Replace the org network-policy block sets in one nft transaction. Root only:
/// this is the system kub0d applying its org's policy, never a desktop click.
fn fleet_sync() -> Result<Value, String> {
    if caller::current_euid() != 0 {
        return Err("fleet-sync must run as root (the system kub0d)".into());
    }
    let spec = read_fleet_spec()?;
    let plan = fleet::plan(&spec, &fleet_host_keep())?;
    ensure_table_and_output_chain()?;
    let (r4, r6) = fleet::rules_present(&list_out_chain()?);
    nft_script(&fleet::render(TABLE, &plan, r4, r6))?;
    reconcile_pause()?;
    let (r4, r6) = fleet::rules_present(&list_out_chain()?);
    if !(r4 && r6) {
        return Err("fleet drop rules did not land".into());
    }
    Ok(json!({
        "ok": true,
        "block4": plan.block4.len(),
        "block6": plan.block6.len(),
        "keep4": plan.keep4.len(),
        "keep6": plan.keep6.len(),
        "paused": is_paused(),
    }))
}

/// Remove every org network-policy rule and set. Idempotent.
/// `execgate-trust|execgate-untrust|execgate-allow-once <sha256> [note]`: queue
/// one request for the system kub0d, which owns the exec gate's trust store.
/// Nothing is enforced or lifted here; the daemon applies the request within a
/// second and the panel's next fleet frame shows the result.
fn execgate_request(args: &[String]) -> Result<Value, String> {
    if caller::current_euid() != 0 {
        return Err("exec-gate requests must run as root (pkexec)".into());
    }
    let op = execgate::op_for_verb(&args[1]).ok_or("unknown exec-gate verb")?;
    let sha = args
        .get(2)
        .ok_or("usage: kub0-block execgate-<trust|untrust|allow-once> <sha256> [note]")?;
    let sha = execgate::canonical_sha256(sha).ok_or("sha256 must be 64 hex characters")?;
    // pkexec and sudo name the invoking user; a bare root shell has none.
    let uid = caller::invoking_uid().unwrap_or(0);
    let note = args.get(3).cloned().unwrap_or_default();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    execgate::append_request(&execgate::dir(), op, &sha, uid, ts, &note)?;
    Ok(json!({
        "ok": true,
        "op": op,
        "sha256": sha,
        "queued": true,
        "note": "the system kub0d applies the request within a second; the panel's exec-gate section shows the result",
    }))
}

fn fleet_clear() -> Result<Value, String> {
    if caller::current_euid() != 0 {
        return Err("fleet-clear must run as root (the system kub0d)".into());
    }
    if matches!(nft_table_listing(), Ok(None)) {
        return Ok(json!({"ok": true, "removed": 0}));
    }
    let handles = fleet::rule_handles(&list_out_chain()?);
    for h in &handles {
        nft(&["delete", "rule", "inet", TABLE, "out", "handle", h])?;
    }
    for set in [fleet::SET4, fleet::SET6, fleet::KEEP4, fleet::KEEP6] {
        nft(&["delete", "set", "inet", TABLE, set])?;
    }
    if !fleet::rule_handles(&list_out_chain()?).is_empty() {
        return Err("fleet rules survived fleet-clear".into());
    }
    Ok(json!({"ok": true, "removed": handles.len()}))
}

/// The script fleet-sync would apply, with no host reads and no side effects, for
/// tests that run it through a throwaway network namespace. `--rules-present`
/// renders a resync: sets refilled, rules left alone, exactly as fleet-sync does
/// once its rules exist.
fn fleet_render(rules_present: bool) -> Result<Value, String> {
    let spec = read_fleet_spec()?;
    let plan = fleet::plan(&spec, &[])?;
    print!("{}", fleet::render(TABLE, &plan, rules_present, rules_present));
    std::process::exit(0);
}

fn nft_script(script: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft exec: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("nft stdin")?
        .write_all(script.as_bytes())
        .map_err(|e| format!("nft stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!("nft -f failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
}

/// The nameservers and default gateways this machine depends on, as
/// (nameservers, gateways). Every file here is world readable, so `status`
/// reports the same list unprivileged and the panel can leave these out of
/// what it offers to block.
fn host_critical() -> (Vec<IpAddr>, Vec<IpAddr>) {
    // The stub resolver's file and the real upstreams behind it: with
    // systemd-resolved the first only names 127.0.0.53.
    let mut nameservers = Vec::new();
    for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(text) = fs::read_to_string(path) {
            nameservers.extend(endpoints::parse_resolv_conf(&text));
        }
    }
    let mut gateways = Vec::new();
    if let Ok(text) = fs::read_to_string("/proc/net/route") {
        gateways.extend(endpoints::parse_proc_net_route(&text));
    }
    if let Ok(text) = fs::read_to_string("/proc/net/ipv6_route") {
        gateways.extend(endpoints::parse_ipv6_route(&text));
    }
    (nameservers, gateways)
}

fn block_ips(app_raw: &str, ips: &[String]) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let (nameservers, gateways) = host_critical();
    let mut parsed: Vec<IpAddr> = Vec::new();
    let mut refused: Vec<Value> = Vec::new();
    for s in ips {
        let ip = s.parse::<IpAddr>().map_err(|_| format!("bad ip {s}"))?;
        let why = endpoints::refusal(&ip, &nameservers)
            .or_else(|| endpoints::gateway_refusal(&ip, &gateways));
        match why {
            Some(why) => refused.push(json!({"ip": ip.to_string(), "reason": why})),
            None => parsed.push(ip),
        }
    }
    parsed.sort_by_key(|i| i.to_string());
    parsed.dedup();
    if parsed.is_empty() {
        return Err(json!({
            "ok": false,
            "error": "every address was one the whole machine depends on; nothing blocked",
            "code": "endpoints-refused",
            "refused": refused,
            "rollback": true
        })
        .to_string());
    }
    // Hold the same lock through nft, conntrack and owner-map commit. Two
    // pkexec helpers can otherwise both read an old map and overwrite one
    // another's ownership, or delete a shared IP during rollback.
    let owner_path = owners_path();
    let _lock = owners::lock(&owner_path, 0)?;
    ensure_ip_sets_and_rules()?;
    let mut set = NftEndpointSet;
    let inserted = insert_missing_endpoints(&mut set, &parsed)?;
    let requested: Vec<String> = parsed.iter().map(ToString::to_string).collect();

    let flush = match flush_conntrack(&parsed) {
        Ok(flush) => flush,
        Err(e) => return Err(rollback_inserted(&mut set, &inserted, e)),
    };
    if !flush.ok {
        return Err(rollback_inserted(
            &mut set,
            &inserted,
            format!("conntrack flush failed ({})", flush.summary()),
        ));
    }

    let mut map = owners::load(&owner_path);
    owners::grant(&mut map, &app, &requested);
    if let Err(e) = owners::save(&owner_path, &map) {
        return Err(rollback_inserted(&mut set, &inserted, e));
    }
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "hostWide": true,
        "app": app,
        "ips": requested,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "refused": refused,
        "verified": true,
        "warning": if refused.is_empty() {
            "endpoints only — affects all apps".to_string()
        } else {
            format!(
                "endpoints only — affects all apps; left {} address(es) the whole machine depends on unblocked",
                refused.len()
            )
        }
    }))
}

fn unblock_ips(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let owner_path = owners_path();
    let _lock = owners::lock(&owner_path, 0)?;
    let mut map = owners::load(&owner_path);
    let (released, retained) = owners::exclusive_release(&mut map, &app);
    if released.is_empty() && retained.is_empty() && !map.contains_key(&app) {
        owners::save(&owner_path, &map)?;
        return Ok(json!({
            "ok": true,
            "mechanism": "endpoints",
            "app": app,
            "released": released,
            "retained": retained,
            "verified": true
        }));
    }
    let mut missing = Vec::new();
    for ip_s in &released {
        let ip: IpAddr = ip_s.parse().map_err(|_| format!("bad stored ip {ip_s}"))?;
        delete_element(&ip)?;
        if !verify_element_absent(&ip) {
            missing.push(ip_s.clone());
        }
    }
    owners::save(&owner_path, &map)?;
    if !missing.is_empty() {
        return Err(format!(
            "failed to remove exclusive endpoint(s) from nft set: {}",
            missing.join(", ")
        ));
    }
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "app": app,
        "released": released,
        "retained": retained,
        "verified": true
    }))
}

fn teardown() -> Result<Value, String> {
    let owner_path = owners_path();
    let _lock = owners::lock(&owner_path, 0)?;
    let mut errors: Vec<String> = Vec::new();
    let listed_before = nft_list_table();
    if !listed_before.trim().is_empty() || Path::new("/sys/fs/cgroup").join(SLICE).exists() {
        let nft_out = Command::new("nft")
            .args(["delete", "table", "inet", TABLE])
            .output();
        match nft_out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.contains("No such file")
                    && !err.contains("does not exist")
                    && !listed_before.trim().is_empty()
                {
                    errors.push(format!("nft delete table: {err}"));
                }
            }
            Err(e) => errors.push(format!("nft exec: {e}")),
        }
    }
    let still = nft_list_table();
    if still.contains(&format!("table inet {TABLE}")) || still.contains("blocked4") {
        errors.push("table inet vallum still present after delete".into());
    }

    let restore_dir = vallum_block::restore::restore_dir();
    if restore_dir.is_dir() {
        if let Ok(rd) = fs::read_dir(&restore_dir) {
            for e in rd.flatten() {
                let stem = e
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if stem.is_empty() {
                    continue;
                }
                match restore_memberships(&stem) {
                    Ok(_) => {
                        let _ = fs::remove_file(e.path());
                    }
                    Err(err) => errors.push(format!("restore {stem}: {err}")),
                }
            }
        }
    }

    let slice = cgroup_slice();
    if slice.is_dir() {
        if let Ok(rd) = fs::read_dir(&slice) {
            for e in rd.flatten() {
                let p = e.path();
                // A cgroup directory is mostly control FILES—memory.max,
                // cpu.stat, and about ninety more. Only subdirectories are
                // child cgroups. rmdir on the rest can only ever return
                // ENOTDIR, and reporting each one buried the single error that
                // mattered (a child cgroup still holding processes) under
                // ninety lines of guaranteed noise.
                if !p.is_dir() {
                    continue;
                }
                if let Err(e) = fs::remove_dir(&p) {
                    errors.push(format!("rmdir {}: {e}", p.display()));
                }
            }
        }
        if let Err(e) = fs::remove_dir(&slice) {
            if slice.exists() {
                errors.push(format!("rmdir {}: {e}", slice.display()));
            }
        }
    }
    if slice.exists() {
        errors.push(format!("{} still exists", slice.display()));
    }
    let _ = fs::remove_file(owners_path());
    // The marker goes only with the table. If the delete failed, a pause rule
    // may still sit at the head of the chain, and dropping the marker would
    // turn the switch back on over it.
    if table_gone() {
        let _ = fs::remove_file(pause::marker_path());
        if let Err(e) = block_state::clear_all() {
            errors.push(format!("block markers: {e}"));
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    temporary::clear_all()?;
    Ok(json!({"ok": true, "teardown": true, "verified": true, "temporaryRules": []}))
}

fn status() -> Result<Value, String> {
    let kernel_listing = nft_table_listing();
    let listed = kernel_listing
        .as_ref()
        .ok()
        .and_then(|v| v.as_ref())
        .cloned()
        .unwrap_or_default();
    let has_table = matches!(kernel_listing, Ok(Some(_)));
    let kernel_known = kernel_listing.is_ok();
    let (cgroup_blocks, cgroup_blocks_source, cgroup_blocks_known) = if kernel_known {
        let blocks = nft_verify::cgroup_blocked_apps(&listed);
        // A privileged status call during installation imports rules that
        // predate these markers. Never remove markers here: a concurrent
        // block must not be lost to a status snapshot.
        if caller::current_euid() == 0 {
            block_state::initialize()?;
            for app in &blocks {
                block_state::mark(app)?;
            }
        }
        (blocks, "kernel", true)
    } else {
        let known = block_state::initialized()?;
        (block_state::list()?, "marker", known)
    };
    let map: OwnerMap = owners::load(&owners_path());
    let caps = probe_blocking_caps();
    let scoped = caller::invoking_uid().and_then(temporary::load);
    let (nameservers, gateways) = host_critical();
    Ok(json!({
        "ok": true,
        "table": has_table,
        "paused": is_paused(),
        "hostCritical": endpoints::critical_list(&nameservers, &gateways),
        "owners": map,
        "cgroupBlocks": cgroup_blocks,
        "cgroupBlocksSource": cgroup_blocks_source,
        "cgroupBlocksKnown": cgroup_blocks_known,
        "temporaryRulesKnown": scoped.is_ok(),
        "temporaryRulesError": scoped.as_ref().err().cloned().unwrap_or_default(),
        "temporaryRules": scoped.unwrap_or_default(),
        "tableSource": if kernel_known { "kernel" } else { "unreadable" },
        "raw": listed,
        "helper": CANONICAL_HELPER,
        "nft": caps.nft,
        "conntrack": caps.conntrack,
        "cgroupv2": caps.cgroupv2,
        "blockingReady": caps.ready(),
        "missing": caps.missing(),
        "packages": caps.packages(),
        "hint": caps.hint()
    }))
}

fn nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft exec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("exist") || err.contains("File exists") || err.contains("No such file") {
        // delete of missing element is success for idempotent unblock
        if args.first().copied() == Some("delete") {
            return Ok(());
        }
        if err.contains("exist") || err.contains("File exists") {
            return Ok(());
        }
    }
    Err(format!("nft {} failed: {err}", args.join(" ")))
}

fn nft_list_table() -> String {
    Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Ok(None) means nft confirmed this table does not exist. Err means the
/// caller lacked permission or the nft read otherwise failed: do not turn it
/// into an authoritative empty block list.
fn nft_table_listing() -> Result<Option<String>, String> {
    let out = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .map_err(|e| format!("nft list table: {e}"))?;
    if out.status.success() {
        return Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()));
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("No such file or directory") || err.contains("does not exist") {
        return Ok(None);
    }
    Err(format!("nft list table: {err}"))
}

fn nft_list_table_json() -> Option<String> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", "inet", TABLE])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    if s.trim().is_empty() {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn scoped_cleanup_deletes_referencing_rules() {
        const PATH: &str = "vallum.slice/vallum-__vallum_scoped_1000_70726f6265";
        if std::env::var_os("KUB0_SCOPED_FAKE_NFT").is_some() {
            delete_rules_containing(PATH).unwrap();
            return;
        }
        // Run the actual cleanup function in a separate test process. Its
        // private PATH cannot execute the real nft, or affect other tests.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vallum-scoped-cleanup-{}-{}", std::process::id(), epoch_ms()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let fake = dir.join("nft");
        let log = dir.join("calls");
        fs::write(&fake, r#"#!/bin/sh
printf '%s\n' "$*" >> "$KUB0_SCOPED_NFT_LOG"
if [ "$1" = "-a" ]; then
  printf '%s\n' 'socket cgroupv2 level 2 "vallum.slice/vallum-__vallum_scoped_1000_70726f6265" ip daddr @t4_probe drop comment "vallum-scoped" # handle 42'
  printf '%s\n' 'socket cgroupv2 level 2 "vallum.slice/vallum-__vallum_scoped_1000_70726f62652" ip daddr @t4_other drop comment "vallum-scoped" # handle 43'
fi
"#).unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "endpoint_tests::scoped_cleanup_deletes_referencing_rules", "--nocapture"])
            .env("KUB0_SCOPED_FAKE_NFT", "1").env("KUB0_SCOPED_NFT_LOG", &log)
            .env("PATH", &dir).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let calls = fs::read_to_string(&log).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(calls.lines().any(|line| line == "delete rule inet vallum out handle 42"), "{calls}");
        assert!(!calls.lines().any(|line| line == "delete rule inet vallum out handle 43"), "{calls}");
    }

    #[derive(Default)]
    struct FakeSet {
        present: BTreeSet<IpAddr>,
        deleted: Vec<IpAddr>,
        fail_add: Option<IpAddr>,
    }

    impl EndpointSet for FakeSet {
        fn contains(&mut self, ip: &IpAddr) -> Result<bool, String> {
            Ok(self.present.contains(ip))
        }
        fn add(&mut self, ip: &IpAddr) -> Result<(), String> {
            if self.fail_add == Some(*ip) {
                return Err(format!("simulated nft failure for {ip}"));
            }
            if !self.present.insert(*ip) {
                return Err("File exists".into());
            }
            Ok(())
        }
        fn delete(&mut self, ip: &IpAddr) -> Result<(), String> {
            self.deleted.push(*ip);
            self.present.remove(ip);
            Ok(())
        }
    }

    #[test]
    fn shared_member_is_owned_but_not_deleted_on_new_block_rollback() {
        let shared: IpAddr = "93.184.216.34".parse().unwrap();
        let fresh: IpAddr = "8.8.8.8".parse().unwrap();
        let mut set = FakeSet::default();
        set.present.insert(shared);
        let inserted = insert_missing_endpoints(&mut set, &[shared, fresh]).unwrap();
        assert_eq!(inserted, vec![fresh]);

        let mut owners = OwnerMap::new();
        owners::grant(&mut owners, "app-a", &[shared.to_string()]);
        owners::grant(
            &mut owners,
            "app-b",
            &[shared.to_string(), fresh.to_string()],
        );
        let (released, retained) = owners::exclusive_release(&mut owners, "app-a");
        assert!(released.is_empty());
        assert_eq!(retained, vec![shared.to_string()]);

        let error = rollback_inserted(&mut set, &inserted, "simulated conntrack failure".into());
        assert!(error.contains("rolled back"));
        assert_eq!(set.deleted, vec![fresh]);
        assert!(set.present.contains(&shared));
        assert!(!set.present.contains(&fresh));
    }

    #[test]
    fn failed_later_insert_rolls_back_earlier_insert_only() {
        let shared: IpAddr = "93.184.216.34".parse().unwrap();
        let first: IpAddr = "8.8.8.8".parse().unwrap();
        let fails: IpAddr = "1.1.1.1".parse().unwrap();
        let mut set = FakeSet {
            fail_add: Some(fails),
            ..FakeSet::default()
        };
        set.present.insert(shared);
        let error = insert_missing_endpoints(&mut set, &[shared, first, fails]).unwrap_err();
        assert!(error.contains("simulated nft failure"));
        assert_eq!(set.deleted, vec![first]);
        assert_eq!(set.present, BTreeSet::from([shared]));
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;

    #[test]
    fn safe_path_names_only_system_directories() {
        for dir in SAFE_PATH.split(':') {
            assert!(
                ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].contains(&dir),
                "unexpected PATH entry {dir}"
            );
        }
    }

    // Nothing else in this file fails if the call is deleted, and without it
    // every tool is found through whatever PATH sudo carried in.
    #[test]
    fn main_pins_the_environment_before_anything_else() {
        let src = include_str!("main.rs");
        let body = src.split("fn main() {").nth(1).expect("fn main");
        let first = body.lines().map(str::trim).find(|l| !l.is_empty());
        assert_eq!(first, Some("pin_environment();"));
    }

    // The parsers and gateway_refusal are unit-tested in endpoints.rs; this is
    // the only thing that fails if block_ips stops consulting them.
    #[test]
    fn block_ips_refuses_the_default_gateway() {
        fn body(name: &str) -> &'static str {
            include_str!("main.rs")
                .split(&format!("fn {name}("))
                .nth(1)
                .and_then(|s| s.split("\nfn ").next())
                .unwrap_or_else(|| panic!("fn {name}"))
        }
        for needle in ["parse_resolv_conf(", "parse_proc_net_route(", "parse_ipv6_route("] {
            assert!(body("host_critical").contains(needle), "host_critical lost {needle}");
        }
        for needle in [
            "host_critical()",
            "endpoints::refusal(&ip, &nameservers)",
            "endpoints::gateway_refusal(&ip, &gateways)",
        ] {
            assert!(body("block_ips").contains(needle), "block_ips lost {needle}");
        }
        // An org policy can never block this host's own resolvers or gateways.
        assert!(body("fleet_host_keep").contains("host_critical()"), "fleet_host_keep lost host_critical");
        assert!(body("fleet_sync").contains("fleet::plan(&spec, &fleet_host_keep())"), "fleet_sync lost the host floor");
        // The panel filters its offer on this list; it must be the same one.
        for needle in ["host_critical()", "\"hostCritical\": endpoints::critical_list(&nameservers, &gateways)"] {
            assert!(body("status").contains(needle), "status lost {needle}");
        }
        // An app block's conntrack flush is host-wide too.
        for needle in ["host_critical()", "remotes_of(&flows, &nameservers, &gateways)"] {
            assert!(body("block_app_with_rule").contains(needle), "block_app_with_rule lost {needle}");
        }
    }

    #[test]
    fn an_app_block_never_flushes_what_an_endpoint_block_refuses() {
        let flow = |remote: &str| Flow {
            proto: sockets::Proto::Tcp,
            local: "192.168.0.10:40000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            state: 1,
            inode: 1,
        };
        let flows: Vec<Flow> = [
            "93.184.216.34:443",
            "192.168.0.254:53",
            "192.168.0.1:443",
            "100.100.100.100:443",
            "[fd7a:115c:a1e0::1]:443",
            "[fe80::1]:443",
            "127.0.0.53:53",
            "0.0.0.0:0",
            "93.184.216.34:80",
            "[2001:db8::7]:443",
        ]
        .iter()
        .map(|r| flow(r))
        .collect();
        let ns: Vec<IpAddr> = vec!["192.168.0.1".parse().unwrap()];
        let gw: Vec<IpAddr> = vec!["192.168.0.254".parse().unwrap()];
        let got: Vec<String> = remotes_of(&flows, &ns, &gw).iter().map(|i| i.to_string()).collect();
        assert_eq!(got, vec!["2001:db8::7", "93.184.216.34"]);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    const POLICY: &str = include_str!("../../polkit/ai.kub0.agent.policy");
    const MAIN: &str = include_str!("main.rs");
    /// Verbs that take protection away. Their authorization is never kept.
    const LOWERING: &[&str] = &[
        "unblock-app", "unblock-ips", "unblock-scoped", "expire-scoped", "pause", "teardown",
        // An org sync can replace a block set with an empty one.
        "fleet-sync", "fleet-clear",
        // Letting a file the exec gate blocked run, once or for good.
        "execgate-trust", "execgate-allow-once",
    ];

    struct Action {
        id: String,
        path: String,
        argv1: Option<String>,
        any: String,
        inactive: String,
        active: String,
    }

    fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
        let start = s.find(open)? + open.len();
        Some(&s[start..start + s[start..].find(close)?])
    }

    /// The `kub0` CLI's actions: the installed binary's paths, never this
    /// helper's, so they cannot match a helper verb.
    const KUB0_PATHS: &[&str] = &["/usr/bin/kub0", "/usr/lib/kub0/kub0"];

    /// This helper's actions: the ones whose exec.path is the helper.
    fn actions() -> Vec<Action> {
        all_actions().into_iter().filter(|a| a.path == CANONICAL_HELPER).collect()
    }

    /// pkexec's lookup (polkit src/programs/pkexec.c, `find_action_for_path`):
    /// the first action whose exec.path equals the program's path and whose
    /// exec.argv1, when it has one, equals argv[1]. `canonicalize` is what
    /// polkit 127 and later do to the program first (`realpath(3)`, right
    /// after `g_find_program_in_path`); 126 and earlier match the path as it
    /// was given. The two versions differ only in that step.
    fn pkexec_action(program: &std::path::Path, argv1: &str, canonicalize: bool) -> Option<Action> {
        let path = if canonicalize {
            std::fs::canonicalize(program).ok()?.to_string_lossy().into_owned()
        } else {
            program.to_string_lossy().into_owned()
        };
        // A test cannot write /usr/lib, so the fixture tree maps onto it.
        let path = path.strip_prefix(&*FIXTURE_ROOT.to_string_lossy()).unwrap_or(&path).to_string();
        all_actions()
            .into_iter()
            .find(|a| a.path == path && a.argv1.as_deref().map_or(true, |v| v == argv1))
    }

    static FIXTURE_ROOT: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        // The install layout under a private root: the helper at its path.
        let root = std::env::temp_dir().join(format!("kub0-block-polkit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let new = root.join(CANONICAL_HELPER.trim_start_matches('/'));
        std::fs::create_dir_all(new.parent().unwrap()).unwrap();
        std::fs::write(&new, b"helper").unwrap();
        std::fs::canonicalize(&root).unwrap()
    });

    fn all_actions() -> Vec<Action> {
        POLICY
            .split("<action id=\"")
            .skip(1)
            .map(|a| Action {
                id: a[..a.find('"').unwrap()].to_string(),
                path: between(a, "exec.path\">", "<").unwrap_or("").to_string(),
                argv1: between(a, "exec.argv1\">", "<").map(str::to_string),
                any: between(a, "<allow_any>", "<").unwrap_or("").to_string(),
                inactive: between(a, "<allow_inactive>", "<").unwrap_or("").to_string(),
                active: between(a, "<allow_active>", "<").unwrap_or("").to_string(),
            })
            .collect()
    }

    /// The arms of main()'s verb match, up to its catch-all.
    fn dispatched_verbs() -> Vec<&'static str> {
        between(MAIN, "let result = match args[1].as_str() {", "other =>")
            .unwrap()
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"')?.split('"').next())
            .collect()
    }

    #[test]
    fn every_action_names_its_verb() {
        // pkexec takes the first action whose exec.path matches, and one
        // without exec.argv1 matches every verb. polkitd lists actions in
        // hash order, so a catch-all would randomly swallow the verbs meant
        // to ask every time.
        let all = actions();
        assert!(!all.is_empty(), "no actions parsed");
        for a in &all {
            let verb = a.argv1.as_deref().unwrap_or_else(|| panic!("{} matches every verb", a.id));
            assert_eq!(a.id, format!("ai.kub0.agent.{verb}"));
            assert_eq!(a.path, CANONICAL_HELPER, "{}", a.id);
            assert_eq!((a.any.as_str(), a.inactive.as_str()), ("no", "no"), "{}", a.id);
        }
    }

    #[test]
    fn every_verb_has_exactly_one_action() {
        let mut verbs = dispatched_verbs();
        verbs.sort_unstable();
        let actions = actions();
        let mut covered: Vec<&str> = actions.iter().filter_map(|a| a.argv1.as_deref()).collect();
        covered.sort_unstable();
        assert_eq!(covered, verbs);
    }

    /// 0.4.5 and 0.4.6 kept a link at the helper's 0.4.x path and a second
    /// set of actions (`ai.kub0.agent.compat.*`) for it. Both are gone: the
    /// helper has one path, and under either polkit that path finds the
    /// verb's own action, never the generic org.freedesktop.policykit.exec.
    #[test]
    fn the_helper_has_one_path_and_every_verb_finds_its_action_there() {
        for a in all_actions() {
            assert!(!a.id.contains(".compat"), "{} is a compat action", a.id);
            assert!(!a.path.contains("vallum"), "{} runs {}", a.id, a.path);
        }
        let new = FIXTURE_ROOT.join(CANONICAL_HELPER.trim_start_matches('/'));
        for verb in dispatched_verbs() {
            let want = if LOWERING.contains(&verb) { "auth_admin" } else { "auth_admin_keep" };
            for canon in [true, false] {
                let a = pkexec_action(&new, verb, canon).unwrap_or_else(|| panic!("{verb}: no action"));
                assert_eq!((a.id.as_str(), a.active.as_str()), (format!("ai.kub0.agent.{verb}").as_str(), want));
            }
        }
    }

    #[test]
    fn every_other_action_runs_the_installed_kub0_and_asks_every_time() {
        let others: Vec<Action> =
            all_actions().into_iter().filter(|a| a.path != CANONICAL_HELPER).collect();
        let mut paths: Vec<&str> = others.iter().map(|a| a.path.as_str()).collect();
        paths.sort_unstable();
        let mut want = KUB0_PATHS.to_vec();
        want.sort_unstable();
        assert_eq!(paths, want, "one action per installed kub0 path, and nothing else");
        for a in &others {
            assert!(a.id.starts_with("ai.kub0.agent.kub0"), "{}", a.id);
            assert_eq!((a.any.as_str(), a.inactive.as_str(), a.active.as_str()), ("no", "no", "auth_admin"), "{}", a.id);
            // Path-only is safe: no other action shares the path.
            assert_eq!(a.argv1, None, "{}", a.id);
        }
    }

    #[test]
    fn verbs_that_lower_protection_ask_every_time() {
        let verbs = dispatched_verbs();
        for v in LOWERING {
            assert!(verbs.contains(v), "{v} is no longer a verb; update LOWERING");
        }
        for a in actions() {
            let verb = a.argv1.unwrap_or_default();
            let want = if LOWERING.contains(&verb.as_str()) { "auth_admin" } else { "auth_admin_keep" };
            assert_eq!(a.active, want, "{verb}");
        }
    }
}
