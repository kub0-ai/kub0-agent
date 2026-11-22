//! One control API, three readers that must agree: the daemon's `VERBS`
//! (`daemon/src/control.rs`), the `kub0` CLI's command table
//! (`request_for` in `cli/src/main.rs`) and what the panel sends
//! (`Service.qml`, routed by `js/Control.js`). Neither the CLI nor the panel
//! links the daemon, so their halves are read as text.
//!
//! - Every verb that changes anything has a `kub0` command, and every verb
//!   the CLI sends is one the daemon answers.
//! - Every change the panel makes has a route (`js/Control.js` `ROUTES`), and
//!   each route names a verb in `VERBS` and takes the path that verb needs:
//!   a control request to the system daemon for a raise, `pkexec kub0` for
//!   anything the daemon keeps to root (a lowering verb, an address block).
//! - The panel calls the helper itself (`runHelper`) nowhere but the
//!   documented fallback for a system daemon it cannot reach.
//! - Every control request the panel names by literal
//!   (`controlRequest("verb", …)`) is in `VERBS`.
//! - Every line the panel writes without a request id is a legacy line the
//!   daemon classifies: a read it answers, or a mutation
//!   `control::legacy_mutation` knows (refused on the system daemon to anyone
//!   but root; the panel sends them to its own user daemon).
//! - The routes the operator chose (2026-11-11, #61 step 2) hold: a policy
//!   snooze goes the root path and never as a line to the user daemon except
//!   on a user-only install; a resume goes the system path; the panel's policy
//!   list and account card are system reads.
//! - One daemon (#61): the panel sends a tag and a watch rule to the daemon it
//!   reads (a request to the system daemon, the legacy line to its own), and
//!   `kub0` has one route for every verb: no verb picks a daemon of its own.

use std::collections::BTreeSet;
use vallumd::control::{access_for, legacy_mutation, Access, VERBS};

const CLI_MAIN: &str = include_str!("../../cli/src/main.rs");
const SERVICE: &str = include_str!("../../Service.qml");
const CONTROL_JS: &str = include_str!("../../js/Control.js");
const ACTIVITY_JS: &str = include_str!("../../js/Activity.js");
const CLI_ARGS: &str = include_str!("../../cli/src/args.rs");

/// The legacy reads `handle_cmd` answers by `cmd` and by `type`.
const LEGACY_READ_CMDS: &[&str] = &["history", "investigate", "timeline"];
const LEGACY_READ_TYPES: &[&str] = &["panel-open", "panel-close", "ping"];

fn body_of<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src.find(signature).unwrap_or_else(|| panic!("no `{signature}`"));
    let end = src[start..].find("\n}\n").expect("unterminated function") + start;
    &src[start..end]
}

/// The wire verbs `request_for` returns: `=> "verb"`, `("verb", m` and a
/// match arm's trailing `"verb"` line.
fn cli_verbs() -> BTreeSet<String> {
    let body = body_of(CLI_MAIN, "fn request_for(");
    let mut out = BTreeSet::new();
    for line in body.lines() {
        let t = line.trim();
        for prefix in ["=> \"", "return (\""] {
            if let Some(i) = t.find(prefix) {
                let rest = &t[i + prefix.len()..];
                out.insert(rest[..rest.find('"').unwrap()].to_string());
            }
        }
        if t.len() > 2 && t.starts_with('"') && t.ends_with('"') && !t[1..t.len() - 1].contains('"') {
            out.insert(t[1..t.len() - 1].to_string());
        }
    }
    assert!(out.len() >= 15, "CLI verb parse found only {out:?}");
    out
}

/// The quoted first argument of every `call("…"` in `src`.
fn quoted_after(src: &str, call: &str) -> Vec<String> {
    src.match_indices(call)
        .map(|(i, _)| {
            let rest = &src[i + call.len()..];
            rest[..rest.find('"').expect("unterminated literal")].to_string()
        })
        .collect()
}

fn panel_requests(service: &str) -> Vec<String> {
    quoted_after(service, "controlRequest(\"")
}

fn panel_legacy_cmds(service: &str) -> Vec<String> {
    quoted_after(service, "cmd: \"")
}

fn panel_legacy_types(service: &str) -> Vec<String> {
    quoted_after(service, "type: \"")
}

#[test]
fn every_verb_that_changes_anything_has_a_kub0_command() {
    let cli = cli_verbs();
    for (verb, access) in VERBS {
        if *access != Access::Read {
            assert!(cli.contains(*verb), "{verb} has no kub0 command");
        }
    }
    for verb in &cli {
        assert!(access_for(verb).is_some(), "kub0 sends {verb}, which the daemon does not answer");
    }
}

fn check_panel(service: &str) -> Result<(), String> {
    for verb in panel_requests(service) {
        if access_for(&verb).is_none() {
            return Err(format!("the panel sends control request {verb:?}, which is not in VERBS"));
        }
    }
    for cmd in panel_legacy_cmds(service) {
        let line = serde_json::json!({ "cmd": cmd });
        if !LEGACY_READ_CMDS.contains(&cmd.as_str()) && legacy_mutation(&line).is_none() {
            return Err(format!("the panel writes legacy cmd {cmd:?}, which the daemon neither answers as a read nor classifies"));
        }
    }
    for ty in panel_legacy_types(service) {
        let line = serde_json::json!({ "type": ty });
        if !LEGACY_READ_TYPES.contains(&ty.as_str()) && legacy_mutation(&line).is_none() {
            return Err(format!("the panel writes legacy type {ty:?}, which the daemon neither answers as a read nor classifies"));
        }
    }
    Ok(())
}

#[test]
fn every_request_the_panel_sends_is_one_the_daemon_classifies() {
    check_panel(SERVICE).unwrap();
    assert!(!panel_legacy_cmds(SERVICE).is_empty(), "the panel parse found no requests at all");
}

/// The check itself catches what it is for, on a copy of the panel with one
/// request added, so the test cannot pass by reading nothing.
#[test]
fn a_panel_request_outside_the_table_fails_the_check() {
    let added = format!("{SERVICE}\nfunction bogus() {{ controlRequest(\"frobnicate\", {{}}) }}\n");
    assert!(check_panel(&added).unwrap_err().contains("frobnicate"));
    let added = format!("{SERVICE}\nfunction bogus() {{ writeSock(JSON.stringify({{ cmd: \"frobnicate\" }})) }}\n");
    assert!(check_panel(&added).unwrap_err().contains("frobnicate"));
    let added = format!("{SERVICE}\nfunction bogus() {{ writeSock(JSON.stringify({{ type: \"frobnicate\" }})) }}\n");
    assert!(check_panel(&added).unwrap_err().contains("frobnicate"));
    let known = format!("{SERVICE}\nfunction fine() {{ controlRequest(\"block-dest\", {{}}) }}\n");
    assert_eq!(check_panel(&known), Ok(()));
}

/// One `js/Control.js` route: `"helper-verb": { path: "…", cmd: "…", ips: … },`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    helper: String,
    path: String,
    cmd: String,
    ips: bool,
}

fn quoted_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    Some(&rest[..rest.find('"')?])
}

fn routes(control: &str) -> Vec<Route> {
    let table = &control[control.find("var ROUTES = {").expect("no ROUTES in js/Control.js")..];
    let table = &table[..table.find("\n}").expect("unterminated ROUTES")];
    table
        .lines()
        .filter(|l| l.contains("path:"))
        .map(|l| {
            let t = l.trim();
            Route {
                helper: t[1..t[1..].find('"').unwrap() + 1].to_string(),
                path: quoted_field(t, "path: \"").expect("route without path").to_string(),
                cmd: quoted_field(t, "cmd: \"").expect("route without cmd").to_string(),
                ips: t.contains("ips: true"),
            }
        })
        .collect()
}

/// The helper verbs the panel builds a change from: `submitChange(["verb"`,
/// `var args = ["verb"`, `runExecGateVerb("verb"`, and the pause switch.
fn panel_changes(service: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for call in ["submitChange([\"", "var args = [\"", "runExecGateVerb(\""] {
        out.extend(quoted_after(service, call));
    }
    if service.contains("submitChange([paused ? \"pause\" : \"resume\"])") {
        out.insert("pause".into());
        out.insert("resume".into());
    }
    out
}

fn needs_root(cmd: &str, ips: bool) -> bool {
    access_for(cmd) == Some(Access::Lower) || (cmd == "block" && ips)
}

fn check_routes(service: &str, control: &str) -> Result<(), String> {
    let routes = routes(control);
    if routes.len() < 9 {
        return Err(format!("route parse found only {routes:?}"));
    }
    for r in &routes {
        if access_for(&r.cmd).is_none() {
            return Err(format!("route {} sends {:?}, which is not in VERBS", r.helper, r.cmd));
        }
        let want = if needs_root(&r.cmd, r.ips) { "root" } else { "system" };
        if r.path != want {
            return Err(format!(
                "route {} takes the {} path, but {:?} needs the {want} path",
                r.helper, r.path, r.cmd
            ));
        }
    }
    let changes = panel_changes(service);
    if changes.len() < 9 {
        return Err(format!("panel change parse found only {changes:?}"));
    }
    for verb in &changes {
        if !routes.iter().any(|r| &r.helper == verb) {
            return Err(format!("the panel builds a {verb:?} change with no route in js/Control.js"));
        }
    }
    Ok(())
}

/// `runHelper(` outside its own definition and `dispatchChange`, the one
/// documented fallback.
fn check_helper_calls(service: &str) -> Result<(), String> {
    let mut rest = service.to_string();
    for allowed in ["  function runHelper(", "  function dispatchChange("] {
        let start = rest.find(allowed).ok_or_else(|| format!("no `{}`", allowed.trim()))?;
        let end = rest[start..].find("\n  }\n").ok_or("unterminated function")? + start;
        rest.replace_range(start..end, "");
    }
    match rest.find("runHelper(") {
        Some(i) => {
            let line = rest[..i].matches('\n').count();
            Err(format!("the panel runs the helper outside the fallback (after its line {line} of the remainder)"))
        }
        None => Ok(()),
    }
}

/// The exec-gate notification's buttons (trust, allow once) lower
/// protection: they run `pkexec /usr/bin/kub0 <verb>`, never the helper.
fn check_notification_actions(activity: &str) -> Result<(), String> {
    if activity.contains("\"/usr/lib/kub0/kub0-block\"") {
        return Err("a notification action runs the helper".into());
    }
    let words = quoted_after(activity, "\"/usr/bin/pkexec\", \"/usr/bin/kub0\", \"");
    if words.is_empty() {
        return Err("no notification action runs kub0".into());
    }
    for w in words {
        if access_for(&w) != Some(Access::Lower) {
            return Err(format!("a notification action runs kub0 {w:?}, which needs no root"));
        }
    }
    Ok(())
}

#[test]
fn every_panel_change_takes_the_path_its_verb_needs() {
    check_routes(SERVICE, CONTROL_JS).unwrap();
    check_helper_calls(SERVICE).unwrap();
    check_notification_actions(ACTIVITY_JS).unwrap();
}

/// The checks catch what they are for, on copies with one thing wrong.
#[test]
fn a_misrouted_or_unrouted_change_fails_the_check() {
    let lowered = CONTROL_JS.replace(
        r#""unblock-app": { path: "root", cmd: "unblock", ips: false },"#,
        r#""unblock-app": { path: "system", cmd: "unblock", ips: false },"#,
    );
    assert_ne!(lowered, CONTROL_JS);
    assert!(check_routes(SERVICE, &lowered).unwrap_err().contains("needs the root path"));
    let address = CONTROL_JS.replace(
        r#""block-ips": { path: "root", cmd: "block", ips: true },"#,
        r#""block-ips": { path: "system", cmd: "block", ips: true },"#,
    );
    assert!(check_routes(SERVICE, &address).unwrap_err().contains("needs the root path"), "an address block is root's");
    let prompt = CONTROL_JS.replace(
        r#""resume": { path: "system", cmd: "resume", ips: false },"#,
        r#""resume": { path: "root", cmd: "resume", ips: false },"#,
    );
    assert!(check_routes(SERVICE, &prompt).unwrap_err().contains("needs the system path"), "no prompt for a raise");
    let unknown = CONTROL_JS.replace(r#"cmd: "block-dest""#, r#"cmd: "frobnicate""#);
    assert!(check_routes(SERVICE, &unknown).unwrap_err().contains("not in VERBS"));
    let unrouted = format!("{SERVICE}\n  function frob() {{ submitChange([\"fleet-clear\"]) }}\n");
    assert!(check_routes(&unrouted, CONTROL_JS).unwrap_err().contains("fleet-clear"));
    let direct = format!("{SERVICE}\n  function frob() {{\n    runHelper([\"unblock-app\", \"x\"])\n  }}\n");
    assert!(check_helper_calls(&direct).is_err());
    let helper = ACTIVITY_JS.replace(r#""/usr/bin/kub0", "trust""#, r#""/usr/lib/kub0/kub0-block", "execgate-trust""#);
    assert!(check_notification_actions(&helper).is_err());
}

/// The body of one `Service.qml` function, at its two-space indent.
fn qml_fn<'a>(service: &'a str, name: &str) -> Result<&'a str, String> {
    let sig = format!("\n  function {name}(");
    let start = service.find(&sig).ok_or_else(|| format!("Service.qml has no function {name}"))?;
    let end = service[start + 1..].find("\n  }\n").ok_or_else(|| format!("{name} is unterminated"))? + start + 1;
    Ok(&service[start..end])
}

/// The operator's routes for snooze, resume, the policy list, tags and
/// watches.
fn check_operator_routes(service: &str, cli_args: &str, cli_main: &str) -> Result<(), String> {
    // A snooze is the system daemon's (root path) and a resume too (system
    // path): both go through submitChange, never straight to a socket.
    for name in ["snoozePolicyRule", "resumePolicyRule"] {
        let body = qml_fn(service, name)?;
        if !body.contains("submitChange([") || body.contains("writeSock(") {
            return Err(format!("{name} must go through submitChange and never write to the user daemon"));
        }
    }
    // The legacy snooze lines live only in the user-only fallback, which only
    // dispatchChange calls, and only when the system daemon is unreachable.
    let fallback = qml_fn(service, "userDaemonPolicyChange")?;
    for line in ["cmd: \"netpolicy-snooze\"", "cmd: \"netpolicy-resume\""] {
        if service.matches(line).count() != fallback.matches(line).count() {
            return Err(format!("{line} is written outside userDaemonPolicyChange"));
        }
    }
    let dispatch = qml_fn(service, "dispatchChange")?;
    let calls = service.matches("userDaemonPolicyChange(").count() - 1;
    if calls != 1 || !dispatch.contains("if (!reachable && Control.isPolicyChange(change.args)) {") || !dispatch.contains("userDaemonPolicyChange(change.args)") {
        return Err("only dispatchChange, with no system daemon reachable, may send a policy change to the user daemon".into());
    }
    // ...and only on a user-only install: with /usr/bin/kub0 present the system
    // daemon is the one that enforces, so an unreachable socket still means kub0.
    if !dispatch.contains("if (!reachable && Control.isPolicyChange(change.args)) {\n      if (!kub0Installed) {") {
        return Err("a policy change reaches the user daemon only on a user-only install (!kub0Installed)".into());
    }
    // The policy list and the account card are read from the system daemon.
    let reads = qml_fn(service, "sendSystemRead")?;
    for verb in ["status", "policies"] {
        if !reads.contains(&format!("controlRequest(\"{verb}\"")) || access_for(verb) != Some(Access::Read) {
            return Err(format!("the panel does not read {verb} from the system daemon"));
        }
    }
    // A tag goes to the system daemon always, and to the panel's own daemon
    // only while that is the one whose rows it shows.
    let tag = qml_fn(service, "tagNetwork")?;
    let on_system = qml_fn(service, "tagOnSystem")?;
    if !tag.contains("if (eventSource !== \"system\")\n      writeSock(JSON.stringify({\n        type: \"tag\",") {
        return Err("tagNetwork must send the tag line to the panel's own daemon, and only while it reads that daemon".into());
    }
    if !(tag.contains("root.tagOnSystem(") && on_system.contains("controlRequest(\"tag\"")) {
        return Err("tagNetwork no longer sends the tag to the system daemon".into());
    }
    // A watch rule goes to the daemon whose rows the panel shows: the `watch`
    // line to its own daemon, a request to the system daemon (which takes the
    // line from root only).
    for (name, verb) in [("setWatch", "watch-set"), ("deleteWatch", "watch-delete")] {
        let body = qml_fn(service, name)?;
        if !body.contains("cmd: \"watch\"") {
            return Err(format!("{name} no longer writes the watch line to the panel's own daemon"));
        }
        if !body.contains(&format!("if (eventSource === \"system\")\n      return watchOnSystem(\"{verb}\"")) || access_for(verb) != Some(Access::Raise) {
            return Err(format!("{name} must send {verb} to the system daemon when the panel reads it"));
        }
    }
    let watch_on_system = qml_fn(service, "watchOnSystem")?;
    if !watch_on_system.contains("root.controlRequest(verb, fields") || watch_on_system.contains("writeSock(") {
        return Err("watchOnSystem must be a request to the system daemon and nothing else".into());
    }
    // Reading the system daemon the panel writes no `note`: that daemon records
    // what it did, and refuses the line from anyone but root.
    let note = qml_fn(service, "noteActivity")?;
    if !note.contains("if (eventSource === \"system\")\n      return\n") {
        return Err("noteActivity must not write to the system daemon".into());
    }
    // kub0 has one route (#61, one daemon): every verb goes to the daemon its
    // `connect` picks, the system daemon when its socket lets the caller in.
    // Until 0.5 watch rules went to the user daemon first and a tag to both.
    for gone in ["Route::UserFirst", "Route::Both", "fn route_of"] {
        if cli_args.contains(gone) {
            return Err(format!("kub0 routes a verb to a daemon of its own again ({gone})"));
        }
    }
    for gone in ["connect_user_first", "tag_both", "fn run_tag"] {
        if cli_main.contains(gone) {
            return Err(format!("kub0 routes a verb to a daemon of its own again ({gone})"));
        }
    }
    if !cli_main.contains("    let mut client = match connect(&g, verb, root) {") {
        return Err("kub0 no longer sends every verb through connect".into());
    }
    // Not only the old names: between building the request and connecting,
    // `run` decides nothing, so no verb can be sent somewhere else first under
    // any name. And the user socket is named once, where the one route picks.
    let from = cli_main.find("    let (verb, mut request, timeout) = request_for(&command, g.timeout);").ok_or("kub0's run no longer builds its request where the route check reads it")?;
    let to = cli_main.find("    let mut client = match connect(&g, verb, root) {").unwrap();
    let between = cli_main.get(from..to).ok_or("kub0's run connects before it builds its request")?;
    for line in between.lines().skip(1) {
        let t = line.trim();
        if !(t.is_empty() || t.starts_with("//") || t == "let root = args::needs_root(verb, &request);") {
            return Err(format!("kub0 decides something between its request and its one route to a daemon of its own: {t}"));
        }
    }
    let code = cli_main.split("#[cfg(test)]").next().unwrap_or(cli_main);
    if code.matches("user_socket()").count() != 1 {
        return Err("kub0 names the user socket outside the one route to a daemon of its own".into());
    }
    Ok(())
}

#[test]
fn the_operators_routes_hold_in_the_panel_and_in_kub0() {
    check_operator_routes(SERVICE, CLI_ARGS, CLI_MAIN).unwrap();
}

/// Each route, dropped on a copy, fails the check.
#[test]
fn a_dropped_operator_route_fails_the_check() {
    let user_snooze = SERVICE.replace(
        "    submitChange([\"policy-snooze\", String(ruleId), String(seconds || 3600)])",
        "    writeSock(JSON.stringify({ cmd: \"netpolicy-snooze\", ruleId: String(ruleId), seconds: seconds || 3600 }))",
    );
    assert_ne!(user_snooze, SERVICE);
    assert!(check_operator_routes(&user_snooze, CLI_ARGS, CLI_MAIN).unwrap_err().contains("snoozePolicyRule"));
    let unguarded = SERVICE.replace(
        "if (!reachable && Control.isPolicyChange(change.args)) {\n      if (!kub0Installed) {",
        "if (!reachable && Control.isPolicyChange(change.args)) {\n      if (true) {",
    );
    assert_ne!(unguarded, SERVICE);
    assert!(check_operator_routes(&unguarded, CLI_ARGS, CLI_MAIN).unwrap_err().contains("user-only install"));
    let no_system_tag = SERVICE.replace("withSystem(function(reachable) { root.tagOnSystem(reachable, fields) })", "");
    assert!(check_operator_routes(&no_system_tag, CLI_ARGS, CLI_MAIN).unwrap_err().contains("system daemon"));
    let no_user_tag = SERVICE.replacen("        type: \"tag\",", "        kind_: \"tag\",", 1);
    assert_ne!(no_user_tag, SERVICE);
    assert!(check_operator_routes(&no_user_tag, CLI_ARGS, CLI_MAIN).unwrap_err().contains("own daemon"));
    // The tag line written whatever daemon the panel reads: the system daemon refuses it.
    let tag_always = SERVICE.replace("    if (eventSource !== \"system\")\n      writeSock(JSON.stringify({\n        type: \"tag\",", "    if (true)\n      writeSock(JSON.stringify({\n        type: \"tag\",");
    assert_ne!(tag_always, SERVICE);
    assert!(check_operator_routes(&tag_always, CLI_ARGS, CLI_MAIN).unwrap_err().contains("own daemon"));
    let system_watch = SERVICE.replace(
        "    return writeSock(JSON.stringify({ cmd: \"watch\", action: \"delete\", id: String(id) }))",
        "    return controlRequest(\"watch-delete\", { id: String(id) }, function() {})",
    );
    assert_ne!(system_watch, SERVICE);
    assert!(check_operator_routes(&system_watch, CLI_ARGS, CLI_MAIN).unwrap_err().contains("deleteWatch"));
    // A watch that stays a legacy line when the panel reads the system daemon.
    let line_only = SERVICE.replace("      return watchOnSystem(\"watch-set\", ", "      return writeSock(\"watch-set\", ");
    assert_ne!(line_only, SERVICE);
    assert!(check_operator_routes(&line_only, CLI_ARGS, CLI_MAIN).unwrap_err().contains("setWatch"));
    let note_to_system = SERVICE.replace("    if (eventSource === \"system\")\n      return\n    var a = app", "    var a = app");
    assert_ne!(note_to_system, SERVICE);
    assert!(check_operator_routes(&note_to_system, CLI_ARGS, CLI_MAIN).unwrap_err().contains("noteActivity"));
    let no_list = SERVICE.replace("controlRequest(\"policies\"", "controlRequest(\"rules\"");
    assert!(check_operator_routes(&no_list, CLI_ARGS, CLI_MAIN).unwrap_err().contains("policies"));
    // A verb given a daemon of its own again, in either file.
    let routed = format!("{CLI_ARGS}\npub fn route_of(verb: &str) -> Route {{ Route::UserFirst }}\n");
    assert!(check_operator_routes(SERVICE, &routed, CLI_MAIN).unwrap_err().contains("a daemon of its own"));
    let both = format!("{CLI_MAIN}\nfn tag_both() {{}}\n");
    assert!(check_operator_routes(SERVICE, CLI_ARGS, &both).unwrap_err().contains("a daemon of its own"));
    let user_first = CLI_MAIN.replace("    let mut client = match connect(&g, verb, root) {", "    let mut client = match connect_user_first(&g, verb, root) {");
    assert_ne!(user_first, CLI_MAIN);
    assert!(check_operator_routes(SERVICE, CLI_ARGS, &user_first).unwrap_err().contains("a daemon of its own"));
    // The same route back under a new name: a verb sent to the user socket
    // before the one connect.
    let renamed = CLI_MAIN.replace(
        "    let mut client = match connect(&g, verb, root) {",
        "    if verb == \"tag\" {\n        let _ = Client::connect(&paths::user_socket());\n    }\n    let mut client = match connect(&g, verb, root) {",
    );
    assert_ne!(renamed, CLI_MAIN);
    assert!(check_operator_routes(SERVICE, CLI_ARGS, &renamed).unwrap_err().contains("a daemon of its own"));
    let elsewhere = format!("fn sneak() {{ let _ = paths::user_socket(); }}\n{CLI_MAIN}");
    assert!(check_operator_routes(SERVICE, CLI_ARGS, &elsewhere).unwrap_err().contains("a daemon of its own"));
}
