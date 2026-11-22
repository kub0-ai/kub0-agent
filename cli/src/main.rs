//! `kub0`: the kub0 endpoint CLI. One unprivileged binary that talks to the
//! running `kub0d` over its socket; it never carries a capability and
//! never runs the helper itself. The daemon decides what the caller may do
//! (`daemon/src/control.rs`) and runs the privileged half as root.

mod args;
mod carry;
mod client;
mod doctor;
mod elevate;
mod install;
mod paths;
#[path = "../../daemon/src/rename.rs"]
mod rename;
mod render;

use args::{Command, Global};
use client::{Client, ConnectError};
use paths::Target;
use render::{ago, cell, duration, kv, now_ms, opt_bool, table, yes_no};
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (global, command) = match args::parse(&argv) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("kub0: {e}\n\n{}", args::USAGE);
            std::process::exit(2);
        }
    };
    std::process::exit(run(global, command, &argv));
}

/// The socket a command goes to, and which daemon that is. `system_connects`
/// is whether a connect to the system socket succeeded; only a non-root
/// caller with no flag asks.
fn resolve_socket(g: &Global, system_connects: bool) -> (PathBuf, Target) {
    if let Some(p) = &g.socket {
        return (p.clone(), Target::User);
    }
    let system = paths::system_socket();
    let user = paths::user_socket();
    let target = paths::pick_target(g.target, paths::euid(), system.exists(), system_connects, user.exists());
    match target {
        Target::System => (system, target),
        Target::User => (user, target),
    }
}

/// Whether to try the system socket first: a non-root caller who named no
/// socket. Root's choice needs no probe.
fn probe_system(g: &Global, uid: u32) -> bool {
    g.socket.is_none() && g.target.is_none() && uid != 0
}

/// What reaches the system daemon for a request, when this shell could not:
/// root for one that needs it (`args::needs_root`), membership of its group
/// otherwise.
fn reach_hint(verb: &str, root: bool) -> String {
    if root {
        let what = if verb == "block" { "an address block (host-wide)".to_string() } else { verb.to_string() };
        format!("{what} needs root on the system daemon: sudo kub0 …")
    } else {
        format!(
            "the system daemon answers root and members of the {} group, and this shell is in neither \
             (`sudo kub0 install` adds the installing user; a new login applies a new membership)",
            paths::STATUS_GROUP
        )
    }
}

fn connect(g: &Global, verb: &str, root: bool) -> Result<Client, i32> {
    let system = paths::system_socket();
    let mut system_err = None;
    let mut first = None;
    if probe_system(g, paths::euid()) {
        match Client::connect(&system) {
            Ok(c) => first = Some(c),
            Err(e) => system_err = Some(e),
        }
    }
    let (socket, target) = resolve_socket(g, first.is_some());
    let attempt = match first {
        Some(c) => Ok(c),
        None => Client::connect(&socket),
    };
    match attempt {
        Ok(c) if !c.hello.requests => {
            eprintln!(
                "kub0: kub0d {} at {} predates kub0 requests; update it (sudo kub0 install, or rebuild the plugin)",
                c.hello.version,
                socket.display()
            );
            Err(3)
        }
        Ok(c) => Ok(c),
        Err(e) => {
            let hint = match (&e, target) {
                (ConnectError::Denied(_), Target::System) => format!("\n{}", reach_hint(verb, root)),
                (ConnectError::Absent(_), Target::User) if paths::euid() != 0 => match &system_err {
                    Some(ConnectError::Denied(_)) => format!("\nno per-user daemon; {}", reach_hint(verb, root)),
                    _ => "\nno daemon running: start the panel (desktop) or `sudo kub0 install` (server)".to_string(),
                },
                (ConnectError::Absent(_), Target::System) => "\nno system daemon: `sudo kub0 install`, or `systemctl status kub0d`".to_string(),
                _ => String::new(),
            };
            eprintln!("kub0: cannot reach kub0d at {}{hint}", e);
            Err(3)
        }
    }
}

/// The wire verb, its arguments and how long to wait for its reply.
fn request_for(command: &Command, timeout: Duration) -> (&'static str, Map<String, Value>, Duration) {
    let long = timeout.max(Duration::from_secs(60));
    let mut m = Map::new();
    let verb = match command {
        Command::Status => "status",
        Command::Whoami => "whoami",
        Command::Logout => "logout",
        Command::Rules => "rules",
        Command::Endpoints => "endpoints",
        Command::Trusts => "trusts",
        Command::Blocks => "blocks",
        Command::Pause => "pause",
        Command::Resume => "resume",
        Command::Sync => return ("sync", m, long),
        Command::Teardown { .. } => return ("teardown", m, long),
        Command::Login { server_url, auth_url } => {
            if let Some(s) = server_url {
                m.insert("serverUrl".into(), json!(s));
            }
            if let Some(a) = auth_url {
                m.insert("authUrl".into(), json!(a));
            }
            return ("login", m, args::LOGIN_TIMEOUT);
        }
        Command::Trust { sha256, note } => {
            m.insert("sha256".into(), json!(sha256));
            m.insert("note".into(), json!(note));
            "trust"
        }
        Command::Untrust { sha256 } => {
            m.insert("sha256".into(), json!(sha256));
            "untrust"
        }
        Command::AllowOnce { sha256 } => {
            m.insert("sha256".into(), json!(sha256));
            "allow-once"
        }
        Command::Block { app, ips, pids } => {
            m.insert("app".into(), json!(app));
            m.insert("ips".into(), json!(ips));
            m.insert("pids".into(), json!(pids));
            return ("block", m, long);
        }
        Command::Unblock { app, ips } => {
            m.insert("app".into(), json!(app));
            m.insert("scope".into(), json!(if *ips { "ips" } else { "app" }));
            return ("unblock", m, long);
        }
        Command::BlockDest { app, ip, seconds, pids } => {
            m.insert("app".into(), json!(app));
            m.insert("ip".into(), json!(ip));
            m.insert("seconds".into(), json!(seconds));
            m.insert("pids".into(), json!(pids));
            return ("block-dest", m, long);
        }
        Command::UnblockDest { app, ip } => {
            m.insert("app".into(), json!(app));
            m.insert("ip".into(), json!(ip));
            return ("unblock-dest", m, long);
        }
        Command::PolicySnooze { rule, seconds } => {
            m.insert("rule".into(), json!(rule));
            m.insert("seconds".into(), json!(seconds));
            "policy-snooze"
        }
        Command::PolicyResume { rule } => {
            m.insert("rule".into(), json!(rule));
            "policy-resume"
        }
        // Bare `share` reads it from `status`.
        Command::Share { on: None } => "status",
        Command::Share { on: Some(true) } => "share-on",
        Command::Share { on: Some(false) } => "share-off",
        Command::WatchAdd { kind, value, note } => {
            m.insert("kind".into(), json!(kind));
            m.insert("value".into(), json!(value));
            m.insert("note".into(), json!(note));
            "watch-set"
        }
        Command::WatchRm { id } => {
            m.insert("id".into(), json!(id));
            "watch-delete"
        }
        Command::Tag { network, label } => {
            m.insert("networkKey".into(), json!(network));
            m.insert("label".into(), json!(label));
            "tag"
        }
        Command::Apps { sort, filter, mine } => {
            m.insert("sort".into(), json!(sort));
            if *filter == args::AppsFilter::Live {
                m.insert("live".into(), json!(true));
            }
            if *mine {
                m.insert("mine".into(), json!(true));
            }
            "apps"
        }
        Command::Conns { app, unattributed, .. } => {
            if !app.is_empty() {
                m.insert("app".into(), json!(app));
            }
            if *unattributed {
                m.insert("unattributed".into(), json!(true));
            }
            "conns"
        }
        Command::Activity { seconds } => {
            m.insert("seconds".into(), json!(seconds));
            "activity"
        }
        Command::History { hours, query, format } => {
            m.insert("hours".into(), json!(hours));
            if !query.is_empty() {
                m.insert("query".into(), json!(query));
            }
            if *format == args::HistoryFormat::Csv {
                m.insert("format".into(), json!("csv"));
            }
            "history"
        }
        Command::Intel { timeline_hours } => {
            if let Some(h) = timeline_hours {
                m.insert("timelineHours".into(), json!(h));
            }
            "intel"
        }
        Command::Why { subject, hours } => {
            m.insert("subject".into(), json!(subject));
            m.insert("hours".into(), json!(hours));
            "investigate"
        }
        Command::Policies => "policies",
        Command::Watches => "watches",
        Command::Brief { hours } => {
            m.insert("hours".into(), json!(hours));
            "brief"
        }
        Command::Help | Command::HelpTopic(_) | Command::Doctor | Command::Install(_) | Command::Version => unreachable!(),
    };
    (verb, m, timeout)
}

fn run(g: Global, command: Command, argv: &[String]) -> i32 {
    match command {
        Command::Help => {
            print!("{}", args::USAGE);
            return 0;
        }
        Command::HelpTopic(ref verb) => {
            print!("{}", args::help_topic(verb).unwrap_or(args::USAGE));
            return 0;
        }
        Command::Doctor => return doctor::run(g.json),
        Command::Install(opts) => return install::run(&opts),
        Command::Version => {
            println!("kub0 {VERSION}");
            if let Ok(c) = connect(&Global { timeout: Duration::from_secs(3), ..g.clone() }, "status", false) {
                println!(
                    "kub0d {} ({} mode, pid {}){}",
                    c.hello.version,
                    c.hello.mode,
                    c.hello.pid,
                    if c.hello.connected { format!(", {} on {}", c.hello.github_username, c.hello.node_name) } else { String::new() }
                );
            }
            return 0;
        }
        Command::Teardown { yes: false } => {
            eprintln!("kub0 teardown: deletes the `inet vallum` nftables table and the vallum.slice cgroups, lifting every block; add --yes");
            return 2;
        }
        _ => {}
    }
    let (verb, mut request, timeout) = request_for(&command, g.timeout);
    let root = args::needs_root(verb, &request);
    // One daemon (#61): every verb goes to the daemon `connect` picks, the
    // system daemon when its socket lets the caller in. Until 0.5 watch rules
    // went to the user daemon first and a tag to both.
    let mut client = match connect(&g, verb, root) {
        Ok(c) => c,
        Err(code) => return code,
    };
    // The system daemon would refuse this to a non-root caller: on a desktop,
    // ask polkit instead of printing `sudo kub0 …`.
    if elevate::should_pkexec(&elevate::here(root, client.hello.mode == "system")) {
        drop(client);
        return elevate::reexec(argv);
    }
    // Root under pkexec or sudo acts for the user who asked.
    let wanted = elevate::as_uid(
        paths::euid(),
        std::env::var("PKEXEC_UID").ok().as_deref(),
        std::env::var("SUDO_UID").ok().as_deref(),
    );
    match elevate::as_uid_plan(wanted, client.hello.as_uid, args::reads(verb)) {
        elevate::AsUid::Send(uid) => {
            request.insert("as_uid".into(), json!(uid));
        }
        elevate::AsUid::Omit => {}
        elevate::AsUid::Refuse => {
            eprintln!("kub0 {verb}: {} (kub0d {}, {} mode)", elevate::OLD_DAEMON, client.hello.version, client.hello.mode);
            return 1;
        }
    }
    let json_out = g.json;
    let mut on_partial = |r: &Value| {
        if json_out {
            println!("{}", serde_json::to_string(r).unwrap_or_default());
            return;
        }
        if let Some(expired) = r.get("expired").and_then(|v| v.as_str()) {
            println!(
                "code {expired} expired unused ({}/{}); a fresh one follows",
                cell(&r["minted"]),
                cell(&r["max"])
            );
        } else if let Some(code) = r.get("code").and_then(|v| v.as_str()) {
            println!(
                "Open {} and enter code {code}  (valid {}, code {}/{})",
                cell(&r["url"]),
                duration(r["expiresIn"].as_u64().unwrap_or(0)),
                cell(&r["minted"]),
                cell(&r["max"])
            );
        }
    };
    let result = match client.request(verb, request, timeout, &mut on_partial) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kub0 {verb}: {e}");
            return 1;
        }
    };
    // `apps --blocked`: what is blocked is the helper's to say (`blocks`).
    let result = match command {
        Command::Apps { filter: args::AppsFilter::Blocked, .. } => {
            match client.request("blocks", Map::new(), timeout, &mut |_| {}) {
                Ok(blocks) => only_blocked(result, &blocks),
                Err(e) => {
                    eprintln!("kub0 apps --blocked: what is blocked comes from the system daemon: {e}");
                    return 1;
                }
            }
        }
        _ => result,
    };
    if g.json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    } else {
        match &command {
            Command::History { format: args::HistoryFormat::Csv, .. } => print!("{}", s(&result, "csv")),
            Command::History { format: args::HistoryFormat::Ndjson, .. } => {
                for e in result["entries"].as_array().into_iter().flatten() {
                    println!("{}", serde_json::to_string(e).unwrap_or_default());
                }
            }
            _ => print!("{}", render(&command, &result, &client.hello)),
        }
    }
    if let Command::Tag { .. } = &command {
        if let Some(note) = tag_stays_here(&client.hello.mode, std::path::Path::new(rename::RUNTIME_DIR).is_dir()) {
            eprintln!("{note}");
        }
    }
    if let Command::Conns { follow: true, app, unattributed } = &command {
        return follow_conns(&mut client, app, *unattributed, g.json);
    }
    0
}

/// The helper's app ids: lowercase, anything else a dash (`helper/src/ids.rs`).
fn helper_id(id: &str) -> String {
    let s: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    s.trim_matches('-').to_string()
}

/// `apps` narrowed to the apps the helper reports blocked: a cgroup block, or
/// addresses owned by the app.
fn only_blocked(mut apps: Value, blocks: &Value) -> Value {
    let mut blocked: std::collections::BTreeSet<String> = blocks["cgroupBlocks"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Some(owners) = blocks["owners"].as_object() {
        for who in owners.values() {
            match who {
                Value::String(s) => {
                    blocked.insert(s.clone());
                }
                Value::Array(a) => blocked.extend(a.iter().filter_map(|v| v.as_str().map(String::from))),
                _ => {}
            }
        }
    }
    if let Some(list) = apps["apps"].as_array_mut() {
        list.retain(|a| blocked.contains(&helper_id(a["id"].as_str().unwrap_or(""))));
    }
    apps
}

/// `conns --follow`: the daemon broadcasts each change to every client, so
/// after the snapshot the connection's own stream is the feed.
fn follow_conns(client: &mut Client, app: &str, unattributed: bool, json_out: bool) -> i32 {
    let result = client.follow(&mut |v: &Value| {
        let kind = v["type"].as_str().unwrap_or("");
        if kind == "connect" && conn_matches(v, app, unattributed) {
            if json_out {
                println!("{}", serde_json::to_string(v).unwrap_or_default());
            } else {
                println!("+ {}", conn_line(v).join("  "));
            }
        } else if kind == "disconnect" && app.is_empty() && !unattributed {
            if json_out {
                println!("{}", serde_json::to_string(v).unwrap_or_default());
            } else {
                println!("- {}", s(v, "id"));
            }
        }
        true
    });
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("kub0 conns --follow: {e}");
            3
        }
    }
}

/// The CLI's half of the daemon's `conns` filter, for followed rows.
fn conn_matches(c: &Value, app: &str, unattributed: bool) -> bool {
    if unattributed && c["app"]["pid"].as_u64().unwrap_or(0) != 0 {
        return false;
    }
    app.is_empty() || s(&c["app"], "id") == app || s(&c["app"], "name").eq_ignore_ascii_case(app)
}

/// `ip:port`, with an IPv6 address bracketed so the port reads as one.
fn host_port(ip: &str, port: u64) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn conn_line(c: &Value) -> Vec<String> {
    vec![
        s(&c["app"], "name"),
        s(c, "proto"),
        host_port(&s(&c["remote"], "ip"), n(&c["remote"], "port")),
        s(c, "hostname"),
        s(c, "country"),
        s(c, "state"),
    ]
}

/// Bytes per second, in the units a person reads.
fn rate(bps: Option<f64>) -> String {
    match bps {
        None => "".into(),
        Some(v) if v < 1024.0 => format!("{v:.0} B/s"),
        Some(v) if v < 1024.0 * 1024.0 => format!("{:.1} KB/s", v / 1024.0),
        Some(v) => format!("{:.1} MB/s", v / 1024.0 / 1024.0),
    }
}

fn render_apps(r: &Value) -> String {
    let apps = r["apps"].as_array().cloned().unwrap_or_default();
    let owned = apps.iter().any(|a| a.get("owner").is_some());
    let mut headers = vec!["app"];
    if owned {
        headers.push("owner");
    }
    headers.extend(["live", "seen", "last seen", "traffic", "pids"]);
    let now = now_ms();
    let rows: Vec<Vec<String>> = apps
        .iter()
        .map(|a| {
            let mut row = vec![s(a, "name")];
            if owned {
                row.push(s(&a["owner"], "name"));
            }
            let up = a["txRate"].as_f64();
            let down = a["rxRate"].as_f64();
            let traffic = match (up, down) {
                (None, None) => String::new(),
                _ => format!("{} up, {} down", rate(up.or(Some(0.0))), rate(down.or(Some(0.0)))),
            };
            let pids: Vec<String> = a["pids"].as_array().map(|p| p.iter().map(cell).collect()).unwrap_or_default();
            row.extend([
                n(a, "connections").to_string(),
                n(a, "seen").to_string(),
                if n(a, "connections") > 0 { "now".into() } else { ago(n(a, "lastSeen"), now) },
                traffic,
                pids.join(" "),
            ]);
            row
        })
        .collect();
    if rows.is_empty() {
        return "no apps\n".into();
    }
    let mut out = table(&headers, &rows);
    out.push_str(&format!(
        "{} app(s), live now and in the last day{}\n",
        rows.len(),
        if r["mine"].is_null() { String::new() } else { format!("; uid {} only", cell(&r["mine"])) }
    ));
    if !s(r, "historyError").is_empty() {
        out.push_str(&format!("history unavailable: {}\n", s(r, "historyError")));
    }
    out
}

fn render_conns(r: &Value) -> String {
    let rows: Vec<Vec<String>> = r["connections"].as_array().map(|a| a.iter().map(conn_line).collect()).unwrap_or_default();
    if rows.is_empty() {
        return "no live connections\n".into();
    }
    table(&["app", "proto", "remote", "host", "country", "state"], &rows)
}

/// An activity entry's detail in a line: a block's mechanism and error, else
/// the fields the entry has, as JSON.
fn activity_detail(e: &Value) -> String {
    let d = &e["detail"];
    match s(e, "kind").as_str() {
        "block" | "unblock" | "block_failed" => [s(d, "mechanism"), s(d, "error")].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(" "),
        _ if d.as_object().is_some_and(|o| o.is_empty()) => String::new(),
        _ => serde_json::to_string(d).unwrap_or_default(),
    }
}

fn render_activity(r: &Value) -> String {
    let now = now_ms();
    let rows: Vec<Vec<String>> = r["entries"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| vec![ago(n(e, "ts"), now), s(e, "kind"), s(&e["app"], "name"), activity_detail(e)])
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        return "no activity in that time\n".into();
    }
    table(&["when", "kind", "app", "detail"], &rows)
}

fn render_history(r: &Value) -> String {
    let now = now_ms();
    let rows: Vec<Vec<String>> = r["entries"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    let c = &e["connection"];
                    let mut row = vec![if b(e, "active") == Some(true) { "now".into() } else { ago(n(e, "lastObserved"), now) }];
                    row.extend(conn_line(c).into_iter().take(5));
                    row
                })
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        return "no retained connections match\n".into();
    }
    let mut out = table(&["last seen", "app", "proto", "remote", "host", "country"], &rows);
    if b(r, "more") == Some(true) {
        out.push_str(&format!("{} shown; more match (narrow --query or --hours, or use --ndjson / --csv)\n", rows.len()));
    }
    out
}

fn render_intel(r: &Value) -> String {
    let mut out = String::new();
    let rows: Vec<Vec<String>> = r["indicators"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| {
                    let ids: Vec<String> = c["indicators"]
                        .as_array()
                        .map(|i| i.iter().map(|x| format!("{}:{}", s(x, "severity"), s(x, "id"))).collect())
                        .unwrap_or_default();
                    let peer = if s(c, "hostname").is_empty() { s(&c["remote"], "ip") } else { s(c, "hostname") };
                    vec![s(&c["app"], "name"), peer, ids.join(" ")]
                })
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        out.push_str("indicators: none on the live rows\n");
    } else {
        out.push_str(&table(&["app", "peer", "indicators"], &rows));
        let counts: Vec<String> = r["counts"]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| format!("{} {k}", cell(v))).collect())
            .unwrap_or_default();
        out.push_str(&format!("indicators: {}\n", counts.join(", ")));
    }
    let listeners: Vec<Vec<String>> = r["listeners"]
        .as_array()
        .map(|a| a.iter().map(|l| vec![s(l, "proto"), host_port(&s(l, "ip"), n(l, "port")), s(l, "app"), s(l, "scope")]).collect())
        .unwrap_or_default();
    out.push('\n');
    if listeners.is_empty() {
        out.push_str("exposure: no listening sockets\n");
    } else {
        out.push_str(&table(&["proto", "listening on", "app", "reachable from"], &listeners));
    }
    out.push_str(&format!("watch rules: {} (kub0 watches)\n", n(r, "watchRules")));
    if let Some(t) = r["timelineText"].as_str() {
        out.push('\n');
        out.push_str(t);
        if !s(r, "timelineError").is_empty() {
            out.push_str(&format!("{}\n", s(r, "timelineError")));
        }
    }
    out
}

fn render_policies(r: &Value) -> String {
    let mut out = String::new();
    let now = now_ms();
    for p in r["netpolicies"].as_array().into_iter().flatten() {
        out.push_str(&format!("{} ({}, {})\n", s(p, "name"), s(p, "id"), s(p, "mode")));
        let rows: Vec<Vec<String>> = p["rules"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|q| {
                        let until = n(q, "snoozedUntil");
                        vec![
                            s(q, "id"),
                            s(q, "label"),
                            s(q, "effectiveAction"),
                            if b(q, "enforced") == Some(true) { "yes".into() } else { "no".into() },
                            if until > now { format!("until {}", duration((until - now) / 1000) + " from now") } else if b(q, "canSnooze") == Some(true) { "can".into() } else { "no".into() },
                            n(q, "hits").to_string(),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !rows.is_empty() {
            out.push_str(&table(&["rule", "label", "action", "enforced", "snooze", "hits"], &rows));
        }
    }
    if out.is_empty() {
        out.push_str(if b(r, "connected") == Some(true) { "no network policies\n" } else { "not logged in; no network policies\n" });
    }
    let e = &r["netpolicyEnforcement"];
    out.push_str(&format!(
        "enforcement: {}{}; refresh {}\n",
        s(e, "state"),
        if s(e, "reason").is_empty() { String::new() } else { format!(" ({})", s(e, "reason")) },
        opt_bool(b(r, "netpolicyRefreshOk"))
    ));
    out
}

fn render_watches(r: &Value) -> String {
    let now = now_ms();
    let rows: Vec<Vec<String>> = r["rules"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|w| vec![s(w, "id"), s(w, "kind"), s(w, "value"), n(w, "hits").to_string(), ago(n(w, "last_hit"), now), s(w, "note")])
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        return "no watch rules (kub0 watch add …)\n".into();
    }
    table(&["id", "kind", "value", "hits", "last hit", "note"], &rows)
}

fn s(v: &Value, key: &str) -> String {
    cell(&v[key])
}

fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or(0)
}

fn b(v: &Value, key: &str) -> Option<bool> {
    v[key].as_bool()
}

fn render(command: &Command, r: &Value, hello: &client::Hello) -> String {
    match command {
        Command::Status => render_status(r),
        Command::Whoami => {
            if b(r, "connected") != Some(true) {
                return format!("not logged in ({})\nnode: {}\n", s(r, "path"), s(r, "nodeName"));
            }
            kv(&[
                ("user", s(r, "githubUsername")),
                ("node", s(r, "nodeName")),
                ("server", s(r, "serverUrl")),
                ("since", ago(n(r, "connectedAt"), now_ms())),
                ("heartbeat", heartbeat_text(r)),
                ("account", s(r, "path")),
            ])
        }
        Command::Login { .. } => format!("connected as {}; account {}\n", s(r, "githubUsername"), s(r, "account")),
        Command::Logout => {
            if b(r, "removed") == Some(true) {
                format!("disconnected; removed {}\n", s(r, "account"))
            } else {
                format!("not connected ({})\n", s(r, "account"))
            }
        }
        Command::Rules => render_rules(r),
        Command::Endpoints => {
            let rows: Vec<Vec<String>> = r["endpoints"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|e| {
                            vec![
                                s(e, "nodeName"),
                                s(e, "state"),
                                s(e, "lastSeen"),
                                s(e, "agentVer"),
                                cell(&e["blocksActive"]),
                                s(e, "arch"),
                                s(e, "kernelVersion"),
                            ]
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut out = String::new();
            if rows.is_empty() {
                out.push_str(if b(r, "connected") == Some(true) { "no endpoints reported yet\n" } else { "not logged in; no org inventory\n" });
            } else {
                out.push_str(&table(&["node", "state", "last seen", "agent", "blocks", "arch", "kernel"], &rows));
            }
            out.push_str(&format!(
                "{} of {} org endpoints; this device {}; inventory {}, refreshed {}\n",
                rows.len(),
                n(r, "orgEndpoints"),
                s(r, "selfState"),
                opt_bool(b(r, "refreshOk")),
                ago(n(r, "updatedAt"), now_ms())
            ));
            out
        }
        Command::Trusts => {
            let rows: Vec<Vec<String>> = r["trusted"]
                .as_array()
                .map(|a| a.iter().map(|t| vec![s(t, "sha256"), ago(n(t, "addedAt"), now_ms()), s(t, "comm"), s(t, "note")]).collect())
                .unwrap_or_default();
            let mut out = String::new();
            if rows.is_empty() {
                out.push_str("no digests trusted on this machine\n");
            } else {
                out.push_str(&table(&["sha256", "added", "file", "note"], &rows));
            }
            out.push_str(&format!(
                "exec gate: {} ({}), {} keys, {} one-shot allow(s) pending\n",
                if b(r, "armed") == Some(true) { "armed" } else if b(r, "enabled") == Some(true) { "idle" } else { "off" },
                s(r, "source"),
                n(r, "keys"),
                n(r, "oncePending")
            ));
            out
        }
        Command::Trust { .. } | Command::Untrust { .. } | Command::AllowOnce { .. } => {
            let applied = b(r, "applied") == Some(true);
            format!(
                "{} {}: {}; {} trusted, {} keys, {} one-shot pending{}\n",
                s(r, "op").replace('_', "-"),
                s(r, "sha256"),
                if applied { "applied" } else { "queued (not yet visible in the gate's state)" },
                n(r, "trustedCount"),
                n(r, "keys"),
                n(r, "oncePending"),
                if b(r, "armed") == Some(true) { "" } else { "; the gate is not armed" }
            )
        }
        Command::Blocks => render_blocks(r),
        Command::PolicySnooze { rule, .. } => format!(
            "{rule}: snoozed on this device for {}\n",
            duration(n(r, "snoozedUntil").saturating_sub(now_ms()) / 1000)
        ),
        Command::PolicyResume { rule } => format!("{rule}: applies again\n"),
        Command::Share { on: None } => format!("destination sharing: {}\n", sharing_text(&r["fleet"])),
        Command::Share { on: Some(_) } => format!("destination sharing: {}\n", sharing_text(r)),
        Command::WatchAdd { .. } => {
            let w = &r["rule"];
            format!(
                "watching {} {} ({}){}\n",
                s(w, "kind"),
                s(w, "value"),
                s(w, "id"),
                if s(w, "note").is_empty() { String::new() } else { format!(": {}", s(w, "note")) }
            )
        }
        Command::WatchRm { .. } => format!("removed watch rule {}\n", s(&r["removed"], "id")),
        Command::Tag { .. } => tag_line(r),
        Command::Apps { .. } => render_apps(r),
        Command::Conns { .. } => render_conns(r),
        Command::Activity { .. } => render_activity(r),
        Command::History { .. } => render_history(r),
        Command::Intel { .. } => render_intel(r),
        Command::Why { .. } => {
            let mut out = s(r, "text");
            if !out.ends_with('\n') {
                out.push('\n');
            }
            if !s(r, "error").is_empty() {
                out.push_str(&format!("{}\n", s(r, "error")));
            }
            out
        }
        Command::Policies => render_policies(r),
        Command::Watches => render_watches(r),
        Command::Brief { .. } => {
            let mut out = s(r, "markdown");
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        Command::Sync => render_sync(r),
        Command::Block { .. }
        | Command::Unblock { .. }
        | Command::BlockDest { .. }
        | Command::UnblockDest { .. }
        | Command::Pause
        | Command::Resume
        | Command::Teardown { .. } => {
            // The helper's own JSON, flattened: every scalar on one line each.
            let mut rows: Vec<(&str, String)> = Vec::new();
            if let Some(obj) = r.as_object() {
                for (k, v) in obj {
                    if k == "raw" || v.is_object() || v.is_array() {
                        continue;
                    }
                    rows.push((k.as_str(), cell(v)));
                }
            }
            if rows.is_empty() {
                "ok\n".to_string()
            } else {
                kv(&rows)
            }
        }
        Command::Help | Command::HelpTopic(_) | Command::Doctor | Command::Install(_) | Command::Version => {
            let _ = hello;
            String::new()
        }
    }
}

/// `yes`/`no`/`unknown`, and who sends it when the system daemon does (a user daemon
/// next to a logged-in system daemon reads kub0's row instead of writing it).
fn heartbeat_text(v: &Value) -> String {
    let ok = opt_bool(b(v, "lastHeartbeatOk"));
    if b(v, "heartbeatDeferred") == Some(true) {
        format!("{ok}, sent by the system daemon")
    } else {
        ok
    }
}

fn render_status(r: &Value) -> String {
    let d = &r["daemon"];
    let a = &r["account"];
    let f = &r["fleet"];
    let g = &r["execGate"];
    let e = &f["enforcement"];
    let mut out = String::new();
    out.push_str(&kv(&[
        ("daemon", format!("kub0d {} ({} mode, pid {}, up {})", s(d, "version"), s(d, "mode"), n(d, "pid"), duration(n(d, "uptimeSeconds")))),
        ("socket", s(d, "socket")),
        (
            "account",
            if b(a, "connected") == Some(true) {
                format!(
                    "{} on {} via {}; heartbeat {} ({})",
                    s(a, "githubUsername"),
                    s(a, "nodeName"),
                    s(a, "serverUrl"),
                    heartbeat_text(a),
                    ago(n(a, "lastHeartbeatTs"), now_ms())
                )
            } else {
                format!("not logged in ({}); node {}", s(a, "path"), s(a, "nodeName"))
            },
        ),
        (
            "org",
            format!(
                "{} endpoints (limit {}), this device {}; inventory refresh {}",
                n(f, "orgEndpoints"),
                n(f, "nodeLimit"),
                s(f, "selfState"),
                opt_bool(b(f, "endpointsRefreshOk"))
            ),
        ),
        (
            "deny list",
            format!(
                "{} rows (version {}, {} reported); stream {}",
                n(f, "denylistCount"),
                n(f, "denylistVersion"),
                n(f, "denylistReported"),
                match b(f, "denylistLive") {
                    Some(true) => "live",
                    Some(false) => "down, polling",
                    None => "not running",
                }
            ),
        ),
        (
            "net policy",
            format!(
                "{} policies; {} ({}): {} rule(s), {} entries; refresh {}",
                n(f, "netpolicyCount"),
                s(e, "state"),
                if b(e, "enforcing") == Some(true) { "enforcing" } else { "not enforcing" },
                e["rules"].as_array().map(|a| a.len()).unwrap_or(0),
                n(e, "entries"),
                opt_bool(b(f, "netpolicyRefreshOk"))
            ),
        ),
        (
            "exec gate",
            format!(
                "{} ({}), {}, {} trusted, {} one-shot pending; blocked {}, failed open {}, denies kept {}",
                if b(g, "armed") == Some(true) { "armed" } else if b(g, "enabled") == Some(true) { "idle" } else { "off" },
                s(g, "source"),
                gate_keys(g, now_ms()),
                n(g, "trustedCount"),
                n(g, "oncePending"),
                n(&g["counters"], "blocked"),
                n(&g["counters"], "failopen"),
                n(g, "denyCount")
            ),
        ),
        ("sharing", sharing_text(f)),
        ("caller", format!("uid {}", cell(&r["peer"]["uid"]))),
    ]));
    out
}

fn render_rules(r: &Value) -> String {
    let mut out = String::new();
    let rows: Vec<Vec<String>> = r["denylist"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|d| vec![s(d, "name"), s(d, "comm"), s(d, "action"), s(d, "promoted_by"), s(d, "created_at"), s(d, "reason")])
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        out.push_str(if b(r, "connected") == Some(true) { "deny list: no rows\n" } else { "deny list: not logged in\n" });
    } else {
        out.push_str(&table(&["name", "comm", "action", "promoted by", "created", "reason"], &rows));
    }
    out.push_str(&format!("deny list version {}, {} rows reported\n", n(r, "denylistVersion"), n(r, "denylistReported")));
    let pols: Vec<Vec<String>> = r["netpolicies"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    let rules = p["rules"].as_array().map(|x| x.len()).unwrap_or(0);
                    let hits: u64 = p["rules"].as_array().map(|x| x.iter().map(|q| n(q, "hits")).sum()).unwrap_or(0);
                    vec![s(p, "id"), s(p, "name"), s(p, "mode"), rules.to_string(), hits.to_string()]
                })
                .collect()
        })
        .unwrap_or_default();
    if !pols.is_empty() {
        out.push('\n');
        out.push_str(&table(&["policy", "name", "mode", "rules", "hits"], &pols));
    }
    let e = &r["enforcement"];
    out.push_str(&format!(
        "network policy: {} ({}); {} rule(s) applied, {} entries; refresh {}{}\n",
        s(e, "state"),
        if b(e, "enforcing") == Some(true) { "enforcing" } else { "not enforcing" },
        e["rules"].as_array().map(|a| a.len()).unwrap_or(0),
        n(e, "entries"),
        opt_bool(b(r, "netpolicyRefreshOk")),
        if s(e, "reason").is_empty() { String::new() } else { format!("; {}", s(e, "reason")) }
    ));
    out
}

/// `sync`: what the daemon's re-apply left in the kernel.
fn render_sync(r: &Value) -> String {
    let e = &r["enforcement"];
    let mut out = if s(e, "state") == "none" {
        // "No block rules" would be wrong for an org whose block rule sits in a
        // monitor-mode policy: it has one, and this device only reports it.
        "nothing to apply: no org policy blocks on this device (none, or monitor mode only); \
         no fleet rules are in the kernel\n"
            .to_string()
    } else {
        format!(
            "applied the org's block rules: {} rule(s), {} entries; {}{}\n",
            e["rules"].as_array().map(|a| a.len()).unwrap_or(0),
            n(e, "entries"),
            if b(e, "enforcing") == Some(true) { "enforcing" } else { "not enforcing" },
            if s(e, "reason").is_empty() { String::new() } else { format!(" ({})", s(e, "reason")) }
        )
    };
    for (rule, why) in e["skipped"].as_object().into_iter().flatten() {
        out.push_str(&format!("skipped {rule}: {}\n", cell(why)));
    }
    out
}

fn render_blocks(r: &Value) -> String {
    let mut out = String::new();
    let missing: Vec<String> = r["missing"].as_array().map(|a| a.iter().map(cell).collect()).unwrap_or_default();
    out.push_str(&kv(&[
        (
            "blocking",
            if b(r, "blockingReady") == Some(true) {
                "ready".to_string()
            } else {
                format!("not ready: missing {}{}", missing.join(", "), if s(r, "hint").is_empty() { String::new() } else { format!(" ({})", s(r, "hint")) })
            },
        ),
        ("table", if b(r, "table") == Some(true) { "inet vallum present".into() } else { "absent".into() }),
        ("paused", yes_no(b(r, "paused") == Some(true))),
        ("helper", s(r, "helper")),
    ]));
    let apps: Vec<String> = r["cgroupBlocks"].as_array().map(|a| a.iter().map(cell).collect()).unwrap_or_default();
    if apps.is_empty() {
        out.push_str("app blocks: none\n");
    } else {
        out.push_str(&format!("app blocks ({}): {}\n", s(r, "cgroupBlocksSource"), apps.join(", ")));
    }
    if let Some(owners) = r["owners"].as_object() {
        if !owners.is_empty() {
            let rows: Vec<Vec<String>> = owners.iter().map(|(ip, who)| vec![ip.clone(), cell(who)]).collect();
            out.push_str(&table(&["address", "blocked for"], &rows));
        }
    }
    let scoped = r["temporaryRules"].as_array().map(|a| a.len()).unwrap_or(0);
    if scoped > 0 {
        out.push_str(&format!("{scoped} temporary destination rule(s)\n"));
    }
    out
}

/// A name given to one's own daemon while a system daemon is installed stays
/// on this machine: that daemon defers its heartbeat to the system one, which
/// is the daemon that reports to the org and did not get the name. The caller
/// reached their own daemon because the system daemon's socket did not let
/// them in, or because they asked for it (`--user`, a panel with capture on).
fn tag_stays_here(daemon_mode: &str, system_installed: bool) -> Option<&'static str> {
    (daemon_mode == "user" && system_installed).then_some(
        "note: this named your own daemon's rows only. Your org gets names from the system daemon: \
         join the kub0 group and log in again, or `sudo kub0 tag …`",
    )
}

/// What a `tag` did: named a network, or took its name away (an empty label).
fn tag_line(r: &Value) -> String {
    if b(r, "deleted") == Some(true) {
        format!("removed the name of {}\n", s(r, "networkKey"))
    } else {
        format!("{} is now {}\n", s(r, "networkKey"), s(r, "label"))
    }
}

/// Destination sharing as a daemon reports it. A daemon older than 0.5 has no such
/// field: it shares only when it was started with `--share-destinations`, and does
/// not say.
fn sharing_text(v: &Value) -> String {
    match b(v, "sharingDestinations") {
        Some(true) => "on: the networks this host reaches are sent to your org".into(),
        Some(false) => "off".into(),
        None => "not reported by this daemon".into(),
    }
}

#[cfg(test)]
mod sharing_text_tests {
    use super::sharing_text;
    use serde_json::json;

    #[test]
    fn sharing_reads_as_on_off_or_not_reported() {
        assert!(sharing_text(&json!({"sharingDestinations": true})).starts_with("on: "));
        assert_eq!(sharing_text(&json!({"sharingDestinations": false})), "off");
        assert_eq!(sharing_text(&json!({})), "not reported by this daemon");
    }
}

/// The key count on the exec gate line, with where the keys are from when that is not
/// a sync since the daemon started. On the org list it saved before it started, the
/// gate's keys are as old as that list; idle with no org list in use, it has none to be
/// armed by (none saved, and none taken from the API: unreachable, or over the 500-row
/// limit). A daemon older than 0.4.8 sends neither field and gets the bare count, and
/// so does an armed gate: its keys are a local deny file's, or an older system daemon's
/// that a newer user daemon mirrors with the field filled in as 0.
fn gate_keys(g: &Value, now: u64) -> String {
    let keys = format!("{} keys", n(g, "keys"));
    if b(g, "listRestored") == Some(true) {
        return format!(
            "{keys} from the org list saved {} (no sync since the daemon started)",
            ago(n(g, "listReceivedAt"), now)
        );
    }
    if b(g, "enabled") == Some(true) && b(g, "armed") != Some(true) && g["listReceivedAt"].as_u64() == Some(0) {
        return format!("{keys} (no org list in use yet)");
    }
    keys
}

#[cfg(test)]
mod gate_keys_tests {
    use super::gate_keys;
    use serde_json::json;

    #[test]
    fn the_key_count_says_when_the_keys_are_a_saved_list_or_no_list_at_all() {
        let now = 100_000_000;
        let synced = json!({"enabled": true, "armed": true, "keys": 55, "listReceivedAt": now - 40_000, "listRestored": false});
        assert_eq!(gate_keys(&synced, now), "55 keys");
        let restored = json!({"enabled": true, "armed": true, "keys": 55, "listReceivedAt": now - 11_520_000, "listRestored": true});
        assert_eq!(
            gate_keys(&restored, now),
            "55 keys from the org list saved 3h 12m ago (no sync since the daemon started)"
        );
        let waiting = json!({"enabled": true, "armed": false, "keys": 0, "listReceivedAt": 0, "listRestored": false});
        assert_eq!(gate_keys(&waiting, now), "0 keys (no org list in use yet)");
        // Armed with the field at 0: a local deny file, or a 0.4.7 system daemon seen
        // through a newer user daemon's mirror. Nothing is claimed about an org list.
        let mirrored = json!({"enabled": true, "armed": true, "keys": 55, "listReceivedAt": 0, "listRestored": false});
        assert_eq!(gate_keys(&mirrored, now), "55 keys");
        // The org's list holds no key: it was received, there is nothing to add.
        let empty = json!({"enabled": true, "armed": false, "keys": 0, "listReceivedAt": now - 1_000, "listRestored": false});
        assert_eq!(gate_keys(&empty, now), "0 keys");
        // 0.4.7 and older send neither field.
        assert_eq!(gate_keys(&json!({"enabled": true, "armed": false, "keys": 0}), now), "0 keys");
        assert_eq!(gate_keys(&json!({"enabled": false, "keys": 0, "listReceivedAt": 0}), now), "0 keys");
    }
}

#[cfg(test)]
mod heartbeat_text_tests {
    use super::heartbeat_text;
    use serde_json::json;

    #[test]
    fn a_deferred_heartbeat_names_the_system_daemon() {
        assert_eq!(heartbeat_text(&json!({"lastHeartbeatOk": true})), "yes");
        assert_eq!(heartbeat_text(&json!({"lastHeartbeatOk": null})), "unknown");
        assert_eq!(
            heartbeat_text(&json!({"lastHeartbeatOk": true, "heartbeatDeferred": true})),
            "yes, sent by the system daemon"
        );
        assert_eq!(
            heartbeat_text(&json!({"lastHeartbeatOk": false, "heartbeatDeferred": false})),
            "no"
        );
        // An older daemon never sends the key.
        assert_eq!(heartbeat_text(&json!({"lastHeartbeatOk": false})), "no");
    }
}

#[cfg(test)]
mod socket_choice_tests {
    use super::*;
    use std::io::{BufRead, Write};

    /// A daemon stand-in on `path`: greets as `mode` with requests on, answers
    /// each request (or refuses it), and sends every command it saw to the
    /// receiver. No real socket under /run is ever touched.
    fn fake_daemon(path: &std::path::Path, mode: &'static str, refuse: bool) -> std::sync::mpsc::Receiver<String> {
        let _ = std::fs::remove_file(path);
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut w = stream.try_clone().unwrap();
                let _ = writeln!(w, "{}", json!({"type": "hello", "version": "0.4.4", "mode": mode, "requests": true}));
                for line in std::io::BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    let _ = tx.send(s(&v, "cmd").to_string());
                    let reply = if refuse {
                        json!({"type": "reply", "req": v["req"], "ok": false, "error": "tag: refused by the fixture"})
                    } else {
                        json!({"type": "reply", "req": v["req"], "ok": true, "result": {"networkKey": v["networkKey"], "label": mode}})
                    };
                    let _ = writeln!(w, "{reply}");
                }
            }
        });
        rx
    }

    fn fixture_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kub0-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One daemon (#61): a tag is one request to the one daemon, answered in one
    /// line. Until 0.5 it went to the system daemon and then the user daemon,
    /// and printed an outcome for each. (That every verb takes the one route is
    /// pinned in daemon/tests/parity.rs, which reads `run`.)
    #[test]
    fn a_tag_is_one_request_with_one_answer() {
        let dir = fixture_dir("tag-one");
        let sock = dir.join("system.sock");
        let seen = fake_daemon(&sock, "system", false);
        let (verb, request, timeout) = request_for(&Command::Tag { network: "203.0.113.0/24".into(), label: "Office VPN".into() }, Duration::from_secs(3));
        assert_eq!(verb, "tag");
        let mut client = Client::connect(&sock).unwrap();
        let reply = client.request(verb, request, timeout, &mut |_| {}).unwrap();
        drop(client);
        // The stand-in keeps listening, so its channel never closes: take what
        // it has seen, which is complete once the reply above has arrived.
        assert_eq!(seen.try_iter().collect::<Vec<_>>(), vec!["tag".to_string()]);
        assert_eq!(reply["networkKey"], "203.0.113.0/24");
        assert_eq!(tag_line(&json!({"networkKey": "203.0.113.0/24", "label": "Office VPN", "deleted": false})), "203.0.113.0/24 is now Office VPN\n");
        // `kub0 tag <network> --clear` sends an empty label; the daemon says it deleted.
        let (_, cleared, _) = request_for(&Command::Tag { network: "203.0.113.0/24".into(), label: String::new() }, Duration::from_secs(3));
        assert_eq!(Value::Object(cleared), json!({"networkKey": "203.0.113.0/24", "label": ""}));
        assert_eq!(tag_line(&json!({"networkKey": "203.0.113.0/24", "label": "", "deleted": true})), "removed the name of 203.0.113.0/24\n");

        // A refusal is the daemon's reason, and nothing is retried elsewhere.
        let refusing = dir.join("refusing.sock");
        let seen = fake_daemon(&refusing, "system", true);
        let mut client = Client::connect(&refusing).unwrap();
        let (verb, request, timeout) = request_for(&Command::Tag { network: "k".into(), label: "l".into() }, Duration::from_secs(3));
        assert_eq!(client.request(verb, request, timeout, &mut |_| {}).unwrap_err(), "tag: refused by the fixture");
        drop(client);
        assert_eq!(seen.try_iter().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A name given to one's own daemon beside a system daemon reports success
    /// and never reaches the org (that daemon defers its heartbeat). The old
    /// two-daemon tag said "system daemon: not reached"; one route must not
    /// hide it.
    #[test]
    fn a_name_that_stays_on_this_machine_is_said() {
        assert!(tag_stays_here("user", true).unwrap().contains("your own daemon's rows only"));
        assert_eq!(tag_stays_here("system", true), None);
        // A per-user install: its own daemon is the one that reports.
        assert_eq!(tag_stays_here("user", false), None);
    }

    #[test]
    fn blocked_apps_are_the_helpers_cgroup_blocks_and_address_owners() {
        let apps = json!({"apps": [{"id":"Firefox.desktop"}, {"id":"curl"}, {"id":"git"}]});
        let blocks = json!({"cgroupBlocks": ["firefox.desktop"], "owners": {"203.0.113.9": ["curl"], "192.0.2.1": "nobody"}});
        let only = only_blocked(apps, &blocks);
        let ids: Vec<&str> = only["apps"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["Firefox.desktop", "curl"]);
        assert_eq!(helper_id("com.Example App!"), "com.example-app");
        assert_eq!(host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(host_port("192.0.2.1", 53), "192.0.2.1:53");
    }

    #[test]
    fn the_reads_send_the_daemons_fields() {
        let t = Duration::from_secs(15);
        let (v, m, _) = request_for(&Command::Apps { sort: "name".into(), filter: args::AppsFilter::Live, mine: true }, t);
        assert_eq!((v, Value::Object(m)), ("apps", json!({"sort":"name","live":true,"mine":true})));
        let (v, m, _) = request_for(&Command::Apps { sort: "recent".into(), filter: args::AppsFilter::Blocked, mine: false }, t);
        assert_eq!((v, Value::Object(m)), ("apps", json!({"sort":"recent"})), "--blocked is the CLI's second request");
        let (v, m, _) = request_for(&Command::History { hours: 6, query: "x".into(), format: args::HistoryFormat::Csv }, t);
        assert_eq!((v, Value::Object(m)), ("history", json!({"hours":6,"query":"x","format":"csv"})));
        let (v, m, _) = request_for(&Command::Why { subject: "1.2.3.4".into(), hours: 24 }, t);
        assert_eq!((v, Value::Object(m)), ("investigate", json!({"subject":"1.2.3.4","hours":24})));
        let (v, m, _) = request_for(&Command::Intel { timeline_hours: Some(48) }, t);
        assert_eq!((v, Value::Object(m)), ("intel", json!({"timelineHours":48})));
        for (c, want) in [
            (Command::Conns { app: String::new(), unattributed: false, follow: true }, "conns"),
            (Command::Activity { seconds: 60 }, "activity"),
            (Command::Policies, "policies"),
            (Command::Watches, "watches"),
            (Command::Brief { hours: 24 }, "brief"),
        ] {
            assert_eq!(request_for(&c, t).0, want);
            assert!(args::reads(want), "{want} is a read");
        }
    }

    #[test]
    fn only_a_non_root_caller_with_no_flag_probes_the_system_socket() {
        let g = Global::default();
        assert!(probe_system(&g, 1000));
        assert!(!probe_system(&g, 0), "root goes to the system daemon without a probe");
        let flagged = [
            Global { socket: Some(PathBuf::from("/tmp/x.sock")), ..Global::default() },
            Global { target: Some(Target::User), ..Global::default() },
            Global { target: Some(Target::System), ..Global::default() },
        ];
        for g in flagged {
            assert!(!probe_system(&g, 1000), "{g:?}");
        }
    }

    #[test]
    fn the_root_hint_is_only_for_requests_that_need_root() {
        let t = Duration::from_secs(15);
        let hint = |c: Command| {
            let (v, m, _) = request_for(&c, t);
            reach_hint(v, args::needs_root(v, &m))
        };
        for c in [
            Command::Unblock { app: "a".into(), ips: false },
            Command::UnblockDest { app: "a".into(), ip: "192.0.2.1".into() },
            Command::Trust { sha256: "a".repeat(64), note: String::new() },
            Command::Pause,
            Command::Login { server_url: None, auth_url: None },
            Command::Logout,
            Command::PolicySnooze { rule: "r".into(), seconds: 3600 },
            Command::Block { app: "a".into(), ips: vec!["192.0.2.1".into()], pids: vec![] },
        ] {
            let h = hint(c.clone());
            assert!(h.contains("needs root") && h.contains("sudo kub0"), "{c:?}: {h}");
        }
        assert!(hint(Command::Block { app: "a".into(), ips: vec!["192.0.2.1".into()], pids: vec![] }).contains("address block"));
        for c in [
            Command::Block { app: "a".into(), ips: vec![], pids: vec!["12".into()] },
            Command::BlockDest { app: "a".into(), ip: "192.0.2.1".into(), seconds: 300, pids: vec!["12".into()] },
            Command::Untrust { sha256: "a".repeat(64) },
            Command::Resume,
            Command::Status,
            Command::WatchAdd { kind: "port".into(), value: "1".into(), note: String::new() },
            Command::Tag { network: "k".into(), label: "l".into() },
            Command::PolicyResume { rule: "r".into() },
        ] {
            let h = hint(c.clone());
            assert!(!h.contains("needs root") && h.contains("members of the kub0 group"), "{c:?}: {h}");
        }
    }

    #[test]
    fn new_commands_send_the_daemons_verbs() {
        let t = Duration::from_secs(15);
        let (v, m, timeout) = request_for(
            &Command::BlockDest { app: "firefox".into(), ip: "192.0.2.1".into(), seconds: 900, pids: vec!["7".into()] },
            t,
        );
        assert_eq!(v, "block-dest");
        assert_eq!(Value::Object(m), json!({"app":"firefox","ip":"192.0.2.1","seconds":900,"pids":["7"]}));
        assert_eq!(timeout, Duration::from_secs(60));
        let (v, m, _) = request_for(&Command::UnblockDest { app: "firefox".into(), ip: "192.0.2.1".into() }, t);
        assert_eq!((v, Value::Object(m)), ("unblock-dest", json!({"app":"firefox","ip":"192.0.2.1"})));
        let (v, m, _) = request_for(&Command::PolicySnooze { rule: "r".into(), seconds: 1800 }, t);
        assert_eq!((v, Value::Object(m)), ("policy-snooze", json!({"rule":"r","seconds":1800})));
        let (v, m, _) = request_for(&Command::PolicyResume { rule: "r".into() }, t);
        assert_eq!((v, Value::Object(m)), ("policy-resume", json!({"rule":"r"})));
        let (v, m, _) = request_for(&Command::WatchAdd { kind: "port".into(), value: "4444".into(), note: "n".into() }, t);
        assert_eq!((v, Value::Object(m)), ("watch-set", json!({"kind":"port","value":"4444","note":"n"})));
        let (v, m, _) = request_for(&Command::WatchRm { id: "w-1".into() }, t);
        assert_eq!((v, Value::Object(m)), ("watch-delete", json!({"id":"w-1"})));
        let (v, m, _) = request_for(&Command::Tag { network: "k".into(), label: "Office".into() }, t);
        assert_eq!((v, Value::Object(m)), ("tag", json!({"networkKey":"k","label":"Office"})));
        // Every new verb is a verb the daemon answers, and lowering ones are marked.
        assert!(args::lowers("unblock-dest") && args::lowers("policy-snooze"));
        assert!(!args::lowers("block-dest") && !args::lowers("watch-delete"));
    }

    #[test]
    fn sync_says_what_the_kernel_holds_now() {
        let applied = json!({"enforcement": {"state":"enforcing","enforcing":true,"rules":["a","b"],"entries":41,
            "skipped":{"c":"no ranges for country XX"},"sharedRanges":9,"appliedTs":1}});
        assert_eq!(
            render_sync(&applied),
            "applied the org's block rules: 2 rule(s), 41 entries; enforcing\nskipped c: no ranges for country XX\n"
        );
        let paused = json!({"enforcement": {"state":"enforcing","enforcing":false,"rules":["a"],"entries":3,
            "reason":"Enforcement is paused from the panel; these rules apply when it resumes"}});
        assert_eq!(
            render_sync(&paused),
            "applied the org's block rules: 1 rule(s), 3 entries; not enforcing \
             (Enforcement is paused from the panel; these rules apply when it resumes)\n"
        );
        let none = json!({"enforcement": {"state":"none","enforcing":false,"rules":[],"entries":0}});
        // Not "the org has no block rules": a monitor-mode policy with a block
        // rule ends here too (seen on the first host that ran 0.4.6).
        let said = render_sync(&none);
        assert_eq!(
            said,
            "nothing to apply: no org policy blocks on this device (none, or monitor mode only); \
             no fleet rules are in the kernel\n"
        );
        assert!(!said.contains("has no block rules"), "{said}");
    }
}
