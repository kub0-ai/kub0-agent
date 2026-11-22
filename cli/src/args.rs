//! Argument parsing, by hand like the daemon's. Global flags may sit
//! anywhere; the first bare word is the verb.

use crate::paths::Target;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// A login waits for the browser: four codes of up to fifteen minutes.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(4 * 15 * 60 + 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub socket: Option<PathBuf>,
    pub target: Option<Target>,
    pub json: bool,
    pub timeout: Duration,
}

impl Default for Global {
    fn default() -> Self {
        Global {
            socket: None,
            target: None,
            json: false,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallOpts {
    pub from: Option<PathBuf>,
    pub polkit: bool,
    pub start: bool,
    pub geo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status,
    Whoami,
    Login { server_url: Option<String>, auth_url: Option<String> },
    Logout,
    Rules,
    Endpoints,
    Trusts,
    Trust { sha256: String, note: String },
    Untrust { sha256: String },
    AllowOnce { sha256: String },
    Blocks,
    Block { app: String, ips: Vec<String>, pids: Vec<String> },
    Unblock { app: String, ips: bool },
    /// `block <app> --to <ip> --for 5m|15m|1h`: the panel's timed destination rule.
    BlockDest { app: String, ip: String, seconds: u64, pids: Vec<String> },
    UnblockDest { app: String, ip: String },
    PolicySnooze { rule: String, seconds: u64 },
    PolicyResume { rule: String },
    /// `share`: show it; `share on|off`: change it.
    Share { on: Option<bool> },
    WatchAdd { kind: String, value: String, note: String },
    WatchRm { id: String },
    Tag { network: String, label: String },
    /// The reads (#61 step 2): what the panel shows, from the daemon.
    Apps { sort: String, filter: AppsFilter, mine: bool },
    Conns { app: String, unattributed: bool, follow: bool },
    Activity { seconds: u64 },
    History { hours: u64, query: String, format: HistoryFormat },
    Intel { timeline_hours: Option<u64> },
    /// `why <app|ip>`: `investigate` on the wire.
    Why { subject: String, hours: u64 },
    Policies,
    Watches,
    Brief { hours: u64 },
    /// `<command> --help` for a command with more to say than the usage.
    HelpTopic(String),
    Pause,
    Resume,
    Sync,
    Teardown { yes: bool },
    Version,
    Doctor,
    Install(InstallOpts),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppsFilter {
    All,
    Blocked,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryFormat {
    Table,
    Csv,
    Ndjson,
}

pub const USAGE: &str = "\
kub0, the kub0 endpoint CLI (talks to the running kub0d over its socket)

usage: kub0 [--socket PATH | --system | --user] [--json] [--timeout SECS] <command> [args]

account
  login [--server-url URL] [--auth-url URL]   device-code login; the daemon keeps the token (root)
  logout                                       remove this daemon's account (root)
  whoami                                       who this daemon is logged in as
  status                                       daemon, account, org rules and exec gate on one screen

org
  rules                                        the org deny list and network policies this endpoint holds
  endpoints                                    every endpoint in the org, as the last heartbeat saw them
  sync                                         re-apply the org's block rules now
  policy snooze <rule> [--for 1h]              stop one org network-policy rule here for a while (root)
  policy resume <rule>                         end a snooze early
  share [on|off]                               send the networks this host reaches to your org, or stop;
                                               bare `share` shows it (on: root)

exec gate
  trusts                                       digests trusted on this machine
  trust <sha256> [note…]                       trust a digest on this machine (root)
  untrust <sha256>                             remove a local trust
  allow-once <sha256>                          let the next exec of a digest through, five minutes (root)

blocks
  blocks                                       what is blocked, and whether blocking can work here
  block <app-id> --pid PID…                    block an app (its process tree)
  block <app-id> --ip ADDR…                    block addresses for the app, which applies host-wide (root)
  block <app-id> --to ADDR --for 5m|15m|1h --pid PID…
                                               block one destination for the app's process tree, for a while
  unblock <app-id> [--ips | --to ADDR]         lift an app block, its address block, or a destination rule (root)
  pause | resume                               hold every block without removing it (root), and back
  teardown --yes                               delete the inet vallum table and vallum.slice (root)

what this machine is doing
  apps [--sort bandwidth|connections|recent|name] [--blocked|--live] [--mine]
                                               apps with connections now or in the last day
  conns [--app APP] [--unattributed] [--follow]
                                               live connections; --follow keeps printing changes
  activity [--since 1h]                        the activity log: blocks, new networks, alerts
  history [--hours N] [--query TEXT] [--csv|--ndjson]
                                               retained connections (up to 168 hours)
  intel [--timeline] [--hours N]               indicators, exposure and watch rules; the timeline
  why <app|ip|kind:value> [--hours N]          the evidence for one app, address or network
  policies                                     the org network policies here, with snoozes
  brief [--hours N]                            a digest of the last N hours

watch and tags
  watches                                      the watch rules on this machine
  watch add <asn|country|cidr|host|port|app> <value> [note…]
                                               alert on every connection that matches
  watch rm <id>                                remove a watch rule you set
  tag <network> <label…> | --clear             name a network, or take its name away

host
  doctor                                       what is installed, reachable and missing on this host
  install [--from DIR] [--no-polkit] [--no-start] [--no-geo]
                                               install the daemon, helper, units and this CLI (root)
  version                                      this CLI and the daemon it reaches
  help

Root talks to the system daemon. Anyone else talks to the system daemon when
its socket lets them in (root and members of the kub0 group, which
`sudo kub0 install` adds the installing user to), else to their own. On the
system daemon a group member may read and raise protection; a command marked
(root) needs root there, because it lowers protection, chooses the org the
host enforces, or blocks addresses for the whole host: `sudo kub0 …`.
Blocking, the exec gate, sync and share are the system daemon's
(`sudo kub0 install`); a daemon the panel started for itself says so.
Exit 0 ok, 1 refused by the daemon, 2 usage, 3 no daemon.
";

/// Watch rules are alerts: what they are and whose they are.
pub const WATCH_HELP: &str = "\
kub0 watch add <asn|country|cidr|host|port|app> <value> [note…]
kub0 watch rm <id>
kub0 watches

A watch rule raises a warning on every connection that matches it, and a line
in the activity log. It alerts; it never blocks.

The rules are this machine's: the panel and kub0 show the same list, from the
daemon they both talk to. On the system daemon everyone in the kub0 group sees
every rule and changes the ones they set; root changes any, and a rule added
with `sudo kub0 watch add` belongs to whoever ran sudo.

The one exception is a panel with capture switched on: it runs a daemon of its
own and keeps its watch rules and names there. `kub0 --user watches` (and
`kub0 --user tag`) reach that one.
";

/// Tags name a network for the panel's rows and for the org.
pub const TAG_HELP: &str = "\
kub0 tag <network> <label…>
kub0 tag <network> --clear

Names a network (its key, as the panel shows it, e.g. 203.0.113.0/24), or
takes its name away. The name shows on every row to that network that the
daemon you reached lists, and the system daemon's heartbeat carries it
to your org.

Two cases where that is not the whole picture, both said when they happen: a
name given to your own daemon while a system daemon runs (you are not in the
kub0 group) stays on this machine, since that daemon reports nothing; and a
panel with capture switched on shows its own daemon's rows, which
`kub0 --user tag` names. Exit 0 ok, 1 refused by the daemon, 3 no daemon.
";

/// The help text for `<verb> --help`, when the verb has more to say.
pub fn help_topic(verb: &str) -> Option<&'static str> {
    match verb {
        "watch" | "watches" => Some(WATCH_HELP),
        "tag" => Some(TAG_HELP),
        _ => None,
    }
}

/// The wire verbs that need root on the system daemon (`daemon/src/control.rs`,
/// `Lower`). The CLI names root only for these and for an address block
/// (`needs_root`); the daemon's test suite pins the list to the daemon's
/// table, since this crate does not link it.
pub const LOWERS: &[&str] = &[
    "login",
    "logout",
    "unblock",
    "unblock-dest",
    "trust",
    "allow-once",
    "pause",
    "teardown",
    "policy-snooze",
    "share-on",
];

pub fn lowers(verb: &str) -> bool {
    LOWERS.contains(&verb)
}

/// The wire verbs that only read (`Access::Read`): they act for no one, so
/// an older daemon that cannot honour `as_uid` may still answer them. Pinned
/// to the daemon's table like `LOWERS`.
pub const READS: &[&str] = &[
    "status", "whoami", "rules", "endpoints", "trusts", "blocks",
    "apps", "conns", "activity", "history", "intel", "investigate", "policies", "watches", "brief",
];

pub fn reads(verb: &str) -> bool {
    READS.contains(&verb)
}

/// Whether a request needs root on the system daemon: a `Lower` verb, or a
/// `block` with addresses, which the helper applies to the whole host
/// (the daemon's `control::authorize_args`).
pub fn needs_root(verb: &str, request: &serde_json::Map<String, serde_json::Value>) -> bool {
    lowers(verb)
        || (verb == "block"
            && request
                .get("ips")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|ip| ip.as_str().is_some_and(|s| !s.trim().is_empty()))))
}

/// The timed destination block's durations: the helper's, the panel's.
pub fn dest_duration(s: &str) -> Option<u64> {
    match s {
        "5m" => Some(300),
        "15m" => Some(900),
        "1h" => Some(3600),
        _ => None,
    }
}

/// `90s`, `30m`, `2h`: a whole number of seconds, minutes or hours.
pub fn duration_secs(s: &str) -> Option<u64> {
    let unit = s.chars().last()?;
    let n: u64 = s[..s.len() - unit.len_utf8()].parse().ok()?;
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// What `watch add` takes; the daemon also knows a few aliases.
pub const WATCH_KINDS: &[&str] = &["asn", "country", "cidr", "host", "port", "app"];

/// `--hours N`, 1 to 168: the history the daemons keep.
fn hours_arg(rest: &[String], j: &mut usize, verb: &str) -> Result<u64, String> {
    let v = take(rest, j, "--hours")?;
    v.parse::<u64>()
        .ok()
        .filter(|h| (1..=168).contains(h))
        .ok_or_else(|| format!("{verb} --hours {v}: a whole number of hours from 1 to 168"))
}

fn take(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    match argv.get(*i) {
        Some(v) if !v.is_empty() && !v.starts_with('-') => Ok(v.clone()),
        _ => Err(format!("{flag} needs a value")),
    }
}

/// `Err(message)` is a usage error; `Ok((_, Command::Help))` is a request
/// for the usage text.
pub fn parse(argv: &[String]) -> Result<(Global, Command), String> {
    let mut g = Global::default();
    let mut words: Vec<String> = Vec::new();
    let mut help = false;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--socket" => g.socket = Some(PathBuf::from(take(argv, &mut i, a)?)),
            "--system" => g.target = Some(Target::System),
            "--user" => g.target = Some(Target::User),
            "--json" => g.json = true,
            "--timeout" => {
                let v = take(argv, &mut i, a)?;
                let secs: u64 = v.parse().map_err(|_| format!("--timeout {v}: not a number of seconds"))?;
                g.timeout = Duration::from_secs(secs.max(1));
            }
            "-h" | "--help" => help = true,
            "-V" | "--version" => return Ok((g, Command::Version)),
            _ => words.push(argv[i].clone()),
        }
        i += 1;
    }
    if help {
        let topic = words.first().map(String::as_str).and_then(help_topic);
        return Ok((g, topic.map_or(Command::Help, |_| Command::HelpTopic(words[0].clone()))));
    }
    let Some(verb) = words.first().map(String::as_str) else {
        return Err("no command".into());
    };
    let rest = &words[1..];
    let no_args = |cmd: Command| -> Result<Command, String> {
        if rest.is_empty() {
            Ok(cmd)
        } else {
            Err(format!("{verb} takes no arguments"))
        }
    };
    let sha_arg = || -> Result<String, String> {
        let s = rest.first().ok_or_else(|| format!("{verb} needs a sha256"))?;
        let s = s.trim().to_ascii_lowercase();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("{verb}: a sha256 is 64 hex characters"));
        }
        Ok(s)
    };
    let cmd = match verb {
        "status" => no_args(Command::Status)?,
        "whoami" => no_args(Command::Whoami)?,
        "logout" => no_args(Command::Logout)?,
        "rules" => no_args(Command::Rules)?,
        "endpoints" => no_args(Command::Endpoints)?,
        "trusts" => no_args(Command::Trusts)?,
        "blocks" => no_args(Command::Blocks)?,
        "pause" => no_args(Command::Pause)?,
        "resume" => no_args(Command::Resume)?,
        "sync" => no_args(Command::Sync)?,
        "version" => no_args(Command::Version)?,
        "doctor" => no_args(Command::Doctor)?,
        "help" => Command::Help,
        "login" => {
            let (mut server_url, mut auth_url) = (None, None);
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--server-url" => server_url = Some(take(rest, &mut j, "--server-url")?),
                    "--auth-url" => auth_url = Some(take(rest, &mut j, "--auth-url")?),
                    other => return Err(format!("login: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Login { server_url, auth_url }
        }
        "trust" => Command::Trust {
            sha256: sha_arg()?,
            note: rest.iter().skip(1).cloned().collect::<Vec<_>>().join(" "),
        },
        "untrust" => {
            if rest.len() > 1 {
                return Err("untrust takes one sha256".into());
            }
            Command::Untrust { sha256: sha_arg()? }
        }
        "allow-once" => {
            if rest.len() > 1 {
                return Err("allow-once takes one sha256".into());
            }
            Command::AllowOnce { sha256: sha_arg()? }
        }
        "block" => {
            let app = rest.first().cloned().ok_or("block needs an app id")?;
            if app.starts_with('-') {
                return Err("block needs an app id before its flags".into());
            }
            let (mut ips, mut pids) = (Vec::new(), Vec::new());
            let (mut to, mut dur): (Option<String>, Option<String>) = (None, None);
            let mut mode = "";
            let mut j = 1;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--ip" => mode = "ip",
                    "--pid" => mode = "pid",
                    "--to" => {
                        to = Some(take(rest, &mut j, "--to")?);
                        mode = "";
                    }
                    "--for" => {
                        dur = Some(take(rest, &mut j, "--for")?);
                        mode = "";
                    }
                    other if other.starts_with('-') => return Err(format!("block: unknown argument {other}")),
                    other => match mode {
                        "ip" => ips.push(other.to_string()),
                        "pid" => {
                            other.parse::<u32>().map_err(|_| format!("block: {other} is not a pid"))?;
                            pids.push(other.to_string())
                        }
                        _ => return Err(format!("block: {other} needs --pid or --ip before it")),
                    },
                }
                j += 1;
            }
            match (to, dur) {
                (None, None) => Command::Block { app, ips, pids },
                (Some(_), None) => return Err("block --to needs --for 5m|15m|1h".into()),
                (None, Some(_)) => return Err("block --for goes with --to ADDR".into()),
                (Some(ip), Some(d)) => {
                    if !ips.is_empty() {
                        return Err("block: --to and --ip are different blocks; use one".into());
                    }
                    let seconds = dest_duration(&d).ok_or_else(|| format!("block --for {d}: use 5m, 15m or 1h"))?;
                    if pids.is_empty() {
                        return Err("block --to needs the app's --pid PID… (the rule follows that process tree)".into());
                    }
                    Command::BlockDest { app, ip, seconds, pids }
                }
            }
        }
        "unblock" => {
            let app = rest.first().cloned().ok_or("unblock needs an app id")?;
            if app.starts_with('-') {
                return Err("unblock needs an app id before its flags".into());
            }
            let mut ips = false;
            let mut to = None;
            let mut j = 1;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--ips" => ips = true,
                    "--to" => to = Some(take(rest, &mut j, "--to")?),
                    other => return Err(format!("unblock: unknown argument {other}")),
                }
                j += 1;
            }
            match to {
                Some(_) if ips => return Err("unblock: --to and --ips are different blocks; use one".into()),
                Some(ip) => Command::UnblockDest { app, ip },
                None => Command::Unblock { app, ips },
            }
        }
        "share" => match rest {
            [] => Command::Share { on: None },
            [w] if w == "on" => Command::Share { on: Some(true) },
            [w] if w == "off" => Command::Share { on: Some(false) },
            _ => return Err("share: use `share`, `share on` or `share off`".into()),
        },
        "policy" => {
            let sub = rest.first().map(String::as_str).ok_or("policy needs snooze or resume")?;
            let rule = rest.get(1).cloned().filter(|r| !r.starts_with('-')).ok_or_else(|| format!("policy {sub} needs a rule id"))?;
            match sub {
                "snooze" => {
                    let mut seconds = 3600;
                    let mut j = 2;
                    while j < rest.len() {
                        match rest[j].as_str() {
                            "--for" => {
                                let d = take(rest, &mut j, "--for")?;
                                seconds = duration_secs(&d)
                                    .filter(|s| (60..=86400).contains(s))
                                    .ok_or_else(|| format!("policy snooze --for {d}: a duration from 1m to 24h (90s, 30m, 2h)"))?;
                            }
                            other => return Err(format!("policy snooze: unknown argument {other}")),
                        }
                        j += 1;
                    }
                    Command::PolicySnooze { rule, seconds }
                }
                "resume" => {
                    if rest.len() > 2 {
                        return Err("policy resume takes one rule id".into());
                    }
                    Command::PolicyResume { rule }
                }
                other => return Err(format!("policy {other}: use snooze or resume")),
            }
        }
        "watch" => match rest.first().map(String::as_str) {
            Some("add") => {
                let kind = rest.get(1).ok_or("watch add needs a kind and a value")?.to_ascii_lowercase();
                if !WATCH_KINDS.contains(&kind.as_str()) {
                    return Err(format!("watch add: {kind} is not a kind; use {}", WATCH_KINDS.join(", ")));
                }
                let value = rest.get(2).cloned().ok_or_else(|| format!("watch add {kind} needs a value"))?;
                Command::WatchAdd { kind, value, note: rest[3..].join(" ") }
            }
            Some("rm") => {
                if rest.len() != 2 {
                    return Err("watch rm takes one rule id".into());
                }
                Command::WatchRm { id: rest[1].clone() }
            }
            _ => return Err("watch needs add or rm".into()),
        },
        "policies" => no_args(Command::Policies)?,
        "watches" => no_args(Command::Watches)?,
        "apps" => {
            let (mut sort, mut filter, mut mine) = (String::from("connections"), AppsFilter::All, false);
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--sort" => {
                        sort = take(rest, &mut j, "--sort")?;
                        if !["bandwidth", "connections", "recent", "name"].contains(&sort.as_str()) {
                            return Err(format!("apps --sort {sort}: use bandwidth, connections, recent or name"));
                        }
                    }
                    "--blocked" | "--live" if filter != AppsFilter::All => {
                        return Err("apps: --blocked and --live are different lists; use one".into())
                    }
                    "--blocked" => filter = AppsFilter::Blocked,
                    "--live" => filter = AppsFilter::Live,
                    "--mine" => mine = true,
                    other => return Err(format!("apps: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Apps { sort, filter, mine }
        }
        "conns" => {
            let (mut app, mut unattributed, mut follow) = (String::new(), false, false);
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--app" => app = take(rest, &mut j, "--app")?,
                    "--unattributed" => unattributed = true,
                    "--follow" | "-f" => follow = true,
                    other => return Err(format!("conns: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Conns { app, unattributed, follow }
        }
        "activity" => {
            let mut seconds = 3600;
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--since" => {
                        let d = take(rest, &mut j, "--since")?;
                        seconds = duration_secs(&d)
                            .filter(|s| *s > 0)
                            .ok_or_else(|| format!("activity --since {d}: a duration such as 30m, 6h or 2d"))?;
                    }
                    other => return Err(format!("activity: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Activity { seconds }
        }
        "history" => {
            let (mut hours, mut query, mut format) = (24, String::new(), HistoryFormat::Table);
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--hours" => hours = hours_arg(rest, &mut j, "history")?,
                    "--query" => query = take(rest, &mut j, "--query")?,
                    "--csv" | "--ndjson" if format != HistoryFormat::Table => {
                        return Err("history: --csv and --ndjson are different formats; use one".into())
                    }
                    "--csv" => format = HistoryFormat::Csv,
                    "--ndjson" => format = HistoryFormat::Ndjson,
                    other => return Err(format!("history: unknown argument {other}")),
                }
                j += 1;
            }
            Command::History { hours, query, format }
        }
        "intel" => {
            let (mut timeline, mut hours) = (false, 24);
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--timeline" => timeline = true,
                    "--hours" => hours = hours_arg(rest, &mut j, "intel")?,
                    other => return Err(format!("intel: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Intel { timeline_hours: timeline.then_some(hours) }
        }
        "why" => {
            let mut subject = None;
            let mut hours = 168;
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--hours" => hours = hours_arg(rest, &mut j, "why")?,
                    other if other.starts_with('-') => return Err(format!("why: unknown argument {other}")),
                    other if subject.is_none() => subject = Some(other.to_string()),
                    other => return Err(format!("why takes one subject, not also {other}")),
                }
                j += 1;
            }
            Command::Why { subject: subject.ok_or("why needs an app, an address, or kind:value")?, hours }
        }
        "brief" => {
            let mut hours = 24;
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--hours" => hours = hours_arg(rest, &mut j, "brief")?,
                    other => return Err(format!("brief: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Brief { hours }
        }
        "tag" => {
            let network = rest.first().cloned().ok_or("tag needs a network and a label")?;
            // `--clear` takes the name away: an empty label on the wire.
            let label = if rest[1..] == ["--clear".to_string()] {
                String::new()
            } else {
                let label = rest[1..].join(" ");
                if label.trim().is_empty() {
                    return Err("tag needs a label, or --clear to remove the name".into());
                }
                label
            };
            Command::Tag { network, label }
        }
        "teardown" => {
            let yes = rest.iter().any(|w| w == "--yes");
            if rest.iter().any(|w| w != "--yes") {
                return Err("teardown takes only --yes".into());
            }
            Command::Teardown { yes }
        }
        "install" => {
            let mut o = InstallOpts { from: None, polkit: true, start: true, geo: true };
            let mut j = 0;
            while j < rest.len() {
                match rest[j].as_str() {
                    "--from" => o.from = Some(PathBuf::from(take(rest, &mut j, "--from")?)),
                    "--no-polkit" => o.polkit = false,
                    "--no-start" => o.start = false,
                    "--no-geo" => o.geo = false,
                    other => return Err(format!("install: unknown argument {other}")),
                }
                j += 1;
            }
            Command::Install(o)
        }
        other => return Err(format!("unknown command {other}")),
    };
    Ok((g, cmd))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<(Global, Command), String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn globals_anywhere_and_a_verb() {
        let (g, c) = p("--json status --timeout 3").unwrap();
        assert!(g.json);
        assert_eq!(g.timeout, Duration::from_secs(3));
        assert_eq!(c, Command::Status);
        let (g, _) = p("status --system").unwrap();
        assert_eq!(g.target, Some(Target::System));
        let (g, _) = p("--socket /tmp/x.sock whoami").unwrap();
        assert_eq!(g.socket, Some(PathBuf::from("/tmp/x.sock")));
        assert!(p("--socket").is_err());
        assert!(p("--timeout x status").is_err());
        assert_eq!(p("").unwrap_err(), "no command");
        assert_eq!(p("--help").unwrap().1, Command::Help);
        assert_eq!(p("-V").unwrap().1, Command::Version);
        assert!(p("status extra").is_err());
        assert!(p("nope").is_err());
    }

    #[test]
    fn exec_gate_verbs_validate_the_digest() {
        let sha = "a".repeat(64);
        assert_eq!(
            p(&format!("trust {sha} my note here")).unwrap().1,
            Command::Trust { sha256: sha.clone(), note: "my note here".into() }
        );
        assert_eq!(p(&format!("untrust {}", sha.to_uppercase())).unwrap().1, Command::Untrust { sha256: sha.clone() });
        assert!(p("trust abc").is_err());
        assert!(p("allow-once").is_err());
        assert!(p(&format!("untrust {sha} extra")).is_err());
    }

    #[test]
    fn block_takes_pids_or_ips_after_the_app() {
        assert_eq!(
            p("block firefox --pid 12 34 --ip 1.2.3.4").unwrap().1,
            Command::Block { app: "firefox".into(), ips: vec!["1.2.3.4".into()], pids: vec!["12".into(), "34".into()] }
        );
        assert!(p("block firefox 12").is_err(), "a bare word needs a mode");
        assert!(p("block firefox --pid x").is_err());
        assert!(p("block --pid 1").is_err());
        assert_eq!(p("unblock firefox --ips").unwrap().1, Command::Unblock { app: "firefox".into(), ips: true });
        assert!(p("unblock firefox --what").is_err());
        assert_eq!(p("teardown").unwrap().1, Command::Teardown { yes: false });
        assert_eq!(p("teardown --yes").unwrap().1, Command::Teardown { yes: true });
    }

    #[test]
    fn block_to_is_a_timed_destination_rule() {
        assert_eq!(
            p("block firefox --to 203.0.113.9 --for 15m --pid 12 34").unwrap().1,
            Command::BlockDest { app: "firefox".into(), ip: "203.0.113.9".into(), seconds: 900, pids: vec!["12".into(), "34".into()] }
        );
        assert_eq!(
            p("block firefox --pid 7 --for 1h --to 2001:db8::1").unwrap().1,
            Command::BlockDest { app: "firefox".into(), ip: "2001:db8::1".into(), seconds: 3600, pids: vec!["7".into()] }
        );
        assert_eq!(p("block firefox --to 192.0.2.1 --for 5m --pid 1").unwrap().1, Command::BlockDest {
            app: "firefox".into(), ip: "192.0.2.1".into(), seconds: 300, pids: vec!["1".into()]
        });
        for bad in [
            "block firefox --to 192.0.2.1 --pid 1",
            "block firefox --for 5m --pid 1",
            "block firefox --to 192.0.2.1 --for 10m --pid 1",
            "block firefox --to 192.0.2.1 --for 300 --pid 1",
            "block firefox --to 192.0.2.1 --for 5m",
            "block firefox --to 192.0.2.1 --for 5m --pid 1 --ip 192.0.2.2",
            "block firefox --to --for 5m --pid 1",
            "block firefox --to 192.0.2.1 --for",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(
            p("unblock firefox --to 203.0.113.9").unwrap().1,
            Command::UnblockDest { app: "firefox".into(), ip: "203.0.113.9".into() }
        );
        assert!(p("unblock firefox --to").is_err());
        assert!(p("unblock firefox --ips --to 192.0.2.1").is_err());
    }

    #[test]
    fn policy_watch_tag_and_note() {
        assert_eq!(p("policy snooze r-1").unwrap().1, Command::PolicySnooze { rule: "r-1".into(), seconds: 3600 });
        assert_eq!(p("policy snooze r-1 --for 30m").unwrap().1, Command::PolicySnooze { rule: "r-1".into(), seconds: 1800 });
        assert_eq!(p("--json policy snooze r-1 --for 2h").unwrap().1, Command::PolicySnooze { rule: "r-1".into(), seconds: 7200 });
        assert_eq!(p("policy resume r-1").unwrap().1, Command::PolicyResume { rule: "r-1".into() });
        assert_eq!(p("share").unwrap().1, Command::Share { on: None });
        assert_eq!(p("share on").unwrap().1, Command::Share { on: Some(true) });
        assert_eq!(p("--json share off").unwrap().1, Command::Share { on: Some(false) });
        for bad in ["share maybe", "share on now"] {
            assert!(p(bad).unwrap_err().contains("share on"), "{bad}");
        }
        for bad in ["policy", "policy snooze", "policy resume", "policy snooze r --for 30s", "policy snooze r --for 25h",
                    "policy snooze r --for soon", "policy snooze r --for", "policy snooze r extra", "policy resume r extra",
                    "policy pause r", "policy snooze --for 1h"] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(
            p("watch add country KP state media").unwrap().1,
            Command::WatchAdd { kind: "country".into(), value: "KP".into(), note: "state media".into() }
        );
        assert_eq!(p("watch add PORT 4444").unwrap().1, Command::WatchAdd { kind: "port".into(), value: "4444".into(), note: String::new() });
        assert_eq!(p("watch rm w-0badf00d").unwrap().1, Command::WatchRm { id: "w-0badf00d".into() });
        for bad in ["watch", "watch add", "watch add country", "watch add planet mars", "watch rm", "watch rm a b", "watch list"] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(
            p("tag 203.0.113.0/24 Office VPN").unwrap().1,
            Command::Tag { network: "203.0.113.0/24".into(), label: "Office VPN".into() }
        );
        assert!(p("tag 203.0.113.0/24").is_err());
        assert!(p("tag").is_err());
        // The panel's block record is not a command.
        assert_eq!(p("note block firefox").unwrap_err(), "unknown command note");
    }

    #[test]
    fn the_reads_parse_with_their_flags() {
        assert_eq!(p("apps").unwrap().1, Command::Apps { sort: "connections".into(), filter: AppsFilter::All, mine: false });
        assert_eq!(
            p("apps --sort bandwidth --live --mine").unwrap().1,
            Command::Apps { sort: "bandwidth".into(), filter: AppsFilter::Live, mine: true }
        );
        assert_eq!(p("apps --blocked").unwrap().1, Command::Apps { sort: "connections".into(), filter: AppsFilter::Blocked, mine: false });
        for bad in ["apps --sort size", "apps --blocked --live", "apps --sort", "apps extra"] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(p("conns --app firefox --unattributed -f").unwrap().1, Command::Conns { app: "firefox".into(), unattributed: true, follow: true });
        assert_eq!(p("conns").unwrap().1, Command::Conns { app: String::new(), unattributed: false, follow: false });
        assert!(p("conns --app").is_err());
        assert_eq!(p("activity").unwrap().1, Command::Activity { seconds: 3600 });
        assert_eq!(p("activity --since 2d").unwrap().1, Command::Activity { seconds: 172_800 });
        assert!(p("activity --since soon").is_err());
        assert_eq!(
            p("history --hours 6 --query firefox --csv").unwrap().1,
            Command::History { hours: 6, query: "firefox".into(), format: HistoryFormat::Csv }
        );
        assert_eq!(p("history --ndjson").unwrap().1, Command::History { hours: 24, query: String::new(), format: HistoryFormat::Ndjson });
        for bad in ["history --hours 0", "history --hours 169", "history --csv --ndjson", "history --hours x"] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(p("intel").unwrap().1, Command::Intel { timeline_hours: None });
        assert_eq!(p("intel --timeline --hours 48").unwrap().1, Command::Intel { timeline_hours: Some(48) });
        assert_eq!(p("why 203.0.113.9").unwrap().1, Command::Why { subject: "203.0.113.9".into(), hours: 168 });
        assert_eq!(p("why asn:13335 --hours 24").unwrap().1, Command::Why { subject: "asn:13335".into(), hours: 24 });
        for bad in ["why", "why a b", "why --hours 1"] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(p("policies").unwrap().1, Command::Policies);
        assert_eq!(p("watches").unwrap().1, Command::Watches);
        assert_eq!(p("brief --hours 12").unwrap().1, Command::Brief { hours: 12 });
        assert!(p("policies extra").is_err());
    }

    /// One daemon (#61): no verb picks a daemon of its own. Until 0.5 watch
    /// rules went to the user daemon first and a tag to both.
    #[test]
    fn the_help_says_whose_the_watch_rules_are_and_names_no_route() {
        assert_eq!(p("watch --help").unwrap().1, Command::HelpTopic("watch".into()));
        assert_eq!(p("watches -h").unwrap().1, Command::HelpTopic("watches".into()));
        assert_eq!(p("tag --help").unwrap().1, Command::HelpTopic("tag".into()));
        assert_eq!(p("apps --help").unwrap().1, Command::Help);
        assert!(WATCH_HELP.contains("changes the ones they set"));
        assert!(TAG_HELP.contains("heartbeat carries it\nto your org"));
        assert!(TAG_HELP.contains("--clear") && USAGE.contains("--clear"));
        // The help does not promise what the parser refuses (it once said an
        // empty label removes the name, which the parser never let through).
        assert_eq!(p("tag 203.0.113.0/24 --clear").unwrap().1, Command::Tag { network: "203.0.113.0/24".into(), label: String::new() });
        assert_eq!(p("tag 203.0.113.0/24 Office VPN").unwrap().1, Command::Tag { network: "203.0.113.0/24".into(), label: "Office VPN".into() });
        for bad in ["tag 203.0.113.0/24", "tag 203.0.113.0/24 --clear now"] {
            assert!(p(bad).is_err() || matches!(p(bad).unwrap().1, Command::Tag { ref label, .. } if !label.is_empty()), "{bad}");
        }
        assert!(p("tag 203.0.113.0/24").unwrap_err().contains("--clear"));
        for text in [USAGE, WATCH_HELP, TAG_HELP] {
            for gone in ["user daemon;", "both daemons", "user daemon is retired", "go to your own"] {
                assert!(!text.contains(gone), "{gone:?} is still in the help");
            }
        }
    }

    #[test]
    fn only_root_verbs_and_address_blocks_are_marked_as_needing_root() {
        for v in ["unblock", "unblock-dest", "trust", "allow-once", "pause", "teardown", "login", "logout", "policy-snooze", "share-on"] {
            assert!(lowers(v), "{v}");
        }
        for v in ["block", "block-dest", "untrust", "resume", "sync", "policy-resume", "watch-set", "watch-delete", "tag", "share-off", "status"] {
            assert!(!lowers(v), "{v}");
        }
        let map = |v: serde_json::Value| v.as_object().unwrap().clone();
        assert!(needs_root("block", &map(serde_json::json!({"app":"a","ips":["192.0.2.1"],"pids":[]}))));
        assert!(!needs_root("block", &map(serde_json::json!({"app":"a","ips":[],"pids":["12"]}))));
        assert!(!needs_root("block", &map(serde_json::json!({"app":"a","ips":[" "],"pids":["12"]}))));
        assert!(!needs_root("block-dest", &map(serde_json::json!({"app":"a","ip":"192.0.2.1"}))));
        assert!(needs_root("login", &serde_json::Map::new()));
        assert_eq!(duration_secs("90s"), Some(90));
        assert_eq!(duration_secs("1h"), Some(3600));
        assert_eq!(duration_secs("h"), None);
        assert_eq!(duration_secs(""), None);
        assert_eq!(duration_secs("5"), None);
        assert_eq!(duration_secs("5é"), None, "a multibyte suffix is no unit, and no panic");
    }

    #[test]
    fn login_and_install_flags() {
        assert_eq!(
            p("login --server-url https://s --auth-url https://a").unwrap().1,
            Command::Login { server_url: Some("https://s".into()), auth_url: Some("https://a".into()) }
        );
        assert!(p("login --bogus").is_err());
        let (_, c) = p("install --from /tmp/dist --no-polkit --no-start").unwrap();
        assert_eq!(
            c,
            Command::Install(InstallOpts { from: Some(PathBuf::from("/tmp/dist")), polkit: false, start: false, geo: true })
        );
        assert!(p("install --from").is_err());
    }
}
