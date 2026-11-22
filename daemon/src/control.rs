//! The `kub0` CLI's half of the command socket: request/reply frames and the
//! authorization table.
//!
//! The socket has always carried fire-and-forget commands (`note`,
//! `netpolicy-snooze`, `watch`, …) whose answers, when there are any, go out
//! as broadcast events to every client. A CLI needs the opposite: one answer,
//! to the client that asked, correlated to its request. A request is any
//! NDJSON line carrying a `req` id next to its `cmd`; its reply is a
//! `type: "reply"` frame with the same `req`, sent to that client only. A
//! long operation (device login) sends `partial: true` replies first.
//!
//! Who may do what is decided here, once, from the peer's credentials
//! (`SO_PEERCRED`) rather than from the socket mode. The rule is "the group
//! raises, root lowers": the system daemon's command socket is
//! root:kub0 0660 (docs/system-status.md), so a member of that group
//! can connect, and this table is what keeps them to reads and raises. A verb
//! that removes or weakens enforcement is `Lower` and needs uid 0. The
//! per-user socket is owner-only 0600, and its owner may do everything on it.
//! Mutating legacy lines (no `req`) bypass this table, so the system daemon
//! accepts them from root alone (`legacy_line_allowed`).

use serde::{Deserialize, Serialize};

/// Longest `req` id accepted. A client that cannot fit a correlation id in 64
/// bytes is not a client this protocol was written for.
pub const MAX_REQ_LEN: usize = 64;

/// What a verb does to the host's protection. Reads never change it; a raise
/// adds protection; a lower removes or weakens it. A trust lowers: the exec
/// gate's key set is `(fleet ∪ file) − trusted`, so trusting a digest lets a
/// deny-listed binary run. Each class matches the polkit policy for the same
/// helper verb (`auth_admin_keep` raises, `auth_admin` lowers), pinned below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Raise,
    Lower,
}

/// Every verb the socket answers with a reply, and what it is.
pub const VERBS: &[(&str, Access)] = &[
    ("status", Access::Read),
    ("whoami", Access::Read),
    ("rules", Access::Read),
    ("endpoints", Access::Read),
    ("trusts", Access::Read),
    ("blocks", Access::Read),
    // What the panel shows, for `kub0` (#61 step 2): the daemon's own data,
    // no change.
    ("apps", Access::Read),
    ("conns", Access::Read),
    ("activity", Access::Read),
    ("history", Access::Read),
    ("intel", Access::Read),
    ("investigate", Access::Read),
    ("policies", Access::Read),
    ("watches", Access::Read),
    ("brief", Access::Read),
    // An app block raises; `block` with addresses is host-wide and needs
    // root on the system daemon (`authorize_args`).
    ("block", Access::Raise),
    ("block-dest", Access::Raise),
    ("untrust", Access::Raise),
    ("resume", Access::Raise),
    ("sync", Access::Raise),
    ("policy-resume", Access::Raise),
    // Alert rules and labels: they change what is shown and logged, never
    // what is enforced.
    ("watch-set", Access::Raise),
    ("watch-delete", Access::Raise),
    ("tag", Access::Raise),
    // Destination sharing sends the networks this host reaches to the org.
    // Stopping it is anyone's who may change things here; starting it is an
    // admin's decision, like the login that chose the org.
    ("share-off", Access::Raise),
    ("share-on", Access::Lower),
    // Which org a host enforces is an admin's decision: a login can bring a
    // new org's deny list and network policies, so it is root's like logout.
    ("login", Access::Lower),
    ("logout", Access::Lower),
    ("unblock", Access::Lower),
    ("unblock-dest", Access::Lower),
    ("trust", Access::Lower),
    ("allow-once", Access::Lower),
    ("pause", Access::Lower),
    ("teardown", Access::Lower),
    ("policy-snooze", Access::Lower),
];

pub fn access_for(cmd: &str) -> Option<Access> {
    VERBS.iter().find(|(v, _)| *v == cmd).map(|(_, a)| *a)
}

/// A parsed request line. `args` is the whole object, so a verb reads its own
/// fields without this module knowing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub req: String,
    pub cmd: String,
    pub args: serde_json::Value,
}

impl Request {
    /// `None` for anything that is not a request: an unparseable line, a
    /// legacy command without `req`, or a `req` that is empty or too long.
    /// Those lines belong to the legacy path and are never answered here.
    pub fn parse(line: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
        let req = v.get("req")?.as_str()?;
        if req.is_empty() || req.len() > MAX_REQ_LEN {
            return None;
        }
        let cmd = v.get("cmd")?.as_str()?.to_string();
        Some(Request {
            req: req.to_string(),
            cmd,
            args: v,
        })
    }

    /// A string argument, trimmed; empty when absent or not a string.
    pub fn str_arg(&self, key: &str) -> String {
        self.args
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    /// A list of strings; non-strings are skipped.
    pub fn list_arg(&self, key: &str) -> Vec<String> {
        self.args
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// One answer. Serialized as `{"type":"reply", …}` on the wire by the daemon's
/// event enum; this struct is the body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Reply {
    pub req: String,
    pub ok: bool,
    /// More replies follow for this `req`.
    pub partial: bool,
    pub result: serde_json::Value,
    pub error: String,
}

impl Reply {
    pub fn ok(req: &str, result: serde_json::Value) -> Self {
        Reply {
            req: req.to_string(),
            ok: true,
            partial: false,
            result,
            error: String::new(),
        }
    }
    pub fn partial(req: &str, result: serde_json::Value) -> Self {
        Reply {
            partial: true,
            ..Reply::ok(req, result)
        }
    }
    pub fn err(req: &str, error: impl Into<String>) -> Self {
        Reply {
            req: req.to_string(),
            ok: false,
            partial: false,
            result: serde_json::Value::Null,
            error: error.into(),
        }
    }
}

/// Who the daemon is talking to, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// `None` when the platform cannot say (no `SO_PEERCRED`).
    pub uid: Option<u32>,
}

/// The daemon's own identity, the only thing a decision is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Daemon {
    pub uid: u32,
    pub system: bool,
}

/// `Ok(())` when `peer` may run `cmd` on this daemon.
///
/// - Root may do everything, in either mode.
/// - The user daemon's owner may do everything on their own daemon: its
///   socket is theirs alone, and nothing it can do touches another user.
///   Anyone else there may only read.
/// - On the system daemon an identified non-root peer (a member of the
///   socket's group) may read and raise; lowering needs uid 0. Some raises
///   need root for their arguments too (`authorize_args`).
/// - A peer the platform cannot identify may only read.
pub fn authorize(cmd: &str, access: Access, peer: Peer, daemon: Daemon) -> Result<(), String> {
    let uid = match peer.uid {
        Some(uid) => uid,
        None => {
            return match access {
                Access::Read => Ok(()),
                _ => Err(format!("{cmd}: the caller's identity is unavailable on this platform; reads only")),
            }
        }
    };
    if uid == 0 {
        return Ok(());
    }
    if !daemon.system {
        if uid == daemon.uid {
            return Ok(());
        }
        return match access {
            Access::Read => Ok(()),
            Access::Raise | Access::Lower => Err(format!(
                "{cmd}: needs root on the system daemon; run: sudo kub0 {cmd}"
            )),
        };
    }
    match access {
        Access::Read | Access::Raise => Ok(()),
        Access::Lower => Err(format!("{cmd}: {}; needs root: sudo kub0 {}", lower_reason(cmd), cli_command(cmd))),
    }
}

/// Why a `Lower` verb is root's, in the refusal.
pub fn lower_reason(cmd: &str) -> &'static str {
    match cmd {
        "login" => "chooses the org whose rules this host enforces",
        "share-on" => "sends the networks this host reaches to your org",
        _ => "lowers protection",
    }
}

/// `block` with addresses: the helper's `block-ips`, which drops them for
/// every process on the host, not one app's tree. Its floor spares only the
/// host's nameservers and gateways, so a member could cut the daemon off from
/// the kub0 server.
pub fn address_block(req: &Request) -> bool {
    req.cmd == "block" && !req.list_arg("ips").is_empty()
}

pub const ADDRESS_BLOCK_NEEDS_ROOT: &str =
    "block: an address block applies to the whole host; needs root: sudo kub0 block <app> --ip …";

/// The argument-level half of authorization, after `authorize` passed the
/// verb: on the system daemon an address block is root's.
pub fn authorize_args(req: &Request, peer: Peer, daemon: Daemon) -> Result<(), String> {
    if daemon.system && peer.uid != Some(0) && address_block(req) {
        return Err(ADDRESS_BLOCK_NEEDS_ROOT.into());
    }
    Ok(())
}

/// Why `req` needs root on the system daemon, and the `kub0` line that runs
/// it; `None` when a member of the socket's group may run it there.
pub fn root_needed(req: &Request) -> Option<(&'static str, String)> {
    if address_block(req) {
        return Some(("an address block applies to the whole host", "block <app> --ip …".into()));
    }
    match access_for(&req.cmd) {
        Some(Access::Lower) => Some((lower_reason(&req.cmd), cli_command(&req.cmd).to_string())),
        _ => None,
    }
}

/// The `kub0` command line for a verb that needs root, for the hint that
/// names root. A verb whose CLI words are its own name is itself.
pub fn cli_command(cmd: &str) -> &str {
    match cmd {
        "unblock" => "unblock <app>",
        "unblock-dest" => "unblock <app> --to <ip>",
        "trust" => "trust <sha256>",
        "allow-once" => "allow-once <sha256>",
        "teardown" => "teardown --yes",
        "policy-snooze" => "policy snooze <rule>",
        "share-on" => "share on",
        "share-off" => "share off",
        other => other,
    }
}

/// `as_uid` on a request: the user a root caller acts for. `kub0` re-run
/// through pkexec is root, and forwards `PKEXEC_UID` here so the helper's
/// ownership checks act on the person who asked, not on root. Honoured only
/// from uid 0; from anyone else the request is refused, never silently
/// stripped. `Ok(None)` when the request carries none.
pub fn as_uid(req: &Request, peer: Peer) -> Result<Option<u32>, String> {
    let Some(v) = req.args.get("as_uid") else {
        return Ok(None);
    };
    if peer.uid != Some(0) {
        return Err(format!("{}: as_uid is honoured only from root", req.cmd));
    }
    v.as_u64()
        .filter(|n| *n <= u64::from(u32::MAX))
        .map(|n| Some(n as u32))
        .ok_or_else(|| format!("{}: as_uid must be a uid", req.cmd))
}

/// Whom a helper-backed verb acts for: the `as_uid` a root caller names,
/// else the peer itself.
pub fn acting_uid(req: &Request, peer: Peer) -> Result<Option<u32>, String> {
    Ok(as_uid(req, peer)?.or(peer.uid))
}

/// The mutating legacy line `v` is, by name, or `None` for a read and for
/// anything the legacy path ignores. Mirrors `handle_cmd`'s dispatch: a line
/// whose `cmd` the legacy path answers is never read by its `type`.
pub fn legacy_mutation(v: &serde_json::Value) -> Option<&'static str> {
    match v.get("cmd").and_then(|x| x.as_str()).unwrap_or("") {
        "netpolicy-snooze" => Some("netpolicy-snooze"),
        "netpolicy-resume" => Some("netpolicy-resume"),
        "note" => Some("note"),
        "watch" => Some("watch"),
        "investigate" | "timeline" | "history" => None,
        _ => match v.get("type").and_then(|x| x.as_str()).unwrap_or("") {
            "tag" => Some("tag"),
            _ => None,
        },
    }
}

/// Whether a mutating legacy line (no `req`, so `authorize` never sees it)
/// is accepted from `peer`. The user daemon's socket is its owner's alone,
/// so there it always is. The system daemon's socket admits its group, and a
/// legacy line has no access class, so there only root's are.
pub fn legacy_line_allowed(peer: Peer, daemon: Daemon) -> bool {
    !daemon.system || peer.uid == Some(0)
}

/// What a client that sent a refused mutating legacy line is told.
pub fn legacy_refusal(cmd: &str) -> String {
    format!(
        "{cmd}: refused; the system daemon accepts this only as a request now, so this panel is older than the daemon: update the panel"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: Daemon = Daemon { uid: 0, system: true };
    const USER: Daemon = Daemon { uid: 1000, system: false };

    fn peer(uid: u32) -> Peer {
        Peer { uid: Some(uid) }
    }

    #[test]
    fn every_verb_has_exactly_one_access() {
        let mut seen = std::collections::BTreeSet::new();
        for (v, _) in VERBS {
            assert!(seen.insert(*v), "duplicate verb {v}");
        }
        assert_eq!(access_for("status"), Some(Access::Read));
        assert_eq!(access_for("unblock"), Some(Access::Lower));
        assert_eq!(access_for("not-a-verb"), None);
    }

    /// The polkit policy states the same split for the helper verbs the panel
    /// runs through pkexec: `auth_admin_keep` (the grant is kept a few minutes)
    /// raises protection, `auth_admin` (asked every time) lowers it. Every
    /// verb that is not a read must be placed here, so a new verb cannot land
    /// in the table without someone deciding which side it is on.
    #[test]
    fn raise_and_lower_match_the_polkit_policy() {
        const POLICY: &str = include_str!("../../polkit/ai.kub0.agent.policy");
        // Each verb with the helper verbs (pkexec exec.argv1) it ends in.
        const HELPER: &[(&str, &[&str])] = &[
            ("login", &[]),
            ("logout", &[]),
            ("block", &["block-app", "block-ips"]),
            ("unblock", &["unblock-app", "unblock-ips"]),
            ("trust", &["execgate-trust"]),
            ("untrust", &["execgate-untrust"]),
            ("allow-once", &["execgate-allow-once"]),
            ("pause", &["pause"]),
            ("resume", &["resume"]),
            ("teardown", &["teardown"]),
            ("sync", &["fleet-sync"]),
            ("block-dest", &["block-scoped"]),
            ("unblock-dest", &["unblock-scoped"]),
            // Daemon-only: no helper verb, so nothing in polkit to agree with.
            ("policy-snooze", &[]),
            ("policy-resume", &[]),
            ("watch-set", &[]),
            ("watch-delete", &[]),
            ("tag", &[]),
            ("share-on", &[]),
            ("share-off", &[]),
        ];
        // `fleet-sync` replaces the org's blocks with whatever set its caller
        // hands it, so polkit asks every time. The daemon's `sync` applies only
        // what it fetched from the org, which never goes below the org's list.
        const DELIBERATE: &[&str] = &["sync"];

        let mut polkit = std::collections::BTreeMap::new();
        for action in POLICY.split("<action id=").skip(1) {
            let field = |key: &str| {
                let start = action.find(key)? + key.len();
                let end = action[start..].find('<')?;
                Some(action[start..start + end].trim().to_string())
            };
            if let (Some(argv1), Some(level)) = (
                field(r#""org.freedesktop.policykit.exec.argv1">"#),
                field("<allow_active>"),
            ) {
                polkit.insert(argv1, level);
            }
        }
        assert!(polkit.len() >= 10, "policy parse found only {polkit:?}");

        for (verb, access) in VERBS {
            if *access == Access::Read {
                continue;
            }
            let (_, helpers) = HELPER
                .iter()
                .find(|(v, _)| v == verb)
                .unwrap_or_else(|| panic!("{verb} is not placed against the polkit policy"));
            for h in *helpers {
                let level = polkit.get(*h).unwrap_or_else(|| panic!("no polkit action for {h}"));
                let polkit_says = match level.as_str() {
                    "auth_admin_keep" => Access::Raise,
                    "auth_admin" => Access::Lower,
                    other => panic!("{h}: unexpected allow_active {other}"),
                };
                if DELIBERATE.contains(verb) {
                    assert_ne!(*access, polkit_says, "{verb}: no longer differs from polkit; drop it from DELIBERATE");
                } else {
                    assert_eq!(*access, polkit_says, "{verb} ({h} is {level} in polkit)");
                }
            }
        }

        // A Lower verb reaches a desktop user through `pkexec /usr/bin/kub0`
        // (the CLI re-runs itself, the panel runs the same): that action must
        // exist and ask every time, like the helper's lowering verbs.
        let kub0 = POLICY
            .split("<action id=")
            .skip(1)
            .find(|a| a.contains(r#""org.freedesktop.policykit.exec.path">/usr/bin/kub0<"#))
            .expect("no polkit action runs /usr/bin/kub0");
        assert!(kub0.contains("<allow_active>auth_admin</allow_active>"), "the kub0 action must ask every time");
        assert!(!kub0.contains("exec.argv1"), "the kub0 action covers every command it re-runs");
    }

    #[test]
    fn a_trust_lowers_and_an_untrust_raises() {
        // The gate denies `(fleet ∪ file) − trusted`: trusting a digest lets a
        // deny-listed binary run.
        assert_eq!(access_for("trust"), Some(Access::Lower));
        assert_eq!(access_for("untrust"), Some(Access::Raise));
        assert!(authorize("trust", Access::Lower, peer(1000), SYSTEM).is_err());
    }

    #[test]
    fn root_may_do_everything_on_both_daemons() {
        for (v, a) in VERBS {
            assert_eq!(authorize(v, *a, peer(0), SYSTEM), Ok(()), "{v} system");
            assert_eq!(authorize(v, *a, peer(0), USER), Ok(()), "{v} user");
        }
    }

    #[test]
    fn the_owner_may_do_everything_on_their_own_user_daemon() {
        for (v, a) in VERBS {
            assert_eq!(authorize(v, *a, peer(1000), USER), Ok(()), "{v}");
        }
    }

    #[test]
    fn another_user_on_a_user_daemon_may_only_read() {
        assert_eq!(authorize("status", Access::Read, peer(1001), USER), Ok(()));
        assert!(authorize("block", Access::Raise, peer(1001), USER).is_err());
        assert!(authorize("unblock", Access::Lower, peer(1001), USER).is_err());
    }

    /// The group raises, root lowers: the socket admits members of its
    /// group, and this is the line that keeps them from lowering.
    #[test]
    fn a_non_root_peer_on_the_system_daemon_may_read_and_raise() {
        for (v, a) in VERBS {
            let r = authorize(v, *a, peer(1000), SYSTEM);
            match a {
                Access::Read | Access::Raise => assert_eq!(r, Ok(()), "{v}"),
                Access::Lower => assert!(r.is_err(), "{v}"),
            }
        }
        for v in ["block", "block-dest", "untrust", "resume", "policy-resume", "watch-set", "watch-delete", "tag", "share-off"] {
            assert_eq!(authorize(v, access_for(v).unwrap(), peer(1000), SYSTEM), Ok(()), "{v}");
        }
    }

    #[test]
    fn every_lower_verb_is_refused_to_a_non_root_peer_on_the_system_daemon() {
        let lowers: Vec<&str> = VERBS.iter().filter(|(_, a)| *a == Access::Lower).map(|(v, _)| *v).collect();
        for v in ["unblock", "unblock-dest", "trust", "allow-once", "pause", "teardown", "login", "logout", "policy-snooze", "share-on"] {
            assert!(lowers.contains(&v), "{v} must lower");
        }
        for v in &lowers {
            for uid in [1, 1000, 65534] {
                let e = authorize(v, Access::Lower, peer(uid), SYSTEM).unwrap_err();
                assert_eq!(e, format!("{v}: {}; needs root: sudo kub0 {}", lower_reason(v), cli_command(v)));
                assert!(e.contains("; needs root: sudo kub0 "), "{e}");
            }
            assert_eq!(authorize(v, Access::Lower, peer(0), SYSTEM), Ok(()), "{v} root");
        }
    }

    #[test]
    fn the_root_hint_names_the_cli_command() {
        assert_eq!(cli_command("unblock-dest"), "unblock <app> --to <ip>");
        assert_eq!(cli_command("policy-snooze"), "policy snooze <rule>");
        assert_eq!(cli_command("pause"), "pause");
        assert_eq!(
            authorize("unblock-dest", Access::Lower, peer(1000), SYSTEM).unwrap_err(),
            "unblock-dest: lowers protection; needs root: sudo kub0 unblock <app> --to <ip>"
        );
    }

    #[test]
    fn the_cli_reads_are_reads_anyone_who_can_connect_may_make() {
        for v in ["apps", "conns", "activity", "history", "intel", "investigate", "policies", "watches", "brief"] {
            assert_eq!(access_for(v), Some(Access::Read), "{v}");
            assert_eq!(authorize(v, Access::Read, peer(1000), SYSTEM), Ok(()), "{v}");
            assert_eq!(authorize(v, Access::Read, peer(1001), USER), Ok(()), "{v}: another user reads a user daemon");
        }
    }

    #[test]
    fn new_verbs_have_their_classes() {
        for (v, a) in [
            ("block-dest", Access::Raise),
            ("unblock-dest", Access::Lower),
            ("policy-snooze", Access::Lower),
            ("policy-resume", Access::Raise),
            ("watch-set", Access::Raise),
            ("watch-delete", Access::Raise),
            ("tag", Access::Raise),
        ] {
            assert_eq!(access_for(v), Some(a), "{v}");
        }
    }

    #[test]
    fn as_uid_is_honoured_from_root_only_and_never_ignored() {
        use serde_json::json;
        let with = req(json!({"cmd":"block","app":"a","pids":["7"],"as_uid":1000}));
        let without = req(json!({"cmd":"block","app":"a","pids":["7"]}));
        assert_eq!(as_uid(&with, peer(0)), Ok(Some(1000)));
        assert_eq!(as_uid(&without, peer(0)), Ok(None));
        assert_eq!(as_uid(&without, peer(1000)), Ok(None));
        assert_eq!(as_uid(&with, peer(1000)).unwrap_err(), "block: as_uid is honoured only from root");
        assert!(as_uid(&with, Peer { uid: None }).is_err());
        for bad in [json!(-1), json!("1000"), json!(1.5), json!(null), json!(4294967296u64)] {
            let r = req(json!({"cmd":"block","app":"a","as_uid":bad}));
            assert!(as_uid(&r, peer(0)).unwrap_err().contains("must be a uid"), "{bad}");
        }
        assert_eq!(as_uid(&req(json!({"cmd":"status","as_uid":0})), peer(0)), Ok(Some(0)));
        // What the helper is told: the named user from root, else the peer.
        assert_eq!(acting_uid(&with, peer(0)), Ok(Some(1000)));
        assert_eq!(acting_uid(&without, peer(0)), Ok(Some(0)));
        assert_eq!(acting_uid(&without, peer(1000)), Ok(Some(1000)));
        assert!(acting_uid(&with, peer(1000)).is_err());
    }

    /// Which org a host enforces is an admin's decision.
    #[test]
    fn login_is_root_only_on_the_system_daemon() {
        assert_eq!(access_for("login"), Some(Access::Lower));
        assert_eq!(
            authorize("login", Access::Lower, peer(1000), SYSTEM).unwrap_err(),
            "login: chooses the org whose rules this host enforces; needs root: sudo kub0 login"
        );
        assert_eq!(authorize("login", Access::Lower, peer(0), SYSTEM), Ok(()));
        assert_eq!(authorize("login", Access::Lower, peer(1000), USER), Ok(()), "a user daemon's owner logs in");
    }

    /// The panel's internal record of a block outcome is not a public verb:
    /// it would only let a member forge activity rows.
    #[test]
    fn note_is_not_a_control_verb() {
        assert_eq!(access_for("note"), None);
    }

    fn req(v: serde_json::Value) -> Request {
        let mut v = v;
        v["req"] = "1".into();
        Request::parse(&v.to_string()).unwrap()
    }

    #[test]
    fn an_address_block_is_root_only_on_the_system_daemon() {
        use serde_json::json;
        let ips = req(json!({"cmd":"block","app":"firefox","ips":["192.0.2.1"]}));
        let app = req(json!({"cmd":"block","app":"firefox","pids":["12"]}));
        let blank = req(json!({"cmd":"block","app":"firefox","ips":[" ", ""]}));
        assert!(address_block(&ips) && !address_block(&app) && !address_block(&blank));
        assert_eq!(authorize_args(&ips, peer(1000), SYSTEM).unwrap_err(), ADDRESS_BLOCK_NEEDS_ROOT);
        assert!(ADDRESS_BLOCK_NEEDS_ROOT.contains("sudo kub0 block <app> --ip"));
        assert_eq!(authorize_args(&ips, peer(0), SYSTEM), Ok(()));
        assert_eq!(authorize_args(&ips, Peer { uid: None }, SYSTEM).map_err(|_| ()), Err(()));
        assert_eq!(authorize_args(&ips, peer(1000), USER), Ok(()), "the user daemon's owner");
        assert_eq!(authorize_args(&app, peer(1000), SYSTEM), Ok(()), "an app block stays the group's");
        assert_eq!(authorize_args(&blank, peer(1000), SYSTEM), Ok(()), "no address, no address block");
        let dest = req(json!({"cmd":"block-dest","app":"firefox","ip":"192.0.2.1","seconds":300,"pids":["12"]}));
        assert_eq!(authorize_args(&dest, peer(1000), SYSTEM), Ok(()), "one app's destination stays the group's");
        // The hint for a refusal off the system daemon agrees.
        assert_eq!(root_needed(&ips).map(|(_, cli)| cli), Some("block <app> --ip …".to_string()));
        assert_eq!(root_needed(&app), None);
        assert_eq!(root_needed(&req(json!({"cmd":"login"}))).map(|(_, cli)| cli), Some("login".to_string()));
    }

    #[test]
    fn mutating_legacy_lines_are_root_only_on_the_system_daemon() {
        use serde_json::json;
        for (line, want) in [
            (json!({"cmd": "netpolicy-snooze", "ruleId": "r", "seconds": 60}), Some("netpolicy-snooze")),
            (json!({"cmd": "netpolicy-resume", "ruleId": "r"}), Some("netpolicy-resume")),
            (json!({"cmd": "note", "kind": "block"}), Some("note")),
            (json!({"cmd": "watch", "action": "delete", "id": "w-1"}), Some("watch")),
            (json!({"type": "tag", "networkKey": "1.2.3.0/24", "label": "x"}), Some("tag")),
            (json!({"cmd": "investigate", "request": "1"}), None),
            (json!({"cmd": "timeline", "request": "1"}), None),
            (json!({"cmd": "history", "request": "1"}), None),
            // The legacy path answers `history` by its cmd and never reads
            // the type, so this is a read, not a tag.
            (json!({"cmd": "history", "type": "tag"}), None),
            (json!({"type": "panel-open"}), None),
            (json!({"type": "panel-close"}), None),
            (json!({"type": "ping"}), None),
            (json!({}), None),
        ] {
            assert_eq!(legacy_mutation(&line), want, "{line}");
        }
        assert!(legacy_line_allowed(peer(0), SYSTEM));
        assert!(!legacy_line_allowed(peer(1000), SYSTEM));
        assert!(!legacy_line_allowed(Peer { uid: None }, SYSTEM));
        assert!(legacy_line_allowed(peer(1000), USER), "the user daemon is unchanged");
        assert!(legacy_line_allowed(Peer { uid: None }, USER));
        assert!(legacy_refusal("watch").contains("update the panel"));
    }

    #[test]
    fn an_unidentified_peer_may_only_read() {
        let p = Peer { uid: None };
        assert_eq!(authorize("rules", Access::Read, p, USER), Ok(()));
        assert!(authorize("login", Access::Raise, p, USER).is_err());
        assert!(authorize("logout", Access::Lower, p, SYSTEM).is_err());
    }

    #[test]
    fn a_request_needs_req_and_cmd() {
        assert_eq!(Request::parse("not json"), None);
        assert_eq!(Request::parse(r#"{"cmd":"note"}"#), None, "legacy command");
        assert_eq!(Request::parse(r#"{"req":"","cmd":"status"}"#), None);
        let long = "x".repeat(MAX_REQ_LEN + 1);
        assert_eq!(Request::parse(&format!(r#"{{"req":"{long}","cmd":"status"}}"#)), None);
        assert_eq!(Request::parse(r#"{"req":"1"}"#), None, "no cmd");
        let r = Request::parse(r#"{"req":"a1","cmd":"block","app":" firefox ","pids":["12","x",3]}"#).unwrap();
        assert_eq!(r.req, "a1");
        assert_eq!(r.cmd, "block");
        assert_eq!(r.str_arg("app"), "firefox");
        assert_eq!(r.list_arg("pids"), vec!["12", "x"]);
        assert_eq!(r.str_arg("missing"), "");
    }

    #[test]
    fn reply_shapes() {
        let ok = Reply::ok("7", serde_json::json!({"a": 1}));
        assert!(ok.ok && !ok.partial && ok.error.is_empty());
        let p = Reply::partial("7", serde_json::json!({}));
        assert!(p.ok && p.partial);
        let e = Reply::err("7", "boom");
        assert!(!e.ok && e.error == "boom" && e.result.is_null());
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["req"], "7");
        assert_eq!(v["ok"], false);
    }
}
