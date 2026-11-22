use crate::activity::ActivityEntry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppIdentity {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub desktop: String,
    pub pid: u32,
    /// True when the process is another uid and we only know it as "system".
    #[serde(default)]
    pub system: bool,
    /// The executable (`/proc/<pid>/exe`), empty when unknown. Rows group by
    /// `id`, and a process can reach another app's id by its exe name, comm
    /// or a .desktop file, so the block confirmation lists these: a second
    /// executable under one name is the sign that the row was joined. Local
    /// only; nothing sent to kub0 carries an AppIdentity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe: String,
    /// Whose process this is, when that is not the daemon's own user: the
    /// system daemon (root) resolves every logged-in user's apps and says
    /// which account runs each one. Absent on the user daemon's rows, on the
    /// system daemon's own (root) rows and on `system` rows. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<AppOwner>,
}

/// The account a process runs as, from the passwd database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppOwner {
    pub uid: u32,
    /// The account name; the uid as text when the database has no entry.
    pub name: String,
}

impl AppIdentity {
    /// The owner's account name, when the row carries one.
    pub fn owner_name(&self) -> Option<&str> {
        self.owner.as_ref().map(|o| o.name.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    pub id: String,
    pub proto: String,
    pub inode: u64,
    pub app: AppIdentity,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub state: String,
    /// ISO 3166-1 alpha-2, empty when unknown or unresolved UDP.
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub lat: f64,
    #[serde(default)]
    pub lon: f64,
    /// UDP with a null remote — listed, never drawn as an arc.
    #[serde(default)]
    pub unresolved: bool,
    #[serde(default, rename = "newNetwork")]
    pub new_network: bool,
    #[serde(default, rename = "networkKey")]
    pub network_key: String,
    /// A name for the peer: the one this user's software asked DNS for (when
    /// the optional collector saw the answer), else the PTR name (when
    /// reverse-DNS is opted in, or the row is unattributed). Empty otherwise.
    #[serde(default)]
    pub hostname: String,
    /// Where `hostname` came from: `dns` (an answer the app received), `ptr`
    /// (a reverse lookup), `source` (a database source reported it), or
    /// empty when there is no name. Additive.
    #[serde(default, rename = "hostnameSource", skip_serializing_if = "String::is_empty")]
    pub hostname_source: String,
    /// Socket uid from `/proc/net`. Absent on historical / projected rows.
    #[serde(default)]
    pub uid: Option<u32>,
    /// Why this row has no owning process. Empty when a pid was found.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Best available guess at *who* this unattributed connection belongs to,
    /// with the evidence that produced it. Absent on rows that already name a
    /// process, and absent when nothing honest could be said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clue: Option<crate::suggest::Clue>,
    /// Human or fleet name for this network key. Absent on attributed rows,
    /// and absent when nothing has been named. Additive: an older panel
    /// ignores it the same way it ignores `clue`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<crate::tags::Tag>,
    /// Last measured TCP payload counters. UDP and unsupported sources are null.
    #[serde(default)]
    pub bytes: Option<crate::traffic::Bytes>,
    /// Observed executable path, distinct from the desktop/group app id.
    #[serde(default)]
    pub exe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ConnectionEvidence>,
    /// Org network-policy rules this connection matched when it was first seen. Monitor
    /// only: a match is counted and shown, never enforced. Absent when nothing matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<crate::netpolicy::ConnPolicy>,
    /// Autonomous system of the remote address, from the bundled DB-IP ASN
    /// Lite database. Absent for private, unresolved and unlisted addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// The ASN's registrant name. Says who announces the range, not who
    /// rents a machine in it; see `docs/INTEL.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Local indicators about this connection, highest severity first.
    /// Computed on this machine from this machine's evidence; see
    /// `docs/INTEL.md`. Absent when there is nothing worth saying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indicators: Vec<crate::intel::Indicator>,
}

/// A socket this machine accepts connections (or datagrams) on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    pub proto: String,
    /// The bound address: `0.0.0.0`/`::` for every interface.
    pub ip: String,
    pub port: u16,
    pub app: AppIdentity,
    pub exe: String,
    #[serde(default)]
    pub uid: Option<u32>,
    /// `loopback`, `all`, or `address` (bound to one specific address).
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionEvidence {
    pub source: crate::flow::SourceKind,
    pub recorded_at: u64,
    pub verdict: Option<crate::flow::Verdict>,
    pub owner_method: String,
    pub hash: Option<String>,
    pub container: Option<String>,
    /// Ancestors, command line and working directory of the owning process at
    /// first sight. Additive; absent on unattributed and database rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<crate::lineage::Lineage>,
    /// The distribution package that owns the executable, as the package
    /// manager names it ("firefox 130.0-1"), or `"none"` when the manager says
    /// no package owns it. Additive; absent until the lookup finishes, and
    /// where no package manager is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

/// How `kub0d` is running. Additive on the hello frame; absent frames mean `User`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DaemonMode {
    #[default]
    User,
    System,
}

/// Additive `hello.account`. Absent frames deserialize as disconnected.
/// Never includes the account token. `github_username` is a public handle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountHello {
    pub connected: bool,
    pub node_name: String,
    #[serde(default)]
    pub github_username: String,
    pub last_heartbeat_ok: Option<bool>,
}

impl Default for AccountHello {
    fn default() -> Self {
        Self {
            connected: false,
            node_name: String::new(),
            github_username: String::new(),
            last_heartbeat_ok: None,
        }
    }
}

/// A Vallum endpoint from the account's tenant inventory. Credentials and
/// unrecognized API fields are never forwarded over local IPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FleetEndpoint {
    pub node_name: String,
    pub state: String,
    pub last_seen: String,
    pub agent_ver: String,
    pub blocks_active: Option<u64>,
    pub kernel_version: String,
    pub arch: String,
}

/// One org deny-list row. Extra API fields are ignored at parse time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DenylistEntry {
    /// What this policy is *for*, in the org's own words -- "Block crypto miners".
    ///
    /// The panel showed `comm || path` here until 2026-09-20, which is the rule's
    /// *matcher*: a fact about how it is implemented, and the one question an
    /// operator scanning a policy list is not asking. A rule with neither rendered
    /// as a bare `--`. Empty when the API sends no name, in which case
    /// [`DenylistEntry::label`] states what the rule does instead.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub comm: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub reason: String,
    /// Who promoted the row (`api`, `loop5-auto`, `vigiles-auto`, ...). Shown
    /// on an exec-gate deny so the owner knows whether a human chose it.
    #[serde(default)]
    pub promoted_by: String,
    /// When the row was created, as the API sent it (RFC 3339). A deny
    /// notification names this as the day kub0 detonated the sample.
    #[serde(default)]
    pub created_at: String,
}

impl DenylistEntry {
    /// The row's display name: the org's `name` when it sent one, else a sentence
    /// saying what the rule does.
    ///
    /// The fallback is deliberately a purpose ("Block xmrig") and not the bare
    /// matcher. It cannot reach the org's own intent -- only a human writing
    /// `name` upstream can say "crypto miners" -- but "Block xmrig" is a true
    /// statement about the rule, and a reader learns from it. `xmrig` alone is a
    /// string they have to already recognise.
    pub fn label(&self) -> String {
        let named = self.name.trim();
        if !named.is_empty() {
            return named.to_string();
        }
        let target = self.target();
        if target.is_empty() {
            // No matcher at all. Naming a verb here would claim the rule does
            // something to something, and we know neither half.
            return "Unnamed rule".to_string();
        }
        if self.action.trim().is_empty() {
            // The gate keys only on the literal `block`, so a row with no
            // action does nothing here. Saying "Block" would claim otherwise.
            return format!("{target} (action unset)");
        }
        format!("{} {target}", self.verb())
    }

    /// The matcher, for the secondary column that carries the implementation
    /// detail the name deliberately drops.
    pub fn matcher(&self) -> String {
        match (self.comm.trim(), self.path.trim()) {
            ("", "") => String::new(),
            (c, "") => c.to_string(),
            ("", p) => p.to_string(),
            (c, p) => format!("{c}  {p}"),
        }
    }

    /// `comm`, else the final component of `path`. A full path is a matcher, not
    /// a name: `/usr/local/bin/xmrig` in a heading elides to the useless half.
    fn target(&self) -> String {
        let comm = self.comm.trim();
        if !comm.is_empty() {
            return comm.to_string();
        }
        self.path
            .trim()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// The action as an English verb. An unrecognised action is echoed rather
    /// than normalised -- a policy whose action we do not model should read
    /// oddly, not read like one we do. The kub0 API accepts `block` and
    /// `monitor`; the exec gate keys only on `block`, so nothing else is
    /// folded into "Block" (an empty action is handled by `label`).
    fn verb(&self) -> String {
        let a = self.action.trim().to_ascii_lowercase();
        match a.as_str() {
            "block" => "Block".to_string(),
            "monitor" => "Monitor".to_string(),
            "warn" | "alert" => "Warn on".to_string(),
            "kill" | "terminate" => "Kill".to_string(),
            "log" | "audit" => "Log".to_string(),
            other => {
                let mut c = other.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "hello")]
    Hello {
        version: String,
        pid: u32,
        coverage: String,
        rdns: bool,
        /// `user` or `system`. Default `user` so historical frames still parse.
        #[serde(default)]
        mode: DaemonMode,
        /// Additive kub0 account snapshot. Never includes the token.
        #[serde(default)]
        account: AccountHello,
        /// Additive: this daemon answers `req`-tagged requests with `reply`
        /// frames (`daemon/src/control.rs`). A `kub0` CLI that greets a
        /// daemon without it says so instead of waiting out its timeout.
        #[serde(default)]
        requests: bool,
        /// Additive: this daemon honours `as_uid` on a request from root
        /// (`control::as_uid`). `kub0` sends `as_uid` only to a daemon that
        /// says so: an older one would ignore it and act as root.
        #[serde(default)]
        as_uid: bool,
    },
    /// One answer to one client's request (`daemon/src/control.rs`). Never
    /// broadcast: the server sends it to the client whose `req` it carries.
    #[serde(rename = "reply")]
    Reply(crate::control::Reply),
    #[serde(rename = "snapshot")]
    Snapshot {
        ts: u64,
        connections: Vec<Connection>,
    },
    #[serde(rename = "connect")]
    Connect {
        ts: u64,
        #[serde(flatten)]
        conn: Connection,
    },
    #[serde(rename = "bandwidth")]
    Bandwidth {
        ts: u64,
        apps: Vec<crate::traffic::AppTraffic>,
    },
    #[serde(rename = "capture-status")]
    CaptureStatus {
        ts: u64,
        #[serde(flatten)]
        status: crate::capture::Status,
    },
    #[serde(rename = "disconnect")]
    Disconnect { ts: u64, id: String },
    #[serde(rename = "tick")]
    Tick {
        ts: u64,
        count: usize,
        /// `/proc/<pid>/fd` directories opened on the last full inode scan.
        #[serde(default, rename = "scannedFdDirs")]
        scanned_fd_dirs: usize,
        /// `read_dir` failures on `/proc/<pid>/fd` during that scan.
        #[serde(default, rename = "unreadableFdDirs")]
        unreadable_fd_dirs: usize,
    },
    #[serde(rename = "digest")]
    Digest {
        ts: u64,
        #[serde(rename = "newNetworks")]
        new_networks: usize,
        keys: Vec<String>,
    },
    #[serde(rename = "status")]
    Status { message: String },
    /// Additive local timeline. Newest 300 on hello, then one-entry frames live.
    #[serde(rename = "activity")]
    Activity { entries: Vec<ActivityEntry> },
    /// Additive: every listening TCP socket and bound non-ephemeral UDP socket,
    /// sent on hello and whenever the set changes. procfs only.
    #[serde(rename = "listeners")]
    Listeners { ts: u64, listeners: Vec<Listener> },
    /// Additive: the user's watch rules, sent on hello and after any change.
    #[serde(rename = "watchlist")]
    Watchlist {
        ts: u64,
        rules: Vec<crate::watch::Rule>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        error: String,
    },
    /// Additive reply to `{"cmd":"timeline"}`: presence per app per bucket.
    #[serde(rename = "timeline")]
    Timeline {
        request: String,
        timeline: crate::intel::Timeline,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        error: String,
    },
    /// Additive reply to `{"cmd":"investigate"}`.
    #[serde(rename = "investigate")]
    Investigate {
        request: String,
        pivot: crate::intel::Pivot,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        error: String,
    },
    /// Additive kub0 fleet snapshot. After hello to each client, then after
    /// every heartbeat attempt. Never includes the account token.
    #[serde(rename = "fleet")]
    Fleet {
        ts: u64,
        connected: bool,
        #[serde(rename = "orgEndpoints")]
        org_endpoints: u64,
        #[serde(rename = "nodeLimit")]
        node_limit: u64,
        #[serde(rename = "selfState")]
        self_state: String,
        #[serde(rename = "lastHeartbeatOk")]
        last_heartbeat_ok: Option<bool>,
        #[serde(rename = "lastHeartbeatTs")]
        last_heartbeat_ts: u64,
        #[serde(rename = "denylistVersion")]
        denylist_version: u64,
        denylist: Vec<DenylistEntry>,
        #[serde(default)]
        endpoints: Vec<FleetEndpoint>,
        #[serde(default, rename = "endpointsUpdatedAt")]
        endpoints_updated_at: u64,
        #[serde(default, rename = "endpointsRefreshOk")]
        endpoints_refresh_ok: Option<bool>,
        /// Additive: false while the org network policy cannot be fetched and the last
        /// one received is still enforced.
        #[serde(default, rename = "netpolicyRefreshOk")]
        netpolicy_refresh_ok: Option<bool>,
        /// Additive: the org network policies this endpoint receives, with this run's
        /// local match counts. Empty when disconnected or the server has none.
        #[serde(default)]
        netpolicies: Vec<crate::netpolicy::PolicyView>,
        #[serde(default, rename = "netpolicyEnforcement")]
        netpolicy_enforcement: crate::netpolicy::Enforcement,
        /// Additive: how many other org endpoints reached each destination
        /// network, from the heartbeat. Empty unless sharing is on and the
        /// server answers (docs/INTEL.md).
        #[serde(default)]
        prevalence: Vec<crate::kub0::Prevalence>,
        /// Additive: whether the server answered prevalence on the last
        /// heartbeat; null until one succeeded.
        #[serde(default, rename = "prevalenceSupported")]
        prevalence_supported: Option<bool>,
        /// Additive: this daemon sends destination network keys on the heartbeat.
        #[serde(default, rename = "sharingDestinations")]
        sharing_destinations: bool,
        /// Additive: whether the deny-list stream is delivering (`true`), down
        /// with the poll as fallback (`false`), or not running (`null`).
        #[serde(default, rename = "denylistLive")]
        denylist_live: Option<bool>,
        /// Additive: the exec gate's state, counters, recent denies and local
        /// trust. Absent on an older daemon. Local only; the kub0 heartbeat
        /// does not carry it. In user mode this is a mirror of what the
        /// system daemon last wrote (`frame.source`).
        #[serde(default, rename = "execGate")]
        exec_gate: crate::execgate::ExecGateFrame,
    },
}

impl Event {
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self)
            .unwrap_or_else(|_| "{\"type\":\"status\",\"message\":\"encode-error\"}".into());
        line.push('\n');
        line
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn connection_id(proto: &str, inode: u64, remote_ip: &str, remote_port: u16) -> String {
    format!("{proto}:{inode}:{remote_ip}:{remote_port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, comm: &str, path: &str, action: &str) -> DenylistEntry {
        DenylistEntry {
            name: name.into(),
            comm: comm.into(),
            path: path.into(),
            action: action.into(),
            reason: String::new(),
            promoted_by: String::new(),
            created_at: String::new(),
        }
    }

    #[test]
    fn the_orgs_own_name_always_wins() {
        let e = entry("Block crypto miners", "xmrig", "/usr/bin/xmrig", "block");
        assert_eq!(e.label(), "Block crypto miners");
    }

    #[test]
    fn a_named_policy_is_trimmed_not_reformatted() {
        // Upstream owns the wording. We may strip whitespace; we may not
        // capitalize, truncate, or "improve" what an operator typed.
        assert_eq!(entry("  no outbound IRC  ", "", "", "").label(), "no outbound IRC");
    }

    #[test]
    fn an_unnamed_policy_says_what_it_does() {
        assert_eq!(entry("", "xmrig", "", "block").label(), "Block xmrig");
        assert_eq!(entry("", "xmrig", "", "monitor").label(), "Monitor xmrig");
        assert_eq!(entry("", "nc", "", "warn").label(), "Warn on nc");
        assert_eq!(entry("", "sshd", "", "kill").label(), "Kill sshd");
        assert_eq!(entry("", "curl", "", "audit").label(), "Log curl");
    }

    #[test]
    fn a_denylist_row_with_no_action_is_labelled_unset_not_block() {
        // The gate keys only on the literal `block`. Labelling an empty action
        // "Block" claimed an enforcement the row does not have.
        assert_eq!(entry("", "xmrig", "", "").label(), "xmrig (action unset)");
        assert_eq!(entry("", "", "/opt/x/tool", "  ").label(), "tool (action unset)");
    }

    #[test]
    fn an_unmodelled_action_is_echoed_not_normalised() {
        // It should read oddly. Mapping it onto a verb we do model would claim
        // the policy does something it may not. `deny` is one of those:
        // The kub0 API never emits it, and the gate does not key on it.
        assert_eq!(entry("", "xmrig", "", "quarantine").label(), "Quarantine xmrig");
        assert_eq!(entry("", "xmrig", "", "deny").label(), "Deny xmrig");
    }

    #[test]
    fn a_path_only_rule_is_named_by_its_final_component() {
        // The heading has one line; a full path elides to the useless half.
        assert_eq!(
            entry("", "", "/usr/local/bin/xmrig", "block").label(),
            "Block xmrig"
        );
        assert_eq!(entry("", "", "/opt/tools/", "block").label(), "Block tools");
    }

    #[test]
    fn a_rule_with_no_matcher_at_all_is_not_given_an_invented_verb() {
        // This is the row that used to render as a bare "--". We know neither
        // what it acts on nor, therefore, that any verb is true of it.
        assert_eq!(entry("", "", "", "block").label(), "Unnamed rule");
        assert_eq!(entry("", "  ", " ", "").label(), "Unnamed rule");
    }

    #[test]
    fn the_matcher_stays_available_as_secondary_detail() {
        // Naming the policy by purpose must not DELETE the implementation fact --
        // an operator asking "what does this actually catch" still needs it.
        assert_eq!(entry("n", "xmrig", "", "").matcher(), "xmrig");
        assert_eq!(entry("n", "", "/usr/bin/nc", "").matcher(), "/usr/bin/nc");
        assert_eq!(entry("n", "nc", "/usr/bin/nc", "").matcher(), "nc  /usr/bin/nc");
        assert_eq!(entry("n", "", "", "").matcher(), "");
    }

    #[test]
    fn replay_fixture_parses() {
        let text = include_str!("../../tests/fixtures/replay.ndjson");
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let ev: Event = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("bad replay line {line}: {e}"));
            n += 1;
            let _ = ev;
        }
        assert!(n >= 10);
    }

    #[test]
    fn connect_without_uid_reason_still_parses() {
        let line = r#"{"type":"connect","ts":1,"id":"tcp:1:1.2.3.4:443","proto":"tcp","inode":1,"app":{"id":"x","name":"x","icon":"x","desktop":"","pid":1,"system":false},"local":{"ip":"10.0.0.1","port":1},"remote":{"ip":"1.2.3.4","port":443},"state":"ESTABLISHED"}"#;
        let ev: Event = serde_json::from_str(line).unwrap();
        match ev {
            Event::Connect { conn, .. } => {
                assert_eq!(conn.uid, None);
                assert_eq!(conn.reason, "");
                assert_eq!(conn.tag, None);
                let out = Event::Connect {
                    ts: 1,
                    conn: conn.clone(),
                }
                .to_line();
                assert!(
                    !out.contains("\"tag\""),
                    "absent tag must not appear on the wire: {out}"
                );
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hello_roundtrip_line() {
        let ev = Event::Hello {
            requests: true,
            as_uid: true,
            version: "1.0.0".into(),
            pid: 7,
            coverage: "tcp+connected-udp".into(),
            rdns: false,
            mode: DaemonMode::User,
            account: AccountHello::default(),
        };
        let line = ev.to_line();
        assert!(line.ends_with('\n'));
        let parsed: Event = serde_json::from_str(line.trim()).unwrap();
        match parsed {
            Event::Hello {
                requests: true,
                version,
                rdns,
                mode,
                ..
            } => {
                assert_eq!(version, "1.0.0");
                assert!(!rdns);
                assert_eq!(mode, DaemonMode::User);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hello_serializes_mode_user_and_system() {
        let user = Event::Hello {
            requests: true,
            as_uid: true,
            version: "0.1.0".into(),
            pid: 1,
            coverage: "tcp+connected-udp".into(),
            rdns: false,
            mode: DaemonMode::User,
            account: AccountHello::default(),
        };
        let system = Event::Hello {
            requests: true,
            as_uid: true,
            version: "0.1.0".into(),
            pid: 1,
            coverage: "tcp+connected-udp".into(),
            rdns: false,
            mode: DaemonMode::System,
            account: AccountHello {
                connected: true,
                node_name: "n1".into(),
                github_username: "alice".into(),
                last_heartbeat_ok: Some(true),
            },
        };
        let user_line = user.to_line();
        let system_line = system.to_line();
        assert!(user_line.contains(r#""mode":"user""#), "{user_line}");
        assert!(system_line.contains(r#""mode":"system""#), "{system_line}");
        let legacy = r#"{"type":"hello","version":"1.0.0","pid":1,"coverage":"tcp+connected-udp","rdns":false}"#;
        let parsed: Event = serde_json::from_str(legacy).unwrap();
        match parsed {
            Event::Hello { mode, account, .. } => {
                assert_eq!(mode, DaemonMode::User);
                assert!(!account.connected);
                assert_eq!(account.last_heartbeat_ok, None);
            }
            _ => panic!("wrong variant"),
        }
        assert!(
            system_line.contains(
                r#""account":{"connected":true,"node_name":"n1","github_username":"alice","last_heartbeat_ok":true}"#
            ),
            "{system_line}"
        );
    }

    #[test]
    fn fleet_frame_is_additive_camel_case() {
        let ev = Event::Fleet {
            ts: 9,
            connected: true,
            org_endpoints: 2,
            node_limit: 10,
            self_state: "monitored".into(),
            last_heartbeat_ok: Some(true),
            last_heartbeat_ts: 8,
            denylist_version: 3,
            denylist: vec![DenylistEntry {
                name: "Block outbound curl".into(),
                comm: "curl".into(),
                path: "/usr/bin/curl".into(),
                action: "block".into(),
                reason: "policy".into(),
                promoted_by: "api".into(),
                created_at: "2026-10-01T00:00:00Z".into(),
            }],
            endpoints: Vec::new(),
            endpoints_updated_at: 0,
            endpoints_refresh_ok: None,
            netpolicy_refresh_ok: Some(false),
            netpolicies: Vec::new(),
            netpolicy_enforcement: Default::default(),
            prevalence: Vec::new(),
            prevalence_supported: None,
            sharing_destinations: false,
            denylist_live: Some(true),
            exec_gate: crate::execgate::ExecGateFrame {
                enabled: true,
                armed: true,
                keys: 7,
                source: "live".into(),
                counters: crate::execgate::ExecGateCounters {
                    blocked: 1,
                    marks: 2,
                    cache_hit: 4,
                    overflow: 3,
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let line = ev.to_line();
        assert!(line.starts_with(r#"{"type":"fleet","#), "{line}");
        assert!(line.contains(r#""orgEndpoints":2"#), "{line}");
        assert!(line.contains(r#""nodeLimit":10"#), "{line}");
        assert!(line.contains(r#""selfState":"monitored""#), "{line}");
        assert!(line.contains(r#""lastHeartbeatOk":true"#), "{line}");
        assert!(line.contains(r#""lastHeartbeatTs":8"#), "{line}");
        assert!(line.contains(r#""denylistVersion":3"#), "{line}");
        assert!(line.contains(r#""netpolicyRefreshOk":false"#), "{line}");
        assert!(line.contains(r#""denylistLive":true"#), "{line}");
        assert!(line.contains(r#""promoted_by":"api""#), "{line}");
        assert!(line.contains(r#""execGate":{"#), "{line}");
        assert!(line.contains(r#""counters":{"#), "{line}");
        assert!(line.contains(r#""cacheHit":4"#), "{line}");
        assert!(line.contains(r#""blocked":1"#), "{line}");
        assert!(line.contains(r#""overCap":0"#), "{line}");
        assert!(line.contains(r#""overflow":3"#), "{line}");
        assert!(line.contains(r#""denies":[]"#), "{line}");
        assert!(line.contains(r#""trusted":[]"#), "{line}");
        let parsed: Event = serde_json::from_str(line.trim()).unwrap();
        match parsed {
            Event::Fleet {
                org_endpoints,
                self_state,
                denylist,
                exec_gate,
                denylist_live,
                ..
            } => {
                assert_eq!(org_endpoints, 2);
                assert_eq!(self_state, "monitored");
                assert_eq!(denylist.len(), 1);
                assert_eq!(denylist[0].comm, "curl");
                assert_eq!(denylist[0].promoted_by, "api");
                assert_eq!(denylist_live, Some(true));
                assert!(exec_gate.enabled);
                assert!(exec_gate.armed);
                assert_eq!(exec_gate.keys, 7);
                assert_eq!(exec_gate.counters.marks, 2);
                assert_eq!(exec_gate.counters.cache_hit, 4);
                assert_eq!(exec_gate.counters.blocked, 1);
                assert_eq!(exec_gate.counters.overflow, 3);
            }
            _ => panic!("wrong variant"),
        }
        // An older daemon's frame has no execGate. It still parses.
        let mut legacy: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        legacy.as_object_mut().unwrap().remove("execGate");
        legacy.as_object_mut().unwrap().remove("denylistLive");
        match serde_json::from_value::<Event>(legacy).unwrap() {
            Event::Fleet { exec_gate, denylist_live, .. } => {
                assert_eq!(exec_gate, crate::execgate::ExecGateFrame::default());
                assert_eq!(denylist_live, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn activity_frame_is_additive() {
        let ev = Event::Activity {
            entries: vec![crate::activity::ActivityEntry::new(
                9,
                crate::activity::ActivityKind::HeartbeatFailed,
                None,
                serde_json::json!({ "ok": false }),
            )],
        };
        let line = ev.to_line();
        assert!(line.starts_with(r#"{"type":"activity","entries":["#), "{line}");
        let parsed: Event = serde_json::from_str(line.trim()).unwrap();
        match parsed {
            Event::Activity { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].kind, crate::activity::ActivityKind::HeartbeatFailed);
            }
            _ => panic!("wrong variant"),
        }
    }
}
