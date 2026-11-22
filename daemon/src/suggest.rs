//! Turning an unattributed socket into something a person can actually name.
//!
//! When the owner scan fails, vallum currently hands the user a row like
//! `45.159.97.144:443` and a `reason` of `"unreadable"`. That is not a clue, it
//! is a shrug. But the daemon already carries most of an answer on the same
//! row and throws it away:
//!
//! ```text
//! uid   971          -> /etc/passwd says "alpm", Arch's package manager
//! PTR   derp15c.…    -> a Tailscale relay, not a destination the user chose
//! port  53           -> a resolver
//! range 100.64/10     -> the user's own tailnet
//! ```
//!
//! Measured on one live desktop (457 unattributed rows, 351 distinct remote
//! IPs), those four pieces of evidence name **68%** of the backlog with no
//! model, no server and no user input. The largest single bucket -- 171 rows,
//! 37% -- was tailscaled probing the DERP relay mesh, which looks like
//! hundreds of unrelated public IPs and is really one daemon doing one thing.
//!
//! 🔑 The ladder runs *lookup* before *inference* on purpose. A uid resolving
//! to a system account and a PTR resolving to a known service are facts; only
//! the bottom rungs are guesses. Keeping them in separate confidence tiers is
//! what lets the UI auto-apply the top and ask about the rest, instead of
//! presenting a fact and a hunch in the same typeface.

use std::collections::HashMap;
use std::net::IpAddr;

/// How much the clue is worth. The tiers are a claim about *provenance*, not
/// about how plausible the label sounds: `Certain` means something looked the
/// answer up, `Weak` means something inferred it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A lookup in a local authority -- /etc/passwd, the loopback range.
    /// Safe to apply without asking.
    Certain,
    /// A PTR record that matches a service we recognise. The DNS answer is
    /// attacker-influenceable in principle, so it names but does not authorise.
    Strong,
    /// An inference from port, address range, or the user's own history.
    /// Always a suggestion, never an answer.
    Weak,
}

/// What *kind* of thing the label names. The distinction that matters is
/// `Service` vs `Hosting`: `linodeusercontent.com` is a truthful PTR that
/// tells you where a box lives and nothing about whose box it is, and
/// presenting that as an identity is how a naming feature starts lying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A local account owns it -- the strongest answer available.
    SystemService,
    /// Named infrastructure the user is running, not a destination they chose.
    Relay,
    /// A resolver.
    Resolver,
    /// A recognised product or network.
    Service,
    /// A hosting provider. Says where, not who.
    Hosting,
    /// This machine, or the LAN.
    Local,
    /// The user's own tailnet.
    Tailnet,
}

/// One nameable answer about one unattributed connection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Clue {
    /// What to show as the name.
    pub label: String,
    /// The evidence, in the user's words, so the guess can be audited rather
    /// than trusted. This is the "clue" half of the feature: a user who
    /// disagrees needs to see *why* before they can correct it.
    pub basis: String,
    pub confidence: Confidence,
    pub kind: Kind,
}

/// Everything known about one unattributed socket at decision time.
///
/// Deliberately plain data with no I/O: the passwd read and the DNS lookup
/// happen in the caller, so the ladder itself is a pure function and its
/// behaviour is pinned by tests rather than by whatever the host resolver
/// happened to answer.
pub struct Evidence<'a> {
    pub uid: Option<u32>,
    /// Highest uid the distribution reserves for system accounts, from
    /// `/etc/login.defs`. Above it sit human logins, which own most of a
    /// desktop and therefore name nothing; see [`clue`].
    pub sys_uid_max: u32,
    /// Resolved account name for `uid`, if it is in the passwd database.
    pub account: Option<&'a Account>,
    /// PTR for the remote address. Empty when absent or not looked up.
    pub hostname: &'a str,
    pub remote: IpAddr,
    pub port: u16,
    /// The kernel routing table. Empty is valid and simply means the route
    /// rungs decline -- see [`clue`].
    pub routes: &'a [crate::routes::Route],
}

/// A passwd entry, reduced to the two fields worth showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    /// The GECOS description -- "Arch Linux Package Management" reads better to
    /// a human than "alpm" does, and both are already on the machine.
    pub gecos: String,
}

impl Account {
    /// "alpm (Arch Linux Package Management)", or just "alpm" when the passwd
    /// entry has no description.
    fn display(&self) -> String {
        if self.gecos.is_empty() || self.gecos == self.name {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.gecos)
        }
    }
}

/// PTR suffix -> what that suffix actually tells us.
///
/// Longest match wins, so `derp15c.tailscale.com` and a hypothetical
/// `login.tailscale.com` can diverge later without reordering the table.
const SUFFIXES: &[(&str, &str, Kind)] = &[
    // Tailscale's DERP mesh is the single largest source of unattributed
    // public IPs on a tailnet-joined desktop: tailscaled latency-probes every
    // relay region on startup and periodically after, so one daemon produces
    // hundreds of distinct destinations across a dozen countries. Naming it is
    // the difference between "37% of your unknowns" and one line.
    ("tailscale.com", "Tailscale relay", Kind::Relay),
    ("1e100.net", "Google", Kind::Service),
    ("archlinux.org", "Arch Linux", Kind::Service),
    ("cloudflare.com", "Cloudflare", Kind::Service),
    ("quad9.net", "Quad9 DNS", Kind::Resolver),
    ("one.one", "Cloudflare DNS", Kind::Resolver),
    ("dns.google", "Google DNS", Kind::Resolver),
    // Below here the PTR names the landlord, not the tenant. Kept because
    // "a machine at Hetzner" beats a bare IP, marked Hosting because it is
    // not an identity and the UI must not let the user tag it as one.
    ("amazonaws.com", "Amazon Web Services", Kind::Hosting),
    ("linodeusercontent.com", "Linode", Kind::Hosting),
    ("vultrusercontent.com", "Vultr", Kind::Hosting),
    ("your-server.de", "Hetzner", Kind::Hosting),
    ("digitalocean.com", "DigitalOcean", Kind::Hosting),
];

/// Tailscale and every other CGNAT user share 100.64/10, so this range is
/// evidence and not proof -- an ISP behind carrier-grade NAT hands out the
/// same addresses. That is why it mints `Weak` and says "looks like".
fn is_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]),
        IpAddr::V6(_) => false,
    }
}

/// Walk the ladder and return the best available answer, or `None` when the
/// only honest response is "unknown".
///
/// Order is load-bearing. A local account beats a PTR because the account says
/// *who* and the PTR says *where*: uid 971 hitting `static.…your-server.de` is
/// pacman fetching from a Hetzner-hosted mirror, and "Arch package manager" is
/// the useful half. The exception is the uids that name nothing -- root, and
/// every human login -- which fall through to the PTR. That fall-through is
/// what rescues the 171 tailscaled rows, all of which are uid 0.
pub fn clue(ev: &Evidence) -> Option<Clue> {
    if ev.remote.is_loopback() {
        return Some(Clue {
            label: "This machine".into(),
            basis: format!("{} is loopback", ev.remote),
            confidence: Confidence::Certain,
            kind: Kind::Local,
        });
    }

    // The routing table is a local authority about the *peer*, and it outranks
    // the local account because the clue names who the connection is with --
    // the row shows the owning process separately. Scoped to internal address
    // ranges on purpose: a split-tunnel VPN installs 0.0.0.0/1 on-link, and
    // without that scope every public address on the internet would be named
    // "a device on your network" at Certain, which is the exact failure the
    // Certain tier exists to prevent.
    if is_internal(ev.remote) {
        if let Some(c) = route_clue(ev) {
            return Some(c);
        }
    }

    // A dedicated service account is the strongest signal on the row: the
    // kernel recorded it, nothing on the network can influence it, and it
    // survives when DNS is unavailable.
    if let (Some(uid), Some(acct)) = (ev.uid, ev.account) {
        if uid != 0 && uid <= ev.sys_uid_max {
            return Some(Clue {
                label: acct.display(),
                basis: format!("runs as uid {uid} ({})", acct.name),
                confidence: Confidence::Certain,
                kind: Kind::SystemService,
            });
        }
    }

    if !ev.hostname.is_empty() {
        let host = ev.hostname.trim_end_matches('.').to_ascii_lowercase();
        if let Some((suffix, label, kind)) = best_suffix(&host) {
            return Some(Clue {
                label: label.to_string(),
                basis: format!("{host} resolves under {suffix}"),
                confidence: Confidence::Strong,
                kind,
            });
        }
        // An unrecognised PTR is still a name, and a name the user can read is
        // most of what they need to tag it themselves.
        return Some(Clue {
            label: registrable(&host),
            basis: format!("reverse DNS says {host}"),
            confidence: Confidence::Strong,
            kind: Kind::Service,
        });
    }

    if is_cgnat(ev.remote) {
        return Some(Clue {
            label: "Your tailnet".into(),
            basis: format!("{} looks like a tailnet address (100.64/10)", ev.remote),
            confidence: Confidence::Weak,
            kind: Kind::Tailnet,
        });
    }

    if crate::geo::is_private(ev.remote) {
        // Reached only when no route matched. A private address we have no
        // route to is genuinely not ours to claim, so the label says what is
        // actually known -- that the address is private -- and not that the
        // machine is on this user's network.
        return Some(Clue {
            label: "Private network".into(),
            basis: format!("{} is a private address, but no route on this host covers it", ev.remote),
            confidence: Confidence::Weak,
            kind: Kind::Local,
        });
    }

    // Port is the weakest rung and only 53 is worth a label -- 443 and 80 name
    // a protocol, not a peer, and "HTTPS" as an identity is noise dressed as
    // an answer.
    if ev.port == 53 {
        return Some(Clue {
            label: "DNS resolver".into(),
            basis: "talks to port 53".into(),
            confidence: Confidence::Weak,
            kind: Kind::Resolver,
        });
    }

    None
}

/// Address ranges where "who is this?" is a question about the user's own
/// network rather than about the internet: RFC 1918, RFC 6598 CGNAT (which is
/// what a tailnet uses), and link-local.
fn is_internal(ip: IpAddr) -> bool {
    is_cgnat(ip) || crate::geo::is_private(ip)
}

/// Interfaces whose on-link peers are mesh members rather than LAN devices.
/// Naming these is the rung that finally calls a cluster node a cluster node.
const MESH_IFACES: &[&str] = &["tailscale0", "nebula0"];

/// Name a peer from the routing table, or decline.
///
/// Certain throughout: every answer here comes from a table the kernel wrote,
/// which is the same provenance as the passwd lookup above it.
fn route_clue(ev: &Evidence) -> Option<Clue> {
    if let Some((route, gw)) = crate::routes::default_gateway(ev.routes) {
        if gw == ev.remote {
            return Some(refine(
                Clue {
                    label: "Your router".into(),
                    basis: format!("{gw} is this machine's default gateway via {}", route.iface),
                    confidence: Confidence::Certain,
                    kind: Kind::Local,
                },
                ev.port,
            ));
        }
    }

    let hit = crate::routes::on_link_for(ev.routes, ev.remote)?;
    let mesh = MESH_IFACES.contains(&hit.iface.as_str());
    Some(refine(
        Clue {
            label: if mesh {
                "On your tailnet".into()
            } else {
                "Device on your network".into()
            },
            basis: format!(
                "{} is on {}, reachable directly via {}",
                ev.remote, hit.dest, hit.iface
            ),
            confidence: Confidence::Certain,
            kind: if mesh { Kind::Tailnet } else { Kind::Local },
        },
        ev.port,
    ))
}

/// Sharpen a label the route table already earned with what the port says.
///
/// Port never mints a clue here -- only refines one. On its own "443" names a
/// protocol, not a peer, and the existing port-53 rung at the bottom of the
/// ladder is deliberately the weakest thing in the file.
fn refine(mut c: Clue, port: u16) -> Clue {
    let what = match port {
        53 => "DNS",
        67 | 68 => "DHCP",
        22 => "SSH",
        139 | 445 => "file sharing",
        631 => "printing",
        _ => return c,
    };
    c.label = format!("{} ({what})", c.label);
    c
}

/// Longest matching suffix, so a more specific entry always beats a broader
/// one regardless of table order.
fn best_suffix(host: &str) -> Option<(&'static str, &'static str, Kind)> {
    SUFFIXES
        .iter()
        .filter(|(suffix, _, _)| {
            host == *suffix || host.ends_with(&format!(".{suffix}"))
        })
        .max_by_key(|(suffix, _, _)| suffix.len())
        .map(|(suffix, label, kind)| (*suffix, *label, *kind))
}

/// The hosting provider a PTR names, if the suffix table marks it as one.
/// Exposed for the indicator engine, which says "where, not who" about it.
pub fn hosting_ptr(host: &str) -> Option<&'static str> {
    if host.is_empty() {
        return None;
    }
    match best_suffix(host) {
        Some((_, label, Kind::Hosting)) => Some(label),
        _ => None,
    }
}

/// Last two labels of a hostname -- enough to recognise an unlisted service
/// without showing the user `static.32.28.180.157.clients.your-server.de`.
fn registrable(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

/// uid -> account, read once from the local passwd database.
///
/// Parsed directly rather than shelling out to `getent passwd`: this runs in
/// the poll loop, the file is small, and a subprocess per unattributed socket
/// is exactly the kind of cost that gets a clue engine turned back off.
#[derive(Default)]
pub struct Accounts(HashMap<u32, Account>);

impl Accounts {
    pub fn load() -> Self {
        Self::parse(&std::fs::read_to_string("/etc/passwd").unwrap_or_default())
    }

    pub fn parse(passwd: &str) -> Self {
        let mut map = HashMap::new();
        for line in passwd.lines() {
            // name:passwd:uid:gid:gecos:home:shell
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 5 {
                continue;
            }
            let Ok(uid) = f[2].parse::<u32>() else {
                continue;
            };
            map.entry(uid).or_insert_with(|| Account {
                name: f[0].to_string(),
                // GECOS is comma-separated; only the first field is the name.
                gecos: f[4].split(',').next().unwrap_or("").trim().to_string(),
            });
        }
        Self(map)
    }

    pub fn get(&self, uid: u32) -> Option<&Account> {
        self.0.get(&uid)
    }
}

/// Fallback when `/etc/login.defs` is absent or silent. 999 is the value
/// shipped by Arch, Debian and Fedora alike, so the default is the answer on
/// almost every host that lacks the file.
pub const DEFAULT_SYS_UID_MAX: u32 = 999;

/// Read `SYS_UID_MAX` from the local login policy.
///
/// Asking the distribution where it draws the system/human line beats
/// hardcoding 1000: it is a local authority, it is one file, and it keeps the
/// `Certain` tier honest on a host that draws the line somewhere else.
pub fn sys_uid_max() -> u32 {
    parse_sys_uid_max(&std::fs::read_to_string("/etc/login.defs").unwrap_or_default())
}

pub fn parse_sys_uid_max(login_defs: &str) -> u32 {
    login_def(login_defs, "SYS_UID_MAX").unwrap_or(DEFAULT_SYS_UID_MAX)
}

/// Fallback when `/etc/login.defs` is absent or silent on `UID_MIN`: the
/// first human login on Arch, Debian and Fedora alike.
pub const DEFAULT_UID_MIN: u32 = 1000;

/// Read `UID_MIN` from the local login policy: the lowest uid the
/// distribution hands to a person. The system daemon names the apps of
/// every uid from here up (`identity::AppResolver`); below it sit the
/// service accounts, which stay `system`.
pub fn uid_min() -> u32 {
    parse_uid_min(&std::fs::read_to_string("/etc/login.defs").unwrap_or_default())
}

pub fn parse_uid_min(login_defs: &str) -> u32 {
    login_def(login_defs, "UID_MIN").unwrap_or(DEFAULT_UID_MIN)
}

/// One numeric key of `login.defs`, or `None` when the file does not set it.
fn login_def(login_defs: &str, key: &str) -> Option<u32> {
    login_defs
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let rest = l.strip_prefix(key)?;
            // The key must be followed by whitespace, or `SYS_UID_MAXIMUM`
            // would match and be read as a different setting.
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            rest.trim().parse::<u32>().ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0::/root:/bin/bash\n\
                          alice:x:1000:1000::/home/alice:/bin/bash\n\
                          alpm:x:971:971:Arch Linux Package Management:/:/usr/bin/nologin\n\
                          clamav:x:64:64:Clam AntiVirus:/:/usr/bin/nologin\n\
                          systemd-resolve:x:975:975:systemd Resolver:/:/usr/bin/nologin\n";

    fn ev<'a>(
        uid: u32,
        account: Option<&'a Account>,
        hostname: &'a str,
        remote: &str,
        port: u16,
    ) -> Evidence<'a> {
        Evidence {
            uid: Some(uid),
            sys_uid_max: DEFAULT_SYS_UID_MAX,
            account,
            hostname,
            remote: remote.parse().unwrap(),
            port,
            routes: &[],
        }
    }

    #[test]
    fn a_service_account_names_the_connection_outright() {
        let accts = Accounts::parse(PASSWD);
        let c = clue(&ev(971, accts.get(971), "", "157.180.28.32", 443)).unwrap();
        assert_eq!(c.label, "alpm (Arch Linux Package Management)");
        assert_eq!(c.confidence, Confidence::Certain);
        assert_eq!(c.kind, Kind::SystemService);
    }

    // The whole point of the ordering: pacman fetching from a Hetzner-hosted
    // mirror must read as the package manager, not as Hetzner. The PTR is
    // true and answers a question nobody asked.
    #[test]
    fn a_service_account_beats_a_hosting_ptr() {
        let accts = Accounts::parse(PASSWD);
        let c = clue(&ev(
            971,
            accts.get(971),
            "static.32.28.180.157.clients.your-server.de",
            "157.180.28.32",
            443,
        ))
        .unwrap();
        assert_eq!(c.label, "alpm (Arch Linux Package Management)");
    }

    // root and the login user own most of the machine, so neither is a name.
    // Falling through to the PTR is what rescues the 171 tailscaled rows.
    #[test]
    fn root_falls_through_to_the_ptr() {
        let accts = Accounts::parse(PASSWD);
        let c = clue(&ev(0, accts.get(0), "derp15c.tailscale.com", "102.67.165.185", 443)).unwrap();
        assert_eq!(c.label, "Tailscale relay");
        assert_eq!(c.kind, Kind::Relay);
        assert_eq!(c.confidence, Confidence::Strong);
    }

    #[test]
    fn a_human_login_never_mints_a_certain_clue() {
        let accts = Accounts::parse(PASSWD);
        let c = clue(&ev(1000, accts.get(1000), "", "8.8.8.8", 443));
        assert!(
            c.is_none(),
            "uid 1000 owns most of the desktop; naming a connection after it says nothing"
        );
    }

    // The boundary comes from the host's own policy, not from a constant in
    // this file. A distribution that reserves uids up to 499 must not have its
    // uid 700 human account reported as a system service.
    #[test]
    fn the_system_boundary_comes_from_login_defs() {
        assert_eq!(parse_sys_uid_max("SYS_UID_MAX 499\n"), 499);
        assert_eq!(parse_sys_uid_max("# SYS_UID_MAX 111\nSYS_UID_MAX\t42\n"), 42);
        assert_eq!(
            parse_sys_uid_max("SYS_UID_MAXIMUM 4\n"),
            DEFAULT_SYS_UID_MAX,
            "a longer key that merely starts with SYS_UID_MAX is a different setting"
        );
        assert_eq!(parse_sys_uid_max(""), DEFAULT_SYS_UID_MAX);
        // The human floor, read the same way; `SYS_UID_MIN` is a different key.
        assert_eq!(parse_uid_min("SYS_UID_MIN 500\nUID_MIN\t2000\n"), 2000);
        assert_eq!(parse_uid_min("# UID_MIN 5\n"), DEFAULT_UID_MIN);
        assert_eq!(parse_uid_min(""), DEFAULT_UID_MIN);

        let accts = Accounts::parse("svc:x:700:700:Some Daemon:/:/bin/false\n");
        let strict = Evidence {
            uid: Some(700),
            sys_uid_max: 499,
            account: accts.get(700),
            hostname: "",
            remote: "203.0.113.4".parse().unwrap(),
            port: 443,
            routes: &[],
        };
        assert!(clue(&strict).is_none(), "700 is a human login when SYS_UID_MAX is 499");
    }

    #[test]
    fn an_unlisted_ptr_still_yields_a_readable_name() {
        let c = clue(&ev(0, None, "edge-star-mini.example.net", "203.0.113.9", 443)).unwrap();
        assert_eq!(c.label, "example.net");
        assert_eq!(c.confidence, Confidence::Strong);
    }

    // A hosting PTR names the landlord. It must not arrive wearing the same
    // Kind as a real service, or the UI will offer it as an identity to tag.
    #[test]
    fn hosting_is_not_reported_as_a_service() {
        let c = clue(&ev(0, None, "192-73-242-1.linodeusercontent.com", "192.73.242.1", 443))
            .unwrap();
        assert_eq!(c.label, "Linode");
        assert_eq!(c.kind, Kind::Hosting);
    }

    #[test]
    fn loopback_is_certain_without_any_lookup() {
        let c = clue(&ev(0, None, "", "127.0.0.53", 53)).unwrap();
        assert_eq!(c.confidence, Confidence::Certain);
        assert_eq!(c.kind, Kind::Local);
    }

    // 100.64/10 is shared with carrier-grade NAT, so it can only ever be a
    // hint. Minting Certain here would auto-apply "Your tailnet" to an ISP.
    #[test]
    fn cgnat_is_a_hint_and_never_certain() {
        let inside = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 7));
        let c = clue(&Evidence { remote: inside, ..ev(0, None, "", "203.0.113.4", 80) }).unwrap();
        assert_eq!(c.label, "Your tailnet");
        assert_eq!(c.confidence, Confidence::Weak);

        // The boundaries are the whole claim, so assert them as octets rather
        // than as host literals: 100.64 and 100.127 are in, 100.63 and 100.128
        // are ordinary public space on either side.
        for (a, b, want) in [
            (100, 64, true),
            (100, 127, true),
            (100, 63, false),
            (100, 128, false),
            (99, 64, false),
        ] {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(a, b, 0, 1));
            assert_eq!(is_cgnat(ip), want, "{ip} should be cgnat={want}");
        }
    }

    #[test]
    fn a_bare_port_443_with_no_other_evidence_stays_unknown() {
        assert!(
            clue(&ev(0, None, "", "203.0.113.4", 443)).is_none(),
            "port 443 names a protocol, not a peer"
        );
    }

    #[test]
    fn port_53_is_the_only_port_worth_a_label() {
        let c = clue(&ev(0, None, "", "203.0.113.4", 53)).unwrap();
        assert_eq!(c.kind, Kind::Resolver);
        assert_eq!(c.confidence, Confidence::Weak);
    }

    #[test]
    fn longest_suffix_wins_regardless_of_table_order() {
        let (suffix, _, _) = best_suffix("derp15c.tailscale.com").unwrap();
        assert_eq!(suffix, "tailscale.com");
        assert!(best_suffix("nottailscale.com").is_none());
        assert!(
            best_suffix("tailscale.com.evil.test").is_none(),
            "a suffix must anchor at the end, not appear anywhere in the name"
        );
    }

    #[test]
    fn gecos_is_truncated_at_the_first_comma() {
        let a = Accounts::parse("svc:x:900:900:Real Name,room,work,home:/:/bin/false\n");
        assert_eq!(a.get(900).unwrap().gecos, "Real Name");
    }

    #[test]
    fn an_account_with_no_description_shows_just_the_name() {
        let accts = Accounts::parse(PASSWD);
        let c = clue(&ev(64, accts.get(64), "", "203.0.113.4", 443)).unwrap();
        assert_eq!(c.label, "clamav (Clam AntiVirus)");
        let bare = Accounts::parse("svc:x:900:900::/:/bin/false\n");
        assert_eq!(bare.get(900).unwrap().display(), "svc");
    }

    #[test]
    fn a_malformed_passwd_line_is_skipped_not_fatal() {
        let a = Accounts::parse("broken\n:::\nok:x:42:42:Fine:/:/bin/sh\n");
        assert!(a.get(42).is_some());
    }

    // --- the routing table as a local authority -------------------------

    /// A laptop on 10.20.0.0/24 via wlp1s0 with the mesh overlay up.
    fn fixture_routes() -> Vec<crate::routes::Route> {
        crate::routes::parse_v4(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
             wlp1s0\t00000000\t0100140A\t0003\t0\t0\t600\t00000000\n\
             wlp1s0\t0000140A\t00000000\t0001\t0\t0\t600\t00FFFFFF\n\
             nebula0\t0000630A\t00000000\t0001\t0\t0\t0\t0000FFFF\n",
        )
    }

    fn route_ev<'a>(remote: &str, port: u16, routes: &'a [crate::routes::Route]) -> Evidence<'a> {
        Evidence {
            uid: Some(0),
            sys_uid_max: DEFAULT_SYS_UID_MAX,
            account: None,
            hostname: "",
            remote: remote.parse().unwrap(),
            port,
            routes,
        }
    }

    #[test]
    fn the_default_gateway_is_named_certain() {
        let r = fixture_routes();
        let c = clue(&route_ev("10.20.0.1", 67, &r)).unwrap();
        assert_eq!(c.label, "Your router (DHCP)");
        assert_eq!(c.confidence, Confidence::Certain);
        assert_eq!(c.kind, Kind::Local);
        assert!(c.basis.contains("wlp1s0"), "basis names the interface: {}", c.basis);
    }

    #[test]
    fn a_same_subnet_host_is_certain_and_names_its_interface() {
        let r = fixture_routes();
        let c = clue(&route_ev("10.20.0.48", 22, &r)).unwrap();
        assert_eq!(c.label, "Device on your network (SSH)");
        assert_eq!(c.confidence, Confidence::Certain);
        assert!(c.basis.contains("wlp1s0"));
    }

    #[test]
    fn a_mesh_interface_route_yields_kind_tailnet() {
        // nebula0 rather than tailscale0: both are in MESH_IFACES and take the
        // same branch, and a CGNAT literal has no business in a public repo.
        let r = fixture_routes();
        let c = clue(&route_ev("10.99.1.5", 443, &r)).unwrap();
        assert_eq!(c.label, "On your tailnet");
        assert_eq!(c.kind, Kind::Tailnet);
        assert_eq!(c.confidence, Confidence::Certain);
    }

    #[test]
    fn a_private_address_with_no_matching_route_stays_weak() {
        let r = fixture_routes();
        // 192.168.x is private but this host has no route to it.
        let c = clue(&route_ev("192.168.1.10", 445, &r)).unwrap();
        assert_eq!(c.confidence, Confidence::Weak, "never Certain without a route");
        assert_eq!(c.label, "Private network");
    }

    #[test]
    fn an_empty_route_table_declines_rather_than_guessing() {
        let c = clue(&route_ev("10.20.0.48", 22, &[])).unwrap();
        assert_eq!(c.confidence, Confidence::Weak);
        assert_eq!(c.label, "Private network");
    }

    #[test]
    fn a_public_address_is_never_named_from_the_route_table() {
        // The guard that matters: a split-tunnel VPN installs 0.0.0.0/1
        // on-link, and a public peer must never come back Certain because of
        // it. 8.8.8.8 is inside the default route and outside every internal
        // range, so the route rungs must not even be consulted.
        let mut r = fixture_routes();
        r.push(crate::routes::Route {
            iface: "tun0".into(),
            dest: "0.0.0.0".parse().unwrap(),
            prefix: 1,
            gateway: None,
        });
        let c = clue(&route_ev("8.8.8.8", 53, &r)).unwrap();
        assert_ne!(c.confidence, Confidence::Certain);
        assert_eq!(c.label, "DNS resolver");
    }

    #[test]
    fn port_refinement_sharpens_the_label_without_changing_confidence() {
        let r = fixture_routes();
        let plain = clue(&route_ev("10.20.0.48", 9999, &r)).unwrap();
        let dns = clue(&route_ev("10.20.0.48", 53, &r)).unwrap();
        assert_eq!(plain.label, "Device on your network");
        assert_eq!(dns.label, "Device on your network (DNS)");
        assert_eq!(plain.confidence, dns.confidence);
    }

    #[test]
    fn a_route_named_peer_outranks_the_service_account_on_the_row() {
        // The clue names who the connection is WITH; the row shows the owning
        // uid separately, so a local authority about the peer wins.
        let r = fixture_routes();
        let accts = Accounts::parse("svc:x:700:700:Some Daemon:/:/bin/false\n");
        let mut ev = route_ev("10.20.0.1", 0, &r);
        ev.uid = Some(700);
        ev.account = accts.get(700);
        assert_eq!(clue(&ev).unwrap().label, "Your router");
    }
}
