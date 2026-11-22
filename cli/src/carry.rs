//! One daemon (#61): the watch rules and network names a person set in the
//! panel lived in the panel's own daemon. `kub0 install` brings them to the
//! system daemon, once per person, so they are still there when the panel
//! reads that daemon. History, the activity log and the seen-set are not
//! carried: the system daemon has kept its own since it was installed.
//!
//! The files are the person's, and `kub0 install` runs as root. They are read
//! as that person (`runuser -u`), so root is never made to read what they
//! could not: a symlink or a state directory pointed elsewhere reads only
//! what they can read anyway. Each entry then goes to the daemon as a request.
//!
//! Nothing that is already on the system daemon is overwritten. The requests
//! come from root, which may change any rule, so the daemon would take a
//! person's rule over one somebody else set, and their name over an existing
//! one: those are left as they are and listed. A new watch rule is sent
//! acting for the person (`as_uid`), so it is theirs to change afterwards.
//!
//! A person is noted as carried over only when it is done: every file that
//! exists was read, and the daemon answered every request. Otherwise the
//! next install tries again.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::client::Client;

/// In the system daemon's state directory: the uids already carried over.
pub const MARKER_FILE: &str = "carried-over.json";
/// A state file larger than this is not one the panel's daemon wrote.
const MAX_BYTES: u64 = 1 << 20;
/// The daemon keeps at most 256 watch rules; no more than that is sent.
const MAX_WATCHES: usize = 256;
/// Names have no cap in the daemon. This one only bounds an install.
const MAX_NAMES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub kind: String,
    pub value: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub network_key: String,
    pub label: String,
    pub kind: String,
    /// The reverse-DNS suffix the name was given under. It goes along, so
    /// the org can still tell when the network has changed hands since.
    pub ptr_suffix: String,
}

/// One file of a person's own daemon, read as them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum File {
    /// Not there (or not a regular file: a FIFO put there is not read).
    Absent,
    Text(String),
    /// There, and not read. The reason is for the person; never file content.
    Unreadable(String),
}

/// What a person's own daemon held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// The directory the files were read from, when either was there.
    pub from: Option<PathBuf>,
    pub watches: Vec<Watch>,
    pub names: Vec<Name>,
    /// Entries over the caps, which are not sent.
    pub cut: usize,
    /// `<file>: <why>` for a file that is there and could not be read.
    pub unreadable: Vec<String>,
}

/// Where the panel's own daemon keeps its state under a home directory: the
/// current directory, then the one 0.4.4 and earlier used (only the panel's
/// own daemon moves it, and on a system install the panel starts none).
/// Under sudo the person's `XDG_STATE_HOME` is not known; the default is.
pub fn user_state_dirs(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".local/state/kub0"), home.join(".local/state/vallum")]
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// `watchlist.json` is a list of rules. Entries without a kind or a value are
/// not rules; the daemon judges the rest. Returns the rules and how many
/// were over the cap.
pub fn parse_watches(file: &str) -> (Vec<Watch>, usize) {
    let rules: Vec<Value> = serde_json::from_str(file).unwrap_or_default();
    let mut all: Vec<Watch> = rules
        .iter()
        .map(|r| Watch { kind: text(r, "kind"), value: text(r, "value"), note: text(r, "note") })
        .filter(|w| !w.kind.is_empty() && !w.value.is_empty())
        .collect();
    let cut = all.len().saturating_sub(MAX_WATCHES);
    all.truncate(MAX_WATCHES);
    (all, cut)
}

/// `tags.json` maps a network key to its tag. Only the person's own names are
/// carried (`source: "user"`): the org's arrive from the org.
pub fn parse_names(file: &str) -> (Vec<Name>, usize) {
    let tags: Map<String, Value> = serde_json::from_str(file).unwrap_or_default();
    let mut names: Vec<Name> = tags
        .iter()
        .filter(|(_, t)| t.get("source").and_then(|s| s.as_str()) == Some("user"))
        .map(|(key, t)| Name {
            network_key: if text(t, "network_key").is_empty() { key.clone() } else { text(t, "network_key") },
            label: text(t, "label"),
            kind: text(t, "kind"),
            ptr_suffix: text(t, "ptr_suffix"),
        })
        .filter(|n| !n.network_key.is_empty() && !n.label.is_empty())
        .collect();
    names.sort_by(|a, b| a.network_key.cmp(&b.network_key));
    let cut = names.len().saturating_sub(MAX_NAMES);
    names.truncate(MAX_NAMES);
    (names, cut)
}

/// Read both files from the first of `dirs` that has either, through `read`.
pub fn find(dirs: &[PathBuf], read: &dyn Fn(&Path) -> File) -> Found {
    for dir in dirs {
        let watches = read(&dir.join("watchlist.json"));
        let names = read(&dir.join("tags.json"));
        if watches == File::Absent && names == File::Absent {
            continue;
        }
        let mut found = Found { from: Some(dir.clone()), ..Found::default() };
        match watches {
            File::Text(t) => {
                let (rules, cut) = parse_watches(&t);
                found.watches = rules;
                found.cut += cut;
            }
            File::Unreadable(why) => found.unreadable.push(format!("watchlist.json: {why}")),
            File::Absent => {}
        }
        match names {
            File::Text(t) => {
                let (list, cut) = parse_names(&t);
                found.names = list;
                found.cut += cut;
            }
            File::Unreadable(why) => found.unreadable.push(format!("tags.json: {why}")),
            File::Absent => {}
        }
        return found;
    }
    Found::default()
}

/// A file read as `user`. `test -f` first: only a regular file is read, so a
/// FIFO put at the path cannot hold the install, and "not there" is told from
/// "could not be read". Then at most [`MAX_BYTES`] of it.
pub fn read_as(user: &str, path: &Path) -> File {
    let is_file = Command::new("runuser")
        .args(["-u", user, "--", "test", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match is_file {
        Err(e) => return File::Unreadable(format!("runuser could not be run ({e})")),
        Ok(s) if s.code() == Some(1) => return File::Absent,
        Ok(s) if !s.success() => return File::Unreadable(format!("could not be looked at as {user} ({s})")),
        Ok(_) => {}
    }
    let child = Command::new("runuser")
        .args(["-u", user, "--", "cat", "--"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return File::Unreadable(format!("runuser could not be run ({e})")),
    };
    let mut bytes = Vec::new();
    let read = match child.stdout.take() {
        Some(out) => out.take(MAX_BYTES + 1).read_to_end(&mut bytes),
        None => Ok(0),
    };
    let _ = child.kill();
    let status = child.wait();
    if bytes.len() as u64 > MAX_BYTES {
        return File::Unreadable("larger than 1 MiB, which the panel's daemon never writes".into());
    }
    match (read, status) {
        (Ok(_), Ok(_)) => match String::from_utf8(bytes) {
            Ok(text) => File::Text(text),
            Err(_) => File::Unreadable("not text".into()),
        },
        _ => File::Unreadable(format!("could not be read as {user}")),
    }
}

/// The uids already carried over, from the marker in the daemon's state directory.
pub fn carried(daemon_state: &Path) -> BTreeSet<u32> {
    std::fs::read_to_string(daemon_state.join(MARKER_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get("uids").and_then(|u| u.as_array()).cloned())
        .map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as u32).collect())
        .unwrap_or_default()
}

pub fn mark(daemon_state: &Path, uid: u32) -> std::io::Result<()> {
    let mut uids = carried(daemon_state);
    uids.insert(uid);
    std::fs::create_dir_all(daemon_state)?;
    let path = daemon_state.join(MARKER_FILE);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json!({ "uids": uids }).to_string())?;
    std::fs::rename(&tmp, &path)
}

/// The network keys the system daemon already has a name for, from its own
/// `tags.json` (it has no request that lists them; root reads the file).
pub fn named_already(daemon_state: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(daemon_state.join("tags.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Map<String, Value>>(&t).ok())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Carried {
    pub watches: usize,
    pub names: usize,
    /// Already on the system daemon, and left as they are there.
    pub kept: Vec<String>,
    /// What the daemon refused, as `<what>: <its reason>`.
    pub refused: Vec<String>,
    /// The daemon stopped answering: nothing after this was sent.
    pub stopped: Option<String>,
}

/// Send every entry the system daemon does not already have: a watch rule
/// acting for `uid`, a name with the PTR suffix it was given under. Stops at
/// the first request the daemon does not answer.
pub fn carry(client: &mut Client, uid: u32, found: &Found, named: &BTreeSet<String>, timeout: Duration) -> Carried {
    let mut done = Carried::default();
    let mut quiet = |_: &Value| {};
    // The rules there now, by kind and value: one that exists is somebody's
    // (maybe this person's own, set from the terminal) and stays as it is.
    let there: Vec<(String, String, Option<u64>)> = match client.request_split("watches", Map::new(), timeout, &mut quiet) {
        Err(e) => {
            done.stopped = Some(e);
            return done;
        }
        Ok(Err(e)) => {
            done.stopped = Some(format!("watches: {e}"));
            return done;
        }
        Ok(Ok(r)) => r["rules"]
            .as_array()
            .map(|a| a.iter().map(|w| (text(w, "kind"), text(w, "value"), w.get("owner").and_then(|o| o.as_u64()))).collect())
            .unwrap_or_default(),
    };
    for w in &found.watches {
        if let Some((_, _, owner)) = there.iter().find(|(k, v, _)| k.eq_ignore_ascii_case(&w.kind) && v.eq_ignore_ascii_case(&w.value)) {
            done.kept.push(format!(
                "watch {} {}: already a rule there ({})",
                w.kind,
                w.value,
                match owner {
                    Some(o) if *o == u64::from(uid) => "yours".to_string(),
                    Some(o) => format!("set by uid {o}"),
                    None => "root's".to_string(),
                }
            ));
            continue;
        }
        let mut args = Map::new();
        args.insert("kind".into(), json!(w.kind));
        args.insert("value".into(), json!(w.value));
        args.insert("note".into(), json!(w.note));
        args.insert("as_uid".into(), json!(uid));
        match client.request_split("watch-set", args, timeout, &mut quiet) {
            Ok(Ok(_)) => done.watches += 1,
            Ok(Err(e)) => done.refused.push(format!("watch {} {}: {e}", w.kind, w.value)),
            Err(e) => {
                done.stopped = Some(e);
                return done;
            }
        }
    }
    for n in &found.names {
        if named.contains(&n.network_key) {
            done.kept.push(format!("name {}: already named there", n.network_key));
            continue;
        }
        let mut args = Map::new();
        args.insert("networkKey".into(), json!(n.network_key));
        args.insert("label".into(), json!(n.label));
        if !n.kind.is_empty() {
            args.insert("kind".into(), json!(n.kind));
        }
        if !n.ptr_suffix.is_empty() {
            args.insert("ptrSuffix".into(), json!(n.ptr_suffix));
        }
        match client.request_split("tag", args, timeout, &mut quiet) {
            Ok(Ok(_)) => done.names += 1,
            Ok(Err(e)) => done.refused.push(format!("name {}: {e}", n.network_key)),
            Err(e) => {
                done.stopped = Some(e);
                return done;
            }
        }
    }
    done
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Whether the person is done: every file that exists was read, and the
/// daemon answered every request. Only then is it noted and not tried again.
pub fn complete(found: &Found, done: &Carried) -> bool {
    found.unreadable.is_empty() && done.stopped.is_none()
}

/// The lines `kub0 install` prints for what was carried.
pub fn report(found: &Found, done: &Carried) -> Vec<String> {
    let from = found.from.as_deref().map(|p| p.display().to_string()).unwrap_or_default();
    let mut lines = vec![format!(
        "carried over {} and {} from the panel's own daemon ({from}) to the system daemon{}",
        plural(done.watches, "watch rule", "watch rules"),
        plural(done.names, "network name", "network names"),
        // What `kub0 tag` does with a name, said where a person may not expect it.
        if done.names > 0 { "; the names go to your org with its heartbeat, as `kub0 tag` names do" } else { "" }
    )];
    for k in &done.kept {
        lines.push(format!("left as it is on the system daemon: {k}"));
    }
    for r in &done.refused {
        lines.push(format!("not carried over, the daemon refused it: {r}"));
    }
    if found.cut > 0 {
        lines.push(format!("not carried over: {} more than one install sends", plural(found.cut, "entry", "entries")));
    }
    for u in &found.unreadable {
        lines.push(format!("not carried over, {from}/{u}"));
    }
    if let Some(e) = &done.stopped {
        lines.push(format!("the system daemon stopped answering ({e}); what was not sent stays where it was"));
    }
    if !complete(found, done) {
        lines.push("`sudo kub0 install` again carries over the rest".into());
    }
    lines
}

/// `name:x:uid:gid:gecos:home:shell` from `getent passwd <user>`.
fn passwd_entry(line: &str) -> Option<(u32, PathBuf)> {
    let f: Vec<&str> = line.trim().split(':').collect();
    let uid = f.get(2)?.parse().ok()?;
    let home = f.get(5).filter(|h| h.starts_with('/'))?;
    Some((uid, PathBuf::from(home)))
}

fn lookup(user: &str) -> Option<(u32, PathBuf)> {
    let out = Command::new("getent").args(["passwd", user]).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| passwd_entry(&String::from_utf8_lossy(&out.stdout))).flatten()
}

/// After `kub0 install` started the system daemon: carry `user`'s watch rules
/// and names over, unless that was done before. Returns the lines to print;
/// none when there is nothing to say. Never fatal: the install is complete
/// without it.
pub fn after_install(user: &str, socket: &Path, daemon_state: &Path) -> Vec<String> {
    let Some((uid, home)) = lookup(user) else {
        return Vec::new();
    };
    if uid == 0 || carried(daemon_state).contains(&uid) {
        return Vec::new();
    }
    let found = find(&user_state_dirs(&home), &|p| read_as(user, p));
    let Some(from) = found.from.clone() else {
        return Vec::new();
    };
    // The unit was started a moment ago: its socket may not be there yet.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client = loop {
        match Client::connect(socket) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => {
                return vec![format!(
                    "watch rules and network names in {} were not carried over: the system daemon did not answer; `sudo kub0 install` again carries them over",
                    from.display()
                )]
            }
        }
    };
    if !client.hello.as_uid {
        return vec![format!(
            "watch rules and network names in {} were not carried over: this system daemon cannot act for a user",
            from.display()
        )];
    }
    let done = carry(&mut client, uid, &found, &named_already(daemon_state), Duration::from_secs(5));
    let mut lines = report(&found, &done);
    if complete(&found, &done) {
        if let Err(e) = mark(daemon_state, uid) {
            lines.push(format!("could not note that in {} ({e}); the next install looks again", daemon_state.join(MARKER_FILE).display()));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kub0-carry-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The person's files read plainly: what `read_as` yields for them.
    fn read_plain(p: &Path) -> File {
        match std::fs::read_to_string(p) {
            Ok(t) => File::Text(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::Absent,
            Err(e) => File::Unreadable(e.to_string()),
        }
    }

    const WATCHLIST: &str = r#"[
        {"id":"w-1","kind":"country","value":"KP","note":"sanctions","ts":1,"hits":4,"last_hit":9},
        {"id":"w-2","kind":"cidr","value":"192.0.2.0/24","ts":2},
        {"id":"w-3","kind":"","value":"x","ts":3},
        {"id":"w-4","kind":"asn","ts":4}
    ]"#;
    const TAGS: &str = r#"{
        "203.0.113.0/24": {"network_key":"203.0.113.0/24","label":"Office VPN","kind":"service","ptr_suffix":"edge.example.net","ts":5,"source":"user"},
        "198.51.100.0/24": {"network_key":"198.51.100.0/24","label":"From the org","kind":"hosting","ptr_suffix":"","ts":6,"source":"fleet"},
        "192.0.2.0/24": {"network_key":"192.0.2.0/24","label":"","kind":"service","ptr_suffix":"","ts":7,"source":"user"}
    }"#;

    fn watch(kind: &str, value: &str, note: &str) -> Watch {
        Watch { kind: kind.into(), value: value.into(), note: note.into() }
    }

    #[test]
    fn the_persons_rules_and_names_are_found_and_the_orgs_are_not() {
        let home = dir("find");
        let dirs = user_state_dirs(&home);
        assert_eq!(find(&dirs, &read_plain), Found::default(), "no file: nothing to carry, nothing to say");
        std::fs::create_dir_all(&dirs[0]).unwrap();
        std::fs::write(dirs[0].join("watchlist.json"), WATCHLIST).unwrap();
        std::fs::write(dirs[0].join("tags.json"), TAGS).unwrap();
        let found = find(&dirs, &read_plain);
        assert_eq!(found.from.as_deref(), Some(dirs[0].as_path()));
        assert_eq!(found.watches, vec![watch("country", "KP", "sanctions"), watch("cidr", "192.0.2.0/24", "")],
            "an entry with no kind or no value is not a rule");
        assert_eq!(
            found.names,
            vec![Name { network_key: "203.0.113.0/24".into(), label: "Office VPN".into(), kind: "service".into(), ptr_suffix: "edge.example.net".into() }],
            "a name the org sent comes from the org, and an empty label names nothing"
        );
        assert!(found.unreadable.is_empty() && found.cut == 0);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A person coming straight from 0.4.4 or earlier: only the panel's own
    /// daemon ever moved that directory, and the panel starts none now.
    #[test]
    fn the_directory_of_0_4_4_and_earlier_is_looked_in_too() {
        let home = dir("old-dir");
        let dirs = user_state_dirs(&home);
        std::fs::create_dir_all(&dirs[1]).unwrap();
        std::fs::write(dirs[1].join("watchlist.json"), WATCHLIST).unwrap();
        let found = find(&dirs, &read_plain);
        assert_eq!(found.from.as_deref(), Some(dirs[1].as_path()));
        assert_eq!(found.watches.len(), 2);
        // The current directory wins when it has anything.
        std::fs::create_dir_all(&dirs[0]).unwrap();
        std::fs::write(dirs[0].join("tags.json"), "{}").unwrap();
        assert_eq!(find(&dirs, &read_plain).from.as_deref(), Some(dirs[0].as_path()));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_file_that_is_there_and_cannot_be_read_is_said_and_keeps_the_person_unmarked() {
        let home = dir("unreadable");
        let dirs = user_state_dirs(&home);
        let read = |p: &Path| {
            if p.ends_with("watchlist.json") { File::Unreadable("larger than 1 MiB".into()) } else { File::Text(TAGS.into()) }
        };
        let found = find(&dirs, &read);
        assert_eq!(found.unreadable, vec!["watchlist.json: larger than 1 MiB".to_string()]);
        assert_eq!(found.names.len(), 1, "the file that did read is still carried");
        let done = Carried { names: 1, ..Carried::default() };
        assert!(!complete(&found, &done), "the unread file must be tried again");
        let lines = report(&found, &done);
        assert!(lines.iter().any(|l| l.contains("watchlist.json: larger than 1 MiB")), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "`sudo kub0 install` again carries over the rest");
        // Junk that reads fine carries nothing and is done.
        let junk = find(&dirs, &|p: &Path| if p.ends_with("tags.json") { File::Text("[1,2]".into()) } else { File::Text("{not json".into()) });
        assert!(junk.from.is_some() && junk.watches.is_empty() && junk.names.is_empty() && junk.unreadable.is_empty());
        assert!(complete(&junk, &Carried::default()));
    }

    #[test]
    fn entries_over_the_caps_are_counted_not_dropped_in_silence() {
        let many: Vec<Value> = (0..MAX_WATCHES + 44).map(|i| json!({"kind": "asn", "value": i.to_string()})).collect();
        let (rules, cut) = parse_watches(&Value::Array(many).to_string());
        assert_eq!((rules.len(), cut), (MAX_WATCHES, 44));
        let found = Found { from: Some(PathBuf::from("/h")), cut, ..Found::default() };
        assert!(report(&found, &Carried::default()).iter().any(|l| l.contains("44 entries more than one install sends")));
    }

    #[test]
    fn a_person_is_carried_over_once() {
        let d = dir("marker");
        assert!(carried(&d).is_empty());
        mark(&d, 1000).unwrap();
        mark(&d, 1001).unwrap();
        mark(&d, 1000).unwrap();
        assert_eq!(carried(&d).into_iter().collect::<Vec<_>>(), vec![1000, 1001]);
        std::fs::write(d.join(MARKER_FILE), "garbage").unwrap();
        assert!(carried(&d).is_empty(), "an unreadable marker is no marker");
        std::fs::write(d.join("tags.json"), TAGS).unwrap();
        assert_eq!(named_already(&d).len(), 3, "every key the daemon has a name for, whoever gave it");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_passwd_line_gives_the_uid_and_the_home() {
        assert_eq!(passwd_entry("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"), Some((1000, PathBuf::from("/home/alice"))));
        assert_eq!(passwd_entry("alice:x:abc:1000::/home/alice:/bin/bash"), None);
        assert_eq!(passwd_entry("alice:x:1000:1000::relative:/bin/bash"), None);
        assert_eq!(passwd_entry(""), None);
    }

    /// A system daemon stand-in that answers as the real one does: `watches`
    /// lists what it holds, a `watch-set` from root overwrites whatever is
    /// there (root may change any rule), and it never refuses on ownership.
    /// It closes the connection after `hang_up_after` requests, if given.
    fn fake_daemon(path: &Path, rules: Value, hang_up_after: Option<usize>) -> std::sync::mpsc::Receiver<Value> {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else { return };
            let mut w = stream.try_clone().unwrap();
            let _ = writeln!(w, "{}", json!({"type": "hello", "version": "0.5.0", "mode": "system", "requests": true, "as_uid": true}));
            for (n, line) in std::io::BufReader::new(stream).lines().enumerate() {
                let Ok(line) = line else { break };
                if hang_up_after == Some(n) {
                    return;
                }
                let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                let reply = if v["cmd"] == "watches" {
                    json!({"type": "reply", "req": v["req"], "ok": true, "result": {"rules": rules, "mode": "system"}})
                } else if v["cmd"] == "watch-set" && v["kind"] == "planet" {
                    json!({"type": "reply", "req": v["req"], "ok": false, "error": "unknown watch kind \"planet\""})
                } else {
                    json!({"type": "reply", "req": v["req"], "ok": true, "result": {}})
                };
                let _ = tx.send(v);
                let _ = writeln!(w, "{reply}");
            }
        });
        rx
    }

    fn found_with(watches: Vec<Watch>, names: Vec<Name>) -> Found {
        Found { from: Some(PathBuf::from("/home/alice/.local/state/kub0")), watches, names, ..Found::default() }
    }

    /// Root may change any rule, so the daemon would take the person's copy
    /// over a rule somebody else set (erasing their note, and leaving it
    /// theirs). What is already there is left as it is, and listed.
    #[test]
    fn what_the_system_daemon_already_has_is_left_as_it_is() {
        let d = dir("carry");
        let sock = d.join("system.sock");
        let there = json!([
            {"id": "w-a", "kind": "asn", "value": "64500", "note": "lab", "owner": 1001},
            {"id": "w-b", "kind": "country", "value": "KP", "note": "", "owner": 1000},
            {"id": "w-c", "kind": "port", "value": "4444", "note": ""}
        ]);
        let seen = fake_daemon(&sock, there, None);
        let found = found_with(
            vec![watch("asn", "64500", ""), watch("country", "KP", "sanctions"), watch("port", "4444", "x"),
                 watch("cidr", "192.0.2.0/24", "new"), watch("planet", "mars", "")],
            vec![
                Name { network_key: "203.0.113.0/24".into(), label: "Office VPN".into(), kind: "service".into(), ptr_suffix: "edge.example.net".into() },
                Name { network_key: "198.51.100.0/24".into(), label: "Mine".into(), kind: String::new(), ptr_suffix: String::new() },
            ],
        );
        let named: BTreeSet<String> = ["198.51.100.0/24".to_string()].into();
        let mut client = Client::connect(&sock).unwrap();
        let done = carry(&mut client, 1000, &found, &named, Duration::from_secs(3));
        drop(client);
        assert_eq!((done.watches, done.names), (1, 1));
        assert_eq!(done.kept, vec![
            "watch asn 64500: already a rule there (set by uid 1001)".to_string(),
            "watch country KP: already a rule there (yours)".to_string(),
            "watch port 4444: already a rule there (root's)".to_string(),
            "name 198.51.100.0/24: already named there".to_string(),
        ]);
        assert_eq!(done.refused, vec!["watch planet mars: unknown watch kind \"planet\"".to_string()]);
        assert!(done.stopped.is_none() && complete(&found, &done));

        let sent: Vec<Value> = seen.try_iter().collect();
        let cmds: Vec<&str> = sent.iter().map(|v| v["cmd"].as_str().unwrap()).collect();
        assert_eq!(cmds, ["watches", "watch-set", "watch-set", "tag"], "nothing is sent for what is already there");
        assert_eq!((&sent[1]["kind"], &sent[1]["value"], &sent[1]["note"], &sent[1]["as_uid"]),
            (&json!("cidr"), &json!("192.0.2.0/24"), &json!("new"), &json!(1000)), "a new rule acts for its owner");
        assert_eq!((&sent[3]["networkKey"], &sent[3]["label"], &sent[3]["kind"], &sent[3]["ptrSuffix"]),
            (&json!("203.0.113.0/24"), &json!("Office VPN"), &json!("service"), &json!("edge.example.net")));
        assert!(sent[3].get("as_uid").is_none(), "a name has no owner");

        let lines = report(&found, &done);
        assert_eq!(lines[0], "carried over 1 watch rule and 1 network name from the panel's own daemon (/home/alice/.local/state/kub0) to the system daemon; the names go to your org with its heartbeat, as `kub0 tag` names do");
        assert!(lines.contains(&"left as it is on the system daemon: watch asn 64500: already a rule there (set by uid 1001)".to_string()));
        assert!(lines.contains(&"not carried over, the daemon refused it: watch planet mars: unknown watch kind \"planet\"".to_string()));
        assert!(!lines.iter().any(|l| l.contains("again carries over")), "it is done: {lines:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The daemon goes away partway. A refusal is the daemon's answer and the
    /// carry goes on; no answer is not, and the person must not be noted as
    /// carried over with rules that were never sent.
    #[test]
    fn a_daemon_that_stops_answering_stops_the_carry_and_leaves_the_person_unmarked() {
        let d = dir("stopped");
        let sock = d.join("system.sock");
        // Answers `watches` and the first `watch-set`, then hangs up.
        let seen = fake_daemon(&sock, json!([]), Some(2));
        let found = found_with(vec![watch("asn", "1", ""), watch("asn", "2", ""), watch("asn", "3", "")], Vec::new());
        let mut client = Client::connect(&sock).unwrap();
        let done = carry(&mut client, 1000, &found, &BTreeSet::new(), Duration::from_secs(3));
        drop(client);
        assert_eq!(done.watches, 1);
        assert!(done.refused.is_empty(), "no answer is not a refusal: {:?}", done.refused);
        assert!(done.stopped.is_some());
        assert!(!complete(&found, &done));
        assert_eq!(seen.try_iter().count(), 2, "nothing is sent after it stopped");
        let lines = report(&found, &done);
        assert!(lines.iter().any(|l| l.starts_with("the system daemon stopped answering")), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "`sudo kub0 install` again carries over the rest");
        let _ = std::fs::remove_dir_all(&d);
    }
}
