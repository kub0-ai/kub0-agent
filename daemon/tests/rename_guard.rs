//! The rename (#61 step 3) keeps `kub0` on every user-visible name. This
//! fails when a 0.4.x name (a binary, path, unit, group, polkit id, socket,
//! environment variable, the panel's old title, its plugin id through 0.4.6
//! or its old settings folder) shows up anywhere outside
//! an explicit allowlist: history kept as it was, test inputs, the crates'
//! own names (not renamed), regions of the docs marked `rename-compat`, and
//! the migration and refusal sites below, each with the number of lines it
//! may spend and why. A site that grows or shrinks fails too, so the list
//! stays exact.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Kept as history: what was true then, under the names it had then.
const HISTORY: &[&str] = &[
    "CHANGELOG.md",
    "LICENSE",
    "THIRD-PARTY.md",
    "docs/PANEL-REDESIGN.md",
];

/// Test inputs: the old paths and names are what they exercise (this file's
/// own fixtures among them).
const TEST_PREFIXES: &[&str] = &["tests/", "daemon/tests/rename_guard.rs"];

/// Usage of the old names that is not a user-visible name: the crates and
/// packages keep theirs (`vallumd`, `vallum-block`).
const CRATE_CONTEXTS: &[&str] = &[
    "-p vallumd",
    "-p vallum-block",
    "name = \"vallumd\"",
    "name = \"vallum-block\"",
    "the `vallumd` library",
];

/// What still names a 0.4.x thing: (file, lines that may, why). Three kinds
/// are left. The one-time migration from a 0.4.x install, kept so that any
/// old version upgrades in one step. The guards that refuse or report an
/// old name instead of honouring it. And the panel's carry-over of its own
/// settings and hotkey. The aliases 0.4.5 and 0.4.6 kept alive (links at
/// the old binary paths, the unit alias, the old socket link, the compat
/// polkit actions, the old status group, the `VALLUM_*` spelling of a
/// variable, the old collector path) are gone, and a file that held only
/// those is no longer listed: an old name there fails.
/// `usize::MAX` is the rename module itself, which is nothing else.
const COMPAT: &[(&str, usize, &str)] = &[
    ("daemon/src/rename.rs", usize::MAX, "the rename module: the 0.4.x names, the state move and their tests"),
    ("daemon/src/kub0.rs", 3, "the state root in use while a move waits; a 0.4.x daemon is not a kub0d (test)"),
    ("daemon/src/execgate.rs", 2, "tests: the 0.4.x directory and helper name are not critical any more"),
    ("daemon/src/main.rs", 6, "migrate-state, the per-user move and the running-0.4.x-daemon guards, with their tests"),
    ("daemon/src/system_status.rs", 1, "a host with both groups uses neither"),
    ("helper/src/lib.rs", 1, "the helper never recreates the old state root (its test)"),
    ("cli/src/paths.rs", 11, "paths::old: what kub0 install moves or removes and kub0 doctor reports"),
    ("cli/src/install.rs", 37, "the upgrade from 0.4.x: staged then switched, old units kept for a rollback, the old paths removed, and their tests"),
    ("cli/src/doctor.rs", 7, "the leftovers, the state-directory gate and old polkit rules the doctor reports, tested"),
    ("Kub0Adapter.qml", 1, "the settings folder through 0.4.6, read once and never written"),
    ("js/Binds.js", 1, "a hotkey written under the plugin id through 0.4.6 is ours and stale"),
    ("compat/install-binds.py", 1, "the hotkey block under the plugin id through 0.4.6 is removed when the new one is written"),
    ("packaging/systemd/kub0d.service", 3, "the unit's own move of a 0.4.x state directory, and its fallback"),
    ("packaging/systemd/kub0-expiry.service", 3, "expiry wherever the scoped records are"),
    ("scripts/install-capture.sh", 2, "the 0.4.x collector and its policy are removed"),
    ("scripts/install-privileged.sh", 2, "what kub0 install does on a 0.4.x host"),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn files() -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root())
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

fn word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Every place `token` starts in `line` where `ok(before, after)` holds.
fn finds(line: &str, token: &str, ok: impl Fn(Option<char>, &str) -> bool) -> bool {
    let mut from = 0;
    while let Some(i) = line[from..].find(token) {
        let at = from + i;
        let before = line[..at].chars().next_back();
        let after = &line[at + token.len()..];
        if ok(before, after) {
            return true;
        }
        from = at + token.len();
    }
    false
}

/// Whether `line` (of a file named `path`) names a 0.4.x thing.
fn old_name(path: &str, line: &str) -> Option<&'static str> {
    let mut l = line.to_string();
    for c in CRATE_CONTEXTS {
        l = l.replace(c, "");
    }
    let l = l.as_str();
    let bounded = |b: Option<char>, a: &str| !word(b) && !word(a.chars().next());
    if finds(l, "vallumd", |b, a| bounded(b, a) && !a.starts_with("::")) {
        return Some("vallumd");
    }
    for t in ["vallum-block", "vallum-status", "vallum-expiry", "vallum-capture"] {
        if finds(l, t, bounded) {
            return Some(t);
        }
    }
    for t in ["/usr/lib/vallum", "/run/vallum", "/var/lib/vallum", "/usr/share/vallum"] {
        if finds(l, t, |_, a| !word(a.chars().next())) {
            return Some(t);
        }
    }
    if finds(l, "ai.kub0.vallum.", |_, a| a.starts_with(|c: char| c.is_ascii_lowercase())) {
        return Some("ai.kub0.vallum.*");
    }
    // The panel's plugin id through 0.4.6 (now ai.kub0.agent) and the folder
    // its settings were in (now ~/.config/kub0).
    // `ai.kub0.vallum.<something>` is the polkit family above, or prose about
    // it; the id itself ends at a space, a quote, a slash or a full stop.
    let id_ends = |_: Option<char>, a: &str| {
        let mut rest = a.chars();
        match rest.next() {
            Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '-' => false,
            Some('.') => rest.next().is_none_or(char::is_whitespace),
            _ => true,
        }
    };
    if finds(l, "ai.kub0.vallum", id_ends) {
        return Some("ai.kub0.vallum (the old plugin id)");
    }
    if finds(l, ".config/vallum", |_, a| !word(a.chars().next())) {
        return Some("~/.config/vallum");
    }
    if finds(l, "VALLUM_", |b, a| !word(b) && a.starts_with(|c: char| c.is_ascii_uppercase())) {
        return Some("VALLUM_*");
    }
    if finds(l, "vallum.sock", |b, _| !(word(b) || matches!(b, Some('.' | '/' | '-')))) {
        return Some("vallum.sock");
    }
    let ui = [".qml", ".js", ".json", ".policy", ".yml"].iter().any(|e| path.ends_with(e));
    if ui && finds(l, "Vallum", bounded) {
        return Some("Vallum (the old title)");
    }
    None
}

/// Every old-name line in `text`, skipping `rename-compat` regions.
fn hits(path: &str, text: &str) -> Vec<(usize, String, &'static str)> {
    let mut out = Vec::new();
    let mut region = false;
    for (n, line) in text.lines().enumerate() {
        if line.contains("<!-- /rename-compat -->") {
            region = false;
            continue;
        }
        if line.contains("<!-- rename-compat") {
            region = true;
            continue;
        }
        if region {
            continue;
        }
        if let Some(what) = old_name(path, line) {
            out.push((n + 1, line.trim().chars().take(140).collect(), what));
        }
    }
    out
}

fn scan() -> BTreeMap<String, Vec<(usize, String, &'static str)>> {
    let mut all = BTreeMap::new();
    for f in files() {
        if HISTORY.contains(&f.as_str()) || TEST_PREFIXES.iter().any(|p| f.starts_with(p)) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root().join(&f)) else {
            continue; // binary, or gone from the worktree
        };
        let h = hits(&f, &text);
        if !h.is_empty() {
            all.insert(f, h);
        }
    }
    all
}

/// Every 0.4.x name outside the allowlist fails, and so does a compat site
/// whose count moved, with the lines printed so the list is easy to fix.
fn check(found: &BTreeMap<String, Vec<(usize, String, &'static str)>>) -> Result<(), String> {
    let mut errors = Vec::new();
    for (file, lines) in found {
        let shown = || lines.iter().map(|(n, l, w)| format!("    {file}:{n} [{w}] {l}")).collect::<Vec<_>>().join("\n");
        match COMPAT.iter().find(|(f, _, _)| f == file) {
            None => errors.push(format!("{file}: a 0.4.x name outside the allowlist\n{}", shown())),
            Some((_, usize::MAX, _)) => {}
            Some((_, want, why)) if *want != lines.len() => errors.push(format!(
                "{file}: {} compat line(s), the allowlist says {want} ({why})\n{}",
                lines.len(),
                shown()
            )),
            Some(_) => {}
        }
    }
    for (file, _, why) in COMPAT {
        if !found.contains_key(*file) {
            errors.push(format!("{file}: listed as a compat site ({why}) but names nothing old; drop it from COMPAT"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

#[test]
fn no_user_visible_old_name_outside_the_allowlist() {
    if let Err(e) = check(&scan()) {
        panic!("{e}");
    }
}

/// The matcher, on its own: what counts as an old name and what does not.
#[test]
fn the_guard_knows_an_old_name_from_a_crate_name() {
    for (path, line) in [
        ("x.rs", "Command::new(\"/usr/lib/vallum/vallum-block\")"),
        ("x.rs", "systemctl status vallumd"),
        ("x.sh", "export VALLUM_EXEC_GATE=0"),
        ("x.rs", "\"ai.kub0.vallum.block-app\""),
        ("x.rs", "join(\"vallum.sock\")"),
        ("x.rs", "groupadd vallum-status"),
        ("Panel.qml", "title: \"Vallum\""),
        ("Service.qml", "readonly property string pluginId: \"ai.kub0.vallum\""),
        ("x.md", "omarchy plugin enable ai.kub0.vallum"),
        ("x.md", "The id was ai.kub0.vallum. It is not now."),
        ("x.rs", "home + \"/.config/vallum\""),
    ] {
        assert!(old_name(path, line).is_some(), "{line}");
    }
    for (path, line) in [
        ("x.rs", "use vallumd::rename;"),
        ("x.yml", "cargo test -p vallumd --lib"),
        ("Cargo.toml", "name = \"vallum-block\""),
        ("Service.qml", "readonly property string pluginId: \"ai.kub0.agent\""),
        ("x.rs", "table inet vallum, vallum.slice/vallum-firefox"),
        ("Panel.qml", "property var liveVallum: VallumAdapter.find()"),
        ("x.md", "the Vallum panel"),
        ("x.rs", "home + \"/.config/kub0\""),
        ("x.rs", "\"/home/u/.config/vallumish\""),
        ("x.md", "polkit `ai.kub0.vallum.*` is now `ai.kub0.agent.*`"),
    ] {
        assert_eq!(old_name(path, line), None, "{line}");
    }
    let marked = "a\n<!-- rename-compat -->\n/run/vallum\n<!-- /rename-compat -->\n/run/vallum\n";
    assert_eq!(hits("x.md", marked).len(), 1, "only the line outside the region");
}

/// A name the guard must catch, added to a file outside the allowlist, fails.
#[test]
fn an_old_name_in_a_new_place_fails_the_check() {
    let mut found = scan();
    found.insert("Panel.qml".into(), hits("Panel.qml", "            title: \"Vallum\""));
    assert!(check(&found).unwrap_err().contains("Panel.qml: a 0.4.x name outside the allowlist"));
    // A listed site that grows by one line fails on its count.
    let mut found = scan();
    found.get_mut("Kub0Adapter.qml").unwrap().push((1, "return home + \"/.config/vallum\"".into(), "~/.config/vallum"));
    assert!(check(&found).unwrap_err().contains("Kub0Adapter.qml: 2 compat line(s)"));
    // The aliases 0.4.5 and 0.4.6 kept alive are gone, and so are their
    // allowances: each of these was a listed compat site until then.
    for (file, line) in [
        ("Service.qml", "property string oldSystemSocketPath: \"/run/vallum/vallum.sock\""),
        ("js/SystemStatus.js", "var oldInstalledCli = \"/usr/lib/vallum/vallumd\""),
        ("polkit/ai.kub0.agent.policy", "<annotate key=\"org.freedesktop.policykit.exec.path\">/usr/lib/vallum/vallum-block</annotate>"),
        ("daemon/src/capture.rs", "pub const OLD_COLLECTOR: &str = \"/usr/lib/vallum/vallum-capture\";"),
        (".github/workflows/build.yml", "runs-on: ${{ vars.KUB0_LINUX_RUNNER || vars.VALLUM_LINUX_RUNNER || 'ubuntu-latest' }}"),
    ] {
        let mut found = scan();
        assert!(!found.contains_key(file), "{file} names something old again");
        found.insert(file.into(), hits(file, line));
        assert!(
            check(&found).unwrap_err().contains(&format!("{file}: a 0.4.x name outside the allowlist")),
            "{file}: {line}"
        );
    }
}
