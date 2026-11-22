//! The CLI does not link the daemon (see `cli/Cargo.toml`), so the few paths
//! it must agree on are pinned here against the daemon's own constants. A
//! drift is a compile-time-cheap test failure instead of a CLI that looks
//! for the socket in the wrong place.

const CLI_PATHS: &str = include_str!("../../cli/src/paths.rs");

fn cli_const(name: &str) -> String {
    let needle = format!("pub const {name}: &str = \"");
    let start = CLI_PATHS
        .find(&needle)
        .unwrap_or_else(|| panic!("cli/src/paths.rs has no `{name}`"))
        + needle.len();
    let end = CLI_PATHS[start..].find('"').expect("unterminated string") + start;
    CLI_PATHS[start..end].to_string()
}

#[test]
fn the_cli_and_the_daemon_agree_on_the_system_paths() {
    // The renamed system paths, the 0.4.x ones and the move between them are
    // one file both crates compile (`daemon/src/rename.rs`, std only).
    let cli_main = include_str!("../../cli/src/main.rs");
    assert!(cli_main.contains("#[path = \"../../daemon/src/rename.rs\"]\nmod rename;"), "the CLI compiles the daemon's rename module");
    for line in [
        "pub const SYSTEM_SOCKET: &str = rename::SYSTEM_SOCKET;",
        "pub const STATUS_GROUP: &str = rename::STATUS_GROUP;",
        "rename::state_path(\"account.json\")",
        "rename::state_path(\"execgate\")",
    ] {
        assert!(CLI_PATHS.contains(line), "cli/src/paths.rs: {line}");
    }
    assert_eq!(vallumd::kub0::system_account_path(), vallumd::rename::state_path("account.json"));
    assert_eq!(vallumd::trust::DIR_NAME, "execgate");
    assert_eq!(vallumd::system_status::STATUS_GROUP, vallumd::rename::STATUS_GROUP);
    assert_eq!(vallumd::system_status::SYSTEM_STATUS_SOCKET, vallumd::rename::STATUS_SOCKET);
    assert_eq!(cli_const("DAEMON"), vallumd::system_status::INSTALLED_CLI);
    // The daemon's SYSTEM_SOCKET and HELPER_PATH live in its binary, not the
    // library; they are pinned by text so this test needs no refactor.
    let daemon_main = include_str!("../src/main.rs");
    assert!(daemon_main.contains("const SYSTEM_SOCKET: &str = vallumd::rename::SYSTEM_SOCKET;"));
    assert!(daemon_main.contains(&format!("const HELPER_PATH: &str = \"{}\";", cli_const("HELPER"))));
    // And the helper agrees on where it lives.
    let helper_main = include_str!("../../helper/src/main.rs");
    assert!(helper_main.contains(&format!("const CANONICAL_HELPER: &str = \"{}\";", cli_const("HELPER"))));
}

/// The CLI says "needs root" for a verb only when the daemon's table says it
/// lowers protection (`Access::Lower`); for every other verb it points at the
/// socket's group. Its list is a copy, pinned here.
#[test]
fn the_cli_names_root_for_exactly_the_lowering_verbs() {
    use std::collections::BTreeSet;
    use vallumd::control::{Access, VERBS};
    let args = include_str!("../../cli/src/args.rs");
    let start = args.find("pub const LOWERS: &[&str] = &[").expect("cli/src/args.rs has no LOWERS");
    let end = args[start..].find("];").expect("unterminated LOWERS") + start;
    let cli: BTreeSet<&str> = args[start..end].split('"').skip(1).step_by(2).collect();
    let daemon: BTreeSet<&str> = VERBS.iter().filter(|(_, a)| *a == Access::Lower).map(|(v, _)| *v).collect();
    assert_eq!(cli, daemon);
}

/// The CLI omits `as_uid` for a read to an older daemon, so its list of
/// reads must be the daemon's.
#[test]
fn the_cli_reads_are_the_daemons() {
    use std::collections::BTreeSet;
    use vallumd::control::{Access, VERBS};
    let args = include_str!("../../cli/src/args.rs");
    let start = args.find("pub const READS: &[&str] = &[").expect("cli/src/args.rs has no READS");
    let end = args[start..].find("];").expect("unterminated READS") + start;
    let cli: BTreeSet<&str> = args[start..end].split('"').skip(1).step_by(2).collect();
    let daemon: BTreeSet<&str> = VERBS.iter().filter(|(_, a)| *a == Access::Read).map(|(v, _)| *v).collect();
    assert_eq!(cli, daemon);
}
