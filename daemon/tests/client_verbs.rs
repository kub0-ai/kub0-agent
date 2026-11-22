//! The daemon's old client verbs moved to `kub0` (#61 step 2). For one
//! release each answers with the command that replaced it and exits
//! non-zero, before it reads a state directory or binds anything, under the
//! name it was run as: `kub0d`, or the 0.4.x path kept as a link to it.

use std::process::Command;

#[test]
fn every_retired_client_verb_names_its_kub0_command_and_fails() {
    for (verb, want) in [
        ("connect", "kub0 login"),
        ("disconnect", "kub0 logout"),
        ("status", "kub0 whoami"),
        ("history", "kub0 history"),
        ("brief", "kub0 brief"),
        ("investigate", "kub0 why"),
        ("timeline", "kub0 intel --timeline"),
        ("watch", "kub0 watch"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_kub0d"))
            .args([verb, "--json"])
            .env("HOME", "/nonexistent")
            .output()
            .expect("run kub0d");
        assert_eq!(out.status.code(), Some(2), "{verb}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(&format!("kub0d {verb} is retired")) && err.contains(want), "{verb}: {err}");
        assert!(out.stdout.is_empty(), "{verb}: nothing on stdout for a script to misread");
    }
}
