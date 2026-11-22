//! Pure helpers for kub0-block: identity guards, process forest, ownership.
//! Live nftables / conntrack exec stays in the binary so unit tests run off-device.

pub mod block_state;
pub mod caller;
pub mod deps;
pub mod endpoints;
pub mod execgate;
pub mod fleet;
pub mod forest;
pub mod ids;
pub mod nft_verify;
pub mod owners;
pub mod pause;
#[path = "../../daemon/src/rename.rs"]
pub mod rename;
pub mod restore;
pub mod sockets;
pub mod temporary;

pub use caller::{authorize_seed_pids, invoking_uid};
pub use deps::BlockingCaps;
pub use ids::{is_forbidden_app, sanitize_app, ForbiddenApp};
pub use owners::{exclusive_release, grant, OwnerMap};

#[cfg(test)]
mod state_dir_wiring {
    /// Every state directory the helper makes goes through
    /// `rename::create_state_dir`, which never recreates /var/lib/vallum
    /// after kub0d moved it (a helper run that resolved the old root just
    /// before the move fails instead of leaving an empty one behind).
    #[test]
    fn the_helper_makes_state_directories_only_through_the_guard() {
        for (name, src) in [
            ("execgate.rs", include_str!("execgate.rs")),
            ("temporary.rs", include_str!("temporary.rs")),
            ("owners.rs", include_str!("owners.rs")),
            ("restore.rs", include_str!("restore.rs")),
            ("block_state.rs", include_str!("block_state.rs")),
            ("pause.rs", include_str!("pause.rs")),
        ] {
            let code = src.split("#[cfg(test)]").next().unwrap();
            assert!(!code.contains("create_dir_all(") && !code.contains(".recursive(true)"), "{name} makes a directory another way");
        }
        let main = include_str!("main.rs");
        let pause = &main[main.find("fn pause_enforcement()").unwrap()..];
        let pause = &pause[..pause.find("\n}\n").unwrap()];
        assert!(pause.contains("rename::create_state_dir(") && !pause.contains("create_dir_all("), "the pause marker's directory");
    }
}
