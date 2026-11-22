//! Unprivileged connection-monitor library used by `kub0d`.
//!
//! Live capture reads Linux `/proc`. Replay, GeoIP, seen-set keying, and
//! parsers are OS-independent so unit tests run on macOS.

pub mod activity;
pub mod traffic;
pub mod capture;
pub mod control;
pub mod device;
pub mod dns;
pub mod history;
pub mod event;
pub mod execgate;
pub mod fileguard;
pub mod flow;
pub mod geo;
pub mod identity;
pub mod intel;
pub mod kub0;
pub mod lineage;
pub mod netpolicy;
pub mod outcomes;
pub mod outq;
pub mod procfs;
pub mod provenance;
pub mod rdns;
pub mod rename;
pub mod routes;
pub mod seen;
pub mod source;
pub mod sse;
pub mod suggest;
pub mod tags;
pub mod trust;
pub mod watch;

pub use activity::{ActivityApp, ActivityEntry, ActivityKind, ActivityLog};
pub use event::{
    AccountHello, AppIdentity, AppOwner, Connection, DaemonMode, DenylistEntry, Endpoint, Event,
};
pub use flow::{Action, App, Flow, FlowState, Peer, Provenance, SourceKind, Verdict};
pub use geo::GeoDb;
pub use identity::AppResolver;
pub use procfs::{parse_proc_net, ParsedSocket, Protocol};
pub use seen::{network_key, SeenSet};
pub use source::{Backfill, Source, SourceError};

pub mod system_status;
