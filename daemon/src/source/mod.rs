//! Flow sources.
//!
//! A source is anything that can be asked "what has happened since last time"
//! and answers in [`crate::flow::Flow`]. Upstream's `/proc` sampler, the
//! OpenSnitch database reader, and the eBPF sensor that comes later are all the
//! same shape to everything above them, which is what keeps listen and
//! intercept from becoming two products.

/// The macOS live sampler. Gated because it is FFI against Darwin's libproc
/// and has no meaning elsewhere; every other module here builds on all hosts so
/// that the parsers stay unit-testable off-platform.
#[cfg(target_os = "macos")]
pub mod libproc;
pub mod opensnitch;

use crate::flow::Flow;

/// What a source does the first time it is asked, when it has no cursor yet.
///
/// This only matters for sources that sit on top of a durable store. A live
/// socket sampler has nothing to backfill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backfill {
    /// Start at the newest record. History exists but is not replayed.
    None,
    /// Replay everything recorded on or after local midnight.
    Today,
    /// Replay the whole store.
    All,
}

#[derive(Debug)]
pub enum SourceError {
    /// The source is not installed or not configured to keep data vallum can
    /// read. Not a failure: the daemon carries on with its other sources.
    Unavailable(String),
    /// Configured, present, and did not work. Worth surfacing.
    Failed(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Unavailable(m) => write!(f, "unavailable: {m}"),
            SourceError::Failed(m) => write!(f, "failed: {m}"),
        }
    }
}

impl std::error::Error for SourceError {}

pub trait Source {
    /// Stable identifier, used in logs and in `--source`.
    fn name(&self) -> &'static str;

    /// Flows observed since the last successful poll, oldest first.
    ///
    /// Returning an empty vector is the normal quiet case. A source that cannot
    /// answer must return `Err` rather than an empty vector, so that "nothing
    /// happened" and "I am broken" are never the same value — the same reason
    /// `bytes` distinguishes null from zero.
    fn poll(&mut self) -> Result<Vec<Flow>, SourceError>;
}
