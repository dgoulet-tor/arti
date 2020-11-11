//! Declare error types for tor-chanmgr

use thiserror::Error;

/// An error returned by a channel manager.
#[derive(Debug, Error)]
pub enum Error {
    /// A ChanTarget was given for which no channel could be built.
    #[error("Target was unusable: {0}")]
    UnusableTarget(String),

    /// We were waiting on a pending channel, but it didn't succeed.
    #[error("Pending channel failed to launch")]
    PendingFailed,
}
