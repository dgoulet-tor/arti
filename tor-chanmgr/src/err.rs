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

    /// It took too long for us to establish this connection.
    #[error("Channel timed out")]
    ChanTimeout,

    /// An internal error or assumption violation in the TLS implementation.
    #[error("Invalid TLS connection")]
    InvalidTls,

    /// A protocol error while making a channel
    #[error("Protocol error while opening a channel: {0}")]
    Proto(#[from] tor_proto::Error),

    /// A protocol error while making a channel
    #[error("I/O error while opening a channel: {0}")]
    Io(#[from] std::io::Error),

    /// An internal error of some kind that should never occur.
    #[error("Internal error: {0}")]
    Internal(&'static str),
}

impl From<futures::task::SpawnError> for Error {
    fn from(_: futures::task::SpawnError) -> Error {
        Error::Internal("Couldn't spawn channel reactor")
    }
}
