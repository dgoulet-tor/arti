//! Declare error types for tor-chanmgr

use std::sync::Arc;
use thiserror::Error;

/// An error returned by a channel manager.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
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

    /// A protocol error while making a channel
    #[error("Protocol error while opening a channel: {0}")]
    Proto(#[from] tor_proto::Error),

    /// A protocol error while making a channel
    #[error("I/O error while opening a channel: {0}")]
    Io(#[source] Arc<std::io::Error>),

    /// An internal error of some kind that should never occur.
    #[error("Internal error: {0}")]
    Internal(&'static str),

    /// We were waiting for a channel to complete, but it failed.
    #[error("Pending channel failed to open: {0}")]
    PendingChanFailed(#[from] PendingChanError),
}

impl From<futures::task::SpawnError> for Error {
    fn from(_: futures::task::SpawnError) -> Error {
        Error::Internal("Couldn't spawn channel reactor")
    }
}

impl From<tor_rtcompat::TimeoutError> for Error {
    fn from(_: tor_rtcompat::TimeoutError) -> Error {
        Error::ChanTimeout
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Error {
        Error::Internal("Thread failed while holding lock")
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(Arc::new(e))
    }
}

/// An error transmitted by a future that trying to build a channel.
#[derive(Debug, Clone)]
pub struct PendingChanError(String);
impl std::error::Error for PendingChanError {}
impl std::fmt::Display for PendingChanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl From<&Error> for PendingChanError {
    fn from(e: &Error) -> PendingChanError {
        PendingChanError(e.to_string())
    }
}
