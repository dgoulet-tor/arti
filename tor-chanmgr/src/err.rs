//! Declare error types for tor-chanmgr

use thiserror::Error;

/// An error returned by a channel manager.
#[derive(Debug, Error)]
pub enum Error {
    /// An IO error occurred when trying to launch a channel.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// An TLS error occurred when trying to launch a channel.
    #[cfg(feature = "nativetls")]
    #[error("TLS error: {0}")]
    NativeTlsError(#[from] native_tls::Error),

    /// A ChanTarget was given for which no channel could be built.
    #[error("Target was unusable: {0}")]
    UnusableTarget(String),

    /// We were waiting on a pending channel, but it didn't succeed.
    #[error("Pending channel failed to launch")]
    PendingFailed,

    /// The tor-proto crate reported an error, most likely in the Tor
    /// handshake.
    #[error("Network: {0}")]
    ProtoError(#[from] tor_proto::Error),

    /// Couldn't launch a reactor task for a channel.
    #[error("Spawn: {0}")]
    SpawnError(#[from] futures::task::SpawnError),
}
