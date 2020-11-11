//! Declare an error type for tor-circmgr

use thiserror::Error;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug)]
pub enum Error {
    /// No suitable relays for a request
    #[error("no relays for circuit: {0}")]
    NoRelays(String),

    /// We were waiting on a pending circuit, but it didn't succeed.
    #[error("Pending circuit failed to launch")]
    PendingFailed,
}
