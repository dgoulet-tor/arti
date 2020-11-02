use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// An error from the protocol module
    #[error("protocol: {0}")]
    ProtoErr(#[from] tor_proto::Error),

    /// No suitable relays for a request
    #[error("no relays for circuit: {0}")]
    NoRelays(String),

    /// Error from channel manager
    #[error("channel: {0}")]
    ChanErr(#[from] tor_chanmgr::Error),

    /// Couldn't launch a reactor task for a circuit.
    #[error("Spawn: {0}")]
    SpawnError(#[from] futures::task::SpawnError),

    /// We were waiting on a pending circuit, but it didn't succeed.
    #[error("Pending circuit failed to launch")]
    PendingFailed,
}
