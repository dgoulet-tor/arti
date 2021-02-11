//! Declare an error type for the tor-dirmgr crate.

use thiserror::Error;

/// An error originated by the directory manager code
#[derive(Error, Debug)]
pub enum Error {
    /// We received a document we didn't want at all.
    #[error("unwanted object: {0}")]
    Unwanted(&'static str),
    /// A bad argument was provided to some configuration function.
    #[error("bad argument: {0}")]
    BadArgument(&'static str),
    /// We couldn't read something from disk that we should have been
    /// able to read.
    #[error("corrupt cache: {0}")]
    CacheCorruption(&'static str),
    /// rusqlite gave us an error.
    #[error("sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    /// A schema version that says we can't read it.
    #[error("unrecognized data storage schema")]
    UnrecognizedSchema,
    /// An updater no longer has anything to update.
    #[error("directory updater has shut down")]
    UpdaterShutdown,
    /// We couldn't configure the network.
    #[error("bad network configuration")]
    BadNetworkConfig(&'static str),
}
