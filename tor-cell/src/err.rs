//! Define an error type for the tor-proto crate.
use std::sync::Arc;
use thiserror::Error;

/// An error type for the tor-proto crate.
///
/// This type should probably be split into several.  There's more
/// than one kind of error that can occur while doing something with
/// the Tor protocol.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    #[error("parsing error: {0}")]
    BytesErr(#[from] tor_bytes::Error),
    /// An error that occurred from the io system.
    #[error("io error: {0}")]
    IoErr(#[source] Arc<std::io::Error>),
    /// There was a programming error somewhere in the code.
    #[error("Internal programming error: {0}")]
    InternalError(String),
    /// Protocol violation at the channel level
    #[error("channel protocol violation: {0}")]
    ChanProto(String),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("invalid stream target address")]
    BadStreamAddress,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoErr(Arc::new(e))
    }
}
