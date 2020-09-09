//! Define an error type for the tor-proto crate.
use thiserror::Error;

/// An error type for the tor-proto crate.
///
/// This type should probably be split into several.  There's more
/// than one kind of error that can occur while doing something with
/// the Tor protocol.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    #[error("parsing error: {0}")]
    BytesErr(#[source] tor_bytes::Error),
    /// An error that occurred from the io system.
    #[error("io error: {0}")]
    IoErr(#[source] std::io::Error),
    /// Somebody asked for a key that we didn't have.
    #[error("specified key was missing")]
    MissingKey,
    /// We tried to produce too much output for some function.
    #[error("couldn't produce that much output")]
    InvalidOutputLength,
    /// We tried to encrypt a message to a hop that wasn't there.
    #[error("tried to encrypt to nonexistent hop")]
    NoSuchHop,
    /// There was a programming error somewhere in the code.
    #[error("Internal programming error: {0}")]
    InternalError(String),
    /// The authentication information on this cell was completely wrong,
    /// or the cell was corrupted.
    #[error("bad relay cell authentication")]
    BadCellAuth,
    /// A circuit-extension handshake failed.
    #[error("handshake failed")]
    BadHandshake,
    /// Protocol violation at the channel level
    #[error("channel protocol violation: {0}")]
    ChanProto(String),
}

impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Self {
        Error::BytesErr(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoErr(e)
    }
}
