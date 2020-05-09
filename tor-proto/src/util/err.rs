//! Define an error type for the tor-proto crate.
use std::fmt;

/// An error type for the tor-proto crate.
///
/// This type should probably be split into several.  There's more
/// than one kind of error that can occur while doing something with
/// the Tor protocol.
///
/// TODO: convert this to use thiserror.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    BytesErr(tor_bytes::Error),
    /// Somebody asked for a key that we didn't have.
    MissingKey,
    /// We tried to produce too much output for some function.
    InvalidOutputLength,
    /// We tried to encrypt a message to a hop that wasn't there.
    NoSuchHop,
    /// There was a programming error somewhere in the code.
    InternalError,
    /// The authentication information on this cell was completely wrong,
    /// or the cell was corrupted.
    BadCellAuth,
    /// A circuit-extension handshake failed.
    BadHandshake,
}

impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Self {
        Error::BytesErr(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            BytesErr(e) => {
                return e.fmt(f);
            }
            MissingKey => "Request that would need a key I don't have",
            InvalidOutputLength => "Tried to extract too much data from a KDF",
            InternalError => "Ran into an internal programming error",
            NoSuchHop => "Tried to send a cell to a hop that wasn't there",
            BadCellAuth => "Cell wasn't for me, or hash was bad",
            BadHandshake => "Incorrect handshake.",
        }
        .fmt(f)
    }
}

impl std::error::Error for Error {}
