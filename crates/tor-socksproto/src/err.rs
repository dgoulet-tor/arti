//! Declare an error type for tor_socksproto
use thiserror::Error;

/// An error that occurs while negotiating a SOCKS handshake.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Tried to handle a message what wasn't complete: try again.
    #[error("Message truncated; need to wait for more")]
    Truncated,

    /// The SOCKS client didn't implement SOCKS correctly.
    ///
    /// (Or, more likely, we didn't account for its behavior.)
    #[error("SOCKS protocol syntax violation")]
    Syntax,

    /// The SOCKS client declared a SOCKS version number that isn't
    /// one we support.
    ///
    /// In all likelihood, this is somebody trying to use the port for
    /// some protocol other than SOCKS.
    #[error("Unrecognized SOCKS protocol version {0}")]
    BadProtocol(u8),

    /// The SOCKS client tried to use a SOCKS feature that we don't
    /// support at all.
    #[error("SOCKS feature not supported")]
    NoSupport,

    /// Tried to progress the SOCKS handshake when it was already
    /// finished.  This is a programming error.
    #[error("SOCKS handshake was finished; no need to call this again")]
    AlreadyFinished,

    /// Something went wrong with the programming of this module.
    #[error("Internal programming error while handling SOCKS handshake")]
    Internal,
}

impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Error {
        use tor_bytes::Error as E;
        match e {
            E::Truncated => Error::Truncated,
            _ => Error::Syntax,
        }
    }
}
