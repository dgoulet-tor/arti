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
    BytesErr(#[from] tor_bytes::Error),
    /// An error that occurred from the io system.
    #[error("io error: {0}")]
    IoErr(#[from] std::io::Error),
    /// An error occurred in the cell-handling layer.
    #[error("cell encoding error: {0}")]
    CellErr(#[source] tor_cell::Error),
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
    /// Protocol violation at the circuit level
    #[error("circuit protocol violation: {0}")]
    CircProto(String),
    /// Circuit destroyed or channel closed.
    #[error("circuit destroyed: {0}")]
    CircDestroy(String),
    /// Channel is closed.
    #[error("channel closed")]
    ChannelClosed,
    /// Circuit is closed.
    #[error("circuit closed")]
    CircuitClosed,
    /// Can't allocate any more circuit or stream IDs on a channel.
    #[error("too many entries in map: can't allocate ID")]
    IDRangeFull,
    /// Couldn't extend a circuit.
    #[error("circuit extension handshake error: {0}")]
    CircExtend(&'static str),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("invalid stream target address")]
    BadStreamAddress,
    /// Stream closed by end cell
    #[error("stream closed: {0}")]
    StreamClosed(&'static str), // TODO: make this a better type.
    /// Stream protocol violation
    #[error("stream protocol violation: {0}")]
    StreamProto(String),
}

impl From<tor_cell::Error> for Error {
    fn from(err: tor_cell::Error) -> Error {
        match err {
            tor_cell::Error::ChanProto(msg) => Error::ChanProto(msg),
            _ => Error::CellErr(err),
        }
    }
}

/// Internal type: Error return value from reactor's run_once
/// function: indicates an error or a shutdown.
#[derive(Debug)]
pub(crate) enum ReactorError {
    /// The reactor should shut down with an abnormal exit condition.
    Err(Error),
    /// The reactor should shut down without an error, since all is well.
    Shutdown,
}
impl From<Error> for ReactorError {
    fn from(e: Error) -> ReactorError {
        ReactorError::Err(e)
    }
}
#[cfg(test)]
impl ReactorError {
    /// Tests only: assert that this is an Error, and return it.
    pub(crate) fn unwrap_err(self) -> Error {
        match self {
            ReactorError::Shutdown => panic!(),
            ReactorError::Err(e) => e,
        }
    }
}
