//! Declare dirclient-specific errors.

use thiserror::Error;
use tor_rtcompat::timer::TimeoutError;

/// An error originating from the tor-dirclient crate.
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// We received an object with a suspiciously good compression ratio
    #[error("possible compression bomb")]
    CompressionBomb,

    /// The directory cache took too long to reply to us.
    #[error("directory timed out")]
    DirTimeout,

    /// We got an EOF before we were done with the headers.
    #[error("truncated HTTP headers")]
    TruncatedHeaders,

    /// Got an HTTP status other than 200
    #[error("unexpected HTTP status {0:?}")]
    HttpStatus(Option<u16>),

    /// Unrecognized Content-Encoding value.
    #[error("unsupported HTTP encoding {0:?}")]
    BadEncoding(String),

    /// Received a response that was longer than we expected.
    #[error("response too long; gave up after {0} bytes")]
    ResponseTooLong(usize),
}

impl From<TimeoutError> for Error {
    fn from(_: TimeoutError) -> Self {
        Error::DirTimeout
    }
}
