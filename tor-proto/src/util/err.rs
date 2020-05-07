use std::fmt;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    BytesErr(tor_bytes::Error),
    MissingKey,
    InvalidOutputLength,
    NoSuchHop,
    InternalError,
    BadCellAuth,
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
