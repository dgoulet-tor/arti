//! Declare an error type.

use thiserror::Error;

/// An error originating from the tor-decompress crate.
#[derive(Error, Debug)]
pub enum Error {
    /// We got a Content-Encoding that we didn't understand.
    #[error("Unrecognized content-encoding {0:?}")]
    ContentEncoding(String),

    /// The library reported a status that we don't handle.
    #[error("Unexpected status from library when decompressing")]
    UnexpectedStatus,

    /// Error from the miniz library
    #[error("zlib decompression failure: {0:?}")]
    MinizError(miniz_oxide::MZError),

    /// Error from the zstd library
    #[error("Zstd decompression failure")]
    ZstdError(#[from] std::io::Error),

    /// Error from the xz2 library
    #[error("Xz2 decompression failure")]
    Xz2Error(#[from] xz2::stream::Error),
}

impl From<miniz_oxide::MZError> for Error {
    fn from(e: miniz_oxide::MZError) -> Error {
        Error::MinizError(e)
    }
}
