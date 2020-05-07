use thiserror::Error;

/// Error type for decoding Tor objects from bytes.
#[derive(Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("object truncated (or not fully present)")]
    Truncated,
    #[error("extra bytes at end of object")]
    ExtraneousBytes,
    #[error("bad object: {0}")]
    BadMessage(&'static str),
    #[error("internal programming error")]
    Internal,
}
