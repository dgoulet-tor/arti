use thiserror::Error;

use std::num::ParseIntError;

#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error("Invalid diff.")]
    BadDiff,
    #[error("Diff refers to an impossible line number.")]
    NoSuchLine,
    #[error("Misformed integer in diff.")]
    InvalidInt,
    #[error("Can't parse the diff.")]
    CantParse,
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Error {
        Error::InvalidInt
    }
}
impl From<hex::FromHexError> for Error {
    fn from(_e: hex::FromHexError) -> Error {
        Error::BadDiff
    }
}
