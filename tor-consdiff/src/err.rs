use thiserror::Error;

use std::num::ParseIntError;

#[derive(Clone, Debug, Error)]
pub enum Error {
    // TODO: it would be neat to have line numbers here.
    #[error("Invalid diff: {0}")]
    BadDiff(&'static str),
    #[error("Diff didn't apply to input: {0}")]
    CantApply(&'static str),
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Error {
        Error::BadDiff("can't parse line number")
    }
}
impl From<hex::FromHexError> for Error {
    fn from(_e: hex::FromHexError) -> Error {
        Error::BadDiff("invalid hexadecimal in 'hash' line")
    }
}
