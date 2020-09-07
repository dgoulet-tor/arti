use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0:?}")]
    Io(#[source] std::io::Error),
    #[error("bad signature")]
    Sig(#[source] signature::Error),
    #[error("not currently valid: {0}")]
    Untimely(#[source] tor_checkable::TimeValidityError),
    #[error("unwanted object: {0}")]
    Unwanted(&'static str),
    #[error("bad document: {0}")]
    BadDoc(#[source] tor_netdoc::Error),
    #[error("bad argument: {0}")]
    BadArgument(&'static str),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<signature::Error> for Error {
    fn from(e: signature::Error) -> Error {
        Error::Sig(e)
    }
}

impl From<tor_checkable::TimeValidityError> for Error {
    fn from(e: tor_checkable::TimeValidityError) -> Error {
        Error::Untimely(e)
    }
}

impl From<tor_netdoc::Error> for Error {
    fn from(e: tor_netdoc::Error) -> Error {
        Error::BadDoc(e)
    }
}
