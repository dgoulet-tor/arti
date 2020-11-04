use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Message truncated; need to wait for more")]
    Truncated,

    #[error("SOCKS protocol syntax violation")]
    Syntax,

    #[error("Unrecognized SOCKS protocol version {0}")]
    BadProtocol(u8),

    #[error("SOCKS feature not supported")]
    NoSupport,

    #[error("SOCKS handshake was finished; no need to call this again")]
    AlreadyFinished,
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
