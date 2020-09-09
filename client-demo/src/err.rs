#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Netdir: {0}")]
    NetDir(#[source] tor_netdir::Error),
    #[error("Protocol: {0}")]
    Proto(#[source] tor_proto::Error),
    #[error("Io: {0}")]
    Io(#[source] std::io::Error),
    #[error("Tls: {0}")]
    Tls(#[source] native_tls::Error),
    #[error("Misc: {0}")]
    Misc(&'static str),
}

impl From<tor_netdir::Error> for Error {
    fn from(e: tor_netdir::Error) -> Self {
        Error::NetDir(e)
    }
}
impl From<tor_proto::Error> for Error {
    fn from(e: tor_proto::Error) -> Self {
        Error::Proto(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
impl From<native_tls::Error> for Error {
    fn from(e: native_tls::Error) -> Self {
        Error::Tls(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
