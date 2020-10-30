#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Netdir: {0}")]
    NetDir(#[from] tor_netdir::Error),
    #[error("Protocol: {0}")]
    Proto(#[from] tor_proto::Error),
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("Tls: {0}")]
    Tls(#[from] native_tls::Error),
    #[error("ChanMgr: {0}")]
    ChanMgr(#[from] tor_chanmgr::Error),
    #[error("Misc: {0}")]
    Misc(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
