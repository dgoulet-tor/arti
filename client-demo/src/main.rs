use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Netdir: {0}")]
    NetDir(#[source] tor_netdir::Error),
    #[error("Protocol: {0}")]
    Proto(#[source] tor_proto::Error),
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

type Result<T> = std::result::Result<T, Error>;

fn get_netdir() -> Result<tor_netdir::NetDir> {
    let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
    pb.push("src");
    pb.push("chutney");
    pb.push("net");
    pb.push("nodes");
    pb.push("000a");

    let mut cfg = tor_netdir::NetDirConfig::new();
    cfg.add_authorities_from_chutney(&pb)?;
    cfg.set_cache_path(&pb);
    Ok(cfg.load()?)
}

fn main() -> Result<()> {
    let _dir = get_netdir()?;

    Ok(())
}
