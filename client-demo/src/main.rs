mod err;

use err::{Error, Result};

use log::{info, LevelFilter};
use std::path::PathBuf;
use tor_linkspec::ChanTarget;

//use async_std::prelude::*;
use async_native_tls::TlsConnector;
use async_std::net;

use rand::thread_rng;

pub struct Channel {}

async fn connect<C: ChanTarget>(target: &C) -> Result<Channel> {
    let addr = target
        .get_addrs()
        .get(0)
        .ok_or(Error::Misc("No addresses for chosen relay‽"))?;

    let connector = TlsConnector::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true);

    info!("Connecting to {}", addr);
    let stream = net::TcpStream::connect(addr).await?;

    info!("Negotiating TLS with {}", addr);
    let _tlscon = connector.connect("ignored", stream).await?;
    info!("TLS negotiated.");

    Ok(Channel {})
}

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
    simple_logging::log_to_stderr(LevelFilter::Info);

    let dir = get_netdir()?;

    let g = dir
        .pick_relay(&mut thread_rng(), |_, u| u)
        .ok_or(Error::Misc("no usable relays"))?;

    async_std::task::block_on(async {
        let _con = connect(&g).await?;

        Ok(())
    })
}
