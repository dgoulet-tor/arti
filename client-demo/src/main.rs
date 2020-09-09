mod err;

use log::{info, LevelFilter};
use std::path::PathBuf;
use tor_linkspec::ChanTarget;
use tor_proto::channel::{Channel, OutboundClientHandshake};

//use async_std::prelude::*;
use async_native_tls::{TlsConnector, TlsStream};
use async_std::net;
use err::{Error, Result};

use rand::thread_rng;

async fn connect<C: ChanTarget>(target: &C) -> Result<Channel<TlsStream<net::TcpStream>>> {
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
    let tlscon = connector.connect("ignored", stream).await?;
    info!("TLS negotiated.");

    let chan = OutboundClientHandshake::new(tlscon).connect().await?;
    info!("version negotiated and cells read.");
    let chan = chan.check(target)?;
    info!("Certs validated (only not really)");
    let chan = chan.finish(&addr.ip()).await?;
    info!("Channel complete.");

    Ok(chan)
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
    // TODO CONFORMANCE: we should stop now if there are required
    // protovers we don't support.

    let g = dir
        .pick_relay(&mut thread_rng(), |_, u| u)
        .ok_or(Error::Misc("no usable relays"))?;

    async_std::task::block_on(async {
        let _chan = connect(&g).await?;

        Ok(())
    })
}
