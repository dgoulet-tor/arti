//! A minimal client for connecting to the tor network
//!
//! Right now, all the client does is load a directory from disk, and
//! launch an authenticated handshake.
//!
//! It expects to find a local chutney network running in
//! `${HOME}/src/chutney/net/nodes/`.  This is hardwired for now, so that
//! I don't accidentally turn it loose on the tor network.

#![warn(missing_docs)]

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

/// Launch an authenticated channel to a relay.
async fn connect<C: ChanTarget>(target: &C) -> Result<Channel<TlsStream<net::TcpStream>>> {
    let addr = target
        .get_addrs()
        .get(0) // Instead we might want to try multiple addresses in parallel
        .ok_or(Error::Misc("No addresses for chosen relay‽"))?;

    // These function names are scary, but they just mean that we're skipping
    // web pki, and using our own PKI functions.
    let connector = TlsConnector::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true);

    info!("Connecting to {}", addr);
    let stream = net::TcpStream::connect(addr).await?;

    info!("Negotiating TLS with {}", addr);
    let tlscon = connector.connect("ignored", stream).await?;
    info!("TLS negotiated.");

    // Extract the peer certificate now before we wrap the tlscon.
    let peer_cert = tlscon
        .peer_certificate()?
        .ok_or(Error::Misc("Somehow a TLS server didn't show a cert?"))?
        .to_der()?;

    let chan = OutboundClientHandshake::new(tlscon).connect().await?;
    info!("Version negotiated and cells read.");

    let chan = chan.check(target, &peer_cert)?;
    info!("Certificates validated; peer authenticated.");

    let chan = chan.finish(&addr.ip()).await?;
    info!("Channel complete.");

    Ok(chan)
}

/// Load a network directory from `~/src/chutney/net/nodes/000a/`
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
