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
use tor_proto::channel::{self, Channel};

//use async_std::prelude::*;
use async_native_tls::TlsConnector;
use async_std::net;
use err::{Error, Result};

use rand::thread_rng;

/// Launch an authenticated channel to a relay.
async fn connect<C: ChanTarget>(target: &C) -> Result<Channel> {
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

    let chan = channel::start_client_handshake(tlscon).connect().await?;
    info!("Version negotiated and cells read.");

    let chan = chan.check(target, &peer_cert)?;
    info!("Certificates validated; peer authenticated.");

    let (chan, reactor) = chan.finish(&addr.ip()).await?;
    info!("Channel complete.");

    async_std::task::spawn(async { reactor.run().await });

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
    simple_logging::log_to_stderr(LevelFilter::Debug);

    let dir = get_netdir()?;
    // TODO CONFORMANCE: we should stop now if there are required
    // protovers we don't support.

    let guard = dir
        .pick_relay(&mut thread_rng(), |_, u| u)
        .ok_or(Error::Misc("no usable relays"))?;

    let mid = dir
        .pick_relay(
            &mut thread_rng(),
            |r, u| {
                if r.same_relay(&guard) {
                    0
                } else {
                    u
                }
            },
        )
        .ok_or(Error::Misc("no usable second hop."))?;

    let exit = dir
        .pick_relay(&mut thread_rng(), |r, u| {
            if r.same_relay(&guard) || r.same_relay(&mid) || !r.supports_exit_port(80) {
                0
            } else {
                u
            }
        })
        .ok_or(Error::Misc("no usable second hop."))?;

    async_std::task::block_on(async {
        let mut rng = thread_rng();
        let chan = connect(&guard).await?;

        let mut circ = chan.new_circ(&mut rng).await?;
        /*
        circ.create_firsthop_fast(&mut rng).await?;
        info!("CREATE_FAST was successful.");
         */

        circ.create_firsthop_ntor(&mut rng, &guard).await?;
        info!("ntor handshake with first hop was successful.");

        circ.extend_ntor(&mut rng, &mid).await?;
        info!("ntor handshake with second hop was successful.");

        circ.extend_ntor(&mut rng, &exit).await?;
        info!("ntor handshake with third hop was successful.");

        info!("Built a three-hop circuit.");

        use tor_proto::relaycell::msg;
        let begin = msg::Begin::new("www.torproject.org", 80, 0)?;
        let request =
            msg::Data::new("GET / HTTP/1.0\r\nHost: www.torproject.org\r\n\r\n".as_bytes());
        let begin = msg::RelayCell::new(99.into(), begin.into());
        let request = msg::RelayCell::new(99.into(), request.into());

        circ.send_relay_cell(2, false, begin).await?;
        circ.send_relay_cell(2, false, request).await?;

        loop {
            let (_hopnum, cell) = circ.recv_relay_cell().await?;
            info!("{}", cell.get_cmd());
            match cell.get_msg() {
                msg::RelayMsg::Data(d) => {
                    // XXXX crash on bad utf8.
                    println!("{}", std::str::from_utf8(d.as_ref()).unwrap());
                }
                msg::RelayMsg::End(_) => {
                    break;
                }
                _ => (),
            }
        }

        Ok(())
    })
}
