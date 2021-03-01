//! Implement a simple SOCKS proxy that relays connections over Tor.

#[allow(unused)]
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use log::{error, info, warn};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
#[allow(unused)]
use tor_rtcompat::traits::*;

use crate::{client::ConnectPrefs, TorClient};
use tor_proto::circuit::IPVersionPreference;
use tor_socksproto::{SocksCmd, SocksRequest};

use anyhow::{Context, Result};

/// Find out which kind of address family we can/should use for a
/// given socks request.
fn ip_preference(req: &SocksRequest, addr: &str) -> IPVersionPreference {
    if addr.parse::<Ipv4Addr>().is_ok() {
        // If they asked for an IPv4 address correctly, nothing else will do.
        IPVersionPreference::Ipv4Only
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        // If they asked for an IPv6 address correctly, nothing else will do.
        IPVersionPreference::Ipv6Only
    } else if req.version() == 4 {
        // SOCKS4 and SOCKS4a only support IPv4
        IPVersionPreference::Ipv4Only
    } else {
        // Otherwise, default to saying IPv4 is preferred.
        IPVersionPreference::Ipv4Preferred
    }
}

/// Given a just-received TCP connection on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
async fn handle_socks_conn(
    client: Arc<TorClient>,
    stream: tor_rtcompat::net::TcpStream,
) -> Result<()> {
    let mut handshake = tor_socksproto::SocksHandshake::new();

    let (mut r, mut w) = tor_rtcompat::net::split_io(stream);
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        // Read some more stuff.
        n_read += r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // try to advance the handshake.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(tor_socksproto::Error::Truncated) => continue,
            Err(e) => return Err(e.into()),
            Ok(action) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            (&mut inbuf).copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            w.write(&action.reply[..])
                .await
                .context("Error while writing reply to SOCKS handshake")?;
        }
        if action.finished {
            break handshake.into_request();
        }
    }
    .unwrap();

    let addr = request.addr().to_string();
    let port = request.port();
    info!("Got a socks request for {}:{}", addr, port);
    if request.command() != SocksCmd::CONNECT {
        warn!("Dropping request; {:?} is unsupported", request.command());
        return Ok(());
    }

    let mut prefs = ConnectPrefs::new();
    prefs.set_ip_preference(ip_preference(&request, &addr));
    let stream = client.connect(&addr, port, Some(prefs)).await;
    let stream = match stream {
        Ok(s) => s,
        // In the case of a stream timeout, send the right SOCKS reply.
        Err(e) => {
            // TODO: Using downcast_ref() here is ugly. maybe we shouldn't
            // be using anyhow at this point?
            match e.downcast_ref::<tor_proto::Error>() {
                Some(tor_proto::Error::StreamTimeout) => {
                    let reply = request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None);
                    w.write(&reply[..])
                        .await
                        .context("Couldn't write SOCKS reply")?;
                    return Err(tor_proto::Error::StreamTimeout.into());
                }
                _ => return Err(e),
            }
        }
    };
    info!("Got a stream for {}:{}", addr, port);
    // TODO: XXXX-A1 Should send a SOCKS reply if something fails.

    let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
    w.write(&reply[..])
        .await
        .context("Couldn't write SOCKS reply")?;

    let (mut rstream, wstream) = stream.split();

    let _t1 = tor_rtcompat::task::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let n = match r.read(&mut buf[..]).await {
                Err(e) => break e.into(),
                Ok(0) => break tor_proto::Error::StreamClosed("closed"),
                Ok(n) => n,
            };
            if let Err(e) = wstream.write_bytes(&buf[..n]).await {
                break e;
            }
        }
    });
    let _t2 = tor_rtcompat::task::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let n = match rstream.read_bytes(&mut buf[..]).await {
                Err(e) => break e,
                Ok(n) => n,
            };
            if let Err(e) = w.write(&buf[..n]).await {
                break e.into();
            }
        }
    });

    // TODO: XXXX-A1 we should close the TCP stream if either task fails.

    Ok(())
}

/// Launch a SOCKS proxy to listen on a given localhost port, and run until
/// indefinitely.
pub async fn run_socks_proxy(client: Arc<TorClient>, socks_port: u16) -> Result<()> {
    use tor_rtcompat::net::TcpListener;
    let mut listeners = Vec::new();

    for localhost in &["127.0.0.1", "::1"] {
        let addr = (*localhost, socks_port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!("Listening on {:?}.", addr);
                listeners.push(listener);
            }
            Err(e) => warn!("Can't listen on {:?}: {}", addr, e),
        }
    }
    if listeners.is_empty() {
        error!("Couldn't open any listeners.");
        return Ok(()); // XXXX should return an error.
    }
    #[cfg(feature = "async-std")]
    let streams_iter = listeners.iter();
    #[cfg(feature = "tokio")]
    let streams_iter = listeners.into_iter();

    let mut incoming =
        futures::stream::select_all(streams_iter.map(tor_rtcompat::net::listener_to_stream));

    while let Some(stream) = incoming.next().await {
        let stream = stream.context("Failed to receive incoming stream on SOCKS port")?;
        let client_ref = Arc::clone(&client);
        tor_rtcompat::task::spawn(async move {
            let res = handle_socks_conn(client_ref, stream).await;
            if let Err(e) = res {
                warn!("connection exited with error: {}", e);
            }
        });
    }

    Ok(())
}
