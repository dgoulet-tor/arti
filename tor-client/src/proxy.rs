use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use log::{error, info, warn};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::TorClient;
use tor_proto::circuit::IPVersionPreference;
use tor_socksproto::{SocksCmd, SocksRequest};

use anyhow::{Context, Result};

fn ip_preference(req: &SocksRequest, addr: &str) -> IPVersionPreference {
    if addr.parse::<Ipv4Addr>().is_ok() {
        IPVersionPreference::Ipv4Only
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        IPVersionPreference::Ipv6Only
    } else if req.version() == 4 {
        IPVersionPreference::Ipv4Only
    } else {
        IPVersionPreference::Ipv4Preferred
    }
}

async fn handle_socks_conn(
    client: Arc<TorClient>,
    stream: tor_rtcompat::net::TcpStream,
) -> Result<()> {
    let mut handshake = tor_socksproto::SocksHandshake::new();

    let (mut r, mut w) = stream.split();
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

    if addr.to_lowercase().ends_with(".onion") {
        info!("That's an onion address; rejecting it.");
        return Ok(());
    }

    let begin_flags = ip_preference(&request, &addr);
    let stream = client.connect(&addr, port, Some(begin_flags)).await;
    /*
        let stream = match stream {
            Ok(s) => s,
            // In the case of a stream timeout, send the right SOCKS reply.
            Err(tor_proto::Error::StreamTimeout) => {
                let reply = request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None);
                w.write(&reply[..])
                    .await
                    .context("Couldn't write SOCKS reply")?;
                return Err(tor_proto::Error::StreamTimeout.into());
            }
            // In any other case, just propagate the error downwards
            Err(e) => return Err(e.into()),
        };
    */
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

pub async fn run_socks_proxy(client: Arc<TorClient>, socks_port: Option<u16>) -> Result<()> {
    use tor_rtcompat::net::TcpListener;

    if socks_port.is_none() {
        info!("Nothing to do: no socks_port configured.");
        return Ok(());
    }
    let socksport = socks_port.unwrap();
    let mut listeners = Vec::new();

    for localhost in &["127.0.0.1", "::1"] {
        let addr = (*localhost, socksport);
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
        return Ok(());
    }
    let mut incoming = futures::stream::select_all(listeners.iter().map(TcpListener::incoming));

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
