//! Implement a simple SOCKS proxy that relays connections over Tor.

use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use log::{error, info, warn};
use std::io::Result as IoResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tor_client::{ConnectPrefs, TorClient};
use tor_rtcompat::{Runtime, TcpListener, TimeoutError};
use tor_socksproto::{SocksCmd, SocksRequest};

use anyhow::{Context, Result};

/// Find out which kind of address family we can/should use for a
/// given socks request.
fn stream_preference(req: &SocksRequest, addr: &str) -> ConnectPrefs {
    let mut prefs = ConnectPrefs::new();
    if addr.parse::<Ipv4Addr>().is_ok() {
        // If they asked for an IPv4 address correctly, nothing else will do.
        prefs.ipv4_only();
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        // If they asked for an IPv6 address correctly, nothing else will do.
        prefs.ipv6_only();
    } else if req.version() == 4 {
        // SOCKS4 and SOCKS4a only support IPv4
        prefs.ipv4_only();
    } else {
        // Otherwise, default to saying IPv4 is preferred.
        prefs.ipv4_preferred();
    }
    prefs
}

/// Given a just-received TCP connection on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
async fn handle_socks_conn<R, S>(runtime: R, client: Arc<TorClient<R>>, stream: S) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
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
    };
    let request = match request {
        Some(r) => r,
        None => {
            warn!("SOCKS handshake succeeded, but couldn't convert into a request.");
            return Ok(());
        }
    };

    let addr = request.addr().to_string();
    let port = request.port();
    info!("Got a socks request for {}:{}", addr, port);
    if request.command() != SocksCmd::CONNECT {
        warn!("Dropping request; {:?} is unsupported", request.command());
        return Ok(());
    }

    let prefs = stream_preference(&request, &addr);
    let stream = client.connect(&addr, port, Some(prefs)).await;
    let stream = match stream {
        Ok(s) => s,
        // In the case of a stream timeout, send the right SOCKS reply.
        Err(e) => {
            // TODO: Using downcast_ref() here is ugly. maybe we shouldn't
            // be using anyhow at this point?
            match e.downcast_ref::<TimeoutError>() {
                Some(_) => {
                    let reply = request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None);
                    w.write(&reply[..])
                        .await
                        .context("Couldn't write SOCKS reply")?;
                    return Err(e);
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

    let (rstream, wstream) = stream.split();

    runtime.spawn(copy_interactive(r, wstream).map(|_| ()))?;
    runtime.spawn(copy_interactive(rstream, w).map(|_| ()))?;

    // TODO: XXXX-A1 we should close the TCP stream if either task fails. Do we?
    // TODO: XXXX-A1 should report the errors.

    Ok(())
}

/// Copy all the data from `reader` into `writer` until we encounter an EOF or
/// an error.
///
/// Unlike as futures::io::copy(), this function is meant for use with
/// interactive readers and writers, in which the writer might need to
/// be flushed for any buffered data to be sent.  It tries to minimize
/// the number of flushes, by only flushing the writer when the reader
/// has no data.
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let mut read_future = reader.read(&mut buf[..]);
        match poll!(&mut read_future) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match read_future.await {
            Err(e) => break Err(e),
            Ok(0) => break Ok(()),
            Ok(n) => writer.write_all(&buf[..n]).await?,
        }
    };

    // Make sure that we flush any lingering data if we can.
    //
    // If there is a difference between closing and dropping, then we
    // only want to do a "proper" close if the reader closed cleanly.
    let flush_result = if loop_result.is_ok() {
        writer.close().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}

/// Launch a SOCKS proxy to listen on a given localhost port, and run until
/// indefinitely.
pub(crate) async fn run_socks_proxy<R: Runtime>(
    runtime: R,
    client: Arc<TorClient<R>>,
    socks_port: u16,
) -> Result<()> {
    let mut listeners = Vec::new();

    let localhosts: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
    for localhost in &localhosts {
        let addr: SocketAddr = (*localhost, socks_port).into();
        match runtime.listen(&addr).await {
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

    let mut incoming =
        futures::stream::select_all(listeners.into_iter().map(TcpListener::incoming));

    while let Some(stream) = incoming.next().await {
        let (stream, _addr) = stream.context("Failed to receive incoming stream on SOCKS port")?;
        let client_ref = Arc::clone(&client);
        let runtime_copy = runtime.clone();
        runtime.spawn(async move {
            let res = handle_socks_conn(runtime_copy, client_ref, stream).await;
            if let Err(e) = res {
                warn!("connection exited with error: {}", e);
            }
        })?;
    }

    Ok(())
}
