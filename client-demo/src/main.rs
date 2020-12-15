//! A minimal client for connecting to the tor network

#![warn(missing_docs)]

use argh::FromArgs;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use log::{error, info, warn, LevelFilter};
use std::path::PathBuf;
use std::sync::Arc;

use tor_chanmgr::transport::nativetls::NativeTlsTransport;
use tor_dirmgr::DirMgr;
use tor_socksproto::SocksCmd;

use anyhow::{Context, Result};

#[derive(FromArgs)]
/// Make a connection to the Tor network, open a SOCKS port, and proxy
/// traffic.
///
/// This is a demo; you get no stability guarantee.
struct Args {
    /// chutney network that we should use instead of the Tor defaults.
    #[argh(option)]
    chutney_dir: Option<PathBuf>,
    /// enable trace-level logging.
    #[argh(switch)]
    trace: bool,
    /// run a socks proxy on port N.
    #[argh(option, default = "9150")]
    socksport: u16,
}

async fn handle_socks_conn(
    dir: Arc<tor_netdir::NetDir>,
    circmgr: Arc<tor_circmgr::CircMgr>,
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

    let exit_ports = [port];
    let circ = circmgr
        .get_or_launch_exit(dir.as_ref().into(), &exit_ports)
        .await
        .context("Unable to launch circuit for request")?;
    info!("Got a circuit for {}:{}", addr, port);
    drop(dir); // This decreases the refcount on the netdir.

    let stream = circ.begin_stream(&addr, port).await?;
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

async fn run_socks_proxy(
    dir: Arc<tor_dirmgr::DirMgr>,
    circmgr: Arc<tor_circmgr::CircMgr>,
    args: Args,
) -> Result<()> {
    use tor_rtcompat::net::TcpListener;

    let socksport = args.socksport;
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
        let d = dir.netdir().await;
        let ci = Arc::clone(&circmgr);
        tor_rtcompat::task::spawn(async move {
            let res = handle_socks_conn(d, ci, stream).await;
            if let Err(e) = res {
                warn!("connection exited with error: {}", e);
            }
        });
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let filt = if args.trace {
        LevelFilter::Trace
    } else {
        LevelFilter::Debug
    };
    simple_logging::log_to_stderr(filt);

    let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();
    if let Some(chutney_dir) = args.chutney_dir.as_ref() {
        dircfg
            .configure_from_chutney(chutney_dir)
            .context("Can't extract Chutney network configuration")?;
    } else {
        dircfg.add_default_authorities();
    }
    let dircfg = dircfg.finalize();

    tor_rtcompat::task::block_on(async {
        let transport = NativeTlsTransport::new();
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(transport));
        let circmgr = Arc::new(tor_circmgr::CircMgr::new(Arc::clone(&chanmgr)));
        let dirmgr = DirMgr::bootstrap_from_config(dircfg, Arc::clone(&circmgr)).await?;

        run_socks_proxy(dirmgr, circmgr, args).await
    })
}
