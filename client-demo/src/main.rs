//! A minimal client for connecting to the tor network
//!
//! Right now, all the client does is load a directory from disk, and
//! launch an authenticated handshake.
//!
//! It expects to find a local chutney network, or a cached tor
//! directory.

#![warn(missing_docs)]

use argh::FromArgs;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use log::{info, warn, LevelFilter};
use std::path::PathBuf;
use std::sync::Arc;

use tor_chanmgr::transport::nativetls::NativeTlsTransport;
use tor_proto::circuit::ClientCirc;

use anyhow::{anyhow, Context, Result};

#[derive(FromArgs)]
/// Make a connection to the Tor network, connect to
/// www.torproject.org, and see a redirect page. Requires a tor
/// directory cache, or running chutney network.
///
/// This is a demo; you get no stability guarantee.
struct Args {
    /// where to find a tor directory cache.  Why not try ~/.tor?
    #[argh(option)]
    tor_dir: Option<PathBuf>,
    /// where to find a chutney directory.
    #[argh(option)]
    chutney_dir: Option<PathBuf>,
    /// how many times to repeat the test
    #[argh(option, default = "1")]
    n: usize,
    /// try doing a flooding test (to 127.0.0.1:9999)? Requires chutney.
    #[argh(switch)]
    flood: bool,
    /// try doing a download test (to 127.0.0.1:9999)? Requires chutney.
    #[argh(switch)]
    dl: bool,
    /// enable trace-level logging
    #[argh(switch)]
    trace: bool,
    /// run a socks proxy on port N. [WILL NOT WORK YET]
    #[argh(option)]
    socksport: Option<u16>,

    /// TODO: Remove this once I have a real directory client.
    #[argh(switch)]
    dirclient: bool,
}

async fn test_cat(circ: Arc<ClientCirc>) -> Result<()> {
    let stream = circ.begin_stream("127.0.0.1", 9999).await?;
    for x in 1..2000 {
        let one_k = [b'x'; 1024];
        stream.write_bytes(&one_k[..]).await?;
        dbg!(x);
    }
    dbg!("done");
    Ok(())
}

async fn test_dl(circ: Arc<ClientCirc>) -> Result<()> {
    let mut stream = circ.begin_stream("127.0.0.1", 9999).await?;
    let mut n_read = 0;
    let mut buf = [0u8; 512];
    while let Ok(n) = stream.read_bytes(&mut buf[..]).await {
        if n == 0 {
            dbg!("Closed, apparently.");
        }
        n_read += n;
        dbg!(n_read);
        if n_read >= 1000000 {
            dbg!(n_read);
            break;
        }
    }
    dbg!("done?");
    Ok(())
}

async fn test_http(circ: Arc<ClientCirc>) -> Result<()> {
    let mut stream = circ
        .begin_stream("www.torproject.org", 80)
        .await
        .context("making stream to www.torproject.org")?;

    let request = b"GET / HTTP/1.0\r\nHost: www.torproject.org\r\n\r\n";

    stream.write_bytes(&request[..]).await?;

    let mut buf = [0u8; 512];
    while let Ok(n) = stream.read_bytes(&mut buf[..]).await {
        if n == 0 {
            break;
        }
        let msg = &buf[..n];
        // XXXX this will crash on bad utf-8
        println!("{}", std::str::from_utf8(msg).unwrap());
    }
    Ok(())
}

/// Load a network directory from `~/src/chutney/net/nodes/000a/`
fn get_netdir(args: &Args) -> Result<tor_netdir::NetDir> {
    if args.tor_dir.is_some() && args.chutney_dir.is_some() {
        eprintln!("Can't specify both --tor-dir and --chutney-dir");
        return Err(anyhow!("Conflicting --tor-dir and --chutney-dir"));
    }
    let mut cfg = tor_netdir::NetDirConfig::new();

    if let Some(ref d) = args.tor_dir {
        cfg.add_default_authorities();
        cfg.set_cache_path(&d);
    } else if let Some(ref d) = args.chutney_dir {
        cfg.add_authorities_from_chutney(&d)
            .context("Loading authorities from chutney directory")?;
        cfg.set_cache_path(&d);
    } else {
        eprintln!("Must specify --tor-dir or --chutney-dir");
        return Err(anyhow!("Missing --tor-dir or --chutney-dir"));
    }

    let partial = cfg.load().context("Loading directory from disk")?;
    Ok(partial.unwrap_if_sufficient().unwrap())
}

async fn handle_socks_conn(
    dir: Arc<tor_netdir::NetDir>,
    circmgr: Arc<tor_circmgr::CircMgr<NativeTlsTransport>>,
    stream: tor_rtcompat::net::TcpStream,
) -> Result<()> {
    let mut handshake = tor_socksproto::SocksHandshake::new();

    let (mut r, mut w) = stream.split();
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        // Read some more stuff.
        n_read += r.read(&mut inbuf[n_read..]).await?;

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
            w.write(&action.reply[..]).await?;
        }
        if action.finished {
            break handshake.into_request();
        }
    }
    .unwrap();

    let addr = request.addr().to_string();
    let port = request.port();
    info!("Got a socks request for {}:{}", addr, port);

    let exit_ports = [port];
    let circ = circmgr
        .get_or_launch_exit(dir.as_ref().into(), &exit_ports)
        .await?;
    info!("Got a circuit for {}:{}", addr, port);

    let stream = circ.begin_stream(&addr, port).await?;
    info!("Got a stream for {}:{}", addr, port);
    // TODO: Should send a SOCKS reply if something fails.

    let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
    w.write(&reply[..]).await?;

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

    // TODO: we should close the TCP stream if either task fails.

    Ok(())
}

async fn run_socks_proxy(
    dir: tor_netdir::NetDir,
    circmgr: tor_circmgr::CircMgr<NativeTlsTransport>,
    args: Args,
) -> Result<()> {
    let dir = Arc::new(dir);
    let circmgr = Arc::new(circmgr);
    let listener =
        tor_rtcompat::net::TcpListener::bind(("localhost", args.socksport.unwrap())).await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        let d = Arc::clone(&dir);
        let ci = Arc::clone(&circmgr);
        tor_rtcompat::task::spawn(async move {
            let res = handle_socks_conn(d, ci, stream).await;
            if let Err(e) = res {
                warn!("connection edited with error: {}", e);
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

    if args.chutney_dir.is_none() && (args.flood || args.dl) {
        eprintln!("--flood and --dl both require --chutney-dir.");
        return Ok(());
    }

    tor_rtcompat::task::block_on(async {
        let transport = NativeTlsTransport::new();
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(transport));

        let circmgr = tor_circmgr::CircMgr::new(Arc::clone(&chanmgr));

        // TODO: This is just a kludge for testing.
        if args.dirclient {
            let fb = tor_netdir::fallback::FallbackSet::new();
            let store = tor_netdir::storage::sqlite::SqliteStore::from_path("/home/nickm/.arti")?;
            let store = tor_dirmgr::DirStoreHandle::new(store);
            let circmgr = Arc::new(circmgr);
            let mut cfg = tor_netdir::NetDirConfig::new();
            cfg.add_default_authorities();
            let authorities = cfg.into_authorities();

            let outcome = tor_dirmgr::bootstrap_directory(
                authorities,
                store.clone(),
                (&fb).into(),
                Arc::clone(&circmgr),
            )
            .await;

            outcome?;
            return Ok(());
        }

        let dir = get_netdir(&args)?;
        // TODO CONFORMANCE: we should stop now if there are required
        // protovers we don't support.

        if args.socksport.is_some() {
            return run_socks_proxy(dir, circmgr, args).await;
        }

        let exit_ports = &[80];
        let circ = circmgr
            .get_or_launch_exit((&dir).into(), exit_ports)
            .await?;

        info!("Built a three-hop circuit.");

        for _ in 0..args.n {
            if args.flood {
                test_cat(Arc::clone(&circ)).await?;
            } else if args.dl {
                test_dl(Arc::clone(&circ)).await?;
            } else {
                test_http(Arc::clone(&circ)).await?;
            }
        }

        circ.terminate().await;

        tor_rtcompat::task::sleep(std::time::Duration::new(3, 0)).await;
        Ok(())
    })
}
