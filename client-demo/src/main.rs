//! A minimal client for connecting to the tor network
//!
//! Right now, all the client does is load a directory from disk, and
//! launch an authenticated handshake.
//!
//! It expects to find a local chutney network, or a cached tor
//! directory.

#![warn(missing_docs)]

mod err;

use argh::FromArgs;
use futures::task::SpawnError;
use log::{info, LevelFilter};
use std::path::PathBuf;
use std::sync::Arc;

use tor_chanmgr::transport::nativetls::NativeTlsTransport;
use tor_proto::circuit::ClientCirc;

use err::{Error, Result};

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
}

struct Spawner {
    name: String,
}

impl Spawner {
    fn new(name: &str) -> Self {
        Spawner {
            name: name.to_string(),
        }
    }
}

impl futures::task::Spawn for Spawner {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> std::result::Result<(), SpawnError> {
        use async_std::task::Builder;
        let builder = Builder::new().name(self.name.clone());
        let _handle = builder.spawn(future).map_err(|_| SpawnError::shutdown())?;
        Ok(())
    }
}

async fn test_cat(mut circ: ClientCirc) -> Result<()> {
    let mut stream = circ.begin_stream("127.0.0.1", 9999).await?;
    for x in 1..2000 {
        let one_k = [b'x'; 1024];
        stream.write_bytes(&one_k[..]).await?;
        dbg!(x);
    }
    dbg!("done");
    Ok(())
}

async fn test_dl(mut circ: ClientCirc) -> Result<()> {
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

async fn test_http(mut circ: ClientCirc) -> Result<()> {
    let mut stream = circ.begin_stream("www.torproject.org", 80).await?;

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
        return Err(Error::Misc("arguments"));
    }
    let mut cfg = tor_netdir::NetDirConfig::new();

    if let Some(ref d) = args.tor_dir {
        cfg.add_default_authorities();
        cfg.set_cache_path(&d);
    } else if let Some(ref d) = args.chutney_dir {
        cfg.add_authorities_from_chutney(&d)?;
        cfg.set_cache_path(&d);
    } else {
        eprintln!("Must specify --tor-dir or --chutney-dir");
        return Err(Error::Misc("arguments"));
    }

    Ok(cfg.load()?)
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

    let dir = get_netdir(&args)?;
    // TODO CONFORMANCE: we should stop now if there are required
    // protovers we don't support.

    async_std::task::block_on(async {
        let spawn = Spawner::new("channel reactors");
        let transport = NativeTlsTransport::new();
        let chanmgr = tor_chanmgr::ChanMgr::new(transport, spawn);

        let spawn = Spawner::new("circuit reactors");
        let circmgr = tor_circmgr::CircMgr::new(Arc::new(chanmgr), Box::new(spawn));

        let exit_ports = &[80];
        let circ = circmgr.get_or_launch_exit(&dir, exit_ports).await?;

        info!("Built a three-hop circuit.");

        for _ in 0..args.n {
            if args.flood {
                test_cat(circ.new_ref()).await?;
            } else if args.dl {
                test_dl(circ.new_ref()).await?;
            } else {
                test_http(circ.new_ref()).await?;
            }
        }

        circ.terminate().await;

        async_std::task::sleep(std::time::Duration::new(10, 0)).await;
        Ok(())
    })
}
