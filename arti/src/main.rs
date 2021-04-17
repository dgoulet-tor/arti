//! A minimal client for connecting to the tor network

#![warn(missing_docs)]

mod proxy;

use std::sync::Arc;

use tor_client::TorClient;
use tor_config::CfgPath;
use tor_dirmgr::{DownloadScheduleConfig, NetDirConfig, NetworkConfig};
use tor_rtcompat::SpawnBlocking;

use anyhow::Result;
use argh::FromArgs;
use log::{info, warn, LevelFilter};
use serde::Deserialize;

#[derive(FromArgs, Debug, Clone)]
/// Make a connection to the Tor network, open a SOCKS port, and proxy
/// traffic.
///
/// This is a demo; you get no stability guarantee.
struct Args {
    /// override the default location(s) for the configuration file
    #[argh(option, short = 'f')]
    rc: Vec<String>,
    /// override a configuration option (uses toml syntax)
    #[argh(option, short = 'c')]
    cfg: Vec<String>,
}

/// Default options to use for our configuration.
const ARTI_DEFAULTS: &str = concat!(
    include_str!("./arti_defaults.toml"),
    include_str!("./authorities.toml"),
);

/// Structure to hold our configuration options, whether from a
/// configuration file or the command line.
///
/// NOTE: These are NOT the final options or their final layout.
/// Expect NO stability here.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ArtiConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    socks_port: Option<u16>,
    /// Whether to log at trace level.
    trace: bool,

    /// Information about the Tor network we want to connect to.
    network: NetworkConfig,

    /// Directories for storing information on disk
    storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: DownloadScheduleConfig,
}

/// Configuration for where information should be stored on disk.
///
/// This section is for read/write storage
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Location on disk for cached directory information
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    #[allow(unused)]
    state_dir: CfgPath,
}

impl ArtiConfig {
    fn get_dir_config(&self) -> Result<NetDirConfig> {
        let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();
        dircfg.set_network_config(self.network.clone());
        dircfg.set_timing_config(self.download_schedule.clone());
        dircfg.set_cache_path(&self.storage.cache_dir.path()?);
        dircfg.finalize()
    }
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let dflt_config = tor_config::default_config_file();

    let mut cfg = config::Config::new();
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;
    tor_config::load(&mut cfg, dflt_config, &args.rc, &args.cfg)?;

    let config: ArtiConfig = cfg.try_into()?;

    let filt = if config.trace {
        LevelFilter::Trace
    } else {
        LevelFilter::Debug
    };
    simple_logging::log_to_stderr(filt);

    let dircfg = config.get_dir_config()?;

    let socks_port = match config.socks_port {
        Some(s) => s,
        None => {
            info!("Nothing to do: no socks_port configured.");
            return Ok(());
        }
    };

    let runtime = tor_rtcompat::runtime();
    let rt_copy = runtime.clone();
    rt_copy.block_on(async {
        let client = Arc::new(TorClient::bootstrap(runtime.clone(), dircfg).await?);
        proxy::run_socks_proxy(runtime, client, socks_port).await
    })
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn load_default_config() -> Result<()> {
        // TODO: this is duplicate code.
        let mut cfg = config::Config::new();
        cfg.merge(config::File::from_str(
            ARTI_DEFAULTS,
            config::FileFormat::Toml,
        ))?;

        let _parsed: ArtiConfig = cfg.try_into()?;
        Ok(())
    }
}
