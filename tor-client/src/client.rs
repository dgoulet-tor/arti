use tor_chanmgr::transport::nativetls::NativeTlsTransport;
use tor_circmgr::TargetPort;
use tor_dirmgr::NetDirConfig;
use tor_proto::circuit::IPVersionPreference;
use tor_proto::stream::DataStream;

use std::sync::Arc;

use anyhow::{Context, Result};
use log::info;

pub struct TorClient {
    circmgr: Arc<tor_circmgr::CircMgr>,
    dirmgr: Arc<tor_dirmgr::DirMgr>,
}

impl TorClient {
    pub async fn bootstrap(dircfg: NetDirConfig) -> Result<TorClient> {
        let transport = NativeTlsTransport::new();
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(transport));
        let circmgr = Arc::new(tor_circmgr::CircMgr::new(Arc::clone(&chanmgr)));
        let dirmgr =
            tor_dirmgr::DirMgr::bootstrap_from_config(dircfg, Arc::clone(&circmgr)).await?;

        Ok(TorClient { circmgr, dirmgr })
    }

    // XXXX use better options
    pub async fn connect(
        &self,
        addr: &str,
        port: u16,
        flags: Option<IPVersionPreference>,
    ) -> Result<DataStream> {
        let exit_ports = [if flags == Some(IPVersionPreference::Ipv6Only) {
            TargetPort::ipv6(port)
        } else {
            TargetPort::ipv4(port)
        }];

        let dir = self.dirmgr.netdir().await;
        let circ = self
            .circmgr
            .get_or_launch_exit(dir.as_ref().into(), &exit_ports)
            .await
            .context("Unable to launch circuit")?;
        info!("Got a circuit for {}:{}", addr, port);
        drop(dir); // This decreases the refcount on the netdir.

        let stream = circ.begin_stream(&addr, port, flags).await?;

        Ok(stream)
    }
}
