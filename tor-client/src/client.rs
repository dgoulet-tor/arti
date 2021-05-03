//! A general interface for Tor client usage.
//!
//! To construct a client, run the `TorClient::bootstrap()` method.
//! Once the client is bootstrapped, you can make connections over the Tor
//! network using `TorClient::connect()`.
use tor_circmgr::TargetPort;
use tor_dirmgr::NetDirConfig;
use tor_proto::circuit::IpVersionPreference;
use tor_proto::stream::DataStream;
use tor_rtcompat::{Runtime, SleepProviderExt};

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::info;

/// An active client connection to the Tor network.
///
/// While it's running, it will fetch directory information, build
/// circuits, and make connections for you.
///
/// Cloning this object makes a new reference to the same underlying
/// handles.
#[derive(Clone)]
pub struct TorClient<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<tor_dirmgr::DirMgr<R>>,
}

/// Preferences for how to route a stream over the Tor network.
#[derive(Debug, Default, Clone)]
pub struct ConnectPrefs {
    /// What kind of IPv6/IPv4 we'd prefer, and how strongly.
    ip_ver_pref: IpVersionPreference,
}

impl ConnectPrefs {
    /// Construct a new ConnnectPrefs.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the preference for what kind of IPv4/IPv6 connection we'd
    /// like to make.
    ///
    /// (By default, IPv4 is preferred.)
    pub fn set_ip_preference(&mut self, pref: IpVersionPreference) {
        self.ip_ver_pref = pref;
    }

    /// Get the begin_flags fields that we should use for the BEGIN
    /// cell for this stream.
    fn begin_flags(&self) -> IpVersionPreference {
        self.ip_ver_pref
    }

    /// Return a TargetPort to describe what kind of exit policy our
    /// target circuit needs to support.
    fn wrap_target_port(&self, port: u16) -> TargetPort {
        match self.ip_ver_pref {
            IpVersionPreference::Ipv6Only => TargetPort::ipv6(port),
            _ => TargetPort::ipv4(port),
        }
    }

    // TODO: Add some way to be IPFlexible, and require exit to suppport both.
}

impl<R: Runtime> TorClient<R> {
    /// Bootstrap a network connection configured by `dircfg`.
    ///
    /// Return a client once there is enough directory material to
    /// connect safely over the Tor network.
    pub async fn bootstrap(runtime: R, dircfg: NetDirConfig) -> Result<TorClient<R>> {
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(runtime.clone()));
        let circmgr = Arc::new(tor_circmgr::CircMgr::new(
            runtime.clone(),
            Arc::clone(&chanmgr),
        ));
        let dirmgr = tor_dirmgr::DirMgr::bootstrap_from_config(
            dircfg,
            runtime.clone(),
            Arc::clone(&circmgr),
        )
        .await?;

        Ok(TorClient {
            runtime,
            circmgr,
            dirmgr,
        })
    }

    /// Launch a connection to the provided address and port over the Tor
    /// network.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    pub async fn connect(
        &self,
        addr: &str,
        port: u16,
        flags: Option<ConnectPrefs>,
    ) -> Result<DataStream> {
        if addr.to_lowercase().ends_with(".onion") {
            return Err(anyhow!("Rejecting .onion address as unsupported."));
        }

        let flags = flags.unwrap_or_default();
        let exit_ports = [flags.wrap_target_port(port)];
        let dir = self.dirmgr.netdir();
        let circ = self
            .circmgr
            .get_or_launch_exit(dir.as_ref().into(), &exit_ports)
            .await
            .context("Unable to launch circuit")?;
        info!("Got a circuit for {}:{}", addr, port);
        drop(dir); // This decreases the refcount on the netdir.

        // TODO: make this configurable.
        let stream_timeout = Duration::new(10, 0);

        let stream_future = circ.begin_stream(&addr, port, Some(flags.begin_flags()));
        let stream = self
            .runtime
            .timeout(stream_timeout, stream_future)
            .await??;

        Ok(stream)
    }

    /// Return a reference to this this client's directory manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn dirmgr(&self) -> Arc<tor_dirmgr::DirMgr<R>> {
        Arc::clone(&self.dirmgr)
    }

    /// Return a reference to this this client's circuit manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn circmgr(&self) -> Arc<tor_circmgr::CircMgr<R>> {
        Arc::clone(&self.circmgr)
    }
}
