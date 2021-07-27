//! A general interface for Tor client usage.
//!
//! To construct a client, run the `TorClient::bootstrap()` method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! `TorClient::connect()`.
use tor_circmgr::{IsolationToken, TargetPort};
use tor_dirmgr::DirMgrConfig;
use tor_proto::circuit::{ClientCirc, IpVersionPreference};
use tor_proto::stream::DataStream;
use tor_rtcompat::{Runtime, SleepProviderExt};

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::info;

/// An active client session on the Tor network.
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
    /// Id of the isolation group the connection should be part of
    isolation_group: IsolationToken,
}

impl ConnectPrefs {
    /// Construct a new ConnnectPrefs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv6.
    pub fn ipv6_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv6.
    ///
    /// When this option is set, we will only pick exit relays that
    /// suppport IPv6, and we will tell them to only give us IPv6
    /// connections.
    pub fn ipv6_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Only;
        self
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv4.
    ///
    /// This is the default.
    pub fn ipv4_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv4.
    ///
    /// When this option is set, we will only pick exit relays that
    /// suppport IPv4, and we will tell them to only give us IPv4
    /// connections.
    pub fn ipv4_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Only;
        self
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

    /// Indicate which other connections might use the same circuit
    /// as this one.
    pub fn set_isolation_group(&mut self, isolation_group: IsolationToken) -> &mut Self {
        self.isolation_group = isolation_group;
        self
    }

    /// Return a u64 to describe which connections might use
    /// the same circuit as this one.
    fn isolation_group(&self) -> IsolationToken {
        self.isolation_group
    }

    // TODO: Add some way to be IPFlexible, and require exit to suppport both.
}

impl<R: Runtime> TorClient<R> {
    /// Bootstrap a network connection configured by `dircfg`.
    ///
    /// Return a client once there is enough directory material to
    /// connect safely over the Tor network.
    pub async fn bootstrap(runtime: R, dircfg: DirMgrConfig) -> Result<TorClient<R>> {
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

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network.
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
        let circ = self.circ(&exit_ports, &flags).await?;
        info!("Got a circuit for {}:{}", addr, port);

        // TODO: make this configurable.
        let stream_timeout = Duration::new(10, 0);

        let stream_future = circ.begin_stream(addr, port, Some(flags.begin_flags()));
        let stream = self
            .runtime
            .timeout(stream_timeout, stream_future)
            .await??;

        Ok(stream)
    }

    /// Perform a remote DNS lookup with the provided hostname.
    ///
    /// On success, return a list of IP addresses.
    pub async fn resolve(
        &self,
        hostname: &str,
        flags: Option<ConnectPrefs>,
    ) -> Result<Vec<IpAddr>> {
        let flags = flags.unwrap_or_default();
        let circ = self.circ(&[], &flags).await?;

        // TODO: make this configurable.
        let resolve_timeout = Duration::new(10, 0);

        let resolve_future = circ.resolve(hostname);
        let addrs = self
            .runtime
            .timeout(resolve_timeout, resolve_future)
            .await??;

        Ok(addrs)
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    pub async fn resolve_ptr(
        &self,
        addr: &str,
        flags: Option<ConnectPrefs>,
    ) -> Result<Vec<String>> {
        let flags = flags.unwrap_or_default();
        let circ = self.circ(&[], &flags).await?;
        let addr = IpAddr::from_str(addr)?;

        // TODO: make this configurable.
        let resolve_ptr_timeout = Duration::new(10, 0);

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .runtime
            .timeout(resolve_ptr_timeout, resolve_ptr_future)
            .await??;

        Ok(hostnames)
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

    /// Get or launch a circuit with given exit ports
    async fn circ(
        &self,
        exit_ports: &[TargetPort],
        flags: &ConnectPrefs,
    ) -> Result<Arc<ClientCirc>> {
        let dir = self.dirmgr.netdir();
        let circ = self
            .circmgr
            .get_or_launch_exit(dir.as_ref().into(), exit_ports, flags.isolation_group())
            .await
            .context("Unable to launch circuit")?;
        drop(dir); // This decreases the refcount on the netdir.

        Ok(circ)
    }
}
