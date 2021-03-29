//! Trait and implementation for a "Connector" type.
//!
//! The `Connector` trait is internal to the tor-chanmgr crate, and
//! helps us avoid having `ChanMgr` be polymorphic on transport type.
//! Instead, it can hold a boxed Connector.

use crate::transport::Transport;
use crate::Result;

use tor_linkspec::ChanTarget;
use tor_llcrypto::pk;

#[cfg(test)]
use crate::testing::{FakeChannel as Channel, FakeChannelBuilder as ChannelBuilder};
#[cfg(not(test))]
use tor_proto::channel::{Channel, ChannelBuilder};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;

/// A Connector knows how to make a channel given the summarized information
/// from a ChanTarget.
#[async_trait]
pub(crate) trait Connector {
    /// Create a new channel to `target`, trying exactly once, not timing out.
    async fn build_channel(&self, target: &TargetInfo) -> Result<Arc<Channel>>;
}

// Every Transport is automatically a Connector.
#[async_trait]
impl<TR: Transport + Send + Sync> Connector for TR {
    async fn build_channel(&self, target: &TargetInfo) -> Result<Arc<Channel>> {
        use tor_rtcompat::tls::CertifiedConn;
        let (addr, tls) = self
            .connect(target)
            .await
            .context("Can't negotiate TLS with channel target")?;

        let peer_cert = tls
            .peer_certificate()?
            .ok_or_else(|| anyhow!("Somehow got a TLS connection without a certificate"))?;

        let mut builder = ChannelBuilder::new();
        builder.set_declared_addr(addr);
        let chan = builder.launch(tls).connect().await?;
        let chan = chan.check(target, &peer_cert)?;
        let (chan, reactor) = chan.finish().await?;

        tor_rtcompat::task::spawn(async {
            let _ = reactor.run().await;
        });
        Ok(chan)
    }
}

/// TargetInfo is a summary of a [`ChanTarget`] that we can pass to
/// [`Connector::build_channel`].
///
/// This is a separate type since we can't declare Connector as having
/// a method that's parameterized in today's Rust.
pub(crate) struct TargetInfo {
    /// Copy of the addresses from the underlying ChanTarget.
    addrs: Vec<SocketAddr>,
    /// Copy of the ed25519 id from the underlying ChanTarget.
    ed_identity: pk::ed25519::Ed25519Identity,
    /// Copy of the rsa id from the underlying ChanTarget.
    rsa_identity: pk::rsa::RsaIdentity,
}

impl ChanTarget for TargetInfo {
    fn addrs(&self) -> &[SocketAddr] {
        &self.addrs[..]
    }
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
        &self.rsa_identity
    }
}

impl TargetInfo {
    /// Construct a TargetInfo from a given ChanTarget.
    pub(crate) fn from_chan_target<C>(target: &C) -> Self
    where
        C: ChanTarget + ?Sized,
    {
        TargetInfo {
            addrs: target.addrs().to_vec(),
            ed_identity: *target.ed_identity(),
            rsa_identity: *target.rsa_identity(),
        }
    }
}
