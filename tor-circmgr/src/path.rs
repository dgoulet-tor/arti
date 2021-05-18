//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub mod dirpath;
pub mod exitpath;

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackDir, Relay};
use tor_proto::channel::Channel;
use tor_proto::circuit::{CircParameters, ClientCirc};
use tor_rtcompat::Runtime;

use futures::task::SpawnExt;
use rand::{CryptoRng, Rng};
use std::sync::Arc;

use crate::{Error, Result};

/// A list of Tor relays through the network.
#[non_exhaustive]
pub enum TorPath<'a> {
    /// A single-hop path for use with a directory cache, when a relay is
    /// known.
    OneHop(Relay<'a>), // This could just be a routerstatus.
    /// A single-hop path for use with a directory cache, when we don't have
    /// a consensus.
    FallbackOneHop(&'a FallbackDir),
    /// A multi-hop path, containing one or more paths.
    Path(Vec<Relay<'a>>),
}

impl<'a> TorPath<'a> {
    /// Internal: Get the first hop of the path as a ChanTarget.
    fn first_hop(&self) -> Result<&(dyn tor_linkspec::ChanTarget + Sync)> {
        use TorPath::*;
        match self {
            OneHop(r) => Ok(r),
            FallbackOneHop(f) => Ok(*f),
            Path(p) if p.is_empty() => Err(Error::NoRelays("Path with no entries!".into()).into()),
            Path(p) => Ok(&p[0]),
        }
    }

    /// Return the final relay in this path, if this is a path for use
    /// with exit circuits.
    fn exit_relay(&self) -> Option<&Relay<'a>> {
        match self {
            TorPath::Path(relays) if !relays.is_empty() => Some(&relays[relays.len() - 1]),
            _ => None,
        }
    }

    /// Return the exit policy of the final relay in this path, if this
    /// is a path for use with exit circuits.
    pub(crate) fn exit_policy(&self) -> Option<super::ExitPolicy> {
        self.exit_relay().map(|exit_relay| super::ExitPolicy {
            v4: Arc::clone(exit_relay.ipv4_policy()),
            v6: Arc::clone(exit_relay.ipv6_policy()),
        })
    }

    /// Internal: get or create a channel for the first hop of a path.
    async fn get_channel<R: Runtime>(&self, chanmgr: &ChanMgr<R>) -> Result<Arc<Channel>> {
        let first_hop = self.first_hop()?;
        let channel = chanmgr.get_or_launch(first_hop).await?;
        Ok(channel)
    }

    /// Try to build a circuit corresponding to this path.
    pub async fn build_circuit<RNG, RT>(
        &self,
        rng: &mut RNG,
        runtime: &RT,
        chanmgr: &ChanMgr<RT>,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        RNG: Rng + CryptoRng,
        RT: Runtime,
    {
        use TorPath::*;
        let chan = self.get_channel(chanmgr).await?;
        let (pcirc, reactor) = chan.new_circ(rng).await?;

        runtime.spawn(async {
            let _ = reactor.run().await;
        })?;

        match self {
            OneHop(_) | FallbackOneHop(_) => {
                let circ = pcirc.create_firsthop_fast(rng, &params).await?;
                Ok(circ)
            }
            Path(p) => {
                let circ = pcirc.create_firsthop_ntor(rng, &p[0], &params).await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay, params).await?;
                }
                Ok(circ)
            }
        }
    }
}
