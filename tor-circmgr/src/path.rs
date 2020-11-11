//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub mod dirpath;
pub mod exitpath;

use tor_chanmgr::ChanMgr;
use tor_netdir::{NetDir, Relay};
use tor_proto::channel::Channel;
use tor_proto::circuit::ClientCirc;

use rand::{CryptoRng, Rng};

use crate::{Error, Result};

/// A list of Tor nodes through the network.
pub enum TorPath<'a> {
    /// A single-hop path for use with a directory cache.
    ///
    /// TODO: This needs to be a more general type, to support anything that can be
    /// a ChanTarget.
    OneHop(Relay<'a>),
    /// A multi-hop path, containing one or more paths.
    Path(Vec<Relay<'a>>),
}

/// An object that knows how to build a path
pub trait PathBuilder {
    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>>;
}

impl<'a> TorPath<'a> {
    /// Internal: get or create a channel for the first hop of a path.
    async fn get_channel<TR>(&self, chanmgr: &ChanMgr<TR>) -> Result<Channel>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        use TorPath::*;
        match self {
            OneHop(r) => Ok(chanmgr.get_or_launch(r).await?),

            Path(p) if p.is_empty() => Err(Error::NoRelays("Path with no entries!".into()).into()),
            Path(p) => Ok(chanmgr.get_or_launch(&p[0]).await?),
        }
    }

    /// Try to build a circuit corresponding to this path.
    pub async fn build_circuit<TR, R>(
        &self,
        rng: &mut R,
        chanmgr: &ChanMgr<TR>,
    ) -> Result<ClientCirc>
    where
        TR: tor_chanmgr::transport::Transport,
        R: Rng + CryptoRng,
    {
        use TorPath::*;
        let chan = self.get_channel(chanmgr).await?;
        let (pcirc, reactor) = chan.new_circ(rng).await?;

        tor_rtcompat::task::spawn(async {
            let _ = reactor.run().await;
        });

        match self {
            OneHop(_) => {
                let circ = pcirc.create_firsthop_fast(rng).await?;
                Ok(circ)
            }
            Path(p) => {
                let mut circ = pcirc.create_firsthop_ntor(rng, &p[0]).await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay).await?;
                }
                Ok(circ)
            }
        }
    }
}
