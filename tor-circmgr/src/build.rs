//! Facilities to build circuits directly, instead of via a circuit manager.

use crate::path::{OwnedPath, TorPath};
use crate::Result;
use futures::task::SpawnExt;
use rand::{CryptoRng, Rng};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tor_chanmgr::ChanMgr;
use tor_proto::circuit::{CircParameters, ClientCirc};
use tor_rtcompat::{Runtime, SleepProviderExt};

/// A factory object to build circuits.
///
/// A `CircuitBuilder` holds references to all the objects that are needed
/// to build circuits correctly.
///
/// In general, you should not need to construct or use this object yourself,
/// unless you are choosing your own paths.
pub struct CircuitBuilder<R: Runtime> {
    /// The runtime used by this circuit builder.
    runtime: R,
    /// A channel manager that this circuit builder uses to make chanels.
    chanmgr: Arc<ChanMgr<R>>,
}

impl<R: Runtime> CircuitBuilder<R> {
    /// Construct a new [`CircuitBuilder`].
    pub fn new(runtime: R, chanmgr: Arc<ChanMgr<R>>) -> Self {
        CircuitBuilder { runtime, chanmgr }
    }

    /// Build a circuit, without performing any timeout operations.
    async fn build_notimeout<RNG: CryptoRng + Rng>(
        &self,
        path: &OwnedPath,
        params: &CircParameters,
        rng: &mut RNG,
    ) -> Result<Arc<ClientCirc>> {
        let chan = self.chanmgr.get_or_launch(path.first_hop()?).await?;
        let (pending_circ, reactor) = chan.new_circ(rng).await?;

        self.runtime.spawn(async {
            let _ = reactor.run().await;
        })?;

        match path {
            OwnedPath::ChannelOnly(_) => {
                let circ = pending_circ.create_firsthop_fast(rng, params).await?;
                Ok(circ)
            }
            OwnedPath::Normal(p) => {
                assert!(!p.is_empty());
                let circ = pending_circ
                    .create_firsthop_ntor(rng, &p[0], params)
                    .await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay, params).await?;
                }
                Ok(circ)
            }
        }
    }

    /// Build a circuit from an [`OwnedPath`].
    pub(crate) async fn build_owned<RNG: CryptoRng + Rng>(
        &self,
        path: &OwnedPath,
        params: &CircParameters,
        rng: &mut RNG,
    ) -> Result<Arc<ClientCirc>> {
        let delay = Duration::from_secs(5); // TODO: make this configurable and inferred.

        let build_future = self.build_notimeout(path, params, rng);
        let circuit = self.runtime.timeout(delay, build_future).await??;

        Ok(circuit)
    }

    /// Try to construct a new circuit from a given path, using appropriate
    /// timeouts.
    ///
    /// This circuit is _not_ automatically registered with any
    /// circuit manager; if you don't hang on it it, it will
    /// automatically go away when the last reference is dropped.
    pub async fn build<RNG: CryptoRng + Rng>(
        &self,
        path: &TorPath<'_>,
        params: &CircParameters,
        rng: &mut RNG,
    ) -> Result<Arc<ClientCirc>> {
        let owned = path.try_into()?;
        self.build_owned(&owned, params, rng).await
    }
}
