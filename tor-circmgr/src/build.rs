//! Facilities to build circuits directly, instead of via a circuit manager.

use crate::path::{OwnedPath, TorPath};
use crate::timeouts::{pareto::ParetoTimeoutEstimator, Action, TimeoutEstimator};
use crate::{Error, Result};
use futures::channel::oneshot;
use futures::task::SpawnExt;
use futures::Future;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use std::convert::TryInto;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
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
    /// A channel manager that this circuit builder uses to make channels.
    chanmgr: Arc<ChanMgr<R>>,
    /// An estimator to determine the correct timeouts for circuit building.
    timeouts: Box<dyn TimeoutEstimator + Send + Sync>,
}

impl<R: Runtime> CircuitBuilder<R> {
    /// Construct a new [`CircuitBuilder`].
    pub fn new(runtime: R, chanmgr: Arc<ChanMgr<R>>) -> Self {
        // XXXX make this configurable and changeable.
        let timeouts = Box::new(ParetoTimeoutEstimator::default());
        CircuitBuilder {
            runtime,
            chanmgr,
            timeouts,
        }
    }

    /// Build a circuit, without performing any timeout operations.
    ///
    /// After each hop is built, increments n_hops_built. (TODO: Find
    /// a better design there.)
    async fn build_notimeout<RNG: CryptoRng + Rng>(
        self: Arc<Self>,
        path: OwnedPath,
        params: CircParameters,
        start_time: Instant,
        n_hops_built: Arc<AtomicU32>,
        mut rng: RNG,
    ) -> Result<Arc<ClientCirc>> {
        let chan = self.chanmgr.get_or_launch(path.first_hop()?).await?;
        let (pending_circ, reactor) = chan.new_circ(&mut rng).await?;

        self.runtime.spawn(async {
            let _ = reactor.run().await;
        })?;

        match path {
            OwnedPath::ChannelOnly(_) => {
                let circ = pending_circ.create_firsthop_fast(&mut rng, &params).await?;
                self.timeouts
                    .note_hop_completed(0, Instant::now() - start_time, true);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                Ok(circ)
            }
            OwnedPath::Normal(p) => {
                assert!(!p.is_empty());
                let n_hops = p.len() as u8;
                let circ = pending_circ
                    .create_firsthop_ntor(&mut rng, &p[0], &params)
                    .await?;
                self.timeouts
                    .note_hop_completed(0, Instant::now() - start_time, n_hops == 0);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                let mut hop_num = 1;
                for relay in p[1..].iter() {
                    circ.extend_ntor(&mut rng, relay, &params).await?;
                    n_hops_built.fetch_add(1, Ordering::SeqCst);
                    self.timeouts.note_hop_completed(
                        hop_num,
                        Instant::now() - start_time,
                        hop_num == n_hops,
                    );
                    hop_num += 1;
                }
                Ok(circ)
            }
        }
    }

    /// Build a circuit from an [`OwnedPath`].
    pub(crate) async fn build_owned<RNG: CryptoRng + Rng + Send + 'static>(
        self: &Arc<Self>,
        path: OwnedPath,
        params: &CircParameters,
        rng: RNG,
    ) -> Result<Arc<ClientCirc>> {
        let action = Action::BuildCircuit { length: path.len() };
        let (timeout, abandon_timeout) = self.timeouts.timeouts(&action);
        let start_time = Instant::now();

        // TODO: This is probably not the best way for build_notimeout to
        // tell us how many hops it managed to build, but at least it is
        // isolated here.
        let hops_built = Arc::new(AtomicU32::new(0));

        let self_clone = Arc::clone(self);
        let params = params.clone();

        let circuit_future =
            self_clone.build_notimeout(path, params, start_time, Arc::clone(&hops_built), rng);

        match double_timeout(&self.runtime, circuit_future, timeout, abandon_timeout).await {
            Ok(circuit) => Ok(circuit),
            Err(Error::CircTimeout) => {
                let n_built = hops_built.load(Ordering::SeqCst);
                self.timeouts
                    .note_circ_timeout(n_built as u8, Instant::now() - start_time);
                Err(Error::CircTimeout)
            }
            Err(e) => Err(e),
        }
    }

    /// Try to construct a new circuit from a given path, using appropriate
    /// timeouts.
    ///
    /// This circuit is _not_ automatically registered with any
    /// circuit manager; if you don't hang on it it, it will
    /// automatically go away when the last reference is dropped.
    pub async fn build<RNG: CryptoRng + Rng>(
        self: &Arc<Self>,
        path: &TorPath<'_>,
        params: &CircParameters,
        rng: &mut RNG,
    ) -> Result<Arc<ClientCirc>> {
        let rng = StdRng::from_rng(rng).expect("couldn't construct temporary rng");
        let owned = path.try_into()?;
        self.build_owned(owned, params, rng).await
    }
}

/// Helper function: spawn a future as a background task, and run it with
/// two separate timeouts.
///
/// If the future does not complete by `timeout`, then return a
/// timeout error immediately, but keep running the future in the
/// background.
///
/// If the future does not complete by `abandon`, then abandon the
/// future completely.
async fn double_timeout<R, F, T>(
    runtime: &R,
    fut: F,
    timeout: Duration,
    abandon: Duration,
) -> Result<T>
where
    R: Runtime,
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (snd, rcv) = oneshot::channel();
    let rt = runtime.clone();
    runtime.spawn(async move {
        let result = rt.timeout(abandon, fut).await;
        let _ignore_cancelled_error = snd.send(result);
    })?;

    let outcome = runtime.timeout(timeout, rcv).await;
    // 4 layers of error to collapse:
    //     One from the receiver being cancelled.
    //     One from the outer timeout.
    //     One from the inner timeout.
    //     One from the actual future's result.
    //
    // (Technically, we could refrain from unwrapping the future's result,
    // but doing it this way helps make it more certain that we really are
    // collapsing all the layers into one.)
    Ok(outcome????)
}
