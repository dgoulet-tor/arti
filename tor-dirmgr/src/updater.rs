//! Code to run as a background task and keep a directory up-to-date.

use crate::retry::RetryDelay;
use crate::{DirMgr, Result};
use tor_circmgr::CircMgr;
use tor_netdoc::doc::netstatus::Lifetime;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use log::{info, warn};
use rand::Rng;

/// A SirectoryUpdater runs in a background task to periodically re-fetch
/// new directory objects as the old ones become outdated.
pub struct DirectoryUpdater<TR>
where
    TR: tor_chanmgr::transport::Transport,
{
    /// A directory manager to use in picking directory caches, and which can
    /// download new directory objects.
    dir_mgr: Weak<DirMgr>,
    /// A circuit manager to use in connecting to the network.
    circ_mgr: Weak<CircMgr<TR>>,
    /// A flag to tell the DirectoryUpdater to exit.
    stopping: AtomicBool,
}

impl<TR> DirectoryUpdater<TR>
where
    TR: tor_chanmgr::transport::Transport,
{
    /// Make a new DirectoryUpdater.  It takes a reference to a directory
    /// manager and circuit manager, but stores weak references to them.  It doesn't
    /// start going till you call 'run' on it.
    pub(crate) fn new(dir_mgr: Arc<DirMgr>, circ_mgr: Arc<CircMgr<TR>>) -> Self {
        DirectoryUpdater {
            dir_mgr: Arc::downgrade(&dir_mgr),
            circ_mgr: Arc::downgrade(&circ_mgr),
            stopping: AtomicBool::new(false),
        }
    }

    /// Tell the DirectoryUpdater to stop fetching.
    ///
    /// (This won't take effect till after the current set of attempted
    /// downloads is done.)
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Run in a loop, and keep the directory manager's directory up-to-date.
    pub(crate) async fn run(&self) -> Result<()> {
        // This is either "None" if we have a valid directory, or a RetryDelay
        // if we're trying to fetch one.
        let mut retry: Option<RetryDelay> = None;

        loop {
            self.wait(&mut retry).await;
            if self.stopping.load(Ordering::SeqCst) {
                // XXXX log something here.
                return Ok(());
            }

            if let (Some(dm), Some(cm)) = (self.dir_mgr.upgrade(), self.circ_mgr.upgrade()) {
                let res = dm.update_directory(cm).await;
                if let Err(e) = res {
                    warn!("Directory fetch failed: {}. Will retry later", e);
                } else {
                    // Since we got a directory, we clear 'retry'.
                    retry = None;
                }
            } else {
                // XXXX log something here.
                return Ok(());
            }
        }
    }

    /// Delay until it's time to try fetching again.
    async fn wait(&self, retry: &mut Option<RetryDelay>) {
        if let Some(ref mut r) = retry {
            // In this case, we have a retry schedule, so we follow it.
            let delay = r.next_delay(&mut rand::thread_rng());
            tor_rtcompat::task::sleep(delay).await;
            return;
        }

        // Okay, we aren't currently downloading a directory.  Pick when we
        // would like to download a directory, and wait until then.
        if let Some(download_time) = self.pick_download_time().await {
            if SystemTime::now() < download_time {
                tor_rtcompat::timer::sleep_until_wallclock(download_time).await;
            }
        }

        // Oops -- pick_download_time() didn't work.  That probably means
        // we didn't actually have a directory after all?  Return right away.
        *retry = Some(RetryDelay::from_msec(1000));
    }

    /// Select a random time to start fetching the next directory, based on the
    /// directory we already have.
    async fn pick_download_time(&self) -> Option<SystemTime> {
        if let Some(dm) = self.dir_mgr.upgrade() {
            if let Some(netdir) = dm.netdir().await {
                let lt = netdir.lifetime();
                let (lowbound, uncertainty) = client_download_range(&lt);
                let zero = Duration::new(0, 0);
                let t = lowbound + rand::thread_rng().gen_range(zero, uncertainty);
                info!("Current directory is fresh until {}, valid until {}. I've picked {} as the earliest to download a new one.",
                      DateTime::<Utc>::from(lt.fresh_until()),
                      DateTime::<Utc>::from(lt.valid_until()),
                      DateTime::<Utc>::from(t));
                return Some(t);
            }
        }

        None
    }
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let fresh_until = lt.fresh_until();
    let valid_until = lt.valid_until();
    let voting_interval = fresh_until.duration_since(valid_after).unwrap();
    let whole_lifetime = valid_until.duration_since(valid_after).unwrap();

    // From dir-spec:
    // "This time is chosen uniformly at random from the interval
    // between the time 3/4 into the first interval after the
    // consensus is no longer fresh, and 7/8 of the time remaining
    // after that before the consensus is invalid."
    let lowbound = voting_interval + (voting_interval * 3) / 4;
    let remainder = whole_lifetime - lowbound;
    let uncertainty = (remainder * 7) / 8;

    (valid_after + lowbound, uncertainty)
}
