//! Code to run as a background task and keep a directory up-to-date.

use crate::retry::RetryDelay;
use crate::{DirMgr, Error, Result};
use tor_circmgr::CircMgr;
use tor_netdoc::doc::netstatus::Lifetime;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rand::Rng;

/// A DirectoryUpdater runs in a background task to periodically re-fetch
/// new directory objects as the old ones become outdated.
pub struct DirectoryUpdater {
    /// A directory manager to use in picking directory caches, and which can
    /// download new directory objects.
    dir_mgr: Weak<DirMgr>,
    /// A circuit manager to use in connecting to the network.
    circ_mgr: Weak<CircMgr>,
    /// A flag to tell the DirectoryUpdater to exit.
    stopping: AtomicBool,
}

impl DirectoryUpdater {
    /// Make a new DirectoryUpdater.  It takes a reference to a directory
    /// manager and circuit manager, but stores weak references to them.  It doesn't
    /// start going till you call 'run' on it.
    pub(crate) fn new(dir_mgr: Arc<DirMgr>, circ_mgr: Arc<CircMgr>) -> Self {
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
        loop {
            let download_time = self.pick_download_time().await;

            // Updating phase: try to add microdescriptors to the directory.
            // Do this until we have all the microdescriptors, or it's time
            // to download the next thing.
            if let Some(download_time) = download_time {
                let mut retry = RetryDelay::from_msec(1000); // XXXX make this configurable?
                while SystemTime::now() < download_time {
                    let again = self.fetch_more_microdescs().await?;
                    if !again {
                        debug!("We have all the microdescriptors for our current consensus");
                        break;
                    }
                    let delay = retry.next_delay(&mut rand::thread_rng());
                    if SystemTime::now() + delay > download_time {
                        debug!("Out of time to fetch additional microdescriptors.");
                        break;
                    }
                    tor_rtcompat::task::sleep(delay).await;
                }

                // We're done with the updating phase: we either got all the mds or
                // ran out of time.
                debug!(
                    "Waiting till {}, when we download the next directory.",
                    DateTime::<Utc>::from(download_time)
                );
                tor_rtcompat::timer::sleep_until_wallclock(download_time).await;
            }

            // Time to get a new directory!
            self.fetch_new_directory().await?;
        }
    }

    /// Keep trying to get a new consensus until we have one, along with any
    /// other directory objects we need to use that consensus.
    async fn fetch_new_directory(&self) -> Result<()> {
        let mut retry = RetryDelay::from_msec(1000); // XXXX make this configurable?
        loop {
            if self.stopping.load(Ordering::SeqCst) {
                return Err(Error::UpdaterShutdown.into());
            }

            if let (Some(dm), Some(cm)) = (self.dir_mgr.upgrade(), self.circ_mgr.upgrade()) {
                let result = dm.fetch_new_directory(cm).await;
                if let Err(e) = result {
                    warn!("Directory fetch failed: {}. Will retry in later.", e);
                    let delay = retry.next_delay(&mut rand::thread_rng());
                    tor_rtcompat::task::sleep(delay).await;
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Perform a _single_ attempt to download any missing microdescriptors for the
    /// current NetDir.  Return true if we are still missing microdescriptors,
    /// and false if we have received them all.
    async fn fetch_more_microdescs(&self) -> Result<bool> {
        if self.stopping.load(Ordering::SeqCst) {
            return Err(Error::UpdaterShutdown.into());
        }

        if let (Some(dm), Some(cm)) = (self.dir_mgr.upgrade(), self.circ_mgr.upgrade()) {
            let result = dm.fetch_additional_microdescs(cm).await;
            match result {
                Ok(n_missing) => Ok(n_missing != 0),
                Err(e) => {
                    warn!("Microdescriptor fetch failed: {}. Will retry later.", e);
                    Ok(true)
                }
            }
        } else {
            Err(Error::UpdaterShutdown.into())
        }
    }

    /// Select a random time to start fetching the next directory, based on the
    /// directory we already have.
    async fn pick_download_time(&self) -> Option<SystemTime> {
        if let Some(dm) = self.dir_mgr.upgrade() {
            let netdir = dm.netdir().await;
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

        None
    }
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let fresh_until = lt.fresh_until();
    let valid_until = lt.valid_until();
    let voting_interval = fresh_until
        .duration_since(valid_after)
        .expect("valid-after must precede fresh-until");
    let whole_lifetime = valid_until
        .duration_since(valid_after)
        .expect("valid-after must precede valid-until");

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
