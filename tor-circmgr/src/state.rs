//! Code to manage persistence for a circuit manager's state.
//!
//! For now, there's only one kind of data we need to persist across
//! runs: timeout data.  Eventually we'll also to persist guard data.
//!
//! Some of the choices here are motivated by another long-term goal:
//! to allow multiple collaborating processes to share data on disk.

use crate::timeouts::pareto::ParetoTimeoutState;
use crate::Result;
use tor_persist::StateMgr;

/// Type alias for an Arc<dyn CircStateMgr>.
pub(crate) type DynStateMgr = std::sync::Arc<dyn CircStateMgr + Send + Sync + 'static>;

/// Crate-local trait, used to represent anything that can store circmgr data.
///
/// We declare a separate trait here, rather than just using
/// `StateMgr`, for two reasons:
/// - We want an interface to StateMgr that gives it more type-safety.
/// - StateMgr isn't object-safe.
pub(crate) trait CircStateMgr {
    /// Return true if we're able to store to this state manager.
    fn have_lock(&self) -> bool;
    /// Try to get the lock on this state manager.
    ///
    /// Returns `Ok(true) if we have the lock, and `Ok(false) if
    /// another process has it.
    fn try_lock(&self) -> Result<bool>;

    /// Try to load our persistent timeout data from storage.
    fn load_timeout_data(&self) -> Result<Option<ParetoTimeoutState>>;
    /// Replace our persistent timeout data on storage with the data
    /// in `state`.
    fn save_timeout_data(&self, state: &ParetoTimeoutState) -> Result<()>;
}

/// Key used to load timeout state information.
const PARETO_TIMEOUT_DATA_KEY: &str = "circuit_timeouts";

impl<M: StateMgr> CircStateMgr for M {
    fn have_lock(&self) -> bool {
        self.can_store()
    }
    fn try_lock(&self) -> Result<bool> {
        Ok(StateMgr::try_lock(self)?)
    }

    fn load_timeout_data(&self) -> Result<Option<ParetoTimeoutState>> {
        Ok(self.load(PARETO_TIMEOUT_DATA_KEY)?)
    }

    fn save_timeout_data(&self, state: &ParetoTimeoutState) -> Result<()> {
        self.store(PARETO_TIMEOUT_DATA_KEY, state)?;
        Ok(())
    }
}
