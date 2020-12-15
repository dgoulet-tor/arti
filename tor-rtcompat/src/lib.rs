//! Compatibility between different async runtimes for Arti
//!
//! We try to isolate these dependencies in a single place so that
//! we depend only on a minimal set of required features that our
//! runtime needs to give us.
//!
//! Right now, this crate exposes a small subset of the async_std
//! runtime, and the async_io rutime that it's built on, for use by
//! the rest of Arti.  Later we should add tokio support.  When we do
//! so, we may change which APIs this crate exposes, depending on
//! which interface is easier to build based on the other.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub(crate) mod impls;

#[cfg(all(feature = "async-std"))]
use impls::async_std as imp;

/// Types used for networking (async_std implementation)
pub mod net {
    pub use crate::imp::net::*;
}

/// Functions for launching and managing tasks.
pub mod task {
    pub use crate::imp::task::*;
}

/// Functions and types for manipulating timers.
pub mod timer {
    use std::time::{Duration, SystemTime};

    pub use crate::imp::timer::*;

    /// Pause until the wall-clock is at `when` or later, trying to
    /// recover from clock jumps.
    pub async fn sleep_until_wallclock(when: SystemTime) {
        loop {
            let now = SystemTime::now();
            if now >= when {
                return;
            }
            let delay = calc_next_delay(now, when);
            crate::task::sleep(delay).await;
        }
    }

    /// Return the amount of time we should wait next, when running
    /// sleep_until_wallclock().
    ///
    /// (This is a separate function for testing.)
    fn calc_next_delay(now: SystemTime, when: SystemTime) -> Duration {
        /// We never sleep more than this much, in case our system clock jumps
        const MAX_SLEEP: Duration = Duration::from_secs(600);
        let remainder = when
            .duration_since(now)
            .unwrap_or_else(|_| Duration::from_secs(0));
        std::cmp::min(MAX_SLEEP, remainder)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn sleep_delay() {
            use calc_next_delay as calc;
            let minute = Duration::from_secs(60);
            let second = Duration::from_secs(1);
            let start = SystemTime::now();

            let target = start + 30 * minute;

            assert_eq!(calc(start, target), minute * 10);
            assert_eq!(calc(target + minute, target), minute * 0);
            assert_eq!(calc(target, target), minute * 0);
            assert_eq!(calc(target - second, target), second);
            assert_eq!(calc(target - minute * 9, target), minute * 9);
            assert_eq!(calc(target - minute * 11, target), minute * 10);
        }
    }
}
