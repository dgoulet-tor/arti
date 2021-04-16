//! Compatibility between different async runtimes for Arti
//!
//! We try to isolate these dependencies in a single place so that
//! we depend only on a minimal set of required features that our
//! runtime needs to give us.
//!
//! Right now this crate supports async_std and tokio; tokio is the
//! default.  You can control this with the `async-std` or `tokio`
//! features on this crate.
//!
//! Our implementation is trickier than needed, for a bunch of
//!  reasons:
//!  * Neither backend's executor supports the Executor or
//!    Spawn traits.
//!  * Tokio has its own AsyncRead and AsyncWrite traits.
//!  * The Rust features system is not really well-suited to
//!    mutually exclusive features, but as implemented the two features
//!    above are mutually exclusive.
//!  * Sleeping is not standardized.
//!
//! Workarounds for all of the above are possible, and in the future
//! we should probably look into them.

use once_cell::sync::OnceCell;

//#![deny(missing_docs)]
//#![deny(clippy::missing_docs_in_private_items)]

pub(crate) mod impls;

mod traits;

// TODO: This is not an ideal situation, and it's arguably an abuse of
// the features feature.  But I can't currently find a reasonable way
// to have the code use the right version of things like "sleep" or
// "spawn" otherwise.
#[cfg(all(feature = "async-std", feature = "tokio"))]
compile_error!("Sorry: At most one of the async-std and tokio features can be used at a time.");

#[cfg(not(any(feature = "async-std", feature = "tokio")))]
compile_error!("Sorry: Exactly one one of the tor-rtcompat/async-std and tor-rtcompat/tokio features must be specified.");

#[cfg(feature = "async-std")]
use impls::async_std as imp;

#[cfg(all(feature = "tokio", not(feature = "async-std")))]
use impls::tokio as imp;

use imp::AsyncRuntime;

static GLOBAL_RUNTIME: OnceCell<AsyncRuntime> = OnceCell::new();

fn runtime_ref() -> &'static impl traits::Runtime {
    GLOBAL_RUNTIME.get_or_init(|| imp::create_runtime().unwrap())
}
pub fn runtime() -> impl traits::Runtime {
    runtime_ref().clone()
}

/// Types used for networking (async_std implementation)
pub mod net {
    pub use crate::imp::net::*;
}

/// Functions for launching and managing tasks.
pub mod task {
    use crate::traits::{SleepProvider, SpawnBlocking};
    use futures::Future;
    use std::time::Duration;

    pub fn sleep(dur: Duration) -> impl Future<Output = ()> + Send {
        crate::runtime_ref().sleep(dur)
    }

    pub fn spawn<T>(task: T)
    where
        T: Future + Send + 'static,
    {
        //use async_executors::SpawnHandleExt;
        use futures::task::SpawnExt;
        use futures::FutureExt;
        crate::runtime_ref().spawn(task.map(|_| ())).unwrap();
    }

    pub fn block_on<T: Future>(task: T) -> T::Output {
        crate::runtime_ref().block_on(task)
    }
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

/// Support for launching TLS connections.
pub mod tls {
    use async_trait::async_trait;
    use futures::io::{AsyncRead, AsyncWrite};
    use std::io::Result as IoResult;
    use std::net::SocketAddr;

    /// An object with a peer certificate.
    pub trait CertifiedConn {
        /// Try to return the (der-encoded) peer certificate for this
        /// connection, if any.
        fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>>;
    }

    /// An object that knows how to make a TLS-over-TCP connection we
    /// can use in Tor.
    #[async_trait]
    pub trait TlsConnector {
        /// The type of connection returned by this connector
        type Conn: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

        /// Launch a TLS-over-TCP connection to a given address.
        /// TODO: document args
        async fn connect(&self, addr: &SocketAddr, sni_hostname: &str) -> IoResult<Self::Conn>;
    }

    pub use crate::imp::tls::*;

    pub use crate::imp::tls::TlsConnector as TlsConnectorImp;
}

/// Traits specific to the runtime in use.
pub mod impl_traits {
    pub use crate::imp::traits::*;
}
