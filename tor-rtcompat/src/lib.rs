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
mod timer;
mod traits;

pub use traits::{
    CertifiedConn, Runtime, SleepProvider, SpawnBlocking, TcpListener, TcpProvider, TlsProvider,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};
}

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

/// Functions for launching and managing tasks.
pub mod task {
    use crate::traits::SpawnBlocking;
    use futures::Future;

    pub fn block_on<T: Future>(task: T) -> T::Output {
        crate::runtime_ref().block_on(task)
    }
}
