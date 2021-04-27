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
//! This crate exposes a [`Runtime`] type that represents the features
//! available from an asynchronous runtime.  This includes the
//! standardized features (spawning tasks), and ones for which no
//! standardized API currently exist (sleeping and networking and
//! TLS).
//!
//! The [`Runtime`] trait is implemented using the [`async_executors`]
//! crate; if that crate later expands to provide similar
//! functionality, this crate will contract.  Implementations are
//! currently provided for `async_executors::TokioTp` (if this crate
//! was builtwith the `tokio` feature) and `async_executors::AsyncStd`
//! (if this crate was built with the `async-std` feature).
//!
//! Note that this crate is explicitly limited to the features that
//! Arti requires.

#![deny(missing_docs)]
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::rc_buffer)]

use std::io::Result as IoResult;

pub(crate) mod impls;
pub mod mock;
pub mod task;

mod timer;
mod traits;

#[cfg(test)]
mod test;

#[cfg(not(any(feature = "async-std", feature = "tokio")))]
compile_error!("Sorry: At least one of the tor-rtcompat/async-std and tor-rtcompat/tokio features must be specified.");

pub use traits::{
    CertifiedConn, Runtime, SleepProvider, SpawnBlocking, TcpListener, TcpProvider, TlsProvider,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

/// Traits used to describe TLS connections and objects that can
/// create them.
pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};
}

#[cfg(feature = "async-std")]
pub use impls::async_std::create_runtime as create_async_std_runtime;
#[cfg(feature = "tokio")]
pub use impls::tokio::create_runtime as create_tokio_runtime;

/// The default runtime type that we return from [`create_runtime()`] or
/// [`test_with_runtime()`]
#[cfg(feature = "tokio")]
type DefaultRuntime = async_executors::TokioTp;

/// The default runtime type that we return from [`create_runtime()`] or
/// [`test_with_runtime()`]
#[cfg(all(feature = "async-std", not(feature = "tokio")))]
type DefaultRuntime = async_executors::AsyncStd;

/// Return a new instance of the default [`Runtime`].
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// If you need more fine-grained control over a runtime, you can
/// create it using an appropriate builder type from
/// [`async_executors`].
pub fn create_runtime() -> IoResult<impl Runtime> {
    create_default_runtime()
}

/// Helper: create and return a default runtime.
#[allow(clippy::unnecessary_wraps)]
fn create_default_runtime() -> IoResult<DefaultRuntime> {
    #[cfg(feature = "tokio")]
    {
        create_tokio_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        Ok(create_async_std_runtime())
    }
    #[cfg(not(any(feature = "async-std", feature = "tokio")))]
    {
        // This isn't reachable, since the crate won't actually compile
        // unless some runtime is enabled.
        panic!("tor-rtcompat was built with no supported runtimes.")
    }
}

/// Run a given asynchronous function, which takes a runtime as an argument,
/// using the default runtime.
///
/// This is intended for writing test cases that need a runtime.
///
/// # Example
///
/// ```
/// # use std::time::Duration;
/// use tor_rtcompat::SleepProviderExt;
///
/// // Run a simple test using a timeout.
/// tor_rtcompat::test_with_runtime(|runtime| async move {
///    async fn one_plus_two() -> u32 { 1 + 2 }
///    let future = runtime.timeout(Duration::from_secs(5), one_plus_two());
///    assert_eq!(future.await, Ok(3));
/// });
/// ```
#[allow(clippy::clone_on_copy)]
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(DefaultRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = create_default_runtime().unwrap();
    runtime.block_on(func(runtime.clone()))
}
