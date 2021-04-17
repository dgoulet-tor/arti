//! Compatibility between different async runtimes for Arti
//!
//! We try to isolate these dependencies in a single place so that
//! we depend only on a minimal set of required features that our
//! runtime needs to give us.
//!
//! Right now this crate supports async_std and tokio; tokio is the
//! default.  You can control this with the `async-std` or `tokio`
//! features on this crate.

//#![deny(missing_docs)]
//#![deny(clippy::missing_docs_in_private_items)]

use std::io::Result as IoResult;

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

#[cfg(feature = "async-std")]
pub use impls::async_std::create_runtime as create_async_std_runtime;
#[cfg(feature = "tokio")]
pub use impls::tokio::create_runtime as create_tokio_runtime;

#[cfg(feature = "tokio")]
pub type DefaultRuntime = async_executors::TokioTp;

#[cfg(all(feature = "async-std", not(feature = "tokio")))]
pub type DefaultRuntime = async_executors::AsyncStd;

pub fn create_runtime() -> IoResult<impl Runtime> {
    create_default_runtime()
}

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
        panic!("tor-rtcompat was built with no supported runtimes.")
    }
}

#[allow(clippy::clone_on_copy)]
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(DefaultRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = create_default_runtime().unwrap();
    runtime.block_on(func(runtime.clone()))
}
