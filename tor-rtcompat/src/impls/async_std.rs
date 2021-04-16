//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

/// Types used for networking (async_std implementation)
pub mod net {
    pub use async_std_crate::net::{TcpListener, TcpStream};

    /// Split a read/write stream into its read and write halves.
    pub fn split_io<T>(stream: T) -> (futures::io::ReadHalf<T>, futures::io::WriteHalf<T>)
    where
        T: futures::io::AsyncRead + futures::io::AsyncWrite,
    {
        use futures::io::AsyncReadExt;
        stream.split()
    }

    /// Return a stream that yields incoming sockets from `lis`
    pub fn listener_to_stream(
        lis: &TcpListener,
    ) -> impl futures::stream::Stream<Item = Result<TcpStream, std::io::Error>> + '_ {
        lis.incoming()
    }
}

/// Functions for launching and managing tasks (async_std implementation)
pub mod task {
    pub use async_std_crate::task::{block_on, sleep, spawn, JoinHandle};

    //pub use async_std_crate::task::JoinHandle;

    /// Stop the task `handle` from running.
    ///
    /// If you drop `handle` without calling this function, it will just
    /// run to completion.
    #[allow(unused)]
    pub async fn cancel_task<T>(handle: JoinHandle<T>) {
        handle.cancel().await;
    }
}

/// Functions and types for manipulating timers (async_std implementation)
pub mod timer {
    use std::time::Duration;

    /// Return a future that will be ready after `duration` has passed.
    pub fn sleep(duration: Duration) -> async_io::Timer {
        async_io::Timer::after(duration)
    }

    pub use async_std_crate::future::{timeout, TimeoutError};
}

/// Implement TLS using async_std and async_native_tls.
pub mod tls {
    use async_std_crate::net::TcpStream;
    use async_trait::async_trait;
    use futures::io::{AsyncRead, AsyncWrite};

    use std::convert::TryFrom;
    use std::io::{Error as IoError, Result as IoResult};
    use std::net::SocketAddr;

    /// The TLS-over-TCP type returned by this module.
    pub type TlsStream = async_native_tls::TlsStream<TcpStream>;

    /// A connection factory for use with async_std.
    pub struct TlsConnector {
        /// The internal connector that we're wrapping with a new API
        connector: async_native_tls::TlsConnector,
    }

    impl TryFrom<native_tls::TlsConnectorBuilder> for TlsConnector {
        type Error = std::convert::Infallible;
        fn try_from(builder: native_tls::TlsConnectorBuilder) -> Result<TlsConnector, Self::Error> {
            let connector = builder.into();
            Ok(TlsConnector { connector })
        }
    }

    #[async_trait]
    impl crate::tls::TlsConnector for TlsConnector {
        type Conn = TlsStream;

        async fn connect(&self, addr: &SocketAddr, hostname: &str) -> IoResult<Self::Conn> {
            let stream = TcpStream::connect(addr).await?;

            let conn = self
                .connector
                .connect(hostname, stream)
                .await
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            Ok(conn)
        }
    }

    impl<S> crate::tls::CertifiedConn for async_native_tls::TlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
            let cert = self.peer_certificate();
            match cert {
                Ok(Some(c)) => {
                    let der = c
                        .to_der()
                        .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
                    Ok(Some(der))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(IoError::new(std::io::ErrorKind::Other, e)),
            }
        }
    }
}

/// Traits specific to async_std
pub mod traits {}

// ==============================

use async_trait::async_trait;
use futures::{Future, FutureExt};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use crate::traits::*;

pub(crate) fn create_runtime() -> IoResult<AsyncRuntime> {
    Ok(async_executors::AsyncStd::new())
}

pub(crate) type AsyncRuntime = async_executors::AsyncStd;

impl SleepProvider for async_executors::AsyncStd {
    type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        Box::pin(async_io::Timer::after(duration).map(|_| ()))
    }
}

#[async_trait]
impl TcpListener for net::TcpListener {
    type Stream = net::TcpStream;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
        net::TcpListener::accept(self).await
    }
}

#[async_trait]
impl TcpProvider for async_executors::AsyncStd {
    type TcpStream = net::TcpStream;
    type TcpListener = net::TcpListener;
    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
        net::TcpStream::connect(addr).await
    }
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        net::TcpListener::bind(*addr).await
    }
}

impl SpawnBlocking for async_executors::AsyncStd {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        async_executors::AsyncStd::block_on(f)
    }
}
