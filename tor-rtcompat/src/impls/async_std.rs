//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

use std::convert::TryInto;

/// Types used for networking (async_std implementation)
pub mod net {
    pub use async_std_crate::net::{TcpListener, TcpStream};
    use futures::future::Future;
    use futures::stream::Stream;
    use pin_project::pin_project;
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // XXXX I hate using this trick.
    #[pin_project]
    pub struct IncomingStreams {
        state: Option<IncomingStreamsState>,
    }
    type FResult = (IoResult<(TcpStream, SocketAddr)>, TcpListener);
    async fn take_and_poll(lis: TcpListener) -> FResult {
        let result = lis.accept().await;
        (result, lis)
    }
    enum IncomingStreamsState {
        Ready(TcpListener),
        Accepting(Pin<Box<dyn Future<Output = FResult>>>),
    }
    impl IncomingStreams {
        pub fn from_listener(lis: TcpListener) -> IncomingStreams {
            IncomingStreams {
                state: Some(IncomingStreamsState::Ready(lis)),
            }
        }
    }
    impl Stream for IncomingStreams {
        type Item = IoResult<(TcpStream, SocketAddr)>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            use IncomingStreamsState as St;
            let this = self.project();
            let state = this.state.take().expect("No valid state!");
            let mut future = match state {
                St::Ready(lis) => Box::pin(take_and_poll(lis)),
                St::Accepting(fut) => fut,
            };
            match future.as_mut().poll(cx) {
                Poll::Ready((val, lis)) => {
                    *this.state = Some(St::Ready(lis));
                    Poll::Ready(Some(val))
                }
                Poll::Pending => {
                    *this.state = Some(St::Accepting(future));
                    Poll::Pending
                }
            }
        }
    }
}

/// Functions for launching and managing tasks (async_std implementation)
pub mod task {}

/// Functions and types for manipulating timers (async_std implementation)
pub mod timer {}

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
    impl crate::traits::TlsConnector for TlsConnector {
        type Conn = TlsStream;

        async fn connect_unvalidated(
            &self,
            addr: &SocketAddr,
            hostname: &str,
        ) -> IoResult<Self::Conn> {
            let stream = TcpStream::connect(addr).await?;

            let conn = self
                .connector
                .connect(hostname, stream)
                .await
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            Ok(conn)
        }
    }

    impl<S> crate::traits::CertifiedConn for async_native_tls::TlsStream<S>
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

#[allow(clippy::unnecessary_wraps)]
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
    type Incoming = net::IncomingStreams;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
        net::TcpListener::accept(self).await
    }
    fn incoming(self) -> net::IncomingStreams {
        net::IncomingStreams::from_listener(self)
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

impl TlsProvider for async_executors::AsyncStd {
    type TlsStream = tls::TlsStream;
    type Connector = tls::TlsConnector;

    fn tls_connector(&self) -> tls::TlsConnector {
        let mut builder = native_tls::TlsConnector::builder();
        // These function names are scary, but they just mean that
        // we're skipping web pki, and using our own PKI functions.
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);

        builder.try_into().expect("Couldn't build a TLS connector!")
    }
}
