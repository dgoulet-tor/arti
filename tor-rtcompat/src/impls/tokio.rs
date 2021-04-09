//! Re-exports of the tokio runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Types used for networking (tokio implementation)
pub mod net {
    pub use tokio_crate::io::split as split_io;
    use tokio_crate::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
    // use tokio_crate::io::{AsyncRead as _, AsyncWrite as _};

    use futures::io::{AsyncRead, AsyncWrite};
    use pin_project::pin_project;
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Wrapper for Tokio's TcpStream that implements the standard
    /// AsyncRead and AsyncWrite.
    #[pin_project]
    pub struct TcpStream {
        /// Underlying tokio_util::compat::Compat wrapper.
        #[pin]
        s: Compat<TokioTcpStream>,
    }
    impl From<TokioTcpStream> for TcpStream {
        fn from(s: TokioTcpStream) -> TcpStream {
            let s = s.compat();
            TcpStream { s }
        }
    }
    impl From<TcpStream> for TokioTcpStream {
        fn from(s: TcpStream) -> TokioTcpStream {
            s.s.into_inner()
        }
    }
    impl AsyncRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            let p = self.project();
            p.s.poll_read(cx, buf)
        }
    }
    impl AsyncWrite for TcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            let p = self.project();
            p.s.poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let p = self.project();
            p.s.poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let p = self.project();
            p.s.poll_close(cx)
        }
    }

    impl TcpStream {
        /// Launch a TCP connection to a given address.
        pub async fn connect(addr: &SocketAddr) -> IoResult<Self> {
            let s = TokioTcpStream::connect(addr).await?;
            Ok(s.into())
        }
    }

    /// Wrap a Tokio TcpListener to behave as a futures::io::TcpListener.
    #[pin_project]
    pub struct TcpListener {
        /// The underlying listener.
        #[pin]
        lis: TokioTcpListener,
    }

    impl TcpListener {
        /// Create a new TcpListener listening on a given socket address.
        pub async fn bind<A>(addr: A) -> IoResult<Self>
        where
            A: Into<SocketAddr>,
        {
            let lis = TokioTcpListener::bind(addr.into()).await?;
            Ok(TcpListener { lis })
        }

        /// Try to accept a socket on this listener.
        pub async fn accept(&self) -> IoResult<(TcpStream, SocketAddr)> {
            let (stream, addr) = self.lis.accept().await?;
            Ok((stream.into(), addr))
        }

        /// Return a stream that yields incoming
        pub fn incoming(&self) -> Incoming<'_> {
            Incoming { lis: &self.lis }
        }
    }

    /// Asynchronous stream that yields incoming connections from a
    /// TcpListener.
    ///
    /// This is analogous to async_std::net::Incoming.
    #[pin_project]
    pub struct Incoming<'a> {
        /// Reference to the underlying listener.
        lis: &'a TokioTcpListener,
    }

    impl<'a> futures::stream::Stream for Incoming<'a> {
        type Item = IoResult<TcpStream>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let p = self.project();
            let (stream, _addr) = futures::ready!(p.lis.poll_accept(cx))?;

            Poll::Ready(Some(Ok(stream.into())))
        }
    }
}

/// Functions for launching and managing tasks (tokio implementation)
pub mod task {
    use std::future::Future;
    use tokio_crate::runtime::Runtime;

    /// Create a runtime and run `future` to completion
    pub fn block_on<F: Future>(future: F) -> F::Output {
        let rt = Runtime::new().unwrap(); // XXXX Not good: This could panic.
        rt.block_on(future)
    }

    pub use tokio_crate::spawn;
    pub use tokio_crate::task::JoinHandle;
    pub use tokio_crate::time::sleep;

    /// Stop the task `handle` from running.
    ///
    /// If you drop `handle` without calling this function, it will just
    /// run to completion.
    pub async fn cancel_task<T>(handle: JoinHandle<T>) {
        handle.abort()
    }
}

/// Functions and types for manipulating timers (tokio implementation)
pub mod timer {
    pub use tokio_crate::time::{error::Elapsed as TimeoutError, sleep, timeout};
}

/// Implement a set of TLS wrappers for use with tokio.
///
/// Right now only tokio_native_tls is supported.
pub mod tls {
    use async_trait::async_trait;
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    use futures::io::{AsyncRead, AsyncWrite};
    use pin_project::pin_project;

    use std::convert::TryFrom;
    use std::io::{Error as IoError, Result as IoResult};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Connection factory for building tls connections with tokio and
    /// native_tls.
    pub struct TlsConnector {
        /// The inner connector objject
        connector: tokio_native_tls::TlsConnector,
    }

    impl TryFrom<native_tls::TlsConnectorBuilder> for TlsConnector {
        type Error = native_tls::Error;
        fn try_from(builder: native_tls::TlsConnectorBuilder) -> native_tls::Result<TlsConnector> {
            let connector = builder.build()?.into();
            Ok(TlsConnector { connector })
        }
    }

    /// A TLS-over-TCP stream, using Tokio.
    #[pin_project]
    pub struct TlsStream {
        /// The inner stream object.
        #[pin]
        s: Compat<tokio_native_tls::TlsStream<tokio_crate::net::TcpStream>>,
    }

    #[async_trait]
    impl crate::tls::TlsConnector for TlsConnector {
        type Conn = TlsStream;

        async fn connect(&self, addr: &SocketAddr, hostname: &str) -> IoResult<Self::Conn> {
            let stream = tokio_crate::net::TcpStream::connect(addr).await?;

            let conn = self
                .connector
                .connect(hostname, stream)
                .await
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            let conn = conn.compat();
            Ok(TlsStream { s: conn })
        }
    }

    impl AsyncRead for TlsStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            let p = self.project();
            p.s.poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TlsStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            let p = self.project();
            p.s.poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let p = self.project();
            p.s.poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            let p = self.project();
            p.s.poll_close(cx)
        }
    }

    impl crate::tls::CertifiedConn for TlsStream {
        fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
            let cert = self.s.get_ref().get_ref().peer_certificate();
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

/// Traits specific to the runtime.
pub mod traits {
    pub use tokio_crate::io::{
        AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt,
        AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt,
    };
}
