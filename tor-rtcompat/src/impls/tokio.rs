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
    pub use tokio_crate::time::sleep;
}

/// Functions and types for manipulating timers (tokio implementation)
pub mod timer {
    pub use tokio_crate::time::{error::Elapsed as TimeoutError, sleep, timeout};
}

/// Traits specific to the runtime.
pub mod traits {
    pub use tokio_crate::io::{
        AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt,
        AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt,
    };
}
