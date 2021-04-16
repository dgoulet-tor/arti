use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, Future};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::Duration;

pub use async_executors::SpawnHandle;
pub use futures::task::Spawn;

/// A runtime that we can use to run Tor as a client.
///
/// DOCDOC
pub trait Runtime: Send + Spawn + SpawnBlocking + Clone + SleepProvider + TcpProvider {}

impl<T> Runtime for T where T: Send + Spawn + SpawnBlocking + Clone + SleepProvider + TcpProvider {}

pub trait SleepProvider {
    type SleepFuture: Future<Output = ()> + Send + 'static;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture;
}

pub trait SpawnBlocking {
    fn block_on<F: Future>(&self, f: F) -> F::Output;
}

// TODO: Use of asynctrait is not ideal, since we have to box with every
// call.  Still, async_io basically makes that necessary :/
#[async_trait]
pub trait TcpProvider {
    type TcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
    type TcpListener: TcpListener<Stream = Self::TcpStream> + Send + Sync + Unpin + 'static;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream>;
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener>;
}

// TODO: Use of asynctrait is not ideal here either.
#[async_trait]
pub trait TcpListener {
    type Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)>;
}
