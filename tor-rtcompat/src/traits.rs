use async_trait::async_trait;
use futures::stream;
use futures::{AsyncRead, AsyncWrite, Future};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::Duration;

pub use async_executors::SpawnHandle;
pub use futures::task::Spawn;

/// A runtime that we can use to run Tor as a client.
///
/// DOCDOC
pub trait Runtime:
    Sync + Send + Spawn + SpawnBlocking + Clone + SleepProvider + TcpProvider + TlsProvider + 'static
{
}

impl<T> Runtime for T where
    T: Sync
        + Send
        + Spawn
        + SpawnBlocking
        + Clone
        + SleepProvider
        + TcpProvider
        + TlsProvider
        + 'static
{
}

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
    type Incoming: stream::Stream<Item = IoResult<(Self::Stream, SocketAddr)>> + Unpin;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)>;
    fn incoming(self) -> Self::Incoming;
}

/// An object with a peer certificate.
pub trait CertifiedConn {
    /// Try to return the (der-encoded) peer certificate for this
    /// connection, if any.
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>>;
}

/// An object that knows how to make a TLS-over-TCP connection we
/// can use in Tor.
///
/// DOCDOC Not for general use.
#[async_trait]
pub trait TlsConnector {
    /// The type of connection returned by this connector
    type Conn: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    /// Launch a TLS-over-TCP connection to a given address.
    /// TODO: document args
    async fn connect_unvalidated(
        &self,
        addr: &SocketAddr,
        sni_hostname: &str,
    ) -> IoResult<Self::Conn>;
}

pub trait TlsProvider {
    type Connector: TlsConnector<Conn = Self::TlsStream> + Send + Sync + Unpin;
    type TlsStream: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    fn tls_connector(&self) -> Self::Connector;
}
