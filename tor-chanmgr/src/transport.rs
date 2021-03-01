//! Types for launching TLS connections to relays

pub mod nativetls;

use crate::Result;

use tor_linkspec::ChanTarget;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};

/// A Transport knows how to build a TLS connection to a relay, in a way
/// that Tor can use.
///
/// Tor doesn't expect to get any particular hostname or sequence of
/// certificates in the reply; it only expects that the peer certificate
/// will later be authenticated inside the Tor handshake.
#[async_trait]
pub trait Transport {
    /// The type that will be returned by this transport.  This should
    /// be an asynchronous TLS connection.
    type Connection: AsyncRead + AsyncWrite + Send + Unpin + CertifiedConn + 'static;

    /// Try to connect to a given relay.
    async fn connect<T: ChanTarget + Sync + ?Sized>(
        &self,
        target: &T,
    ) -> Result<(std::net::SocketAddr, Self::Connection)>;
}

/// A CertifiedConn is a connection that has authenticated using some
/// certificate.
///
/// (As far as Tor is concerned, this certificate is just a bunch of bytes.)
pub trait CertifiedConn {
    /// Return the peer's certificate, if it has one.
    fn peer_cert(&self) -> Result<Option<Vec<u8>>>;
}
