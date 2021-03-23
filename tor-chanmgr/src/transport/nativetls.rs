//! Build TLS connections using the async_native_tls or tokio_native_tls crate.

// XXXX-A2 This should get refactored significantly.  Probably we should have
// a boxed-connection-factory type that we can use instead.  Once we have a
// pluggable designn, we'll really need something like that.
//
// Probably, much of this code should move into tor-rtcompat, or a new
// crate similar to tor-rtcompat, that can handle our TLS drama.

use super::{CertifiedConn, Transport};
use crate::{Error, Result};
use tor_linkspec::ChanTarget;
use tor_rtcompat::net::TcpStream;

use anyhow::Context;
use async_trait::async_trait;
// use futures::io::{AsyncRead, AsyncWrite};
use async_native_tls::{TlsConnector, TlsStream};

use log::info;

/// A Transport that uses async_native_tls.
pub struct NativeTlsTransport {
    /// connector object used to build TLS connections
    connector: TlsConnector,
}

impl NativeTlsTransport {
    /// Construct a new NativeTlsTransport.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // These function names are scary, but they just mean that
        // we're skipping web pki, and using our own PKI functions.
        let mut builder = native_tls::TlsConnector::builder();
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);

        let connector = builder.into();

        NativeTlsTransport { connector }
    }
}

/// The connection type returned by NativeTlsTransport.
type TlsConnection = TlsStream<TcpStream>;

#[async_trait]
impl Transport for NativeTlsTransport {
    type Connection = TlsConnection;

    async fn connect<T: ChanTarget + Sync + ?Sized>(
        &self,
        target: &T,
    ) -> Result<(std::net::SocketAddr, Self::Connection)> {
        // TODO: This just uses the first address. Instead we could be smarter,
        // or use "happy eyeballs, or whatever.  Maybe we will want to
        // refactor as we do so?
        let addr = target
            .addrs()
            .get(0)
            .ok_or_else(|| Error::UnusableTarget("No addresses for chosen relay".into()))?;

        info!("Connecting to {}", addr);
        let stream = TcpStream::connect(addr)
            .await
            .context("Can't make a TCP stream to target relay.")?;

        info!("Negotiating TLS with {}", addr);

        // TODO: add a random hostname here if it will be used for SNI?
        let connection = self.connector.connect("ignored", stream).await?;
        Ok((*addr, connection))
    }
}

impl CertifiedConn for TlsConnection {
    fn peer_cert(&self) -> Result<Option<Vec<u8>>> {
        let cert = self.peer_certificate();

        match cert {
            Ok(Some(cert)) => Ok(Some(cert.to_der()?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
