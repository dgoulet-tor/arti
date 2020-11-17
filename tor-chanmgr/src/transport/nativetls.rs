//! Build TLS connections using the async_native_tls crate.
//!
//! Requires that this crate was built with the `nativetls` feature,
//! which is currently on-by-default.

use super::{CertifiedConn, Transport};
use crate::{Error, Result};
use tor_linkspec::ChanTarget;
use tor_rtcompat::net::TcpStream;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};

use log::info;

/// A Transport that uses async_native_tls.
pub struct NativeTlsTransport {
    /// connector object used to build TLS connections
    connector: async_native_tls::TlsConnector,
}

impl NativeTlsTransport {
    /// Construct a new NativeTlsTransport.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // These function names are scary, but they just mean that
        // we're skipping web pki, and using our own PKI functions.
        let connector = async_native_tls::TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);

        NativeTlsTransport { connector }
    }
}

#[async_trait]
impl Transport for NativeTlsTransport {
    type Connection = async_native_tls::TlsStream<TcpStream>;

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
        let stream = TcpStream::connect(addr).await?;

        info!("Negotiating TLS with {}", addr);
        // TODO: add a random hostname here if it will be used for SNI?
        Ok((*addr, self.connector.connect("ignored", stream).await?))
    }
}

impl<S> CertifiedConn for async_native_tls::TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn peer_cert(&self) -> Result<Option<Vec<u8>>> {
        match self.peer_certificate() {
            Ok(Some(cert)) => Ok(Some(cert.to_der()?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
