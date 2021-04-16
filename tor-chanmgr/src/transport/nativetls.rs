//! Build TLS connections using the async_native_tls or tokio_native_tls crate.

// XXXX-A2 This should get refactored significantly.  Probably we should have
// a boxed-connection-factory type that we can use instead.  Once we have a
// pluggable designn, we'll really need something like that.
//
// Probably, much of this code should move into tor-rtcompat, or a new
// crate similar to tor-rtcompat, that can handle our TLS drama.

use super::Transport;
use crate::{Error, Result};
use tor_linkspec::ChanTarget;
use tor_rtcompat::traits::TlsConnector;

use async_trait::async_trait;

use log::info;

/// A Transport that uses a connector based on native_tls.
pub struct NativeTlsTransport<C: TlsConnector> {
    /// connector object used to build TLS connections
    connector: C,
}

impl<C: TlsConnector> NativeTlsTransport<C> {
    /// Construct a new NativeTlsTransport.
    pub fn new(connector: C) -> Result<Self> {
        Ok(NativeTlsTransport { connector })
    }
}

#[async_trait]
impl<C: TlsConnector + Send + Sync + Unpin> Transport for NativeTlsTransport<C> {
    type Connection = C::Conn;

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

        info!("Negotiating TLS with {}", addr);

        // TODO: add a random hostname here if it will be used for SNI?
        let connection = self.connector.connect_unvalidated(addr, "ignored").await?;
        Ok((*addr, connection))
    }
}
