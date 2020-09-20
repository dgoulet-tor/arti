//! Talking directly (over a TLS connection) to a Tor node
//!
//! Right now, we only support connecting to a Tor relay as a client.
//!
//! To do so, launch a TLS connection, then call `start_client_handshake()`
//!
//! TODO: channel padding support.

mod circmap;
mod handshake;
mod reactor;

use crate::chancell::{codec, msg, ChanCell};
use crate::circuit;
use crate::{Error, Result};

use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use futures::sink::{Sink, SinkExt};
use futures::stream::StreamExt;

use std::cell::Cell;
use std::sync::Arc;

use log::trace;
use rand::Rng;

// reexport
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

type CellFrame<T> = futures_codec::Framed<T, codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
pub struct Channel {
    inner: Arc<Mutex<ChannelImpl>>,
}

/// Main implementation type for a channel.
struct ChannelImpl {
    link_protocol: u16,
    // This uses a separate mutex from the circmap, since we only
    // need the circmap when we're making a new circuit, but we need
    // this _all the time_.
    tls: Box<dyn Sink<ChanCell, Error = Error> + Unpin + 'static>,
    // TODO: I wish I didn't need a second Arc here, but I guess I do?
    // An rwlock would be better.
    circmap: Arc<Mutex<circmap::CircMap>>,
    sendclosed: Cell<Option<oneshot::Sender<()>>>,
}

/// Launch a new client handshake over a TLS stream.
///
/// After calling this function, you'll need to call `connect()` on
/// the result to start the handshake.  If that succeeds, you'll have
/// authentication info from the relay: call `check()` on the result
/// to check that.  Finally, to finish the handshake, call `finish()`
/// on the result of _that_.
pub fn start_client_handshake<T>(tls: T) -> OutboundClientHandshake<T>
where
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    handshake::OutboundClientHandshake::new(tls)
}

impl Channel {
    /// Construct a channel and reactor.
    fn new<T>(link_protocol: u16, tls: CellFrame<T>) -> (Self, reactor::Reactor<T>)
    where
        T: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        use circmap::{CircIDRange, CircMap};
        let circmap = Arc::new(Mutex::new(CircMap::new(CircIDRange::High)));

        let (sink, stream) = tls.split();

        let (sendclosed, recvclosed) = oneshot::channel::<()>();

        let inner = ChannelImpl {
            tls: Box::new(sink),
            link_protocol,
            circmap: circmap.clone(),
            sendclosed: Cell::new(Some(sendclosed)),
        };

        let reactor = reactor::Reactor::new(circmap, recvclosed, stream);

        let channel = Channel {
            inner: Arc::new(Mutex::new(inner)),
        };

        (channel, reactor)
    }

    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        let msg = cell.get_msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell on client channel",
                msg.get_cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell after handshake is done",
                msg.get_cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&self, cell: ChanCell) -> Result<()> {
        trace!(
            "Sending {} on {}",
            cell.get_msg().get_cmd(),
            cell.get_circid()
        );
        self.check_cell(&cell)?;
        let sink = &mut self.inner.lock().await.tls;
        // XXXX I don't like holding the lock here. :(
        sink.send(cell).await?;

        Ok(())
    }

    /// Return a newly allocated ClientCirc object. A circuit ID is
    /// allocated, but no handshaking is done.
    // XXXX TODO: make this hidden, and wrap it in another function that
    // does the handshake. That way we only need to handle RELAY
    // and destroy.
    pub async fn new_circ<R: Rng>(&self, rng: &mut R) -> Result<circuit::ClientCirc> {
        // TODO: blocking is risky, but so is unbounded.
        let (sender, receiver) = mpsc::channel(128);

        let id = {
            let inner = self.inner.lock().await;
            let mut cmap = inner.circmap.lock().await;
            cmap.add_ent(rng, sender)?
        };

        Ok(circuit::ClientCirc::new(id, self.clone(), receiver))
    }
}

impl Clone for Channel {
    fn clone(&self) -> Self {
        Channel {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for ChannelImpl {
    fn drop(&mut self) {
        if let Some(sender) = self.sendclosed.take() {
            let _ignore = sender.send(());
        }
    }
}
