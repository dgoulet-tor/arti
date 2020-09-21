//! Talking directly (over a TLS connection) to a Tor node
//!
//! Right now, we only support connecting to a Tor relay as a client.
//!
//! To do so, launch a TLS connection, then call `start_client_handshake()`
//!
//! # Design
//!
//! For now, this code splits the channel into two pieces: a "Channel"
//! object that can be used by circuits to write cells onto the
//! channel, and a "Reactor" object that runs as a task in the
//! background, to read channel cells and pass them to circuits as
//! appropriate.
//!
//! I'm not at all sure that's the best way to do that, but it's what
//! I could think of.
//!
//! # Limitations
//!
//! This is client-only, and only supports link protocol version 4.
//!
//! TODO: There is no channel padding.
//!
//! TODO: There is no flow control, rate limiting, queueing, or
//! fairness.

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

// Type alias: A Sink and Stream that transforms a TLS connection into
// a cell-based communication mechanism.
type CellFrame<T> = futures_codec::Framed<T, codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
pub struct Channel {
    inner: Arc<Mutex<ChannelImpl>>,
}

/// Main implementation type for a channel.
struct ChannelImpl {
    /// What link protocol is the channel using?
    link_protocol: u16,
    /// The underlying channel, as a Sink of ChanCell.  Writing
    /// a ChanCell onto this sink sends it over the TLS channel.
    tls: Box<dyn Sink<ChanCell, Error = Error> + Send + Unpin + 'static>,
    /// A circuit map, to translate circuit IDs into circuits.
    ///
    /// The ChannelImpl side of this object only needs to use this
    /// when creating circuits; it's shared with the reactor, which uses
    /// it for dispatch.
    // This uses a separate mutex from the circmap, since we only need
    // the circmap when we're making a new circuit, the reactor needs
    // it all the time.
    circmap: Arc<Mutex<circmap::CircMap>>,
    /// A oneshot sender used to tell the Reactor task to shut down.
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
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    handshake::OutboundClientHandshake::new(tls)
}

impl Channel {
    /// Construct a channel and reactor.
    ///
    /// Internal method, called to finalize the channel when we've
    /// sent our netinfo cell, received the peer's netinfo cell, and
    /// we're finally ready to create circuits.
    fn new<T>(link_protocol: u16, tls: CellFrame<T>) -> (Self, reactor::Reactor<T>)
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
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

    /// Check whether a cell type is acceptable on an open client channel.
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

    /// Return a newly allocated PendingClientCirc object with
    /// corresponding reactor. A circuit ID is allocated, but no
    /// handshaking is done.
    ///
    /// To use the results of this method, call Reactor::run() in a
    /// new task, then use the methods of PendingClientCirc to build
    /// the circuit.
    pub async fn new_circ<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(circuit::PendingClientCirc, circuit::reactor::Reactor)> {
        // TODO: blocking is risky, but so is unbounded.
        let (sender, receiver) = mpsc::channel(128);
        let (createdsender, createdreceiver) = oneshot::channel::<msg::ChanMsg>();

        let id = {
            let inner = self.inner.lock().await;
            let mut cmap = inner.circmap.lock().await;
            cmap.add_ent(rng, createdsender, sender)?
        };

        Ok(circuit::PendingClientCirc::new(
            id,
            self.clone(),
            createdreceiver,
            receiver,
        ))
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
