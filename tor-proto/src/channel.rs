//! Talking directly (over a TLS connection) to a Tor node
//!
//! Right now, we only support connecting to a Tor relay as a client.
//!
//! To do so, launch a TLS connection, then pass it to a ChannelBuilder.
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
mod codec;
mod handshake;
mod logid;
mod reactor;

pub(crate) use crate::channel::logid::LogId;
use crate::channel::reactor::{CtrlMsg, CtrlResult};
use crate::circuit;
use crate::circuit::celltypes::CreateResponse;
use crate::{Error, Result};
use tor_cell::chancell::{msg, ChanCell, CircID};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RSAIdentity;

use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use futures::sink::{Sink, SinkExt};
use futures::stream::StreamExt;

use std::cell::Cell;
use std::sync::{Arc, Weak};

use log::trace;
use rand::Rng;

// reexport
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

/// Type alias: A Sink and Stream that transforms a TLS connection into
/// a cell-based communication mechanism.
type CellFrame<T> = futures_codec::Framed<T, crate::channel::codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
pub struct Channel {
    /// reference-counted locked wrapper around the channel object
    inner: Arc<Mutex<ChannelImpl>>,
}

/// Main implementation type for a channel.
struct ChannelImpl {
    /// What link protocol is the channel using?
    #[allow(dead_code)] // We don't support protocols where this would matter
    link_protocol: u16,
    /// The underlying channel, as a Sink of ChanCell.  Writing
    /// a ChanCell onto this sink sends it over the TLS channel.
    tls: Box<dyn Sink<ChanCell, Error = tor_cell::Error> + Send + Unpin + 'static>,
    /// If true, this channel is closing.
    closed: bool,
    /// A circuit map, to translate circuit IDs into circuits.
    ///
    /// The ChannelImpl side of this object only needs to use this
    /// when creating circuits; it's shared with the reactor, which uses
    /// it for dispatch.
    // This uses a separate mutex from the channel, since we only need
    // the circmap when we're making a new circuit, the reactor needs
    // it all the time.
    circmap: Weak<Mutex<circmap::CircMap>>,
    /// A stream used to send control messages to the Reactor.
    sendctrl: mpsc::Sender<CtrlResult>,
    /// A oneshot sender used to tell the Reactor task to shut down.
    sendclosed: Cell<Option<oneshot::Sender<CtrlMsg>>>,

    /// Logging identifier for this stream.  (Used for logging only.)
    logid: LogId,

    /// Context for allocating unique circuit log identifiers.
    circ_logid_ctx: logid::CircLogIdContext,
    /*
        /// Validated Ed25519 identity for this peer.
        ed25519_id: Ed25519Identity,
        /// Validated RSA identity for this peer.
        rsa_id: RSAIdentity,
    */
}

/// Structure for building and launching a Tor channel.
pub struct ChannelBuilder {
    /// If present, a description of the address we're trying to connect to,
    /// to be used in log messages.
    ///
    /// TODO: at some point, check this against the addresses in the
    /// netinfo cell too.
    target: Option<std::net::SocketAddr>,
}

impl ChannelBuilder {
    /// Construct a new ChannelBuilder.
    pub fn new() -> Self {
        ChannelBuilder { target: None }
    }

    /// Set the declared target address of this channel.
    ///
    /// Note that nothing enforces the correctness of this address: it
    /// doesn't have to match the real address target of the TLS
    /// stream.  For now it is only used for logging.
    pub fn set_declared_addr(&mut self, target: std::net::SocketAddr) {
        self.target = Some(target);
    }

    /// Launch a new client handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on
    /// the result to start the handshake.  If that succeeds, you'll have
    /// authentication info from the relay: call `check()` on the result
    /// to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T>(self, tls: T) -> OutboundClientHandshake<T>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        handshake::OutboundClientHandshake::new(tls, self.target)
    }
}

impl Default for ChannelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Construct a channel and reactor.
    ///
    /// Internal method, called to finalize the channel when we've
    /// sent our netinfo cell, received the peer's netinfo cell, and
    /// we're finally ready to create circuits.
    fn new<T>(
        link_protocol: u16,
        tls: CellFrame<T>,
        logid: LogId,
        _ed25519_id: Ed25519Identity,
        _rsa_id: RSAIdentity,
    ) -> (Self, reactor::Reactor<T>)
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        use circmap::{CircIDRange, CircMap};
        let circmap = Arc::new(Mutex::new(CircMap::new(CircIDRange::High)));

        let (sink, stream) = tls.split();

        let (sendctrl, recvctrl) = mpsc::channel::<CtrlResult>(128);
        let (sendclosed, recvclosed) = oneshot::channel::<CtrlMsg>();

        let inner = ChannelImpl {
            tls: Box::new(sink),
            link_protocol,
            closed: false,
            circmap: Arc::downgrade(&circmap),
            sendctrl,
            sendclosed: Cell::new(Some(sendclosed)),
            logid,
            circ_logid_ctx: logid::CircLogIdContext::new(),
            /*
            ed25519_id,
            rsa_id,
             */
        };
        let inner = Arc::new(Mutex::new(inner));
        let reactor =
            reactor::Reactor::new(inner.clone(), circmap, recvctrl, recvclosed, stream, logid);

        let channel = Channel { inner };

        (channel, reactor)
    }

    /// Check whether a cell type is acceptable on an open client channel.
    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        let msg = cell.msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell on client channel",
                msg.cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell after handshake is done",
                msg.cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&self, cell: ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        self.check_cell(&cell)?;
        let inner = &mut self.inner.lock().await;
        match cell.msg() {
            Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
            _ => trace!(
                "{}: Sending {} for {}",
                inner.logid,
                cell.msg().cmd(),
                cell.circid()
            ),
        }
        inner.send_cell(cell).await
        // XXXX I don't like holding the lock here. :(
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
        let (createdsender, createdreceiver) = oneshot::channel::<CreateResponse>();
        let (send_circ_destroy, recv_circ_destroy) = oneshot::channel();

        let (circ_logid, id) = {
            let mut inner = self.inner.lock().await;
            if inner.closed {
                return Err(Error::ChannelClosed);
            }
            inner
                .sendctrl
                .send(Ok(CtrlMsg::Register(recv_circ_destroy)))
                .await
                .map_err(|_| Error::InternalError("Can't queue circuit closer".into()))?;
            if let Some(circmap) = inner.circmap.upgrade() {
                let my_logid = inner.logid;
                let circ_logid = inner.circ_logid_ctx.next(my_logid);
                let mut cmap = circmap.lock().await;
                (circ_logid, cmap.add_ent(rng, createdsender, sender)?)
            } else {
                return Err(Error::ChannelClosed);
            }
        };
        trace!("{}: Allocated CircID {}", circ_logid, id);

        let destroy_handle = CircDestroyHandle::new(id, send_circ_destroy);

        Ok(circuit::PendingClientCirc::new(
            id,
            self.clone(),
            createdreceiver,
            destroy_handle,
            receiver,
            circ_logid,
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
            let _ignore = sender.send(CtrlMsg::Shutdown);
        }
    }
}

impl ChannelImpl {
    /// Try to send `cell` on this channel.
    async fn send_cell(&mut self, cell: ChanCell) -> Result<()> {
        if self.closed {
            return Err(Error::ChannelClosed);
        }
        self.tls.send(cell).await?;
        Ok(())
    }
}

/// Helper structure: when this is dropped, the reactor is told to kill
/// the circuit.
pub(crate) struct CircDestroyHandle {
    /// The circuit ID in question
    id: CircID,
    /// A oneshot sender to tell the reactor.  This has to be a oneshot,
    /// so that we can send to it on drop.
    sender: Cell<Option<oneshot::Sender<CtrlMsg>>>,
}

impl CircDestroyHandle {
    /// Create a new CircDestroyHandle
    fn new(id: CircID, sender: oneshot::Sender<CtrlMsg>) -> Self {
        CircDestroyHandle {
            id,
            sender: Cell::new(Some(sender)),
        }
    }
}

impl Drop for CircDestroyHandle {
    fn drop(&mut self) {
        if let Some(s) = self.sender.take() {
            let _ignore_cancel = s.send(CtrlMsg::CloseCircuit(self.id));
        }
    }
}
