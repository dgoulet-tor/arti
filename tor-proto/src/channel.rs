//! Code for talking directly (over a TLS connection) to a Tor node.
//!
//! Channels form the basis of the rest of the Tor protocol: they are
//! the only way for two Tor instances to talk.
//!
//! Channels are not useful directly for application requests: after
//! making a channel, it needs to get used to build circuits, and the
//! circuits are used to anonymize streams.  The streams are the
//! objects corresponding to directory requests.
//!
//! In general, you shouldn't try to manage channels on your own;
//! however, there is no alternative in Arti today.  (A future
//! channel-manager library will probably fix that.)
//!
//! To launch a channel:
//!
//!  * Create a TLS connection as an object that implements AsyncRead
//!    + AsyncWrite, and pass it to a [ChannelBuilder].  This will
//!    yield an [handshake::OutboundClientHandshake] that represents
//!    the state of the handshake.
//!  * Call [handshake::OutboundClientHandshake:connect] on the result
//!    to negotiate the rest of the handshake.  This will verify
//!    syntactic correctness of the handshake, but not its cryptographic
//!    integrity.
//!  * Call [handshake::UnverifiedChannel::check] on the result.  This
//!    finishes the cryptographic checks.
//!  * Call [handshake::VerifiedChannel::finish] on the result. This
//!    completes the handshake and produces an open channel and Reactor.
//!  * Launch an asynchronous task to call the reactor's run() method.
//!
//! One you have a running channel, you can create circuits on it with
//! its [Channel::new_circ] method.  See
//! [crate::circuit::PendingClientCirc] for information on how to
//! procede from there.
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
use tor_cell::chancell::{msg, ChanCell, CircId};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RSAIdentity;

use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use futures::sink::{Sink, SinkExt};
use futures::stream::Stream;

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
///
/// TODO: This is actually reference-counted counted handle.  In theory
/// I'm supposed to give it a name to reflect that.
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
    sendclosed: Option<oneshot::Sender<CtrlMsg>>,

    /// Logging identifier for this stream.  (Used for logging only.)
    logid: LogId,

    /// Context for allocating unique circuit log identifiers.
    circ_logid_ctx: logid::CircLogIdContext,
    /// Validated Ed25519 identity for this peer.
    #[allow(unused)]
    ed25519_id: Ed25519Identity,
    /// Validated RSA identity for this peer.
    #[allow(unused)]
    rsa_id: RSAIdentity,
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
        tls_sink: Box<dyn Sink<ChanCell, Error = tor_cell::Error> + Send + Unpin + 'static>,
        tls_stream: T,
        logid: LogId,
        ed25519_id: Ed25519Identity,
        rsa_id: RSAIdentity,
    ) -> (Self, reactor::Reactor<T>)
    where
        T: Stream<Item = std::result::Result<ChanCell, tor_cell::Error>> + Send + Unpin + 'static,
    {
        use circmap::{CircIdRange, CircMap};
        let circmap = Arc::new(Mutex::new(CircMap::new(CircIdRange::High)));

        let (sendctrl, recvctrl) = mpsc::channel::<CtrlResult>(128);
        let (sendclosed, recvclosed) = oneshot::channel::<CtrlMsg>();

        let inner = ChannelImpl {
            tls: tls_sink,
            link_protocol,
            closed: false,
            circmap: Arc::downgrade(&circmap),
            sendctrl,
            sendclosed: Some(sendclosed),
            logid,
            circ_logid_ctx: logid::CircLogIdContext::new(),
            ed25519_id,
            rsa_id,
        };
        let inner = Arc::new(Mutex::new(inner));
        let reactor = reactor::Reactor::new(
            inner.clone(),
            circmap,
            recvctrl,
            recvclosed,
            tls_stream,
            logid,
        );

        let channel = Channel { inner };

        (channel, reactor)
    }

    /// Allocate and return a new reference to this channel.
    fn new_ref(&self) -> Self {
        Channel {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Check whether a cell type is acceptable on an open client channel.
    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        let msg = cell.msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::InternalError(format!(
                "Can't send {} cell on client channel",
                msg.cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::InternalError(format!(
                "Can't send {} cell after handshake is done",
                msg.cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&self, cell: ChanCell) -> Result<()> {
        self.check_cell(&cell)?;
        let inner = &mut self.inner.lock().await;
        inner.send_cell(cell).await
    }

    /// Return a newly allocated PendingClientCirc object with
    /// a corresponding circuit reactor. A circuit ID is allocated, but no
    /// messages are sent, and no cryptography is done.
    ///
    /// To use the results of this method, call Reactor::run() in a
    /// new task, then use the methods of
    /// [crate::circuit::PendingClientCirc] to build the circuit.
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
        trace!("{}: Allocated CircId {}", circ_logid, id);

        let destroy_handle = CircDestroyHandle::new(id, send_circ_destroy);

        Ok(circuit::PendingClientCirc::new(
            id,
            self.new_ref(),
            createdreceiver,
            Some(destroy_handle),
            receiver,
            circ_logid,
        ))
    }

    /// Shut down this channel immediately, along with all circuits that
    /// are using it.
    ///
    /// Note that other references to this channel may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a channel: the channel should close on its own once nothing
    /// is using it any more.
    pub async fn terminate(self) {
        let mut inner = self.inner.lock().await;
        inner.shutdown();
        // ignore any failure to flush; we can't do anything about it.
        let _ignore = inner.tls.flush().await;
    }
}

impl Drop for ChannelImpl {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl ChannelImpl {
    /// Try to send `cell` on this channel.
    async fn send_cell(&mut self, cell: ChanCell) -> Result<()> {
        if self.closed {
            return Err(Error::ChannelClosed);
        }
        use msg::ChanMsg::*;
        match cell.msg() {
            Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
            _ => trace!(
                "{}: Sending {} for {}",
                self.logid,
                cell.msg().cmd(),
                cell.circid()
            ),
        }
        self.tls.send(cell).await?; // XXXX I don't like holding the lock here.
        Ok(())
    }

    /// Shut down this channel; causes all circuits using this channel
    /// to become unusable.
    fn shutdown(&mut self) {
        if let Some(sender) = self.sendclosed.take() {
            let _ignore = sender.send(CtrlMsg::Shutdown);
        }
        self.closed = true;
    }
}

/// Helper structure: when this is dropped, the reactor is told to kill
/// the circuit.
pub(crate) struct CircDestroyHandle {
    /// The circuit ID in question
    id: CircId,
    /// A oneshot sender to tell the reactor.  This has to be a oneshot,
    /// so that we can send to it on drop.
    sender: Option<oneshot::Sender<CtrlMsg>>,
}

impl CircDestroyHandle {
    /// Create a new CircDestroyHandle
    fn new(id: CircId, sender: oneshot::Sender<CtrlMsg>) -> Self {
        CircDestroyHandle {
            id,
            sender: Some(sender),
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

#[cfg(test)]
pub(crate) mod test {
    // Most of this module is tested via tests that also check on the
    // reactor code; there are just a few more cases to examine here.
    use super::*;
    use crate::channel::codec::test::MsgBuf;
    use crate::channel::reactor::test::new_reactor;
    use futures::stream::StreamExt;
    use futures_await_test::async_test;
    use tor_cell::chancell::{msg, msg::ChanMsg, ChanCell};

    /// Type returned along with a fake channel: used to impersonate a
    /// reactor and a network.
    #[allow(unused)]
    pub(crate) struct FakeChanHandle {
        pub cells: mpsc::Receiver<ChanCell>,
        circmap: Arc<Mutex<circmap::CircMap>>,
        ignore_control_msgs: mpsc::Receiver<CtrlResult>,
    }

    /// Make a new fake reactor-less channel.  For testing only, obviously.
    ///
    /// This function is used for testing _circuits_, not channels.
    pub(crate) fn fake_channel() -> (Channel, FakeChanHandle) {
        let (cell_send, cell_recv) = mpsc::channel(64);
        let (ctrl_send, ctrl_recv) = mpsc::channel(64);

        let cell_send = cell_send.sink_map_err(|_| {
            tor_cell::Error::InternalError("Error from mpsc stream while testing".into())
        });

        let circmap = circmap::CircMap::new(circmap::CircIdRange::High);
        let circmap = Arc::new(Mutex::new(circmap));
        let logid = LogId::new();
        let inner = ChannelImpl {
            link_protocol: 4,
            tls: Box::new(cell_send),
            closed: false,
            circmap: Arc::downgrade(&circmap),
            sendctrl: ctrl_send,
            sendclosed: None,
            logid,
            circ_logid_ctx: logid::CircLogIdContext::new(),
            ed25519_id: [0u8; 32].into(),
            rsa_id: [0u8; 20].into(),
        };
        let channel = Channel {
            inner: Arc::new(Mutex::new(inner)),
        };
        let handle = FakeChanHandle {
            cells: cell_recv,
            circmap,
            ignore_control_msgs: ctrl_recv,
        };

        (channel, handle)
    }

    #[async_test]
    async fn send_bad() {
        let (chan, _reactor, mut output, _input) = new_reactor();

        let cell = ChanCell::new(7.into(), msg::Created2::new(&b"hihi"[..]).into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_err());
        assert_eq!(
            format!("{}", e.unwrap_err()),
            "Internal programming error: Can't send CREATED2 cell on client channel"
        );
        let cell = ChanCell::new(0.into(), msg::Certs::new_empty().into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_err());
        assert_eq!(
            format!("{}", e.unwrap_err()),
            "Internal programming error: Can't send CERTS cell after handshake is done"
        );

        let cell = ChanCell::new(5.into(), msg::Create2::new(2, &b"abc"[..]).into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_ok());
        let got = output.next().await.unwrap();
        assert!(matches!(got.msg(), ChanMsg::Create2(_)));
    }

    #[test]
    fn chanbuilder() {
        let mut builder = ChannelBuilder::default();
        builder.set_declared_addr("127.0.0.1:9001".parse().unwrap());
        let tls = MsgBuf::new(&b""[..]);
        let _outbound = builder.launch(tls);
    }
}
