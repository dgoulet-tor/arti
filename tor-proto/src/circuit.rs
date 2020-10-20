//! Multi-hop paths over the Tor network.
//!
//! Right now, we only implement "client circuits" -- also sometimes
//! called "origin circuits".  A client circuit is one that is
//! constructed by this Tor instance, and used in its own behalf to
//! send data over the Tor network.
//!
//! Each circuit has multiple hops over the Tor network: each hop
//! knows only the hop before and the hop after.  The client shares a
//! separate set of keys with each hop.
//!
//! # Implementation
//!
//! Each open circuit has a corresponding Reactor object that runs in
//! an asynchronous task, and manages incoming cells from the
//! circuit's upstream channel.  These cells are either RELAY cells or
//! DESTROY cells.  DESTROY cells are handled immediately.
//! RELAY cells are either for a particular stream, in which case they
//! get forwarded to a TorStream object, or for no particular stream,
//! in which case they are considered "meta" cells (like EXTENEDED2)
//! that should only get accepted if something is waiting for them.
//!
//! # Limitations
//!
//! This is client-only.
//!
//! There's one big mutex on the whole circuit: the reactor needs to hold
//! it to process a cell, and streams need to hold it to send.
//!
//! XXXX There is no flow-control or rate-limiting or fairness.

pub(crate) mod celltypes;
mod halfstream;
mod logid;
pub(crate) mod reactor;
pub(crate) mod sendme;
mod streammap;

use crate::channel::{Channel, CircDestroyHandle};
use crate::circuit::celltypes::*;
pub(crate) use crate::circuit::logid::LogId;
use crate::circuit::reactor::{CtrlMsg, CtrlResult};
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody,
};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::stream::{DataStream, TorStream};
use crate::{Error, Result};
use tor_cell::chancell::{self, msg::ChanMsg, ChanCell, CircID};
use tor_cell::relaycell::msg::{RelayMsg, Sendme};
use tor_cell::relaycell::{RelayCell, RelayCmd, StreamID};

use tor_linkspec::LinkSpec;

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use futures::sink::SinkExt;

use std::cell::Cell;
use std::sync::Arc;

use rand::{thread_rng, CryptoRng, Rng};

use log::{debug, trace};

/// A circuit that we have constructed over the Tor network.
#[derive(Clone)]
pub struct ClientCirc {
    /// Reference-counted locked reference to the inner circuit object.
    c: Arc<Mutex<ClientCircImpl>>,
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call create_firsthop_fast() or create_firsthop_ntor()
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: ClientCirc,
}

/// A result type used to tell a circuit about some a "meta-cell"
/// (like extended, intro_established, etc).
type MetaResult = Result<(HopNum, RelayMsg)>;

/// The implementation type for this circuit.
struct ClientCircImpl {
    /// This circuit's ID on the upstream channel.
    id: CircID,
    /// The channel that this circuit uses to send its cells to the
    /// next hop.
    channel: Channel,
    /// The cryptographic state for this circuit for outbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit
    crypto_out: OutboundClientCrypt,
    /// This circuit can't be used because it has been closed, locally
    /// or remotely.
    closed: bool,
    /// When this is dropped, the channel reactor is told to send a DESTROY
    /// cell.
    circ_closed: Option<CircDestroyHandle>,
    /// Per-hop circuit information.
    ///
    /// Note that hops.len() must be the same as crypto.n_layers().
    hops: Vec<CircHop>,
    /// A stream that can be used to register streams with the reactor.
    control: mpsc::Sender<CtrlResult>,
    /// A oneshot sender that can be used to tell the reactor to shut down.
    sendshutdown: Cell<Option<oneshot::Sender<CtrlMsg>>>,
    /// A oneshot sender that can be used by the reactor to report a
    /// meta-cell to an owning task.
    ///
    /// For the purposes of this implementation, a "meta" cell
    /// is a RELAY cell with a stream ID value of 0.
    sendmeta: Cell<Option<oneshot::Sender<MetaResult>>>,
    /// An identifier for this circuit, for logging purposes.
    logid: LogId,
}

/// A handle to a circuit as held by a stream. Used to send cells.
///
/// Rather than using the stream directly, the stream uses this object
/// to send its relay cells to the correct hop, using the correct stream ID.
///
/// When this object is dropped, the reactor will be told to close the stream.
// XXXX TODO: rename this
pub(crate) struct StreamTarget {
    /// The stream ID for this stream on its circuit.
    stream_id: StreamID,
    /// Which hop on this circuit is this stream built from?
    // XXXX Using 'hop' by number here will cause bugs if circuits can get
    // XXXX truncated and then re-extended.
    hop: HopNum,
    /// Reference to the circuit that this stream is on.
    circ: ClientCirc,
    /// Window for sending cells on this circuit.
    window: sendme::StreamSendWindow,
    /// One-shot sender that should get a message once this stream
    /// is dropped.
    stream_closed: Cell<Option<oneshot::Sender<CtrlMsg>>>,
    /// Window to track incoming cells and SENDMEs.
    // XXXX Putting this field here in this object means that this
    // object isn't really so much a "target", since a "target"
    // doesn't know how to receive.  Maybe we should rename it to be
    // some kind of a "handle" or something?
    pub(crate) recvwindow: sendme::StreamRecvWindow,
}

/// Information about a single hop of a client circuit, from the sender-side
/// point of view.
///
/// (see also circuit::reactor::InboundHop)
struct CircHop {
    /// If true, this hop is using an older link protocol and we
    /// shouldn't expect good authenticated SENDMEs from it.
    auth_sendme_optional: bool,
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
}

impl CircHop {
    /// Construct a new (sender-side) view of a circuit hop.
    fn new(auth_sendme_optional: bool) -> Self {
        CircHop {
            auth_sendme_optional,
            // TODO: this value should come from the consensus and not be
            // hardcoded. XXXXA1
            sendwindow: sendme::CircSendWindow::new(1000),
        }
    }
}

impl ClientCirc {
    /// Helper: Register a handler that will be told about the RELAY message
    /// with StreamID 0.
    ///
    /// This pattern is useful for parts of the protocol where the circuit
    /// originator sends a single request, and waits for a single relay
    /// message in response.  (For example, EXTEND/EXTENDED,
    /// ESTABLISH_RENDEZVOUS/RENDEZVOUS_ESTABLISHED, and so on.)
    ///
    /// It isn't suitable for SENDME cells, INTRODUCE2 cells, or TRUNCATED
    /// cells.
    ///
    /// Only one handler can be registerd at a time; until it fires or is
    /// cancelled, you can't register another.
    ///
    /// Note that you should register a meta handler _before_ you send whatever
    /// cell you're waiting a response to, or you might miss the response.
    // TODO: It would be cool for this to take a list of allowable
    // cell types to get in response, so that any other cell types are
    // treated as circuit protocol violations automatically.
    async fn register_meta_handler(&mut self) -> Result<oneshot::Receiver<MetaResult>> {
        let (sender, receiver) = oneshot::channel();

        let circ = self.c.lock().await;
        // Store the new sender as the meta-handler for this circuit.
        let prev = circ.sendmeta.replace(Some(sender));
        // Was there previously a handler?
        if prev.is_some() {
            circ.sendmeta.replace(prev); // put the old value back.
            return Err(Error::InternalError(
                "Tried to register a second meta-cell handler".into(),
            ));
        }

        trace!("{}: Registered a meta-cell handler", circ.logid);

        Ok(receiver)
    }

    /// Helper: extend the circuit by one hop.
    ///
    /// The `rng` is used to generate handshake material.  The
    /// `handshake_id` is the numeric identifer for what kind of
    /// handshake we're doing.  The `key is the relay's onion key that
    /// goes along with the handshake, and the `linkspecs` are the
    /// link specifiers to include in the EXTEND cell to tell the
    /// current last hop which relay to connect to.
    async fn extend_impl<R, L, FWD, REV, H>(
        &mut self,
        rng: &mut R,
        handshake_id: u16,
        key: &H::KeyType,
        linkspecs: Vec<LinkSpec>,
        supports_flowctrl_1: bool,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV>,
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        H::KeyGen: KeyGenerator,
    {
        use tor_cell::relaycell::msg::{Body, Extend2};
        // Perform the first part of the cryptographic handshake
        let (state, msg) = H::client1(rng, &key)?;
        // Cloning linkspecs is only necessary because of the log
        // below. Would be nice to fix that.
        let extend_msg = Extend2::new(linkspecs.clone(), handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.as_message());

        // We'll be waiting for an EXTENDED2 cell; install the handler.
        let receiver = self.register_meta_handler().await?;

        // Now send the EXTEND2 cell to the the last hop...
        let (logid, hop) = {
            let mut c = self.c.lock().await;
            let n_hops = c.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();
            debug!(
                "{}: Extending circuit to hop {} with {:?}",
                c.logid,
                n_hops + 1,
                linkspecs
            );

            // Send the message to the last hop...
            c.send_relay_cell(
                hop, true, // use a RELAY_EARLY cell
                cell,
            )
            .await?;

            (c.logid, hop)
            // note that we're dropping the lock here, since we're going
            // to wait for a response.
        };

        trace!("{}: waiting for EXTENDED2 cell", logid);
        // ... and now we wait for a response.
        let (from_hop, msg) = receiver.await.map_err(|_| {
            Error::CircDestroy("Circuit closed while waiting for extended cell".into())
        })??;

        // XXXX If two EXTEND cells are of these are launched on the
        // same circuit at once, could they collide in this part of
        // the function? XXXXM3

        // Did we get the right response?
        if from_hop != hop || msg.cmd() != RelayCmd::EXTENDED2 {
            self.c.lock().await.shutdown();
            return Err(Error::CircProto(format!(
                "wanted EXTENDED2 from {}; got {} from {}",
                hop,
                msg.cmd(),
                from_hop
            )));
        }

        // ???? Do we need to shutdown the circuit for the remaining error
        // ???? cases in this function?

        let msg = match msg {
            RelayMsg::Extended2(e) => e,
            _ => return Err(Error::InternalError("Body didn't match cmd".into())),
        };
        let server_handshake = msg.into_body();

        trace!("{}: Received EXTENDED2 cell; completing handshake.", logid);
        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let keygen = H::client2(state, server_handshake)?;
        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit extended.", logid);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back) = layer.split();
        self.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    ///
    /// This function is a bit tricky, since we need to add the
    /// hop to our own structures, and tell the reactor to add it to the
    /// reactor's structures as well, and wait for the reactor to tell us
    /// that it did.
    async fn add_hop(
        &self,
        supports_flowctrl_1: bool,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
    ) -> Result<()> {
        let inbound_hop = crate::circuit::reactor::InboundHop::new();
        let (snd, rcv) = oneshot::channel();
        {
            let mut c = self.c.lock().await;
            c.control
                .send(Ok(CtrlMsg::AddHop(inbound_hop, rev, snd)))
                .await
                .map_err(|_| Error::InternalError("Can't queue AddHop request".into()))?;
        }

        // XXXX need to do something make sure that we aren't trying to add
        // two hops at once. XXXXM3

        rcv.await
            .map_err(|_| Error::InternalError("AddHop request cancelled".into()))?;

        {
            let mut c = self.c.lock().await;
            let hop = CircHop::new(supports_flowctrl_1);
            c.hops.push(hop);
            c.crypto_out.add_layer(fwd);
        }
        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.  Same caveats apply from extend_impl.
    pub async fn extend_ntor<R, Tg>(&mut self, rng: &mut R, target: &Tg) -> Result<()>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let key = NtorPublicKey {
            id: target.rsa_identity().clone(),
            pk: *target.ntor_onion_key(),
        };
        let linkspecs = target.linkspecs();
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.extend_impl::<R, Tor1RelayCrypto, _, _, NtorClient>(
            rng,
            0x0002,
            &key,
            linkspecs,
            supports_flowctrl_1,
        )
        .await
    }

    /// Helper, used to begin a stream.
    ///
    /// This function allocates a stream ID, and sends the message
    /// (like a BEGIN or RESOLVE), but doesn't wait for a response.
    ///
    /// The caller will typically want to see the first cell in response,
    /// to see whether it is e.g. an END or a CONNECTED.
    async fn begin_stream_impl(&mut self, begin_msg: RelayMsg) -> Result<TorStream> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.

        // XXXX Both a bound and a lack of bound are scary here :/
        let (sender, receiver) = mpsc::channel(128);

        let (send_close, recv_close) = oneshot::channel::<CtrlMsg>();
        let window = sendme::StreamSendWindow::new(StreamTarget::SEND_WINDOW_INIT);

        let (id_snd, id_rcv) = oneshot::channel();
        let hopnum;
        {
            let mut c = self.c.lock().await;
            let h = c.hops.len() - 1;
            hopnum = (h as u8).into();

            c.control
                .send(Ok(CtrlMsg::AddStream(
                    hopnum,
                    sender,
                    window.new_ref(),
                    id_snd,
                )))
                .await
                .map_err(|_| Error::InternalError("Can't queue new-stream request.".into()))?;
        }

        let id = id_rcv
            .await
            .map_err(|_| Error::InternalError("Didn't receive a stream ID.".into()))?;
        let id = id?;

        let relaycell = RelayCell::new(id, begin_msg);

        {
            let mut c = self.c.lock().await;
            c.send_relay_cell(hopnum, false, relaycell).await?;
            c.control
                .send(Ok(CtrlMsg::Register(recv_close)))
                .await
                .map_err(|_| Error::InternalError("Can't queue stream closer".into()))?;
        }

        /// Initial value for inbound flow-control window on streams.
        const STREAM_RECV_INIT: u16 = 500;

        let target = StreamTarget {
            circ: self.clone(),
            stream_id: id,
            hop: hopnum,
            window,
            recvwindow: sendme::StreamRecvWindow::new(STREAM_RECV_INIT),
            stream_closed: Cell::new(Some(send_close)),
        };

        Ok(TorStream::new(target, receiver))
    }

    /// Start a DataStream connection to the given address and port,
    /// using a BEGIN cell.
    async fn begin_data_stream(&mut self, msg: RelayMsg) -> Result<DataStream> {
        let mut stream = self.begin_stream_impl(msg).await?;
        let response = stream.recv().await?;

        // XXXXX We need to remove the stream if we get an END cell or
        // a weird cell. XXXXM3

        if response.cmd() == RelayCmd::CONNECTED {
            Ok(DataStream::new(stream))
        } else if response.cmd() == RelayCmd::END {
            Err(Error::StreamClosed("end cell when waiting for connection"))
        } else {
            self.c.lock().await.shutdown();
            Err(Error::StreamProto(format!(
                "Received {} while waiting for connection",
                response.cmd()
            )))
        }
    }

    /// Start a connection to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(&mut self, target: &str, port: u16) -> Result<DataStream> {
        // TODO: this should take flags to specify IP version preference
        let beginmsg = tor_cell::relaycell::msg::Begin::new(target, port, 0)?;
        self.begin_data_stream(beginmsg.into()).await
    }

    /// Start a new connection to the last router in the circuit, using
    /// a BEGIN_DIR cell.
    pub async fn begin_dir_stream(&mut self) -> Result<DataStream> {
        self.begin_data_stream(RelayMsg::BeginDir).await
    }
    // XXXX Add a RESOLVE implementation, it will be simple.

    /// Shut down this circuit immediately, along with all streams that
    /// are using it.
    ///
    /// Note that other references to this circuit may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a circuit: the channel should close on its own once nothing
    /// is using it any more.
    pub async fn terminate(self) {
        self.c.lock().await.shutdown();
    }
}

impl ClientCircImpl {
    /// Return a mutable reference to the nth hop of this circuit, if one
    /// exists.
    fn get_hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    async fn handle_meta_cell(&mut self, hopnum: HopNum, msg: RelayMsg) -> Result<()> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.
        if let RelayMsg::Sendme(s) = msg {
            return self.handle_sendme(hopnum, s).await;
        }
        if let RelayMsg::Truncated(_) = msg {
            // XXXX need to handle Truncated cells. This isn't the right
            // way, but at least it's safe.
            return Err(Error::CircuitClosed);
        }

        trace!("{}: Received meta-cell {:?}", self.logid, msg);

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some(sender) = self.sendmeta.take() {
            // Somebody was waiting for a message -- maybe this message
            sender
                .send(Ok((hopnum, msg)))
                // I think this means that the channel got closed.
                .map_err(|_| Error::CircuitClosed)
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    async fn handle_sendme(&mut self, hopnum: HopNum, msg: Sendme) -> Result<()> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self.get_hop_mut(hopnum).unwrap(); // XXXX risky
        let auth: Option<[u8; 20]> = match msg.into_tag() {
            Some(v) if v.len() == 20 => {
                // XXXX ugly code.
                let mut tag = [0u8; 20];
                (&mut tag).copy_from_slice(&v[..]);
                Some(tag)
            }
            Some(_) => return Err(Error::CircProto("malformed tag on circuit sendme".into())),
            None => {
                if !hop.auth_sendme_optional {
                    return Err(Error::CircProto("missing tag on circuit sendme".into()));
                } else {
                    None
                }
            }
        };
        match hop.sendwindow.put(auth).await {
            Some(_) => Ok(()),
            None => Err(Error::CircProto("bad auth tag on circuit sendme".into())),
        }
    }

    /// Helper: Put a cell onto this circuit's channel.
    ///
    /// This takes a raw cell that has already been encrypted, puts
    /// a circuit ID on it, and sends it.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Helper: Encode the relay cell `cell`, encrypt it, and send it to the
    /// 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&mut self, hop: HopNum, early: bool, cell: RelayCell) -> Result<()> {
        if self.closed {
            return Err(Error::CircuitClosed);
        }
        let c_t_w = sendme::cell_counts_towards_windows(&cell);
        let mut body: RelayCellBody = cell.encode(&mut thread_rng())?.into();
        let tag = self.crypto_out.encrypt(&mut body, hop)?;
        let msg = chancell::msg::Relay::from_raw(body.into());
        let msg = if early {
            ChanMsg::RelayEarly(msg)
        } else {
            ChanMsg::Relay(msg)
        };
        // If the cell counted towards our sendme window, decrement
        // that window, and maybe remember the authentication tag.
        if c_t_w {
            // XXXX I wish I didn't have to copy the tag.
            // TODO: I'd like to use get_hops_mut here, but the borrow checker
            // won't let me.
            assert!(tag.len() == 20); // XXXX risky
            let mut tag_copy = [0u8; 20];
            (&mut tag_copy[..]).copy_from_slice(&tag[..]);
            // This blocks if the send window is empty.
            self.hops[Into::<usize>::into(hop)]
                .sendwindow
                .take(&tag_copy)
                .await;
        }
        self.send_msg(msg).await
    }

    /// Shut down this circuit's reactor and mark the circuit as closed.
    ///
    /// This is idempotent and safe to call more than once.
    fn shutdown(&mut self) {
        self.closed = true;
        if let Some(sender) = self.sendshutdown.take() {
            // ignore the error, since it can only be canceled.
            let _ = sender.send(CtrlMsg::Shutdown);
        }
        // Drop the circuit destroy handle now so that a DESTROY cell
        // gets sent.
        drop(self.circ_closed.take());
    }
}

impl PendingClientCirc {
    /// Instantiate a new circuit object: used from Channel::new_circ().
    ///
    /// Does not send a CREATE* cell on its own.
    ///
    ///
    pub(crate) fn new(
        id: CircID,
        channel: Channel,
        createdreceiver: oneshot::Receiver<CreateResponse>,
        circ_closed: CircDestroyHandle,
        input: mpsc::Receiver<ClientCircChanMsg>,
        logid: LogId,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let crypto_out = OutboundClientCrypt::new();
        let (sendclosed, recvclosed) = oneshot::channel::<CtrlMsg>();
        // Should this be bounded, really? XXX
        let (sendctrl, recvctrl) = mpsc::channel::<CtrlResult>(128);
        let hops = Vec::new();

        let circuit_impl = ClientCircImpl {
            id,
            channel,
            crypto_out,
            hops,
            closed: false,
            circ_closed: Some(circ_closed),
            control: sendctrl,
            sendshutdown: Cell::new(Some(sendclosed)),
            sendmeta: Cell::new(None),
            logid,
        };
        let circuit = ClientCirc {
            c: Arc::new(Mutex::new(circuit_impl)),
        };
        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: circuit.clone(),
        };
        let reactor = reactor::Reactor::new(circuit.c, recvctrl, recvclosed, input, logid);
        (pending, reactor)
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, FWD, REV, H, W>(
        self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
        supports_flowctrl_1: bool,
    ) -> Result<ClientCirc>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV> + 'static + Send, // need all this?XXXX
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let PendingClientCirc { circ, recvcreated } = self;
        let (state, msg) = H::client1(rng, &key)?;
        let create_cell = wrap.to_chanmsg(msg);
        let logid = {
            let mut c = circ.c.lock().await;
            debug!("{}: Extending to hop 1 with {}", c.logid, create_cell.cmd());
            c.send_msg(create_cell).await?;
            c.logid
        };

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let server_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, server_handshake)?;

        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit created.", logid);

        let (layer_fwd, layer_back) = layer.split();
        circ.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
        )
        .await?;
        Ok(circ)
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast<R>(self, rng: &mut R) -> Result<ClientCirc>
    where
        R: Rng + CryptoRng,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::fast::CreateFastClient;
        let wrap = CreateFastWrap;
        self.create_impl::<R, Tor1RelayCrypto, _, _, CreateFastClient, _>(rng, &wrap, &(), false)
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target.
    pub async fn create_firsthop_ntor<R, Tg>(self, rng: &mut R, target: &Tg) -> Result<ClientCirc>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        let key = NtorPublicKey {
            id: target.rsa_identity().clone(),
            pk: *target.ntor_onion_key(),
        };
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.create_impl::<R, Tor1RelayCrypto, _, _, NtorClient, _>(
            rng,
            &wrap,
            &key,
            supports_flowctrl_1,
        )
        .await
    }
}

/// An object that can put a given handshake into a ChanMsg for a CREATE*
/// cell, and unwrap a CREATED* cell.
trait CreateHandshakeWrap {
    /// Construct an appropriate ChanMsg to hold this kind of handshake.
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    /// Decode a ChanMsg to an appropriate handshake value, checking
    /// its type.
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            CreatedFast(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with unexpected cell.",
            )),
        }
    }
}

/// A CreateHandshakeWrap that generates CREATE2 and handles CREATED2
struct Create2Wrap {
    /// The handshake type to put in the CREATE2 cell.
    handshake_type: u16,
}
impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::Create2::new(self.handshake_type, bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            Created2(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE2 with unexpected cell.",
            )),
        }
    }
}

impl StreamTarget {
    /// Initial value for outbound flow-control window on streams.
    const SEND_WINDOW_INIT: u16 = 500;

    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        if sendme::msg_counts_towards_windows(&msg) {
            // Decrement the stream window (and block if it's empty)
            self.window.take(&()).await;
        }
        let cell = RelayCell::new(self.stream_id, msg);
        let mut c = self.circ.c.lock().await;
        c.send_relay_cell(self.hop, false, cell).await
    }

    /// Called when a circuit-level protocol error has occured and the
    /// circuit needs to shut down.
    pub(crate) async fn protocol_error(&mut self) {
        let mut c = self.circ.c.lock().await;
        c.shutdown();
    }
}

impl Drop for ClientCircImpl {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Drop for StreamTarget {
    fn drop(&mut self) {
        if let Some(sender) = self.stream_closed.take() {
            // This "clone" call is a bit dangerous: it means that we might
            // allow the other side to send a couple of cells that get
            // decremented from self.recvwindow but don't get reflected
            // in the circuit-owned view of the window.
            let window = self.recvwindow.clone();
            let _ = sender.send(CtrlMsg::CloseStream(self.hop, self.stream_id, window));
        }
        // If there's an error, no worries: it's hard-cancel, and we
        // can just ignore it. XXXX (I hope?)
    }
}
