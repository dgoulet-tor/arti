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
//!
//! XXXX We don't send DESTROY cells when we should, or handle them well.

pub(crate) mod reactor;
mod streammap;

use crate::chancell::{self, msg::ChanMsg, ChanCell, CircID};
use crate::channel::Channel;
use crate::circuit::reactor::{CtrlMsg, CtrlResult};
use crate::crypto::cell::{ClientCrypt, ClientLayer, CryptInit, HopNum};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::relaycell::msg::{RelayCell, RelayMsg, Sendme};
use crate::relaycell::{RelayCmd, StreamID};
use crate::stream::TorStream;
use crate::{Error, Result};

use tor_linkspec::LinkSpec;

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use futures::sink::SinkExt;

use std::cell::Cell;
use std::sync::Arc;

use rand::{thread_rng, CryptoRng, Rng};

/// A circuit that we have constructed over the Tor network.
#[derive(Clone)]
pub struct ClientCirc {
    c: Arc<Mutex<ClientCircImpl>>,
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call create_firsthop_fast() or create_firsthop_ntor()
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<ChanMsg>,
    /// The ClientCirc object that we can expose on success.
    circ: ClientCirc,
}

/// The implementation type for this circuit.
struct ClientCircImpl {
    /// This circuit's ID on the upstream channel.
    id: CircID,
    /// The channel that this circuit uses to send its cells to the
    /// next hop.
    channel: Channel,
    /// The cryptographic state for this circuit.  This object is divided
    /// into multiple layers, each of which is shared with one hop of the
    /// circuit
    crypto: ClientCrypt,
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
    sendmeta: Cell<Option<oneshot::Sender<(HopNum, RelayMsg)>>>,
}
// XXXX TODO: need to send a destroy cell on drop, and tell the reactor to
// XXXX shut down.

/// A handle to a circuit as held by a stream. Used to send cells.
///
/// Rather than using the stream directly, the stream uses this object
/// to send its relay cells to the correct hop, using the correct stream ID.
///
/// When this object is dropped, the reactor will be told to close the stream.
// XXXX TODO: rename this
pub(crate) struct StreamTarget {
    stream_id: StreamID,
    // XXXX Using 'hop' by number here will cause bugs if circuits can get
    // XXXX truncated and then re-extended.
    hop: HopNum,
    circ: ClientCirc,
    stream_closed: Cell<Option<oneshot::Sender<CtrlMsg>>>,
}

/// Information about a single hop of a client circuit.
struct CircHop {
    map: streammap::StreamMap,
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
    async fn register_meta_handler(&mut self) -> Result<oneshot::Receiver<(HopNum, RelayMsg)>> {
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
    async fn extend_impl<R, L, H>(
        &mut self,
        rng: &mut R,
        handshake_id: u16,
        key: &H::KeyType,
        linkspecs: Vec<LinkSpec>,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer + 'static + Send,
        H: ClientHandshake,
        H::KeyGen: KeyGenerator,
    {
        use crate::relaycell::msg::{Body, Extend2};
        // Perform the first part of the cryptographic handshake
        let (state, msg) = H::client1(rng, &key)?;
        let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.as_message());

        // We'll be waiting for an EXTENDED2 cell; install the handler.
        let receiver = self.register_meta_handler().await?;

        // Now send the EXTEND2 cell to the the last hop...
        let hop = {
            let mut c = self.c.lock().await;
            let hop = ((c.crypto.n_layers() - 1) as u8).into();

            // Send the message to the last hop...
            c.send_relay_cell(
                hop, true, // use a RELAY_EARLY cell
                cell,
            )
            .await?;

            hop
            // note that we're dropping the lock here, since we're going
            // to wait for a response.
        };

        // ... and now we wait for a response.
        let (from_hop, msg) = receiver.await.map_err(|_| {
            Error::CircProto("Circuit closed while waiting for extended cell".into())
        })?;

        // XXXX If two EXTEND cells are of these are launched on the
        // same circuit at once, could they collide in this part of
        // the function?

        // Did we get the right response?
        if from_hop != hop || msg.get_cmd() != RelayCmd::EXTENDED2 {
            return Err(Error::CircProto(format!(
                "wanted EXTENDED2 from {}; got {} from {}",
                hop,
                msg.get_cmd(),
                from_hop
            )));
        }
        let msg = match msg {
            RelayMsg::Extended2(e) => e,
            _ => return Err(Error::InternalError("Body didn't match cmd".into())),
        };
        let server_handshake = msg.into_body();

        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let keygen = H::client2(state, server_handshake)?;
        let layer = L::construct(keygen)?;

        // If we get here, it succeeded.  Add a new hop to the circuit.
        {
            let mut c = self.c.lock().await;
            let hop = CircHop {
                map: streammap::StreamMap::new(),
            };
            c.hops.push(hop);
            c.crypto.add_layer(Box::new(layer));
        }
        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.  Same caveats apply from extend_impl.
    pub async fn extend_ntor<R, Tg>(&mut self, rng: &mut R, target: &Tg) -> Result<()>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::ExtendTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let key = NtorPublicKey {
            id: target.get_rsa_identity().clone(),
            pk: *target.get_ntor_onion_key(),
        };
        let linkspecs = target.get_linkspecs();
        self.extend_impl::<R, Tor1RelayCrypto, NtorClient>(rng, 0x0002, &key, linkspecs)
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

        let mut c = self.c.lock().await;
        let hopnum = c.hops.len() - 1;
        let id = c.hops[hopnum].map.add_ent(sender)?;
        let relaycell = RelayCell::new(id, begin_msg);
        let hopnum = (hopnum as u8).into();
        let (send_close, recv_close) = oneshot::channel::<CtrlMsg>();
        c.send_relay_cell(hopnum, false, relaycell).await?;
        c.control
            .send(Ok(CtrlMsg::Register(recv_close)))
            .await
            .map_err(|_| Error::InternalError("Can't queue stream closer".into()))?;

        let target = StreamTarget {
            circ: self.clone(),
            stream_id: id,
            hop: hopnum,
            stream_closed: Cell::new(Some(send_close)),
        };

        Ok(TorStream::new(target, receiver))
    }

    /// Start a connection to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(&mut self, target: &str, port: u16) -> Result<TorStream> {
        // TODO: this should take flags to specify IP version preference
        let beginmsg = crate::relaycell::msg::Begin::new(target, port, 0)?;

        let mut stream = self.begin_stream_impl(beginmsg.into()).await?;
        let response = stream.recv().await?;

        // XXXXX We need to remove the stream if we get an END cell or
        // a weird cell.

        if response.get_cmd() == RelayCmd::CONNECTED {
            Ok(stream) // Return a DataStream XXXX
        } else if response.get_cmd() == RelayCmd::END {
            // XXX Handle this properly and give a reasonable error.
            Err(Error::InternalError("XXXX end cell".into()))
        } else {
            // XXX Handle this properly and give a reasonable error.
            Err(Error::InternalError("XXXX weird cell".into()))
        }
    }

    // XXXX Add a RESOLVE implementation, it will be simple.
}

impl ClientCircImpl {
    /// Handle a RELAY cell on this circuit with stream ID 0.
    fn handle_meta_cell(&mut self, hopnum: HopNum, msg: RelayMsg) -> Result<()> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.
        if let RelayMsg::Sendme(s) = msg {
            return self.handle_sendme(hopnum, s);
        }
        if let RelayMsg::Truncated(_) = msg {
            // XXXX need to handle Truncated cells.
            return Ok(());
        }

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some(sender) = self.sendmeta.take() {
            // Somebody was waiting for a message -- maybe this message
            sender
                .send((hopnum, msg))
                // XXX I think this means that the channel got closed.
                .map_err(|_| Error::InternalError("XXXX".into()))
        } else {
            // Nobody wanted this.
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.get_cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    fn handle_sendme(&mut self, _hopnum: HopNum, _msg: Sendme) -> Result<()> {
        // TODO: SENDME
        Ok(())
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
        let mut body = cell.encode(&mut thread_rng())?;
        self.crypto.encrypt(&mut body, hop)?;
        let msg = chancell::msg::Relay::from_raw(body.into());
        let msg = if early {
            ChanMsg::RelayEarly(msg)
        } else {
            ChanMsg::Relay(msg)
        };
        self.send_msg(msg).await
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
        createdreceiver: oneshot::Receiver<ChanMsg>,
        input: mpsc::Receiver<ChanMsg>,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let crypto = ClientCrypt::new();
        let (sendclosed, recvclosed) = oneshot::channel::<CtrlMsg>();
        // Should this be bounded, really? XXX
        let (sendctrl, recvctrl) = mpsc::channel::<CtrlResult>(128);
        let hops = Vec::new();

        let circuit_impl = ClientCircImpl {
            id,
            channel,
            crypto,
            hops,
            control: sendctrl,
            sendshutdown: Cell::new(Some(sendclosed)),
            sendmeta: Cell::new(None),
        };
        let circuit = ClientCirc {
            c: Arc::new(Mutex::new(circuit_impl)),
        };
        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: circuit.clone(),
        };
        let reactor = reactor::Reactor::new(circuit, recvctrl, recvclosed, input);
        (pending, reactor)
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, H, W>(
        self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
    ) -> Result<ClientCirc>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer + 'static + Send,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        let PendingClientCirc { circ, recvcreated } = self;
        let (state, msg) = H::client1(rng, &key)?;
        let create_cell = wrap.to_chanmsg(msg);
        {
            let mut c = circ.c.lock().await;
            c.send_msg(create_cell).await?;
        }

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed, I think".into()))?;

        let server_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, server_handshake)?;

        let layer = L::construct(keygen)?;

        {
            let mut c = circ.c.lock().await;
            let hop = CircHop {
                map: streammap::StreamMap::new(),
            };
            c.hops.push(hop);
            c.crypto.add_layer(Box::new(layer));
        }
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
        self.create_impl::<R, Tor1RelayCrypto, CreateFastClient, _>(rng, &wrap, &())
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target.
    pub async fn create_firsthop_ntor<R, Tg>(self, rng: &mut R, target: &Tg) -> Result<ClientCirc>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::ExtendTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        let key = NtorPublicKey {
            id: target.get_rsa_identity().clone(),
            pk: *target.get_ntor_onion_key(),
        };
        self.create_impl::<R, Tor1RelayCrypto, NtorClient, _>(rng, &wrap, &key)
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
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>> {
        match msg {
            ChanMsg::CreatedFast(m) => Ok(m.into_body()),
            ChanMsg::Destroy(_) => Err(Error::CircExtend(
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
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>> {
        match msg {
            ChanMsg::Created2(m) => Ok(m.into_body()),
            ChanMsg::Destroy(_) => Err(Error::CircExtend("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE2 with unexpected cell.",
            )),
        }
    }
}

impl StreamTarget {
    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        let cell = RelayCell::new(self.stream_id, msg);
        let mut c = self.circ.c.lock().await;
        c.send_relay_cell(self.hop, false, cell).await
    }
}

impl Drop for ClientCircImpl {
    fn drop(&mut self) {
        if let Some(sender) = self.sendshutdown.take() {
            // ignore the error, since it can only be canceled.
            let _ = sender.send(CtrlMsg::Shutdown);
        }
    }
}

impl Drop for StreamTarget {
    fn drop(&mut self) {
        if let Some(sender) = self.stream_closed.take() {
            // ignore the error, since it can only be canceled.
            let _ = sender.send(CtrlMsg::CloseStream(self.hop, self.stream_id));
        }
    }
}
