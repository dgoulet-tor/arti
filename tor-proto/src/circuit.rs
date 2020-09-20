//! Multi-hop paths over the Tor network.

pub(crate) mod reactor;
mod streammap;

use crate::chancell::{self, msg::ChanMsg, ChanCell, CircID};
use crate::channel::Channel;
use crate::crypto::cell::{ClientCrypt, ClientLayer, CryptInit, HopNum};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::relaycell::msg::{RelayCell, RelayMsg, Sendme};
use crate::relaycell::{RelayCmd, StreamID};
use crate::stream::TorStream;
use crate::{Error, Result};

use tor_linkspec::LinkSpec;

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;

use std::cell::Cell;
use std::sync::Arc;

use rand::{thread_rng, CryptoRng, Rng};

/// A Circuit that we have constructed over the Tor network.
#[derive(Clone)]
pub struct ClientCirc {
    c: Arc<Mutex<ClientCircImpl>>,
}

/// A Circuit that needs to send a create cell and receive a created cell.
pub struct PendingClientCirc {
    recvcreated: oneshot::Receiver<ChanMsg>,
    circ: ClientCirc,
}

// TODO: need to send a destroy cell on drop
struct ClientCircImpl {
    id: CircID,
    channel: Channel,
    crypto: ClientCrypt,
    hops: Vec<CircHop>,
    sendclosed: Cell<Option<oneshot::Sender<()>>>,
    sendmeta: Cell<Option<oneshot::Sender<(HopNum, RelayMsg)>>>,
}

// XXXX rename this
pub(crate) struct StreamTarget {
    stream_id: StreamID,
    // XXXX Using 'hop' by number here will cause bugs if circuits can get
    // XXXX truncated and then re-extended.
    hop: HopNum,
    circ: ClientCirc,
}

struct CircHop {
    map: streammap::StreamMap,
}

impl PendingClientCirc {
    /// Instantiate a new circuit object.
    pub(crate) fn new(
        id: CircID,
        channel: Channel,
        createdreceiver: oneshot::Receiver<ChanMsg>,
        input: mpsc::Receiver<ChanMsg>,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let crypto = ClientCrypt::new();
        let (sendclosed, recvclosed) = oneshot::channel::<()>();
        let hops = Vec::new();

        let circuit_impl = ClientCircImpl {
            id,
            channel,
            crypto,
            hops,
            sendclosed: Cell::new(Some(sendclosed)),
            sendmeta: Cell::new(None),
        };
        let circuit = ClientCirc {
            c: Arc::new(Mutex::new(circuit_impl)),
        };
        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: circuit.clone(),
        };
        let reactor = reactor::Reactor::new(circuit, recvclosed, input);
        (pending, reactor)
    }
}

impl ClientCirc {
    async fn register_meta_handler(&mut self) -> Result<oneshot::Receiver<(HopNum, RelayMsg)>> {
        let (sender, receiver) = oneshot::channel();

        let circ = self.c.lock().await;
        let prev = circ.sendmeta.replace(Some(sender));
        if prev.is_some() {
            circ.sendmeta.replace(prev); // put the old value back.
            return Err(Error::InternalError(
                "Tried to register second meta-cell handler".into(),
            ));
        }

        Ok(receiver)
    }

    /// Helper: extend the circuit.
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
        let (state, msg) = H::client1(rng, &key)?;
        let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.as_message());

        let receiver = self.register_meta_handler().await?;

        let hop = {
            let mut c = self.c.lock().await;
            let hop = (c.crypto.n_layers() - 1) as u8;

            // Send the message to the last hop...
            c.send_relay_cell(
                hop, true, // early
                cell,
            )
            .await?;

            hop
        };

        // and wait for a response.
        // XXXX This is no good for production use.  We shouldn't wait
        // XXXX for the _NEXT_ relay cell, but instead for the next
        // XXXX EXTENDED/EXTENDED2 cell.  Other relay cells should go
        // XXXX elsewhere.
        let (from_hop, msg) = receiver.await.map_err(|_| {
            Error::CircProto("Circuit closed while waiting for extended cell".into())
        })?;

        // XXXX if two of these are launched on the same circuit at once,
        // XXXX they could collide in here.

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
            _ => return Err(Error::InternalError("body didn't match cmd".into())),
        };
        let server_handshake = msg.into_body();

        let keygen = H::client2(state, server_handshake)?;
        let layer = L::construct(keygen)?;

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

    /// Extend the circuit via Ntor.  Same caveats apply from extend_impl.
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

    async fn begin_stream_impl(&mut self, begin_msg: RelayMsg) -> Result<TorStream> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.

        // XXXX Both a bound and a lack of bound are scary here :/
        let (sender, receiver) = mpsc::channel(128);

        let mut rng = rand::thread_rng();

        let mut c = self.c.lock().await;
        let hopnum = c.hops.len() - 1;
        let id = c.hops[hopnum].map.add_ent(&mut rng, sender)?;
        let relaycell = RelayCell::new(id, begin_msg);
        c.send_relay_cell(hopnum as u8, false, relaycell).await?;

        let target = StreamTarget {
            circ: self.clone(),
            stream_id: id,
            hop: hopnum as u8,
        };

        Ok(TorStream::new(target, receiver))
    }

    /// Start a connection to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(&mut self, target: &str, port: u16) -> Result<TorStream> {
        // TODO: this should take flags?
        let beginmsg = crate::relaycell::msg::Begin::new(target, port, 0)?;

        let mut stream = self.begin_stream_impl(beginmsg.into()).await?;
        let response = stream.recv().await?;

        if response.get_cmd() == RelayCmd::CONNECTED {
            Ok(stream)
        } else if response.get_cmd() == RelayCmd::END {
            Err(Error::InternalError("XXXX end cell".into()))
        } else {
            Err(Error::InternalError("XXXX weird cell".into()))
        }
    }
}

impl ClientCircImpl {
    /// Handle a RELAY cell on this circuit with stream ID 0
    fn handle_meta_cell(&mut self, hopnum: u8, msg: RelayMsg) -> Result<()> {
        if let RelayMsg::Sendme(s) = msg {
            return self.handle_sendme(hopnum, s);
        }
        // For all other command types, we'll only get them in response
        // to another command that should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.

        if let Some(sender) = self.sendmeta.take() {
            sender
                .send((hopnum, msg))
                .map_err(|_| Error::InternalError("XXXX".into()))
        } else {
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.get_cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    fn handle_sendme(&mut self, _hopnum: u8, _msg: Sendme) -> Result<()> {
        // TODO: SENDME
        Ok(())
    }

    /// Put a cell onto this circuit.
    ///
    /// This takes a raw cell; you may need to encrypt it.
    // TODO: This shouldn't be public.
    async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Encode the message `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// TODO: This is not a good long-term API.  It should become private
    /// if we keep it.
    ///
    /// TODO: use HopNum
    async fn send_relay_cell(&mut self, hop: u8, early: bool, cell: RelayCell) -> Result<()> {
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

trait CreateHandshakeWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>>;
}

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

struct Create2Wrap {
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
    pub(crate) async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        let cell = RelayCell::new(self.stream_id, msg);
        let mut c = self.circ.c.lock().await;
        c.send_relay_cell(self.hop, false, cell).await
    }
}
