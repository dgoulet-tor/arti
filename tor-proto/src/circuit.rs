//! Multi-hop paths over the Tor network.

use crate::chancell::{
    self,
    msg::{self, ChanMsg},
    ChanCell, CircID,
};
use crate::channel::Channel;
use crate::crypto::cell::{ClientLayer, CryptInit};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::relaycell::{msg::RelayCell, msg::RelayMsg, StreamCmd};
use crate::{Error, Result};

use tor_linkspec::LinkSpec;

use futures::channel::mpsc;
use futures::stream::StreamExt;

use rand::{thread_rng, CryptoRng, Rng};

use crate::crypto::cell::ClientCrypt;

/// A Circuit that we have constructed over the Tor network.
// TODO: need to send a destroy cell on drop
pub struct ClientCirc {
    id: CircID,
    channel: Channel,
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ChanMsg>,
    crypto: ClientCrypt,
}

impl ClientCirc {
    /// Instantiate a new circuit object.
    pub(crate) fn new(id: CircID, channel: Channel, input: mpsc::Receiver<ChanMsg>) -> Self {
        let crypto = ClientCrypt::new();
        ClientCirc {
            id,
            channel,
            input,
            crypto,
        }
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

    /// Read a cell from this circuit.
    ///
    /// This is a raw cell as sent on the channel: if it's a relay cell,
    /// it'll need to be decrypted.
    async fn read_msg(&mut self) -> Result<ChanMsg> {
        // XXXX handle close better?
        self.input.next().await.ok_or(Error::CircuitClosed)
    }

    /// Encode the message `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// TODO: This is not a good long-term API.  It should become private
    /// if we keep it.
    ///
    /// TODO: use HopNum
    pub async fn send_relay_cell(&mut self, hop: u8, early: bool, cell: RelayCell) -> Result<()> {
        assert!((hop as usize) < self.crypto.n_layers());
        let mut body = cell.encode(&mut thread_rng())?;
        self.crypto.encrypt(&mut body, hop)?;
        let msg = chancell::msg::Relay::from_raw(body.into());
        let msg = if early {
            ChanMsg::RelayEarly(msg)
        } else {
            ChanMsg::Relay(msg)
        };
        self.send_msg(msg).await?;
        Ok(())
    }

    /// Receive a message from the circuit, decrypt it, and return it as a
    /// RelayCell.
    ///
    /// TODO: This is not a good long-term API.  It should become private
    /// if we keep it.
    ///
    /// TODO: use HopNum
    pub async fn recv_relay_cell(&mut self) -> Result<(u8, RelayCell)> {
        let chanmsg = self.read_msg().await?;
        let body = match chanmsg {
            ChanMsg::Relay(r) => r,
            _ => {
                return Err(Error::ChanProto(format!(
                    "{} cell received on circuit",
                    chanmsg.get_cmd()
                )))
            }
        };

        // Decrypt, if possible.
        let mut cell = body.into_relay_cell();
        let hopnum = self.crypto.decrypt(&mut cell)?;
        let msg = RelayCell::decode(cell)?;

        Ok((hopnum, msg))
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, H, W>(
        &mut self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer + 'static,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        if self.crypto.n_layers() != 0 {
            return Err(Error::CircExtend("Circuit already extended."));
        }

        let (state, msg) = H::client1(rng, &key)?;
        let create_cell = wrap.to_chanmsg(msg);
        self.send_msg(create_cell).await?;
        let reply = self.read_msg().await?;

        let server_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, server_handshake)?;

        let layer = L::construct(keygen)?;

        self.crypto.add_layer(Box::new(layer));
        Ok(())
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
        L: CryptInit + ClientLayer + 'static,
        H: ClientHandshake,
        H::KeyGen: KeyGenerator,
    {
        use crate::relaycell::msg::{Body, Extend2};
        if self.crypto.n_layers() == 0 {
            return Err(Error::CircExtend("Circuit not yet created"));
        }
        let hop = (self.crypto.n_layers() - 1) as u8;

        let (state, msg) = H::client1(rng, &key)?;
        let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.as_message());

        // Send the message to the last hop...
        self.send_relay_cell(
            hop, true, // early
            cell,
        )
        .await?;

        // and wait for a response.
        // XXXX This is no good for production use.  We shouldn't wait
        // XXXX for the _NEXT_ relay cell, but instead for the next
        // XXXX EXTENDED/EXTENDED2 cell.  Other relay cells should go
        // XXXX elsewhere.
        let (from_hop, cell) = self.recv_relay_cell().await?;

        // Did we get the right response?
        if from_hop != hop || cell.get_cmd() != StreamCmd::EXTENDED2 {
            return Err(Error::CircProto(format!(
                "wanted EXTENDED2 from {}; got {} from {}",
                hop,
                cell.get_cmd(),
                from_hop
            )));
        }
        let (streamid, msg) = cell.into_streamid_and_msg();
        if streamid != 0.into() {
            return Err(Error::CircProto(format!(
                "got nonzero stream ID {} on EXTENDED2",
                streamid
            )));
        }
        let msg = match msg {
            RelayMsg::Extended2(e) => e,
            _ => return Err(Error::InternalError("body didn't match cmd".into())),
        };
        let server_handshake = msg.into_body();

        let keygen = H::client2(state, server_handshake)?;
        let layer = L::construct(keygen)?;

        self.crypto.add_layer(Box::new(layer));
        Ok(())
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast<R>(&mut self, rng: &mut R) -> Result<()>
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
    pub async fn create_firsthop_ntor<R, Tg>(&mut self, rng: &mut R, target: &Tg) -> Result<()>
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
}

trait CreateHandshakeWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>>;
}

struct CreateFastWrap;
impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        msg::CreateFast::new(bytes).into()
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
        msg::Create2::new(self.handshake_type, bytes).into()
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
