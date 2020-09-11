//! Multi-hop paths over the Tor network.

use crate::chancell::{
    msg::{self, ChanMsg},
    ChanCell, CircID,
};
use crate::channel::Channel;
use crate::{Error, Result};

use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;

use rand::{CryptoRng, Rng};

use crate::crypto::cell::ClientCrypt;

/// A Circuit that we have constructed over the Tor network.
// TODO: I wish this weren't parameterized.
// TODO: need to send a destroy cell on drop
pub struct ClientCirc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    id: CircID,
    channel: Channel<T>,
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ChanMsg>,
    crypto: ClientCrypt,
}

impl<T> ClientCirc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Instantiate a new circuit object.
    pub(crate) fn new(id: CircID, channel: Channel<T>, input: mpsc::Receiver<ChanMsg>) -> Self {
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
        use crate::crypto::cell::{CryptInit, Tor1RelayCrypto};
        use crate::crypto::handshake::{fast, ClientHandshake};

        if self.crypto.n_layers() != 0 {
            return Err(Error::CircExtend("Circuit already extended."));
        }

        let (state, msg) = fast::CreateFastClient::client1(rng, &())?;
        let create_fast = CreateFastWrap::to_chanmsg(msg);
        self.send_msg(create_fast).await?;
        let reply = self.read_msg().await?;

        let server_handshake = CreateFastWrap::from_chanmsg(reply)?;

        let keygen = fast::CreateFastClient::client2(state, server_handshake)?;

        let state = Tor1RelayCrypto::construct(keygen)?;
        self.crypto.add_layer(Box::new(state));
        Ok(())
    }
}

trait CreateHandshakeWrap {
    fn to_chanmsg(bytes: Vec<u8>) -> ChanMsg;
    fn from_chanmsg(msg: ChanMsg) -> Result<Vec<u8>>;
}

struct CreateFastWrap;
impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(bytes: Vec<u8>) -> ChanMsg {
        msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(msg: ChanMsg) -> Result<Vec<u8>> {
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
