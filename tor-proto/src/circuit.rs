//! Multi-hop paths over the Tor network.

use crate::chancell::{msg::ChanMsg, ChanCell, CircID};
use crate::channel::Channel;
use crate::{Error, Result};

use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;

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
}

impl<T> ClientCirc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Instantiate a new circuit object.
    pub(crate) fn new(id: CircID, channel: Channel<T>, input: mpsc::Receiver<ChanMsg>) -> Self {
        ClientCirc { id, channel, input }
    }

    /// Put a cell onto this circuit.
    ///
    /// This takes a raw cell; you may need to encrypt it.
    pub async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Read a cell from this circuit.
    ///
    /// This is a raw cell as sent on the channel: if it's a relay cell,
    /// it'll need to be decrypted.
    pub async fn read_msg(&mut self) -> Result<ChanMsg> {
        // XXXX handlebetter
        self.input.next().await.ok_or(Error::CircuitClosed)
    }
}
