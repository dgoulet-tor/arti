//! Code to handle incoming cells on a circuit
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.
//!
//! TODO: perhaps this should share code with channel::reactor; perhaps
//! it should just not exist.

use super::streammap::StreamEnt;
use crate::chancell::{msg::ChanMsg, msg::Relay};
use crate::circuit::ClientCirc;
use crate::relaycell::msg::RelayCell;
use crate::{Error, Result};

use futures::channel::{mpsc, oneshot};
use futures::future::Fuse;
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use futures::FutureExt;

/// Object to handle incoming cells on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// A onshot receiver that lets the reactor know when to shut down.
    /// The circuit holds the corresponding Sender.
    closeflag: Fuse<oneshot::Receiver<()>>,
    /// Input Stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ChanMsg>,
    /// The main implementation of the reactor.
    core: ReactorCore,
}

/// This is a separate; we use it when handling cells.
struct ReactorCore {
    /// Reference to the circuit.
    circuit: ClientCirc,
}

impl Reactor {
    /// Construct a new Reactor.
    pub(super) fn new(
        circuit: ClientCirc,
        closeflag: oneshot::Receiver<()>,
        input: mpsc::Receiver<ChanMsg>,
    ) -> Self {
        let core = ReactorCore { circuit };
        Reactor {
            closeflag: closeflag.fuse(),
            input,
            core,
        }
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    pub async fn run(mut self) -> Result<()> {
        let mut close_future = self.closeflag;
        loop {
            let mut next_future = self.input.next().fuse();
            // What's next to do?
            let item = select_biased! {
                // we were asked to close
                _ = close_future => return Ok(()),
                // we got a message on our channel, or it closed.
                item = next_future => item,
            };
            let item = match item {
                // the channel closed; we're done.
                None => return Ok(()),
                // we got a ChanMsg!
                Some(r) => r,
            };

            let exit = self.core.handle_cell(item).await?;
            if exit {
                // XXXX does this really shutdown?
                return Ok(());
            }
        }
    }
}

impl ReactorCore {
    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return true if we should exit.
    async fn handle_cell(&mut self, cell: ChanMsg) -> Result<bool> {
        use ChanMsg::*;
        match cell {
            Relay(r) | RelayEarly(r) => {
                self.handle_relay_cell(r).await?;
                Ok(false)
            }
            Destroy(_) => {
                self.handle_destroy_cell()?;
                Ok(true)
            }
            _ => Err(Error::InternalError(
                "Unsupported cell type on circuit.".into(),
            )),
        }
    }

    /// React to a Relay or RelayEarly cell.
    async fn handle_relay_cell(&mut self, cell: Relay) -> Result<()> {
        let mut body = cell.into_relay_body();
        // XXX I don't like locking the whole circuit
        let mut circ = self.circuit.c.lock().await;

        // Decrypt the cell.  If it's recognized, then find the corresponding
        // hop.
        let hopnum: u8 = circ.crypto.decrypt(&mut body)?;
        let hop = &mut circ.hops[hopnum as usize];

        // Decode the cell.
        let msg = RelayCell::decode(body)?;
        let (streamid, msg) = msg.into_streamid_and_msg();
        // If this cell wants/refuses to have a Stream ID, does it
        // have/not have one?
        if !msg.get_cmd().accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                streamid,
                msg.get_cmd()
            )));
        }

        // If this has a reasonable streamID value of 0, it's a meta cell,
        // not meant for a particualr stream.
        if streamid == 0.into() {
            return circ.handle_meta_cell(hopnum, msg);
        }

        if let Some(StreamEnt::Open(s)) = hop.map.get_mut(streamid) {
            // The stream for this message exists, and is open.

            // XXXX handle errors better. Does this one mean that the
            // the stream is closed?

            // XXXX should we really be holding the mutex for this?

            // XXXX reject cells that should never go to a client,
            // XXXX like BEGIN.
            s.send(msg).await.map_err(|_| Error::CircProto("x".into()))
        } else {
            // No stream wants this message.

            // XXXX what do we do with unrecognized cells?
            Ok(())
        }
    }

    /// Helper: process a destroy cell.
    fn handle_destroy_cell(&mut self) -> Result<()> {
        // XXXX anything more to do here?
        Ok(())
    }
}
