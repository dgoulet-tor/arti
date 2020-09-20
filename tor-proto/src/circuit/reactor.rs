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
    closeflag: Fuse<oneshot::Receiver<()>>,
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ChanMsg>,
    core: ReactorCore,
}

/// This is a separate; we use it when handling cells.
struct ReactorCore {
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
            let item = select_biased! {
                _ = close_future => return Ok(()), // we were asked to close
                item = next_future => item,
            };
            let item = match item {
                None => return Ok(()), // the stream closed.
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

    async fn handle_relay_cell(&mut self, cell: Relay) -> Result<()> {
        let mut body = cell.into_relay_body();
        // XXX I don't like locking the whole circuit
        let mut circ = self.circuit.c.lock().await;
        let hopnum: u8 = circ.crypto.decrypt(&mut body)?;
        let hop = &mut circ.hops[hopnum as usize];

        let msg = RelayCell::decode(body)?;
        let (streamid, msg) = msg.into_streamid_and_msg();
        if !msg.get_cmd().accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                streamid,
                msg.get_cmd()
            )));
        }

        if streamid == 0.into() {
            return circ.handle_meta_cell(hopnum, msg);
        }

        if let Some(StreamEnt::Open(s)) = hop.map.get_mut(streamid) {
            // XXXX handle errors better.
            // XXXX should we really be holding the mutex for this?

            // XXXX reject cells that should never go to a client,
            // XXXX like BEGIN.
            s.send(msg).await.map_err(|_| Error::CircProto("x".into()))
        } else {
            // XXXX what do we do with unrecognized cells?
            Ok(())
        }
    }

    fn handle_destroy_cell(&mut self) -> Result<()> {
        // XXXX anything more to do here?
        Ok(())
    }
}
