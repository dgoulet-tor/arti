//! Code to handle incoming cells on a channel.
//!
//! The role of this code is to run in a separate asynchronous task,
//! and routes cells to the right circuits.
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.

use super::circmap::{CircEnt, CircMap};
use super::CellFrame;
use crate::chancell::{msg::ChanMsg, ChanCell, CircID};
use crate::{Error, Result};

use futures::channel::oneshot;
use futures::future::Fuse;
use futures::io::AsyncRead;
use futures::lock::Mutex;
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::{SplitStream, StreamExt};
use futures::FutureExt;

use std::sync::Arc;

use log::trace;

/// Object to handle incoming cells on a channel.
///
/// This type is returned when you finish a channel; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the channel won't work."]
pub struct Reactor<T>
where
    T: AsyncRead + Unpin,
{
    /// A future that will fire if we're told to shut down the
    /// reactor.
    closeflag: Fuse<oneshot::Receiver<()>>,
    /// A Stream from which we can read ChanCells.  This should be backed
    /// by a TLS connection.
    input: SplitStream<CellFrame<T>>,
    /// The reactorcore object that knows how to handle cells.
    core: ReactorCore,
}

/// This is a separate; we use it when handling cells.
struct ReactorCore {
    // TODO: This lock is used pretty asymmetrically.  The reactor
    // task needs to use the circmap all the time, whereas other tasks
    // only need the circmap when dealing with circuit creation.
    // Maybe it would be better to use some kind of channel to tell
    // the reactor about new circuits?
    /// A map from circuit ID to Sinks on which we can deliver cells.
    circs: Arc<Mutex<CircMap>>,
}

impl<T> Reactor<T>
where
    T: AsyncRead + Unpin,
{
    /// Construct a new Reactor.
    ///
    /// Cells should be taken from input and routed according to circmap.
    ///
    /// When closeflag fires, the reactor should shut down.
    pub(super) fn new(
        circmap: Arc<Mutex<CircMap>>,
        closeflag: oneshot::Receiver<()>,
        input: SplitStream<CellFrame<T>>,
    ) -> Self {
        let core = ReactorCore { circs: circmap };
        Reactor {
            closeflag: closeflag.fuse(),
            input,
            core,
        }
    }

    /// Launch the reactor, and run until the channel closes or we
    /// encounter an error.
    pub async fn run(mut self) -> Result<()> {
        let mut close_future = self.closeflag;
        loop {
            let mut next_future = self.input.next().fuse();
            // Let's see what's next: maybe we got a cell, maybe the TLS
            // connection got closed, or maybe we've been told to shut
            // down.
            let item = select_biased! {
                // we were asked to shut down.
                _ = close_future => return Ok(()),
                // we got a cell or a close.
                item = next_future => item,
            };
            let item = match item {
                None => return Ok(()), // the TLS connection closed.
                Some(r) => r?,         // it's a cell!
            };

            self.core.handle_cell(item).await?;
        }
    }
}

impl ReactorCore {
    /// Helper: process a cell on a channel.  Most cell types get ignored
    /// or rejected; a few get delivered to circuits.
    async fn handle_cell(&mut self, cell: ChanCell) -> Result<()> {
        let (circid, msg) = cell.into_circid_and_msg();
        trace!("Received {} on {}", msg.get_cmd(), circid);
        use ChanMsg::*;

        match msg {
            // These aren't allowed on clients.
            Create(_) | CreateFast(_) | Create2(_) | RelayEarly(_) | PaddingNegotiate(_) => Err(
                Error::ChanProto(format!("{} cell on client channel", msg.get_cmd())),
            ),

            // In theory this is allowed in clients, but we should never get
            // one, since we don't use TAP.
            Created(_) => Err(Error::ChanProto(format!("{} cell received", msg.get_cmd()))),

            // These aren't allowed after handshaking is done.
            Versions(_) | Certs(_) | Authorize(_) | Authenticate(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "{} cell after handshake is done",
                msg.get_cmd()
            ))),

            // These are always ignored.
            Padding(_) | VPadding(_) | Unrecognized(_) => Ok(()),

            // These are allowed, and need to be handled.
            Relay(_) => self.deliver_relay(circid, msg).await,

            Destroy(_) => self.deliver_destroy(circid, msg).await,

            CreatedFast(_) | Created2(_) => self.deliver_created(circid, msg).await,
        }
    }

    /// Give the RELAY cell `msg` to the appropriate circuid.
    async fn deliver_relay(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        let mut map = self.circs.lock().await;

        if let Some(CircEnt::Open(s)) = map.get_mut(circid) {
            // There's an open circuit; we can give it the RELAY cell.
            // XXXX handle errors better.
            // XXXX should we really be holding the mutex for this?
            // XXXX I think that this one actually means the other side
            // is closed
            s.send(msg).await.map_err(|_| {
                Error::InternalError("Circuit queue rejected message. Is it closing? XXX".into())
            })
        } else {
            // XXXX handle this case better; don't just drop the cell.
            Ok(())
        }
    }

    /// Handle a CREATED{,_FAST,2} cell by passing it on to the appropriate
    /// circuit, if that circuit is waiting for one.
    async fn deliver_created(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        let mut map = self.circs.lock().await;
        if let Some(target) = map.advance_from_opening(circid) {
            // XXXX handle errors better.
            // XXXX should we really be holding the mutex for this?
            // XXXX I think that this one actually means the other side
            // is closed
            target.send(msg).map_err(|_| {
                Error::InternalError(
                    "Circuit queue rejected created message. Is it closing? XXX".into(),
                )
            })
        } else {
            Err(Error::ChanProto(format!(
                "Unexpected {} cell",
                msg.get_cmd()
            )))
        }
    }

    /// Handle a DESTROY cell by removing the corresponding circuit
    /// from the map, and pasing the destroy cell onward to the circuit.
    async fn deliver_destroy(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        // XXXX TODO: do we need to put a dummy entry in the map until
        // the other side of the circuit object is gone?

        let mut map = self.circs.lock().await;
        // Remove the circuit from the map: nothing more can be done with it.
        let entry = map.remove(circid);
        match entry {
            // If the circuit is waiting for CREATED, tell it that it
            // won't get one.
            Some(CircEnt::Opening(oneshot, _)) => {
                oneshot
                    .send(msg)
                    // XXXX I think that this one actually means the other side
                    // is closed
                    .map_err(|_| {
                        Error::InternalError(
                            "pending circuit wasn't interested in Destroy cell?".into(),
                        )
                    })
            }
            // It's an open circuit: tell it that it got a DESTROY cell.
            Some(CircEnt::Open(mut sink)) => sink
                .send(msg)
                .await
                // XXXX I think that this one actually means the other side
                // is closed
                .map_err(|_| {
                    Error::InternalError("circuit wan't interested in destroy cell?".into())
                }),
            // Got a DESTROY cell for a circuit we don't have.
            // XXXX do more?
            None => Ok(()),
        }
    }
}
