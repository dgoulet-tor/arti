//! Code to handle incoming cells on a channel
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
    closeflag: Fuse<oneshot::Receiver<()>>,
    input: SplitStream<CellFrame<T>>,
    core: ReactorCore,
}

/// This is a separate; we use it when handling cells.
struct ReactorCore {
    // TODO: This lock is used pretty asymmetrically.  The reactor
    // task needs to use the circmap all the time, whereas other tasks
    // only need the circmap when dealing with circuit creation.
    // Maybe it would be better to use some kind of channel to tell
    // the reactor about new circuits?
    circs: Arc<Mutex<CircMap>>,
}

impl<T> Reactor<T>
where
    T: AsyncRead + Unpin,
{
    /// Construct a new Reactor.
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
            let item = select_biased! {
                _ = close_future => return Ok(()), // we were asked to close
                item = next_future => item,
            };
            let item = match item {
                None => return Ok(()), // the stream closed.
                Some(r) => r?,
            };

            self.core.handle_cell(item).await?;
        }
    }
}

impl ReactorCore {
    /// Helper: process a cell on a channel.  Most cells get ignored
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

            // We should never see this, since we don't use TAP.
            Created(_) => Err(Error::ChanProto(format!("{} cell received", msg.get_cmd()))),

            // These aren't allowed after handshaking is done.
            Versions(_) | Certs(_) | Authorize(_) | Authenticate(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "{} cell after handshake is done",
                msg.get_cmd()
            ))),

            // These are always ignored.
            Padding(_) | VPadding(_) | Unrecognized(_) => Ok(()),

            // These are allowed and need to be handled.
            Relay(_) | CreatedFast(_) | Created2(_) | Destroy(_) => {
                self.deliver_msg(circid, msg).await
            }
        }
    }

    /// Give `msg` to the appropriate circuid.
    async fn deliver_msg(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        let mut map = self.circs.lock().await;

        if let Some(CircEnt::Open(s)) = map.get_mut(circid) {
            // XXXX handle errors better.
            // XXXX should we really be holding the mutex for this?
            s.send(msg).await.map_err(|_| Error::ChanProto("x".into()))
        } else {
            // XXXX handle this case better; don't just drop the cell.
            Ok(())
        }
    }
}
