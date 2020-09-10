//! Talking directly (over a TLS connection) to a Tor node
//!
//! Right now, we only support connecting to a Tor relay as a client.
//!
//! To do so, launch a TLS connection, then call `start_client_handshake()`
//!
//! TODO: channel padding support.

mod circmap;
mod handshake;
mod reactor;

use crate::chancell::{codec, msg, ChanCell};
use crate::{Error, Result};

use futures::channel::oneshot;
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use futures::sink::SinkExt;
use futures::stream::{SplitSink, StreamExt};

use std::sync::Arc;

use log::trace;

// reexport
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

type CellFrame<T> = futures_codec::Framed<T, codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
#[derive(Clone)]
pub struct Channel<T: AsyncRead + AsyncWrite + Unpin> {
    inner: Arc<ChannelImpl<T>>,
}

/// Main implementation type for a channel.
struct ChannelImpl<T: AsyncRead + AsyncWrite + Unpin> {
    link_protocol: u16,
    // This uses a separate mutex from the circmap, since we only
    // need the circmap when we're making a new circuit, but we need
    // this _all the time_.
    tls: Mutex<SplitSink<CellFrame<T>, ChanCell>>,
    // I wish I didn't need a second Arc here, but I guess I do?
    circmap: Arc<Mutex<circmap::CircMap>>,
    sendclosed: oneshot::Sender<()>,
}

/// Launch a new client handshake over a TLS stream.
///
/// After calling this function, you'll need to call `connect()` on
/// the result to start the handshake.  If that succeeds, you'll have
/// authentication info from the relay: call `check()` on the result
/// to check that.  Finally, to finish the handshake, call `finish()`
/// on the result of _that_.
pub fn start_client_handshake<T>(tls: T) -> OutboundClientHandshake<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    handshake::OutboundClientHandshake::new(tls)
}

impl<T> Channel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Construct a channel and reactor.
    fn new(link_protocol: u16, tls: CellFrame<T>) -> (Self, reactor::Reactor<T>) {
        use circmap::{CircIDRange, CircMap};
        let circmap = Arc::new(Mutex::new(CircMap::new(CircIDRange::All)));

        let (sink, stream) = tls.split();

        let (sendclosed, recvclosed) = oneshot::channel::<()>();

        let inner = ChannelImpl {
            tls: Mutex::new(sink),
            link_protocol,
            circmap: circmap.clone(),
            sendclosed,
        };

        let reactor = reactor::Reactor::new(circmap, recvclosed, stream);

        let channel = Channel {
            inner: Arc::new(inner),
        };

        (channel, reactor)
    }

    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        let msg = cell.get_msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell on client channel",
                msg.get_cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "Can't send {} cell after handshake is done",
                msg.get_cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&self, cell: ChanCell) -> Result<()> {
        trace!("Sending {}", cell.get_msg().get_cmd());
        self.check_cell(&cell)?;
        let mut sink = self.inner.tls.lock().await;
        sink.send(cell).await?;

        Ok(())
    }
}

/*
    XXXX this doesn't work, since we'd have to take ownership of the
    XXXX oneshot.

    XXXX maybe I should wrap the oneshot in a cell or something?

impl<T> Drop for ChannelImpl<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn drop(&mut self) {
        self.sendclosed.send(());
    }
}
*/
