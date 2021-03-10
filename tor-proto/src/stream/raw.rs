//! Declare the lowest level of stream: a stream that operates on raw
//! cells.

use crate::circuit::{sendme, StreamTarget};
use crate::{Error, Result};
use tor_cell::relaycell::msg::{RelayMsg, Sendme};

use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::stream::StreamExt;

use std::sync::atomic::{AtomicBool, Ordering};

/// A RawCellStream is a client's cell-oriented view of a stream over the
/// Tor network.
pub struct RawCellStream {
    /// Wrapped view of the circuit, hop, and streamid that we're using.
    ///
    /// TODO: do something similar with circuits?
    target: Mutex<StreamTarget>,
    /// A Stream over which we receive relay messages.  Only relay messages
    /// that can be associated with a stream ID will be received.
    receiver: Mutex<mpsc::Receiver<RelayMsg>>,
    /// Have we been informed that this stream is closed, or received a fatal
    /// error?
    stream_ended: AtomicBool,
}

impl RawCellStream {
    /// Internal: build a new RawCellStream.
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::Receiver<RelayMsg>) -> Self {
        RawCellStream {
            target: Mutex::new(target),
            receiver: Mutex::new(receiver),
            stream_ended: AtomicBool::new(false),
        }
    }

    /// Try to read the next relay message from this stream.
    pub async fn recv(&self) -> Result<RelayMsg> {
        let msg = self
            .receiver
            .lock()
            .await
            .next()
            .await
            // This probably means that the other side closed the
            // mpsc channel.
            .ok_or(Error::StreamClosed(
                "stream channel disappeared without END cell?",
            ))?;

        // Possibly decrement the window for the cell we just received, and
        // send a SENDME if doing so took us under the threshold.
        if sendme::msg_counts_towards_windows(&msg) {
            let mut target = self.target.lock().await;
            if target.recvwindow.take()? {
                self.send_sendme(&mut target).await?;
            }
        }

        Ok(msg)
    }

    /// Send a relay message along this stream
    pub async fn send(&self, msg: RelayMsg) -> Result<()> {
        self.target.lock().await.send(msg).await
    }

    /// Return true if this stream is marked as having ended.
    pub fn has_ended(&self) -> bool {
        self.stream_ended.load(Ordering::SeqCst)
    }

    /// Mark this stream as having ended
    pub fn note_ended(&self) {
        // TODO: This shouldn't be public.
        self.stream_ended.store(true, Ordering::SeqCst);
    }

    /// Inform the circuit-side of this stream about a protocol error
    pub async fn protocol_error(&self) {
        self.target.lock().await.protocol_error().await
    }

    /// Send a SENDME cell and adjust the receive window.
    async fn send_sendme(&self, target: &mut StreamTarget) -> Result<()> {
        let sendme = Sendme::new_empty();
        target.send(sendme.into()).await?;
        target.recvwindow.put();
        Ok(())
    }

    /// Ensure that all the data in this stream has been flushed in to
    /// the circuit, and close it.
    pub async fn close(self) -> Result<()> {
        // Not much to do here right now.
        drop(self);
        Ok(())
    }
}
