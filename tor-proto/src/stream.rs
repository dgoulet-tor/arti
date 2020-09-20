//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use ClientCirc::begin_stream()
//!
//! # Limitations
//!
//! This should eventually expose a bytes-oriented type rather than a
//! cell-oriented type.

use crate::circuit::StreamTarget;
use crate::relaycell::msg::RelayMsg;
use crate::{Error, Result};

use futures::channel::mpsc;
use futures::stream::StreamExt;

/// A TorStream is a client's cell-oriented view of a stream over the
/// Tor network.
pub struct TorStream {
    /// Wrapped view of the circuit, hop, and streamid that we're using.
    ///
    /// TODO: do something similar with circuits?
    target: StreamTarget,
    /// A Stream over which we receive relay messages.  Only relay messages
    /// that can be associated with a stream ID will be received.
    receiver: mpsc::Receiver<RelayMsg>,
}

impl TorStream {
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::Receiver<RelayMsg>) -> Self {
        TorStream { target, receiver }
    }

    /// Try to read the next relay message from this stream.
    pub async fn recv(&mut self) -> Result<RelayMsg> {
        self.receiver
            .next()
            .await
            .ok_or_else(|| Error::InternalError("XXXX".into()))
    }

    /// Send a relay message along this stream
    pub async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        self.target.send(msg).await
    }
}

// XXXX TODO send END cell when dropping!
