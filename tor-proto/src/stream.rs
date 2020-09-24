//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use ClientCirc::begin_stream()
//!
//! # Limitations
//!
//! TODO: This should eventually expose a bytes-oriented type rather than a
//! cell-oriented type.
//!
//! XXXX TODO: There is no fariness, rate-limiting, or flow control.

use crate::circuit::StreamTarget;
use crate::relaycell::msg::{Data, RelayMsg, Resolved};
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

    /// Have we been informed that this stream is closed?  If so this is
    /// the message or the error that told us.
    received_end: Option<Result<RelayMsg>>,
}

impl TorStream {
    /// Internal: build a new TorStream.
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::Receiver<RelayMsg>) -> Self {
        TorStream {
            target,
            receiver,
            received_end: None,
        }
    }

    /// Try to read the next relay message from this stream.
    pub async fn recv(&mut self) -> Result<RelayMsg> {
        self.receiver
            .next()
            .await
            // This probably means that the other side closed the
            // mpsc channel.
            .ok_or_else(|| Error::InternalError("XXXX".into()))
    }

    /// Send a relay message along this stream
    pub async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        self.target.send(msg).await
    }
}

/// A DataStream is a wrapper around a TorStream for byte-oriented IO.
/// It's suitable for use with BEGIN or BEGIN_DIR streams.
pub struct DataStream {
    s: TorStream,
    pending: Option<Vec<u8>>, // bad design, but okay I guess.
}

// TODO: I'd like this to implement AsyncRead and AsyncWrite.

impl DataStream {
    pub(crate) fn new(s: TorStream) -> Self {
        DataStream { s, pending: None }
    }

    /// Write all the bytes in b onto the stream, using as few data
    /// cells as possible.
    ///
    /// TODO: We should have DataStream implement AsyncWrite.
    ///
    /// TODO: should we do some variant of Nagle's algorithm?
    pub async fn write_bytes(&mut self, b: &[u8]) -> Result<()> {
        for chunk in b.chunks(Data::MAXLEN) {
            let cell = Data::new(chunk);
            self.s.send(cell.into()).await?;
        }
        Ok(())
    }

    /// Try to read some amount of bytes from the stream; return how
    /// much we read.
    ///
    // TODO: this could probably have better behavior when there's
    // more than one cell to read, but we have to be sure not to
    // block any more once we have data.
    //
    // AsyncRead would be better.
    pub async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        fn split_and_write(buf: &mut [u8], mut v: Vec<u8>) -> (usize, Option<Vec<u8>>) {
            if v.len() > buf.len() {
                let remainder = v.split_off(buf.len());
                buf.copy_from_slice(&v[..]);
                return (v.len(), Some(remainder));
            } else {
                (&mut buf[..v.len()]).copy_from_slice(&v[..]);
                return (v.len(), None);
            }
        }

        if self.s.received_end.is_some() {
            return Ok(0); // XXXX NO! This is closed!
        }

        if let Some(pending) = self.pending.take() {
            let (n, new_pending) = split_and_write(buf, pending);
            if new_pending.is_some() {
                self.pending = new_pending;
            }
            return Ok(n);
        }

        // We don't loop here; if we did, we might block while we had some
        // data to return.
        let cell = self.s.recv().await;

        match cell {
            Ok(RelayMsg::Data(d)) => {
                let (n, pending) = split_and_write(buf, d.into());
                if pending.is_some() {
                    self.pending = pending;
                }
                Ok(n)
            }
            Err(_) | Ok(RelayMsg::End(_)) => {
                self.s.received_end = Some(cell);
                Ok(0) // XXXX NO! This should be a close error
            }
            Ok(_) => {
                // XXXX This is a bad cell; what do we do?
                Ok(0)
            }
        }
    }
}

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    s: TorStream,
}

impl ResolveStream {
    pub(crate) fn new(s: TorStream) -> Self {
        ResolveStream { s }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        let cell = self.s.recv().await?;
        match cell {
            RelayMsg::End(_) => Err(Error::InternalError(
                "XXXX bad error type, do something smarter.".into(),
            )),
            RelayMsg::Resolved(r) => Ok(r),
            _ => Err(Error::InternalError(
                "XXXX what do i do if it's a bad cell?".into(),
            )),
        }
    }
}
