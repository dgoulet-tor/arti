//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use [crate::circuit::ClientCirc::begin_stream].
//!
//! # Limitations
//!
//! TODO: This should eventually expose a bytes-oriented type rather than a
//! cell-oriented type.
//!
//! XXXX TODO: There is no fariness, rate-limiting, or flow control.

use crate::circuit::{sendme, StreamTarget};
use crate::{Error, Result};
use tor_cell::relaycell::msg::{Data, RelayMsg, Resolved, Sendme};

use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::stream::StreamExt;
use std::sync::Arc;

/// A TorStream is a client's cell-oriented view of a stream over the
/// Tor network.
pub struct TorStream {
    /// Wrapped view of the circuit, hop, and streamid that we're using.
    ///
    /// TODO: do something similar with circuits?
    target: Mutex<StreamTarget>,
    /// A Stream over which we receive relay messages.  Only relay messages
    /// that can be associated with a stream ID will be received.
    receiver: Mutex<mpsc::Receiver<RelayMsg>>,
    /// Have we been informed that this stream is closed?  If so this is
    /// the message or the error that told us.
    #[allow(dead_code)] //XXXXXX-A1
    received_end: Option<Result<RelayMsg>>,
}

impl TorStream {
    /// Internal: build a new TorStream.
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::Receiver<RelayMsg>) -> Self {
        TorStream {
            target: Mutex::new(target),
            receiver: Mutex::new(receiver),
            received_end: None,
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

    /// Inform the circuit-side of this stream about a protocol error
    async fn protocol_error(&self) {
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

/// A DataStream is a wrapper around a TorStream for byte-oriented IO.
/// It's suitable for use with BEGIN or BEGIN_DIR streams.
// TODO: I'd like this to implement AsyncRead and AsyncWrite.
pub struct DataStream {
    /// Underlying writer for this stream
    w: DataWriter,
    /// Underlying reader for this stream
    r: DataReader,
}

/// Wrapper for the write part of a DataStream
// TODO: I'd like this to implement AsyncWrite.
pub struct DataWriter {
    /// The underlying TorStream object.
    s: Arc<TorStream>,
}

/// Wrapper for the read part of a DataStream
// TODO: I'd like this to implement AsyncRead
pub struct DataReader {
    /// The underlying TorStream object.
    s: Arc<TorStream>,

    /// If present, data that we received on this stream but have not
    /// been able to send to the caller yet.
    pending: Option<Vec<u8>>, // bad design, but okay I guess.
}

impl DataStream {
    /// Wrap a TorStream as a DataStream.
    ///
    /// Call only after a CONNECTED cell has been received.
    pub(crate) fn new(s: TorStream) -> Self {
        let s = Arc::new(s);
        let r = DataReader {
            s: Arc::clone(&s),
            pending: None,
        };
        let w = DataWriter { s };
        DataStream { r, w }
    }

    /// Write all the bytes in b onto the stream, using as few data
    /// cells as possible.
    pub async fn write_bytes(&self, buf: &[u8]) -> Result<()> {
        self.w.write_bytes(buf).await
    }

    /// Try to read some amount of bytes from the stream; return how
    /// much we read.
    pub async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.r.read_bytes(buf).await
    }

    /// Divide this DataStream into its consituent parts.
    pub fn split(self) -> (DataReader, DataWriter) {
        (self.r, self.w)
    }
}

impl DataWriter {
    /// Write all the bytes in b onto the stream, using as few data
    /// cells as possible.
    ///
    /// TODO: We should have DataWriter implement AsyncWrite.
    ///
    /// TODO: should we do some variant of Nagle's algorithm?
    pub async fn write_bytes(&self, b: &[u8]) -> Result<()> {
        for chunk in b.chunks(Data::MAXLEN) {
            let cell = Data::new(chunk);
            self.s.send(cell.into()).await?;
        }
        Ok(())
    }
}

impl DataReader {
    /// Try to read some amount of bytes from the stream; return how
    /// much we read.
    ///
    // TODO: this could probably have better behavior when there's
    // more than one cell to read, but we have to be sure not to
    // block any more once we have data.
    //
    // AsyncRead would be better.
    pub async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        /// Helper: pull as many bytes as possible out of `v` (from
        /// the front), and store them into `buf`.  Return a tuple
        /// containing the number of bytes transferred, and the
        /// remainder of `v` (if nonempty).
        fn split_and_write(buf: &mut [u8], mut v: Vec<u8>) -> (usize, Option<Vec<u8>>) {
            if v.len() > buf.len() {
                let remainder = v.split_off(buf.len());
                buf.copy_from_slice(&v[..]);
                (v.len(), Some(remainder))
            } else {
                (&mut buf[..v.len()]).copy_from_slice(&v[..]);
                (v.len(), None)
            }
        }

        /* XXXX-A1 RESTORE THIS
                if self.s.received_end.is_some() {
                    return Err(Error::StreamClosed("Stream is closed."));
                }
        */

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
                /* XXXXX-A1 RESTORE THIS
                self.s.received_end = Some(cell);
                 */
                Err(Error::StreamClosed("received an end cell"))
            }
            Ok(m) => {
                self.s.protocol_error().await;
                Err(Error::StreamProto(format!(
                    "Unexpected {} cell on steam",
                    m.cmd()
                )))
            }
        }
    }
}

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    /// The underlying TorStream.
    s: TorStream,
}

impl ResolveStream {
    /// Wrap a TorStream into a ResolveStream.
    ///
    /// Call only after sending a RESOLVE cell.
    #[allow(dead_code)] // need to implement a caller for this.
    pub(crate) fn new(s: TorStream) -> Self {
        ResolveStream { s }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        let cell = self.s.recv().await?;
        match cell {
            RelayMsg::End(_) => Err(Error::StreamClosed("Received end cell on resolve stream")),
            RelayMsg::Resolved(r) => Ok(r),
            m => {
                self.s.protocol_error().await;
                Err(Error::StreamProto(format!(
                    "Unexpected {} on resolve stream",
                    m.cmd()
                )))
            }
        }
    }
}
