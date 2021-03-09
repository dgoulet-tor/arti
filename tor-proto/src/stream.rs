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
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Have we been informed that this stream is closed, or received a fatal
    /// error?
    #[allow(dead_code)]
    stream_ended: AtomicBool,
}

impl TorStream {
    /// Internal: build a new TorStream.
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::Receiver<RelayMsg>) -> Self {
        TorStream {
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

    /// Buffered data to send over the connection.
    // TODO: this buffer is probably smaller than we want, but it's good
    // enough for now.
    buf: [u8; Data::MAXLEN],

    /// Number of unflushed bytes in buf.
    n_pending: usize,
}

/// Wrapper for the read part of a DataStream
// TODO: I'd like this to implement AsyncRead
pub struct DataReader {
    /// The underlying TorStream object.
    s: Arc<TorStream>,

    /// If present, data that we received on this stream but have not
    /// been able to send to the caller yet.
    // TODO: This data structure is probably not what we want, but
    // it's good enough for now.
    pending: Vec<u8>,

    /// Index into pending to show what we've already read.
    offset: usize,
}

impl DataStream {
    /// Wrap a TorStream as a DataStream.
    ///
    /// Call only after a CONNECTED cell has been received.
    pub(crate) fn new(s: TorStream) -> Self {
        let s = Arc::new(s);
        let r = DataReader {
            s: Arc::clone(&s),
            pending: Vec::new(),
            offset: 0,
        };
        let w = DataWriter {
            s,
            buf: [0; Data::MAXLEN],
            n_pending: 0,
        };
        DataStream { r, w }
    }

    /// Write all the bytes in b onto the stream, using as few data
    /// cells as possible.
    pub async fn write_bytes(&mut self, buf: &[u8]) -> Result<()> {
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
    pub async fn write_bytes(&mut self, b: &[u8]) -> Result<()> {
        for chunk in b.chunks(Data::MAXLEN) {
            self.queue_bytes(&chunk[..]);
            self.flush_buf().await?;
        }
        Ok(())
    }

    /// Try to flush the current buffer contents as a data cell
    async fn flush_buf(&mut self) -> Result<()> {
        if self.n_pending != 0 {
            let cell = Data::new(&self.buf[..self.n_pending]);
            self.n_pending = 0;
            self.s.send(cell.into()).await
        } else {
            Ok(())
        }
    }

    /// Add as many bytes as possible from `b` to our internal buffer;
    /// return the number we were able to add.
    fn queue_bytes(&mut self, b: &[u8]) -> usize {
        let empty_space = &mut self.buf[self.n_pending..];
        if empty_space.is_empty() {
            // that is, len == 0
            return 0;
        }

        let n_to_copy = std::cmp::min(b.len(), empty_space.len());
        empty_space[..n_to_copy].copy_from_slice(&b[..n_to_copy]);
        self.n_pending += n_to_copy;
        n_to_copy
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
        if self.s.stream_ended.load(Ordering::SeqCst) {
            return Err(Error::StreamClosed("Stream is closed."));
        }

        if !self.buf_is_empty() {
            return Ok(self.extract_bytes(buf));
        }

        // We don't loop here; if we did, we might block while we had some
        // data to return.

        self.read_cell().await?;

        Ok(self.extract_bytes(buf))
    }

    /// Pull as many bytes as we can off of self.pending, and return that
    /// number of bytes.
    fn extract_bytes(&mut self, buf: &mut [u8]) -> usize {
        let remainder = &self.pending[self.offset..];
        let n_to_copy = std::cmp::min(buf.len(), remainder.len());
        buf[..n_to_copy].copy_from_slice(&remainder[..n_to_copy]);
        self.offset += n_to_copy;

        n_to_copy
    }

    /// Return true iff there are no buffered bytes here to yield
    fn buf_is_empty(&self) -> bool {
        self.pending.len() == self.offset
    }

    /// Load self.pending with the contents of a new data cell.
    async fn read_cell(&mut self) -> Result<()> {
        let cell = self.s.recv().await;

        match cell {
            Ok(RelayMsg::Data(d)) => {
                self.add_data(d.into());
                Ok(())
            }
            Err(_) | Ok(RelayMsg::End(_)) => {
                self.s.stream_ended.store(true, Ordering::SeqCst);
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

    /// Add the data from `d` to the end of our pending bytes.
    fn add_data(&mut self, d: Vec<u8>) {
        if self.buf_is_empty() {
            // No data pending?  Just take d as the new pending.
            self.pending = d;
            self.offset = 0;
        } else {
            // XXXX This has potential to grow `pending` without
            // bound.  Fortunately, we don't read data in this
            // (non-empty) case right now.
            self.pending.extend_from_slice(&d[..]);
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
