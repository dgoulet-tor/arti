//! Declare DataStream, a type that wraps RawCellStream so as to be useful
//! for byte-oriented communication.

use super::RawCellStream;
use crate::{Error, Result};

use futures::io::AsyncRead;
use futures::task::{Context, Poll};
use futures::Future;
use pin_project::pin_project;

use std::io::Result as IoResult;
use std::pin::Pin;
use std::sync::Arc;

use tor_cell::relaycell::msg::{Data, RelayMsg};

/// A DataStream is a Tor stream packaged so as to be useful for
/// byte-oriented IO.
///
/// It's suitable for use with BEGIN or BEGIN_DIR streams.
// TODO: I'd like this to implement AsyncRead and AsyncWrite.
pub struct DataStream {
    /// Underlying writer for this stream
    w: DataWriter,
    /// Underlying reader for this stream
    r: DataReader,
}

/// Wrapper for the Write part of a DataStream
// TODO: I'd like this to implement AsyncWrite.
pub struct DataWriter {
    /// Internal state for this writer
    imp: DataWriterImpl,
}

/// Wrapper for the Read part of a DataStream
// TODO: I'd like this to implement AsyncRead
#[pin_project]
pub struct DataReader {
    /// Internal state for this reader.
    ///
    /// This is stored in an Option so that we can mutate it in
    /// poll_read().  It might be possible to do better here, and we
    /// should refactor if so.
    state: Option<DataReaderState>,
}

impl DataStream {
    /// Wrap a RawCellStream as a DataStream.
    ///
    /// Call only after a CONNECTED cell has been received.
    pub(crate) fn new(s: RawCellStream) -> Self {
        let s = Arc::new(s);
        let r = DataReader {
            state: Some(DataReaderState::Ready(DataReaderImpl {
                s: Arc::clone(&s),
                pending: Vec::new(),
                offset: 0,
            })),
        };
        let w = DataWriter {
            imp: DataWriterImpl {
                s,
                buf: [0; Data::MAXLEN],
                n_pending: 0,
            },
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

/// Internal: the write part of a DataStream
struct DataWriterImpl {
    /// The underlying RawCellStream object.
    s: Arc<RawCellStream>,

    /// Buffered data to send over the connection.
    // TODO: this buffer is probably smaller than we want, but it's good
    // enough for now.
    buf: [u8; Data::MAXLEN],

    /// Number of unflushed bytes in buf.
    n_pending: usize,
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
            self.imp.queue_bytes(&chunk[..]);
            self.imp.flush_buf().await?;
        }
        Ok(())
    }
}

impl DataWriterImpl {
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

/// An enumeration for the state of a DataReader.
///
/// We have to use an enum here because, when we're waiting for
/// ReadingCell to complete, the future returned by `read_cell()` owns the
/// DataCellImpl.  If we wanted to store the future and the cell at the
/// same time, we'd need to make a self-referential structure, which isn't
/// possible in safe Rust AIUI.
enum DataReaderState {
    /// In this state the reader is not currently fetching a cell; it
    /// either has data or not.
    Ready(DataReaderImpl),
    /// The reader is currently fetching a cell: this future is the
    /// progress it is making.
    ReadingCell(Pin<Box<dyn Future<Output = (DataReaderImpl, Result<()>)> + Send>>),
}

/// Wrapper for the read part of a DataStream
struct DataReaderImpl {
    /// The underlying RawCellStream object.
    s: Arc<RawCellStream>,

    /// If present, data that we received on this stream but have not
    /// been able to send to the caller yet.
    // TODO: This data structure is probably not what we want, but
    // it's good enough for now.
    pending: Vec<u8>,

    /// Index into pending to show what we've already read.
    offset: usize,
}

impl DataReader {
    /// Try to read some amount of bytes from the stream; return how
    /// much we read.
    ///
    // TODO: Remove this method.
    pub async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        use futures::io::AsyncReadExt;
        Ok(self.read(buf).await?)
    }
}

impl AsyncRead for DataReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();

        // We're pulling the state object out of the reader.  We MUST
        // put it back before this function returns.
        let mut state = this.state.take().expect("Missing state in DataReader");

        loop {
            let mut future = match state {
                DataReaderState::Ready(mut imp) => {
                    // There may be data to read already.
                    // XXXX-NMNM handle close
                    let n_copied = imp.extract_bytes(buf);
                    if n_copied != 0 {
                        // We read data into the buffer.  Tell the caller.
                        *this.state = Some(DataReaderState::Ready(imp));
                        return Poll::Ready(Ok(n_copied));
                    }

                    // No data available!  We have to launch a read.
                    Box::pin(imp.read_cell())
                }
                DataReaderState::ReadingCell(fut) => fut,
            };

            // We have a future that reppresents an in-progress read.
            // See if it can make progress.
            match future.as_mut().poll(cx) {
                Poll::Ready((imp, Err(e))) => {
                    // XXXX-NMNM maybe record this error so we can't call again
                    // XXXX-NMNM What do we do if a data cell has zero bytes?
                    *this.state = Some(DataReaderState::Ready(imp));
                    return Poll::Ready(Err(e.into()));
                }
                Poll::Ready((imp, Ok(()))) => {
                    // It read a cell!  Continue the loop.
                    state = DataReaderState::Ready(imp);
                }
                Poll::Pending => {
                    // The future is pending; store it and tell the
                    // caller to get back to us later.
                    *this.state = Some(DataReaderState::ReadingCell(future));
                    return Poll::Pending;
                }
            }
        }
    }
}

impl DataReaderImpl {
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
    ///
    /// This function takes ownership of self so that we can avoid
    /// self-referential lifetimes.
    async fn read_cell(mut self) -> (Self, Result<()>) {
        let cell = self.s.recv().await;

        let result = match cell {
            Ok(RelayMsg::Data(d)) => {
                self.add_data(d.into());
                Ok(())
            }
            Err(_) | Ok(RelayMsg::End(_)) => Err(Error::StreamClosed("received an end cell")),
            Ok(m) => {
                self.s.protocol_error().await;
                Err(Error::StreamProto(format!(
                    "Unexpected {} cell on steam",
                    m.cmd()
                )))
            }
        };

        (self, result)
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
