//! Decompression support for Tor directory connections.
//!
//! There are different compression algorithms that can be used on the
//! Tor network; right now only zlib, lzma and identity decompression are
//! supported here.
//!
//! This provides a single streaming API for decompression; we may
//! want others in the future.

use anyhow::Result;

/// Possible return conditions from a decompression operation.
#[derive(Debug, Clone)]
pub(crate) enum StatusKind {
    /// Some data was written.
    Written,
    /// We're out of space in the output buffer.
    OutOfSpace,
    /// We finished writing.
    Done,
}

/// Return value from [`Decompressor::process`].  It describes how much data
/// was transferred, and what the caller needs to do next.
#[derive(Debug, Clone)]
pub(crate) struct Status {
    /// The (successful) result of the decompression
    pub status: StatusKind,
    /// How many bytes were consumed from `inp`.
    pub consumed: usize,
    /// How many bytes were written into `out`.
    pub written: usize,
}

/// An implementation of a compression algorithm, including its state.
pub(crate) trait Decompressor {
    /// Decompress data from 'inp' into 'out'.  If 'finished' is true, no
    /// more data will be provided after the current contents of inputs.
    fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status>;
}

/// Implementation for the identity decompressor.
///
/// This does more copying than Rust best practices would prefer, but
/// we should never actually use it in practice.
pub(crate) mod identity {
    use super::{Decompressor, Status, StatusKind};
    use anyhow::Result;

    /// An identity decompressor
    pub struct Identity;

    impl Decompressor for Identity {
        fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status> {
            if out.is_empty() && !inp.is_empty() {
                return Ok(Status {
                    status: StatusKind::OutOfSpace,
                    consumed: 0,
                    written: 0,
                });
            }
            let to_copy = std::cmp::min(inp.len(), out.len());
            (&mut out[..to_copy]).copy_from_slice(&inp[..to_copy]);

            let statuskind = if finished && to_copy == inp.len() {
                StatusKind::Done
            } else {
                StatusKind::Written
            };
            Ok(Status {
                status: statuskind,
                consumed: to_copy,
                written: to_copy,
            })
        }
    }
}

/// Implementation for the [`Decompressor`] trait on
/// [`::miniz_oxide::inflate::stream::InflateState`].
///
/// This implements zlib compression as used in Tor.
mod miniz_oxide {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use miniz_oxide::inflate::stream::InflateState;
    use miniz_oxide::{MZError, MZFlush, MZStatus};

    impl Decompressor for InflateState {
        fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status> {
            let flush = if finished {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            let res = miniz_oxide::inflate::stream::inflate(self, inp, out, flush);

            let statuskind = match res.status {
                Ok(MZStatus::StreamEnd) => StatusKind::Done,
                Ok(MZStatus::Ok) => StatusKind::Written,
                Err(MZError::Buf) => StatusKind::OutOfSpace,
                other => return Err(anyhow!("miniz compression error: {:?}", other)),
            };

            Ok(Status {
                status: statuskind,
                consumed: res.bytes_consumed,
                written: res.bytes_written,
            })
        }
    }
}

/// Implementation for the [`Decompressor`] trait on [`zstd::stream`].
///
/// This implements zstd compression as used in Tor.
mod zstd {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use zstd::stream::raw::{Decoder, Operation};

    impl Decompressor for Decoder<'static> {
        fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status> {
            let result = self.run_on_buffers(inp, out);
            if finished {
                // It does not do anything, just returns Ok(0) if finished_frame = true
                //self.finish(output, finished_frame)
            }
            match result {
                Ok(res) => {
                    let status = if finished {
                        StatusKind::Done
                    } else {
                        StatusKind::Written
                    };

                    Ok(Status {
                        status,
                        consumed: res.bytes_read,
                        written: res.bytes_written,
                    })
                }
                Err(err) => return Err(anyhow!("zstd compression error: {:?}", err)),
            }
        }
    }
}

/// Implementation for the [`Decompressor`] trait on [`xz2::Stream`].
///
/// This implements lzma compression as used in Tor.
mod lzma {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use xz2::stream::{Action, Status as Xz2Status, Stream};

    impl Decompressor for Stream {
        fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status> {
            let action = if finished {
                Action::Finish
            } else {
                Action::Run
            };

            let previously_consumed = self.total_in();
            let previously_written = self.total_out();

            let res = self.process(inp, out, action);

            let statuskind = match res {
                Ok(Xz2Status::StreamEnd) => StatusKind::Done,
                Ok(Xz2Status::Ok) => StatusKind::Written,
                Ok(Xz2Status::GetCheck) => StatusKind::Written,
                Ok(Xz2Status::MemNeeded) => StatusKind::OutOfSpace,
                other => return Err(anyhow!("lzma compression error: {:?}", other)),
            };

            Ok(Status {
                status: statuskind,
                consumed: (self.total_in() - previously_consumed) as usize,
                written: (self.total_out() - previously_written) as usize,
            })
        }
    }
}
