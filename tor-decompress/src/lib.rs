//! Decompression support for Tor directory connections.
//!
//! There are different compression algorithms that can be used on the
//! Tor network; right now only zlib, lzma and identity decompression are
//! supported here.
//!
//! This provides a single streaming API for decompression; we may
//! want others in the future.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use anyhow::{anyhow, Result};

/// Possible return conditions from a decompression operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusKind {
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
pub struct Status {
    /// The (successful) result of the decompression
    pub status: StatusKind,
    /// How many bytes were consumed from `inp`.
    pub consumed: usize,
    /// How many bytes were written into `out`.
    pub written: usize,
}

/// An implementation of a compression algorithm, including its state.
pub trait Decompressor {
    /// Decompress data from 'inp' into 'out'.  If 'finished' is true, no
    /// more data will be provided after the current contents of inputs.
    fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status>;
}

/// Return a decompressor object corresponding to a given Content-Encoding.
pub fn from_content_encoding(encoding: Option<&str>) -> Result<Box<dyn Decompressor + Send>> {
    match encoding {
        None | Some("identity") => identity::new_boxed(),
        Some("deflate") => miniz_oxide::new_boxed(),
        Some("x-tor-lzma") => lzma::new_boxed(),
        Some("x-zstd") => zstd::new_boxed(),
        Some(other) => Err(anyhow!("Unrecognized content-encoding {:?}", other)),
    }
}

/// Implementation for the identity decompressor.
///
/// This does more copying than Rust best practices would prefer, but
/// we should never actually use it in practice.
pub mod identity {
    use super::{Decompressor, Status, StatusKind};
    use anyhow::Result;

    /// An identity decompressor
    pub struct Identity;

    /// Create a new boxed identity decompressor.
    pub fn new_boxed() -> Result<Box<dyn Decompressor + Send + 'static>> {
        Ok(Box::new(Identity))
    }

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
pub mod miniz_oxide {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use miniz_oxide::inflate::stream::InflateState;
    use miniz_oxide::{MZError, MZFlush, MZStatus};

    /// Create a new boxed miniz_oxide decompressor.
    pub fn new_boxed() -> Result<Box<dyn Decompressor + Send + 'static>> {
        Ok(InflateState::new_boxed(miniz_oxide::DataFormat::Zlib))
    }

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
pub mod zstd {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use zstd::stream::raw::{Decoder, Operation};

    /// Create a new boxed zstd decompressor.
    pub fn new_boxed() -> Result<Box<dyn Decompressor + Send + 'static>> {
        Ok(Box::new(::zstd::stream::raw::Decoder::new()?))
    }

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
                Err(err) => Err(anyhow!("zstd compression error: {:?}", err)),
            }
        }
    }
}

/// Implementation for the [`Decompressor`] trait on [`xz2::Stream`].
///
/// This implements lzma compression as used in Tor.
pub mod lzma {
    use super::{Decompressor, Status, StatusKind};

    use anyhow::{anyhow, Result};
    use xz2::stream::{Action, Status as Xz2Status, Stream};

    /// Create a new boxed lzma decompressor.
    pub fn new_boxed() -> Result<Box<dyn Decompressor + Send + 'static>> {
        Ok(Box::new(Stream::new_lzma_decoder(16 * 1024 * 1024)?))
    }

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

#[cfg(test)]
mod test {
    use super::{from_content_encoding, Decompressor, StatusKind};
    use anyhow::anyhow;
    use std::str;

    #[test]
    fn decompress_zstd() {
        let original_input =
            "Tor is amazing, Tor is amazing, Tor is amazing, you work now please, good Tor.";
        let input = vec![
            40, 181, 47, 253, 32, 78, 173, 1, 0, 228, 2, 84, 111, 114, 32, 105, 115, 32, 97, 109,
            97, 122, 105, 110, 103, 44, 32, 121, 111, 117, 32, 119, 111, 114, 107, 32, 110, 111,
            119, 32, 112, 108, 101, 97, 115, 101, 44, 32, 103, 111, 111, 100, 32, 84, 111, 114, 46,
            1, 0, 6, 159, 75,
        ];

        let mut decoder = zstd::stream::raw::Decoder::new().unwrap();
        let mut output = [0u8; 78];
        let status = decoder.process(&input[..], &mut output[..], true).unwrap();
        assert!(matches!(status.status, StatusKind::Done));
        assert_eq!(status.consumed, 62);
        assert_eq!(status.written, 78);
        let out = str::from_utf8(&output[..]).unwrap();
        assert_eq!(out, original_input);
    }
    #[test]
    fn decompress_in_parts_zstd() {
        let original_input =
            "Tor is amazing, Tor is amazing, Tor is amazing, you work now please, good Tor.";
        let input = vec![
            40, 181, 47, 253, 32, 78, 173, 1, 0, 228, 2, 84, 111, 114, 32, 105, 115, 32, 97, 109,
            97, 122, 105, 110, 103, 44, 32, 121, 111, 117, 32, 119, 111, 114, 107, 32, 110, 111,
            119, 32, 112, 108, 101, 97, 115, 101, 44, 32, 103, 111, 111, 100, 32, 84, 111, 114, 46,
            1, 0, 6, 159, 75,
        ];
        let mut decoder = zstd::stream::raw::Decoder::new().unwrap();
        let mut output = [0u8; 78];
        let empty_space = [0u8; 78];
        let status = decoder
            .process(&input[0..30], &mut output[..], false)
            .unwrap();
        assert!(matches!(status.status, StatusKind::Written));
        assert_eq!(status.consumed, 30);
        // There will be no writing till we consume the whole input
        assert_eq!(status.written, 0);
        assert_eq!(output, empty_space);

        let status = decoder
            .process(&input[30..50], &mut output[..], false)
            .unwrap();

        assert!(matches!(status.status, StatusKind::Written));
        assert_eq!(status.consumed, 20);
        assert_eq!(status.written, 0);
        assert_eq!(output, empty_space);

        let status = decoder
            .process(&input[50..], &mut output[..], true)
            .unwrap();

        assert!(matches!(status.status, StatusKind::Done));
        assert_eq!(status.consumed, 12);
        assert_eq!(status.written, 78);

        let out = str::from_utf8(&output[..]).unwrap();
        assert_eq!(out, original_input);
    }

    fn check_decomp(name: Option<&str>, inp: &[u8]) -> Vec<u8> {
        let mut d = from_content_encoding(name).unwrap();
        let mut buf = vec![0; 2048];
        let s = d.process(inp, &mut buf[..], true).unwrap();
        // TODO: what if d requires multiple steps to work?
        assert_eq!(s.status, StatusKind::Done);
        assert_eq!(s.consumed, inp.len());
        buf.truncate(s.written);
        buf
    }

    #[test]
    fn test_from_content_encoding_ident() {
        assert_eq!(
            &check_decomp(None, &b"Hello world"[..])[..],
            &b"Hello world"[..]
        );

        assert_eq!(
            &check_decomp(Some("identity"), &b"Hello world"[..])[..],
            &b"Hello world"[..]
        );
    }

    #[test]
    fn test_from_content_encoding_err() {
        let name = "quantum-entanglement";
        let r = from_content_encoding(Some(name));
        assert!(r.is_err());

        let e = r.err();
        let msg = format!("Unrecognized content-encoding \"{}\"", name);
        let err_msg = format!("{}", anyhow!(e.unwrap()));
        assert_eq!(msg, err_msg);
    }
}
