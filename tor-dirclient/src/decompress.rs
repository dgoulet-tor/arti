use anyhow::Result;

#[derive(Debug, Clone)]
pub(crate) enum StatusKind {
    Written,
    OutOfSpace,
    Done,
}

#[derive(Debug, Clone)]
pub(crate) struct Status {
    pub status: StatusKind,
    pub consumed: usize,
    pub written: usize,
}

pub(crate) trait Decompressor {
    fn process(&mut self, inp: &[u8], out: &mut [u8], finished: bool) -> Result<Status>;
}

pub(crate) mod identity {
    use super::{Decompressor, Status, StatusKind};
    use anyhow::Result;

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
                other => return Err(anyhow!("compression error: {:?}", other)),
            };

            Ok(Status {
                status: statuskind,
                consumed: res.bytes_consumed,
                written: res.bytes_written,
            })
        }
    }
}
