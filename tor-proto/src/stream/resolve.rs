//! Declare a type for streams that do hostname lookups

use super::RawCellStream;
use crate::{Error, Result};
use tor_cell::relaycell::msg::{RelayMsg, Resolved};

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    /// The underlying RawCellStream.
    s: RawCellStream,
}

impl ResolveStream {
    /// Wrap a RawCellStream into a ResolveStream.
    ///
    /// Call only after sending a RESOLVE cell.
    #[allow(dead_code)] // need to implement a caller for this.
    pub(crate) fn new(s: RawCellStream) -> Self {
        ResolveStream { s }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        let cell = self.s.recv().await?;
        match cell {
            RelayMsg::End(_) => Err(Error::StreamClosed("Received end cell on resolve stream")), // TODO: look at the reason in the End message.
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
