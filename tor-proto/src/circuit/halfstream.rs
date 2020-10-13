//! Type and code for handling a "half-closed" stream.
//!
//! A half-closed stream is one that we've sent an END on, but where
//! we might still receive some cells.

use crate::circuit::sendme::{StreamRecvWindow, StreamSendWindow};
use crate::{Error, Result};
use tor_cell::relaycell::msg::RelayMsg;

/// Type to track state of half-closed streams.
///
/// A half-closed stream is one where we've sent an END cell, but where
/// the other side might still send us data.
///
/// We need to track these streams instead of forgetting about them entirely,
/// since otherwise we'd be vulnerable to a class of "DropMark" attacks;
/// see https://gitlab.torproject.org/tpo/core/tor/-/issues/25573 .
pub(super) struct HalfStream {
    /// Send window for this stream. Used to detect whether we get too many
    /// SENDME cells.
    sendw: StreamSendWindow,
    /// Receive window for this stream. Used to detect whether we get too
    /// many data cells.
    recvw: StreamRecvWindow,
    /// If true, accept a connected cell on this stream.
    connected_ok: bool,
}

impl HalfStream {
    /// Create a new half-closed stream.
    pub fn new(sendw: StreamSendWindow, recvw: StreamRecvWindow, connected_ok: bool) -> Self {
        HalfStream {
            sendw,
            recvw,
            connected_ok,
        }
    }

    /// Process an incoming message and adjust this HalfStream accordingly.
    /// Give an error if the protocol has been violated.
    ///
    /// The caller must handle END cells; it is an internal error to pass
    /// END cells to this method.
    /// no ends here.
    pub async fn handle_msg(&mut self, msg: &RelayMsg) -> Result<()> {
        match msg {
            RelayMsg::Sendme(_) => {
                self.sendw.put(Some(())).await.ok_or_else(|| {
                    Error::CircProto("Too many sendmes on a closed stream!".into())
                })?;
                Ok(())
            }
            RelayMsg::Data(_) => {
                if self.recvw.take().is_none() {
                    Err(Error::CircProto(
                        "Impossibly many cells sent to a closed stream!".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            RelayMsg::Connected(_) => {
                if self.connected_ok {
                    self.connected_ok = false;
                    Ok(())
                } else {
                    Err(Error::CircProto(
                        "Bad CONNECTED cell on a closed stream!".into(),
                    ))
                }
            }
            RelayMsg::End(_) => Err(Error::InternalError(
                "END cell in HalfStream::handle_msg().".into(),
            )),
            _ => Err(Error::CircProto(format!(
                "Bad {} cell on a closed stream!",
                msg.cmd()
            ))),
        }
    }
}
