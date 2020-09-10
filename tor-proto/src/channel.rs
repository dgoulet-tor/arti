//! Talking directly (over a TLS connection) to a Tor node
//!
//! Right now, we only support connecting to a Tor relay as a client.
//!
//! To do so, launch a TLS connection, then call `start_client_handshake()`

mod handshake;

use crate::chancell::codec;
use futures::io::{AsyncRead, AsyncWrite};

// reexport
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

type CellFrame<T> = futures_codec::Framed<T, codec::ChannelCodec>;

/// An open client channel, ready to send and receive tor cells.
pub struct Channel<T: AsyncRead + AsyncWrite + Unpin> {
    link_protocol: u16,
    tls: CellFrame<T>,
}

/// Launch a new client handshake over a TLS stream.
pub fn start_client_handshake<T>(tls: T) -> OutboundClientHandshake<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    handshake::OutboundClientHandshake::new(tls)
}
