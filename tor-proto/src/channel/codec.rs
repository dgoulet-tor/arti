//! Wrap tor_cell::...:::ChannelCodec for use with the futures_codec
//! crate.
use tor_cell::chancell::{codec, ChanCell};

use bytes::BytesMut;

/// Asynchronous wrapper around ChannelCodec in tor_cell, with implementation
/// for use with futures_codec.
///
/// This type lets us wrap a TLS channel (or some other secure
/// AsyncRead+AsyncWrite type) as a Sink and a Stream of ChanCell, so we
/// can forget about byte-oriented communication.
pub(crate) struct ChannelCodec(codec::ChannelCodec);

impl ChannelCodec {
    /// Create a new ChannelCoded with a given link protocol.
    pub(crate) fn new(link_proto: u16) -> Self {
        ChannelCodec(codec::ChannelCodec::new(link_proto))
    }
}

impl futures_codec::Encoder for ChannelCodec {
    type Item = ChanCell;
    type Error = tor_cell::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.0.write_cell(item, dst)
    }
}

impl futures_codec::Decoder for ChannelCodec {
    type Item = ChanCell;
    type Error = tor_cell::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.decode_cell(src)
    }
}
