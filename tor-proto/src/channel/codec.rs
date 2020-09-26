/// Wrap tor_cell::ChannelCodec for use as a with the futures_codec crate.
use tor_cell::chancell::{codec, ChanCell};

use bytes::BytesMut;

pub(crate) struct ChannelCodec(codec::ChannelCodec);

impl ChannelCodec {
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
