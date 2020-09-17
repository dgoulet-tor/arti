#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_proto::chancell::codec::ChannelCodec;
use futures_codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut bytes = data.into();
    let _ = ChannelCodec::new(4).decode(&mut bytes);
});
