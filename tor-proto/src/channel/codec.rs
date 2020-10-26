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
pub struct ChannelCodec(codec::ChannelCodec);

impl ChannelCodec {
    /// Create a new ChannelCodec with a given link protocol.
    pub(crate) fn new(link_proto: u16) -> Self {
        ChannelCodec(codec::ChannelCodec::new(link_proto))
    }
}

impl futures_codec::Encoder for ChannelCodec {
    type Item = ChanCell;
    type Error = tor_cell::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dbg!(&item);
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

#[cfg(test)]
pub(crate) mod test {
    use futures::io::{AsyncRead, AsyncWrite, Cursor, Result};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures::task::{Context, Poll};
    use futures_await_test::async_test;
    use hex_literal::hex;
    use pin_project::pin_project;
    use std::pin::Pin;

    use super::ChannelCodec;
    use tor_cell::chancell::{msg, ChanCell, ChanCmd, CircId};

    /// Helper type for reading and writing bytes to/from buffers.
    // TODO: We might want to move this
    #[pin_project]
    pub(crate) struct MsgBuf {
        /// Data we have received as a reader.
        #[pin]
        inbuf: futures::io::Cursor<Vec<u8>>,
        /// Data we write as a writer.
        #[pin]
        outbuf: futures::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for MsgBuf {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize>> {
            self.project().inbuf.poll_read(cx, buf)
        }
    }
    impl AsyncWrite for MsgBuf {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            self.project().outbuf.poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            self.project().outbuf.poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            self.project().outbuf.poll_close(cx)
        }
    }

    impl MsgBuf {
        pub fn new<T: Into<Vec<u8>>>(output: T) -> Self {
            let inbuf = Cursor::new(output.into());
            let outbuf = Cursor::new(Vec::new());
            MsgBuf { inbuf, outbuf }
        }

        pub fn consumed(&self) -> usize {
            self.inbuf.position() as usize
        }

        pub fn all_consumed(&self) -> bool {
            self.inbuf.get_ref().len() == self.consumed()
        }

        pub fn into_response(self) -> Vec<u8> {
            self.outbuf.into_inner()
        }
    }

    fn frame_buf(mbuf: MsgBuf) -> futures_codec::Framed<MsgBuf, ChannelCodec> {
        futures_codec::Framed::new(mbuf, ChannelCodec::new(4))
    }

    #[async_test]
    async fn check_encoding() -> std::result::Result<(), tor_cell::Error> {
        let mb = MsgBuf::new(&b""[..]);
        let mut framed = frame_buf(mb);

        let destroycell = msg::Destroy::new(2.into());
        framed
            .send(ChanCell::new(7.into(), destroycell.into()))
            .await?;

        let nocerts = msg::Certs::new_empty();
        framed.send(ChanCell::new(0.into(), nocerts.into())).await?;

        framed.flush().await?;

        let data = framed.into_inner().into_response();

        assert_eq!(&data[0..10], &hex!("00000007 04 0200000000")[..]);

        assert_eq!(&data[514..], &hex!("00000000 81 0001 00")[..]);
        Ok(())
    }

    #[async_test]
    async fn check_decoding() -> std::result::Result<(), tor_cell::Error> {
        let mut dat = Vec::new();
        dat.extend_from_slice(&hex!("00000007 04 0200000000")[..]);
        dat.resize(514, 0);
        dat.extend_from_slice(&hex!("00000000 81 0001 00")[..]);
        let mb = MsgBuf::new(&dat[..]);
        let mut framed = frame_buf(mb);

        let destroy = framed.next().await.unwrap()?;
        let nocerts = framed.next().await.unwrap()?;

        assert_eq!(destroy.circid(), CircId::from(7));
        assert_eq!(destroy.msg().cmd(), ChanCmd::DESTROY);
        assert_eq!(nocerts.circid(), CircId::from(0));
        assert_eq!(nocerts.msg().cmd(), ChanCmd::CERTS);

        assert!(framed.into_inner().all_consumed());

        Ok(())
    }
}
