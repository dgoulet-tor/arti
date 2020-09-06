use crate::chancell::{
    msg::{ChanMsg, ChannelMessage},
    ChanCmd, CircID,
};
use crate::crypto::cell::CELL_BODY_LEN;
use arrayref::{array_mut_ref, array_ref};
use bytes;
use futures_codec;
use tor_bytes::{self, Reader, Writer};

// XXXX make a crate-level error type
pub enum Error {
    Io(std::io::Error),
    Bytes(tor_bytes::Error),
    Misc(),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}
impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Error {
        Error::Bytes(e)
    }
}

// Note: only link versions 3 and higher are supported.  Versions cell
// is not supported via coder/decoder ,since it always uses a two-byte
// circuit-ID.
pub struct ChannelCodec {
    link_version: u16,
}

impl futures_codec::Encoder for ChannelCodec {
    type Item = (CircID, ChannelMessage);
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let (circid, msg) = item;
        let cmd = msg.get_cmd();
        dst.write_u32(circid.into());
        dst.write_u8(cmd.into());

        // now write the cell body and handle the length.
        if cmd.is_var_cell() {
            let pos = dst.len(); // always 5?
            dst.write_u16(0);
            msg.write_body_onto(dst);
            let len = dst.len() - pos - 2;
            if len > std::u16::MAX as usize {
                return Err(Error::Misc());
            }
            // go back and set the length.
            *(array_mut_ref![&mut dst[pos..pos + 2], 0, 2]) = (len as u16).to_be_bytes();
        } else {
            let pos = dst.len(); // Always 5?
            msg.write_body_onto(dst);
            let len = dst.len() - pos;
            if len > CELL_BODY_LEN {
                return Err(Error::Misc());
            }
            // pad to end of fixed-length cell
            dst.write_zeros(CELL_BODY_LEN - len);
        }
        Ok(())
    }
}

impl futures_codec::Decoder for ChannelCodec {
    type Item = (CircID, ChannelMessage);
    type Error = Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 7 {
            // Smallest possible command: varcell with len 0
            return Ok(None);
        }
        let cmd: ChanCmd = src[4].into();
        let varcell = cmd.is_var_cell();
        let cell_len: usize = if varcell {
            let msg_len = u16::from_be_bytes(*array_ref![&src[5..7], 0, 2]);
            msg_len as usize + 7
        } else {
            514
        };
        if src.len() < cell_len {
            return Ok(None);
        }

        let cell = src.split_to(cell_len).freeze();
        let mut r = Reader::from_bytes(&cell);
        let circid = r.take_u32()?.into();
        r.advance(if varcell { 1 } else { 3 })?;
        let msg = r.extract()?;
        Ok(Some((circid, msg)))
    }
}
