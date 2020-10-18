//! Implementation for parsing and encoding relay cells

use crate::chancell::{RawCellBody, CELL_DATA_LEN};
use tor_bytes::{Error, Result};
use tor_bytes::{Reader, Writer};

use arrayref::array_mut_ref;
use caret::caret_int;
use rand::{CryptoRng, Rng};

pub mod msg;

caret_int! {
    /// A command that identifies the type of a relay cell
    pub struct RelayCmd(u8) {
        /// Start a new stream
        BEGIN = 1,
        /// Data on a stream
        DATA = 2,
        /// Close a stream
        END = 3,
        /// Acknowledge a BEGIN; stream is open
        CONNECTED = 4,
        /// Used for flow control
        SENDME = 5,
        /// Extend a circuit to a new hop; deprecated
        EXTEND = 6,
        /// Reply to EXTEND handshake; deprecated
        EXTENDED = 7,
        /// Partially close a circuit
        TRUNCATE = 8,
        /// Circuit has been partially closed
        TRUNCATED = 9,
        /// Padding cell
        DROP = 10,
        /// Start a DNS lookup
        RESOLVE = 11,
        /// Reply to a DNS lookup
        RESOLVED = 12,
        /// Start a directory stream
        BEGIN_DIR = 13,
        /// Extend a circuit to a new hop
        EXTEND2 = 14,
        /// Reply to an EXTEND2 cell.
        EXTENDED2 = 15,

        /// HS: establish an introduction point.
        ESTABLISH_INTRO = 32,
        /// HS: establish a rendezvous point.
        ESTABLISH_RENDEZVOUS = 33,
        /// HS: send introduction (client to introduction point)
        INTRODUCE1 = 34,
        /// HS: send introduction (introduction point to service)
        INTRODUCE2 = 35,
        /// HS: connect rendezvous point (service to rendezvous point)
        RENDEZVOUS1 = 36,
        /// HS: connect rendezvous point (rendezvous point to client)
        RENDEZVOUS2 = 37,
        /// HS: Response to ESTABLISH_INTRO
        INTRO_ESTABLISHED = 38,
        /// HS: Response to ESTABLISH_RENDEZVOUS
        RENDEZVOUS_ESTABLISHED = 39,
        /// HS: Response to INTRODUCE1 from introduction point to client
        INTRODUCE_ACK = 40,

        // TODO: 41 and 42 are used for padding.
    }
}

/// Possible requirements on stream IDs for a relay command.
enum StreamIDReq {
    /// Can only be used with a stream ID of 0
    WantZero,
    /// Can only be used with a stream ID that isn't 0
    WantNonZero,
    /// Can be used with any stream ID
    Any,
}

impl RelayCmd {
    /// Check whether this command requires a certain kind of
    /// StreamID, and return a corresponding StreamIDReq.
    fn expects_streamid(self) -> StreamIDReq {
        match self {
            RelayCmd::BEGIN
            | RelayCmd::DATA
            | RelayCmd::END
            | RelayCmd::CONNECTED
            | RelayCmd::RESOLVE
            | RelayCmd::RESOLVED
            | RelayCmd::BEGIN_DIR => StreamIDReq::WantNonZero,
            RelayCmd::EXTEND
            | RelayCmd::EXTENDED
            | RelayCmd::TRUNCATE
            | RelayCmd::TRUNCATED
            | RelayCmd::DROP
            | RelayCmd::EXTEND2
            | RelayCmd::EXTENDED2
            | RelayCmd::ESTABLISH_INTRO
            | RelayCmd::ESTABLISH_RENDEZVOUS
            | RelayCmd::INTRODUCE1
            | RelayCmd::INTRODUCE2
            | RelayCmd::RENDEZVOUS1
            | RelayCmd::RENDEZVOUS2
            | RelayCmd::INTRO_ESTABLISHED
            | RelayCmd::RENDEZVOUS_ESTABLISHED
            | RelayCmd::INTRODUCE_ACK => StreamIDReq::WantZero,
            RelayCmd::SENDME => StreamIDReq::Any,
            _ => StreamIDReq::Any,
        }
    }
    /// Return true if this command is one that accepts the particular
    /// stream ID `id`
    pub fn accepts_streamid_val(self, id: StreamID) -> bool {
        match (self.expects_streamid(), id.is_zero()) {
            (StreamIDReq::WantNonZero, true) => false,
            (StreamIDReq::WantZero, false) => false,
            (_, _) => true,
        }
    }
}

/// Identify a single stream on a circuit.
///
/// These identifiers are local to each hop on a circuit
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct StreamID(u16);

impl From<u16> for StreamID {
    fn from(v: u16) -> StreamID {
        StreamID(v)
    }
}

impl Into<u16> for StreamID {
    fn into(self: StreamID) -> u16 {
        self.0
    }
}

impl std::fmt::Display for StreamID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl StreamID {
    /// Return true if this is the zero StreamID.
    ///
    /// A zero-valid circuit ID denotes a relay message that is not related to
    /// any particular stream, but which applies to the circuit as a whole.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

/// A parsed relay cell.
#[derive(Debug)]
pub struct RelayCell {
    /// The stream ID for the stream that this cell corresponds to.
    streamid: StreamID,
    /// The relay message for this cell.
    msg: msg::RelayMsg,
}

impl RelayCell {
    /// Construct a new relay cell.
    pub fn new(streamid: StreamID, msg: msg::RelayMsg) -> Self {
        RelayCell { streamid, msg }
    }
    /// Consume this cell and return its components.
    pub fn into_streamid_and_msg(self) -> (StreamID, msg::RelayMsg) {
        (self.streamid, self.msg)
    }
    /// Return the command for this cell.
    pub fn cmd(&self) -> RelayCmd {
        self.msg.cmd()
    }
    /// Return the underlying message for this cell.
    pub fn msg(&self) -> &msg::RelayMsg {
        &self.msg
    }
    /// Consume this relay message and encode it as a 509-byte padded cell
    /// body.
    pub fn encode<R: Rng + CryptoRng>(self, rng: &mut R) -> crate::Result<RawCellBody> {
        /// We skip this much space before adding any random padding to the
        /// end of the cell
        const MIN_SPACE_BEFORE_PADDING: usize = 4;

        // TODO: This implementation is inefficient; it copies too much.
        let encoded = self.encode_to_vec();
        let enc_len = encoded.len();
        if enc_len > CELL_DATA_LEN {
            return Err(crate::Error::InternalError(
                "too many bytes in relay cell".into(),
            ));
        }
        let mut raw = [0u8; CELL_DATA_LEN];
        raw[0..enc_len].copy_from_slice(&encoded);

        if enc_len < CELL_DATA_LEN - MIN_SPACE_BEFORE_PADDING {
            rng.fill_bytes(&mut raw[enc_len + MIN_SPACE_BEFORE_PADDING..]);
        }

        Ok(raw)
    }

    /// Consume a relay cell and return its contents, encoded for use
    /// in a RELAY or RELAY_EARLY cell
    ///
    /// TODO: not the best interface, as this requires copying into a cell.
    fn encode_to_vec(self) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_u8(self.msg.cmd().into());
        w.write_u16(0); // "Recognized"
        w.write_u16(self.streamid.0);
        w.write_u32(0); // Digest
        let len_pos = w.len();
        w.write_u16(0); // Length.
        let body_pos = w.len();
        self.msg.encode_onto(&mut w);
        assert!(w.len() >= body_pos); // nothing was removed
        let payload_len = w.len() - body_pos;
        assert!(payload_len <= std::u16::MAX as usize);
        *(array_mut_ref![w, len_pos, 2]) = (payload_len as u16).to_be_bytes();
        w
    }
    /// Parse a RELAY or RELAY_EARLY cell body into a RelayCell.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub fn decode(body: RawCellBody) -> Result<Self> {
        let mut reader = Reader::from_slice(body.as_ref());
        RelayCell::decode_from_reader(&mut reader)
    }
    /// Parse a RELAY or RELAY_EARLY cell body into a RelayCell from a reader.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cmd = r.take_u8()?.into();
        r.advance(2)?; // "recognized"
        let streamid = StreamID(r.take_u16()?);
        r.advance(4)?; // digest
        let len = r.take_u16()? as usize;
        if r.remaining() < len {
            return Err(Error::BadMessage("Insufficient data in relay cell"));
        }
        r.truncate(len);
        let msg = msg::RelayMsg::decode_from_reader(cmd, r)?;
        Ok(RelayCell { streamid, msg })
    }
}
