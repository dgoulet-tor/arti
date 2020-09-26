//! Encoding and decoding for relay messages
//!
//! Relay messages are sent along circuits, inside RELAY or RELAY_EARLY
//! cells.

use super::RelayCmd;
use super::StreamID;
use crate::chancell::msg::{TAP_C_HANDSHAKE_LEN, TAP_S_HANDSHAKE_LEN};
use crate::chancell::{RawCellBody, CELL_DATA_LEN};
use std::net::{IpAddr, Ipv4Addr};
use tor_bytes::{Error, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_linkspec::LinkSpec;
use tor_llcrypto::pk::rsa::RSAIdentity;

use arrayref::array_mut_ref;
use rand::{CryptoRng, Rng};

/// A parsed relay cell.
#[derive(Debug)]
pub struct RelayCell {
    streamid: StreamID,
    msg: RelayMsg,
}

impl RelayCell {
    /// Construct a new relay cell.
    pub fn new(streamid: StreamID, msg: RelayMsg) -> Self {
        RelayCell { streamid, msg }
    }
    /// Consume this cell and return its components.
    pub fn into_streamid_and_msg(self) -> (StreamID, RelayMsg) {
        (self.streamid, self.msg)
    }
    /// Return the command for this cell.
    pub fn get_cmd(&self) -> RelayCmd {
        self.msg.get_cmd()
    }
    /// Return the underlying message for this cell.
    pub fn get_msg(&self) -> &RelayMsg {
        &self.msg
    }
    /// Return true if this cell counts to the circuit-level sendme
    /// window.
    ///
    /// (A stream-level sendme counts towards circuit windows, but
    /// a circuit-level sendme doesn't.)
    pub fn counts_towards_circuit_windows(&self) -> bool {
        !self.streamid.is_zero() || self.msg.counts_towards_windows()
    }
    /// Consume this relay message and encode it as a 509-byte padded cell
    /// body.
    pub fn encode<R: Rng + CryptoRng>(self, rng: &mut R) -> crate::Result<RawCellBody> {
        // always this many zero-values bytes before padding.
        // XXXX We should specify this value more exactly, to avoid fingerprinting
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
        w.write_u8(self.msg.get_cmd().into());
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
        let msg = RelayMsg::decode_from_reader(cmd, r)?;
        Ok(RelayCell { streamid, msg })
    }
}

/// A single parsed relay message, sent or received along a circuit
#[derive(Debug, Clone)]
pub enum RelayMsg {
    /// Create a stream
    Begin(Begin),
    /// Send data on a stream
    Data(Data),
    /// Close a stream
    End(End),
    /// Successful response to a Begin message
    Connected(Connected),
    /// For flow control
    Sendme(Sendme),
    /// Extend a circuit to a new hop (deprecated)
    Extend(Extend),
    /// Successful response to an Extend message (deprecated)
    Extended(Extended),
    /// Extend a circuit to a new hop
    Extend2(Extend2),
    /// Successful response to an Extend2 message
    Extended2(Extended2),
    /// Partially close a circuit
    Truncate,
    /// Tell the client the a circuit has been partially closed
    Truncated(Truncated),
    /// Used for padding
    Drop,
    /// Launch a DNS request
    Resolve(Resolve),
    /// Response to a Resolve message
    Resolved(Resolved),
    /// Start a directory stream
    BeginDir,

    /// An unrecognized command.
    Unrecognized(Unrecognized),
    // No hs for now.
}

/// Internal: traits in common different cell bodies.
pub trait Body: Sized {
    /// Convert this type into a RelayMsg, wrapped appropriate.
    fn as_message(self) -> RelayMsg;
    /// Decode a relay cell body from a provided reader.
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self>;
    /// Encode the body of this cell into the end of a vec.
    fn encode_onto(self, w: &mut Vec<u8>);
}

impl<B: Body> From<B> for RelayMsg {
    fn from(b: B) -> RelayMsg {
        b.as_message()
    }
}

impl RelayMsg {
    /// Return the stream command associated with this message.
    pub fn get_cmd(&self) -> RelayCmd {
        use RelayMsg::*;
        match self {
            Begin(_) => RelayCmd::BEGIN,
            Data(_) => RelayCmd::DATA,
            End(_) => RelayCmd::END,
            Connected(_) => RelayCmd::CONNECTED,
            Sendme(_) => RelayCmd::SENDME,
            Extend(_) => RelayCmd::EXTEND,
            Extended(_) => RelayCmd::EXTENDED,
            Extend2(_) => RelayCmd::EXTEND2,
            Extended2(_) => RelayCmd::EXTENDED2,
            Truncate => RelayCmd::TRUNCATE,
            Truncated(_) => RelayCmd::TRUNCATED,
            Drop => RelayCmd::DROP,
            Resolve(_) => RelayCmd::RESOLVE,
            Resolved(_) => RelayCmd::RESOLVED,
            BeginDir => RelayCmd::BEGIN_DIR,
            Unrecognized(u) => u.get_cmd(),
        }
    }
    /// Extract the body of this message from `r`
    pub fn decode_from_reader(c: RelayCmd, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match c {
            RelayCmd::BEGIN => RelayMsg::Begin(Begin::decode_from_reader(r)?),
            RelayCmd::DATA => RelayMsg::Data(Data::decode_from_reader(r)?),
            RelayCmd::END => RelayMsg::End(End::decode_from_reader(r)?),
            RelayCmd::CONNECTED => RelayMsg::Connected(Connected::decode_from_reader(r)?),
            RelayCmd::SENDME => RelayMsg::Sendme(Sendme::decode_from_reader(r)?),
            RelayCmd::EXTEND => RelayMsg::Extend(Extend::decode_from_reader(r)?),
            RelayCmd::EXTENDED => RelayMsg::Extended(Extended::decode_from_reader(r)?),
            RelayCmd::EXTEND2 => RelayMsg::Extend2(Extend2::decode_from_reader(r)?),
            RelayCmd::EXTENDED2 => RelayMsg::Extended2(Extended2::decode_from_reader(r)?),
            RelayCmd::TRUNCATE => RelayMsg::Truncate,
            RelayCmd::TRUNCATED => RelayMsg::Truncated(Truncated::decode_from_reader(r)?),
            RelayCmd::DROP => RelayMsg::Drop,
            RelayCmd::RESOLVE => RelayMsg::Resolve(Resolve::decode_from_reader(r)?),
            RelayCmd::RESOLVED => RelayMsg::Resolved(Resolved::decode_from_reader(r)?),
            RelayCmd::BEGIN_DIR => RelayMsg::BeginDir,

            _ => RelayMsg::Unrecognized(Unrecognized::decode_with_cmd(c, r)?),
        })
    }
    /// Encode the body of this message, not including command or length
    pub fn encode_onto(self, w: &mut Vec<u8>) {
        use RelayMsg::*;
        match self {
            Begin(b) => b.encode_onto(w),
            Data(b) => b.encode_onto(w),
            End(b) => b.encode_onto(w),
            Connected(b) => b.encode_onto(w),
            Sendme(b) => b.encode_onto(w),
            Extend(b) => b.encode_onto(w),
            Extended(b) => b.encode_onto(w),
            Extend2(b) => b.encode_onto(w),
            Extended2(b) => b.encode_onto(w),
            Truncate => (),
            Truncated(b) => b.encode_onto(w),
            Drop => (),
            Resolve(b) => b.encode_onto(w),
            Resolved(b) => b.encode_onto(w),
            BeginDir => (),
            Unrecognized(b) => b.encode_onto(w),
        }
    }

    /// Return true if this message is counted by flow-control windows.
    pub fn counts_towards_windows(&self) -> bool {
        // TODO Instead of looking at !sendme, tor looks at data. We
        // should document and  make the spec conform.
        match self {
            RelayMsg::Sendme(_) => false,
            _ => true,
        }
    }
}

/// Message to create a enw stream
#[derive(Debug, Clone)]
pub struct Begin {
    addr: Vec<u8>,
    port: u16,
    flags: u32,
}
impl Begin {
    /// Construct a new Begin cell
    pub fn new(addr: &str, port: u16, flags: u32) -> crate::Result<Self> {
        if !addr.is_ascii() {
            return Err(crate::Error::BadStreamAddress);
        }
        Ok(Begin {
            addr: addr.as_bytes().into(),
            port,
            flags,
        })
    }
}

impl Body for Begin {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Begin(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.take_until(b':')?;
        let port = r.take_until(0)?;
        let flags = if r.remaining() >= 4 { r.take_u32()? } else { 0 };

        if !addr.is_ascii() {
            return Err(Error::BadMessage("target address in begin cell not ascii"));
        }

        let port = std::str::from_utf8(port)
            .map_err(|_| Error::BadMessage("port in begin cell not utf8"))?;

        let port = u16::from_str_radix(port, 10)
            .map_err(|_| Error::BadMessage("port in begin cell not a valid port"))?;

        Ok(Begin {
            addr: addr.into(),
            port,
            flags,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_all(&self.addr[..]);
        w.write_u8(b':');
        w.write_all(self.port.to_string().as_bytes());
        w.write_u8(0);
        if self.flags != 0 {
            w.write_u32(self.flags);
        }
    }
}

/// Data on a stream
#[derive(Debug, Clone)]
pub struct Data {
    body: Vec<u8>,
}
impl Data {
    /// The longest allowable body length for a single data cell.
    pub const MAXLEN: usize = CELL_DATA_LEN - 11;

    /// Construct a new data cell.
    pub fn new(inp: &[u8]) -> Self {
        // XXXX check length!
        Data { body: inp.into() }
    }
}
impl Into<Vec<u8>> for Data {
    fn into(self) -> Vec<u8> {
        self.body
    }
}
impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.body[..]
    }
}

impl Body for Data {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Data(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Data {
            body: r.take(r.remaining())?.into(),
        })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.body);
    }
}

/// Closing a stream
#[derive(Debug, Clone)]
pub struct End {
    reason: u8,
    addr: Option<(IpAddr, u32)>,
}
const REASON_MISC: u8 = 1;
const REASON_EXITPOLICY: u8 = 4;
impl End {
    /// Make a new END_REASON_MISC message.
    ///
    /// Clients send this every time they decide to close a stream.
    pub fn new_misc() -> Self {
        End {
            reason: REASON_MISC,
            addr: None,
        }
    }
    /// Make a new END message with the provided end reason.
    ///
    /// TODO: reason should be an enum-like thing.
    pub fn new_with_reason(reason: u8) -> Self {
        End { reason, addr: None }
    }
}
impl Body for End {
    fn as_message(self) -> RelayMsg {
        RelayMsg::End(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(End {
                reason: REASON_MISC,
                addr: None,
            });
        }
        let reason = r.take_u8()?;
        if reason == REASON_EXITPOLICY {
            let addr = match r.remaining() {
                8 => IpAddr::V4(r.extract()?),
                20 => IpAddr::V6(r.extract()?),
                _ => {
                    // Ignores other message lengths
                    return Ok(End { reason, addr: None });
                }
            };
            let ttl = r.take_u32()?;
            Ok(End {
                reason,
                addr: Some((addr, ttl)),
            })
        } else {
            Ok(End { reason, addr: None })
        }
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u8(self.reason);
        if self.reason == REASON_EXITPOLICY && self.addr.is_some() {
            let (addr, ttl) = self.addr.unwrap();
            match addr {
                IpAddr::V4(v4) => w.write(&v4),
                IpAddr::V6(v6) => w.write(&v6),
            }
            w.write_u32(ttl);
        }
    }
}

/// Successful response to a Begin message
#[derive(Debug, Clone)]
pub struct Connected {
    addr: Option<(IpAddr, u32)>,
}
impl Connected {
    /// Construct a new empty connected cell.
    pub fn new_empty() -> Self {
        Connected { addr: None }
    }
    /// Construct a connected cell with an address and a time-to-live value.
    pub fn new_with_addr(addr: IpAddr, ttl: u32) -> Self {
        Connected {
            addr: Some((addr, ttl)),
        }
    }
}
impl Body for Connected {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Connected(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(Connected { addr: None });
        }
        let ipv4 = r.take_u32()?;
        let addr = if ipv4 == 0 {
            if r.take_u8()? != 6 {
                return Ok(Connected { addr: None });
            }
            IpAddr::V6(r.extract()?)
        } else {
            IpAddr::V4(ipv4.into())
        };
        let ttl = r.take_u32()?;

        Ok(Connected {
            addr: Some((addr, ttl)),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        if let Some((addr, ttl)) = self.addr {
            match addr {
                IpAddr::V4(v4) => w.write(&v4),
                IpAddr::V6(v6) => {
                    w.write_u32(0);
                    w.write_u8(6);
                    w.write(&v6);
                }
            }
            w.write_u32(ttl);
        }
    }
}

/// Used for flow control to increase flow control window
#[derive(Debug, Clone)]
pub struct Sendme {
    digest: Option<Vec<u8>>,
}
impl Sendme {
    /// Return a new empty sendme cell
    ///
    /// This format is used on streams, and on circuits without sendme
    /// authentication.
    pub fn new_empty() -> Self {
        Sendme { digest: None }
    }
    /// This format is used on circuits with sendme authentication.
    pub fn new_tag(x: [u8; 20]) -> Self {
        Sendme {
            digest: Some(x.into()),
        }
    }
    /// Consume this cell and return its authentication tag, if any
    pub fn into_tag(self) -> Option<Vec<u8>> {
        self.digest
    }
}
impl Body for Sendme {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Sendme(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let digest = if r.remaining() == 0 {
            None
        } else {
            let ver = r.take_u8()?;
            match ver {
                0 => None,
                1 => {
                    let dlen = r.take_u16()?;
                    Some(r.take(dlen as usize)?.into())
                }
                _ => {
                    // XXXX is this an error?
                    None
                }
            }
        };
        Ok(Sendme { digest })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        match self.digest {
            // SPEC: we should be clear in the spec that this is what we
            // do when linkauth is off.
            None => (),
            Some(mut x) => {
                w.write_u8(1);
                w.write_u16(x.len() as u16);
                w.append(&mut x)
            }
        }
    }
}

/// Obsolete circuit extension message
#[derive(Debug, Clone)]
pub struct Extend {
    addr: Ipv4Addr,
    port: u16,
    handshake: Vec<u8>,
    rsaid: RSAIdentity,
}
impl Extend {
    /// Construct a new (deprecated) extend cell
    pub fn new(addr: Ipv4Addr, port: u16, handshake: Vec<u8>, rsaid: RSAIdentity) -> Self {
        Extend {
            addr,
            port,
            handshake,
            rsaid,
        }
    }
}
impl Body for Extend {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Extend(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.extract()?;
        let port = r.take_u16()?;
        let handshake = r.take(TAP_C_HANDSHAKE_LEN)?.into();
        let rsaid = r.extract()?;
        Ok(Extend {
            addr,
            port,
            handshake,
            rsaid,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write(&self.addr);
        w.write_u16(self.port);
        w.write_all(&self.handshake[..]);
        w.write(&self.rsaid);
    }
}

/// Obsolete circuit extension message (reply)
#[derive(Debug, Clone)]
pub struct Extended {
    handshake: Vec<u8>,
}
impl Extended {
    /// Construct a new Extended message with the provided handshake
    pub fn new(handshake: Vec<u8>) -> Self {
        Extended { handshake }
    }
}
impl Body for Extended {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Extended(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake = r.take(TAP_S_HANDSHAKE_LEN)?.into();
        Ok(Extended { handshake })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.handshake)
    }
}

/// Extend the circuit to a new hop
#[derive(Debug, Clone)]
pub struct Extend2 {
    linkspec: Vec<LinkSpec>,
    handshake_type: u16,
    handshake: Vec<u8>,
}
impl Extend2 {
    /// Create a new Extend2 cell.
    pub fn new(mut linkspec: Vec<LinkSpec>, handshake_type: u16, handshake: Vec<u8>) -> Self {
        linkspec.sort_by(|a, b| a.partial_cmp(b).unwrap());

        Extend2 {
            linkspec,
            handshake_type,
            handshake,
        }
    }
}

impl Body for Extend2 {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Extend2(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let linkspec = r.extract_n(n as usize)?;
        let handshake_type = r.take_u16()?;
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Extend2 {
            linkspec,
            handshake_type,
            handshake,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        assert!(self.linkspec.len() <= std::u8::MAX as usize);
        assert!(self.handshake.len() <= std::u16::MAX as usize);
        w.write_u8(self.linkspec.len() as u8);
        for ls in self.linkspec.iter() {
            w.write(ls);
        }
        w.write_u16(self.handshake_type);
        w.write_u16(self.handshake.len() as u16);
        w.write_all(&self.handshake[..]);
    }
}

/// Successful reply to an Extend2
#[derive(Debug, Clone)]
pub struct Extended2 {
    handshake: Vec<u8>,
}
impl Extended2 {
    /// Construct a new Extended2 message with the provided handshake
    pub fn new(handshake: Vec<u8>) -> Self {
        Extended2 { handshake }
    }
    /// Consume this extended2 cell and return its body.
    pub fn into_body(self) -> Vec<u8> {
        self.handshake
    }
}
impl Body for Extended2 {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Extended2(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?;
        Ok(Extended2 {
            handshake: handshake.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        assert!(self.handshake.len() <= std::u16::MAX as usize);
        w.write_u16(self.handshake.len() as u16);
        w.write_all(&self.handshake[..]);
    }
}

/// The remaining hops of this circuit have gone away
#[derive(Debug, Clone)]
pub struct Truncated {
    reason: u8,
}
impl Truncated {
    /// Construct a new truncated message.
    ///
    /// TODO: add an enum for reasons.
    pub fn new(reason: u8) -> Self {
        Truncated { reason }
    }
}
impl Body for Truncated {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Truncated(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Truncated {
            reason: r.take_u8()?,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u8(self.reason);
    }
}

/// Launch a DNS lookup
#[derive(Debug, Clone)]
pub struct Resolve {
    query: Vec<u8>,
}
impl Resolve {
    /// Construct a new resolve message to look up a hostname.
    pub fn new(s: &str) -> Self {
        Resolve {
            query: s.as_bytes().into(),
        }
    }
    /// Construct a new resolve message to do a reverse lookup on an address
    pub fn new_reverse(addr: &IpAddr) -> Self {
        let query = match addr {
            IpAddr::V4(v4) => {
                let [a, b, c, d] = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", d, c, b, a)
            }
            IpAddr::V6(v6) => {
                let mut s = String::with_capacity(72);
                for o in v6.octets().iter().rev() {
                    let high_nybble = o >> 4;
                    let low_nybble = o & 15;
                    s.push_str(&format!("{:x}.{:x}.", low_nybble, high_nybble));
                }
                s.push_str("ip6.arpa");
                s
            }
        };
        dbg!(&query);
        Resolve {
            query: query.into_bytes(),
        }
    }
}
impl Body for Resolve {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Resolve(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let query = r.take_until(0)?;
        Ok(Resolve {
            query: query.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_all(&self.query[..]);
        w.write_u8(0);
    }
}

/// Possible response to a DNS lookup
#[derive(Debug, Clone)]
pub enum ResolvedVal {
    /// We found an IP address
    Ip(IpAddr),
    /// We found a hostname
    Hostname(Vec<u8>),
    /// Error; try again
    TransientError,
    /// Error; don't try again
    NontransientError,
    /// A DNS lookup response that we didn't recognize
    Unrecognized(u8, Vec<u8>),
}
/// Indicates a hostname response
const RES_HOSTNAME: u8 = 0;
/// Indicates an IPv4 response
const RES_IPV4: u8 = 4;
/// Indicates an IPv6 response
const RES_IPV6: u8 = 6;
/// Transient error (okay to try again)
const RES_ERR_TRANSIENT: u8 = 0xF0;
/// Non-transient error (don't try again)
const RES_ERR_NONTRANSIENT: u8 = 0xF1;

impl Readable for ResolvedVal {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        fn res_len(tp: u8) -> Option<usize> {
            match tp {
                RES_IPV4 => Some(4),
                RES_IPV6 => Some(16),
                _ => None,
            }
        }
        let tp = r.take_u8()?;
        let len = r.take_u8()? as usize;
        if let Some(expected_len) = res_len(tp) {
            if len != expected_len {
                return Err(Error::BadMessage("Wrong length for RESOLVED answer"));
            }
        }
        use ResolvedVal::*;
        Ok(match tp {
            RES_HOSTNAME => Hostname(r.take(len)?.into()),
            RES_IPV4 => Ip(IpAddr::V4(r.extract()?)),
            RES_IPV6 => Ip(IpAddr::V6(r.extract()?)),
            RES_ERR_TRANSIENT => {
                r.advance(len)?;
                TransientError
            }
            RES_ERR_NONTRANSIENT => {
                r.advance(len)?;
                NontransientError
            }
            _ => Unrecognized(tp, r.take(len)?.into()),
        })
    }
}

impl Writeable for ResolvedVal {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) {
        use ResolvedVal::*;
        match self {
            Hostname(h) => {
                w.write_u8(RES_HOSTNAME);
                assert!(h.len() <= std::u8::MAX as usize);
                w.write_u8(h.len() as u8);
                w.write_all(&h[..]);
            }
            Ip(IpAddr::V4(a)) => {
                w.write_u8(RES_IPV4);
                w.write_u8(4); // length
                w.write(a);
            }
            Ip(IpAddr::V6(a)) => {
                w.write_u8(RES_IPV6);
                w.write_u8(16); // length
                w.write(a);
            }
            TransientError => {
                w.write_u8(RES_ERR_TRANSIENT);
                w.write_u8(0); // length
            }
            NontransientError => {
                w.write_u8(RES_ERR_NONTRANSIENT);
                w.write_u8(0); // length
            }
            Unrecognized(tp, v) => {
                w.write_u8(*tp);
                assert!(v.len() <= std::u8::MAX as usize);
                w.write_u8(v.len() as u8);
                w.write_all(&v[..]);
            }
        }
    }
}

/// Response to a Resolve message
#[derive(Debug, Clone)]
pub struct Resolved {
    answers: Vec<(ResolvedVal, u32)>,
}
impl Resolved {
    /// Return a new empty Resolved object with no answers.
    pub fn new_empty() -> Self {
        Resolved {
            answers: Vec::new(),
        }
    }
    /// Return a new Resolved object reporting a name lookup error.
    ///
    /// TODO: Is getting no answer an error; or it is represented by
    /// a list of no answers?
    pub fn new_err(transient: bool, ttl: u32) -> Self {
        let mut res = Self::new_empty();
        let err = if transient {
            ResolvedVal::TransientError
        } else {
            ResolvedVal::NontransientError
        };
        res.add_answer(err, ttl);
        res
    }
    /// Add a single answer to this Resolved message
    pub fn add_answer(&mut self, answer: ResolvedVal, ttl: u32) {
        self.answers.push((answer, ttl));
    }
}
impl Body for Resolved {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Resolved(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let mut answers = Vec::new();
        while r.remaining() > 0 {
            let rv = r.extract()?;
            let ttl = r.take_u32()?;
            answers.push((rv, ttl));
        }
        Ok(Resolved { answers })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        for (rv, ttl) in self.answers.iter() {
            w.write(rv);
            w.write_u32(*ttl);
        }
    }
}

/// A relay message that we didn't recognize
#[derive(Debug, Clone)]
pub struct Unrecognized {
    cmd: RelayCmd,
    body: Vec<u8>,
}

impl Unrecognized {
    /// Return the command associated with this message
    pub fn get_cmd(&self) -> RelayCmd {
        self.cmd
    }
    /// Decode this message, using a provided command.
    pub fn decode_with_cmd(cmd: RelayCmd, r: &mut Reader<'_>) -> Result<Self> {
        let mut r = Unrecognized::decode_from_reader(r)?;
        r.cmd = cmd;
        Ok(r)
    }
}

impl Body for Unrecognized {
    fn as_message(self) -> RelayMsg {
        RelayMsg::Unrecognized(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Unrecognized {
            cmd: 0.into(),
            body: r.take(r.remaining())?.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_all(&self.body[..])
    }
}
