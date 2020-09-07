//! Encoding and decoding for relay messages
//!
//! Relay messages are sent along circuits, inside RELAY or RELAY_EARLY
//! cells.

use super::StreamCmd;
use super::StreamID;
use crate::chancell::msg::{TAP_C_HANDSHAKE_LEN, TAP_S_HANDSHAKE_LEN};
use std::net::{IpAddr, Ipv4Addr};
use tor_bytes::{Error, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::rsa::RSAIdentity;

use arrayref::array_mut_ref;

/// A parsed relay cell.
pub struct RelayCell {
    streamid: StreamID,
    body: RelayMsg,
}

impl RelayCell {
    /// Consume a relay cell and return its contents, encoded for use
    /// in a RELAY or RELAY_EARLY cell
    // TODO: not the best interface
    fn encode(self) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_u8(self.body.get_cmd().into());
        w.write_u16(0); // "Recognized"
        w.write_u16(self.streamid.0);
        w.write_u32(0); // Digest
        let len_pos = w.len();
        w.write_u16(0); // Length.
        let body_pos = w.len();
        self.body.encode_onto(&mut w);
        assert!(w.len() >= body_pos); // nothing was removed
        let payload_len = w.len() - body_pos;
        assert!(payload_len <= std::u16::MAX as usize); // XXXX overflow?
        *(array_mut_ref![w, len_pos, 2]) = (payload_len as u16).to_be_bytes();
        w
    }
    /// Parse a RELAY or RELAY_EARLY cell body into a RelayCell.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    // TODO: not the best interface
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cmd = r.take_u8()?.into();
        r.advance(2)?; // "recognized"
        let streamid = StreamID(r.take_u16()?);
        r.advance(4)?; // digest
        let len = r.take_u16()? as usize;
        if r.remaining() < len {
            return Err(Error::BadMessage("XX"));
        }
        r.truncate(len);
        let body = RelayMsg::decode_from_reader(cmd, r)?;
        Ok(RelayCell { streamid, body })
    }
}

/// A single parsed relay message, sent or received along a circuit
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
    Truncate(Truncate),
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
trait Body: Sized {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self>;
    fn decode(body: Vec<u8>) -> Result<Self> {
        let mut reader = Reader::from_slice(&body[..]);
        Self::decode_from_reader(&mut reader)
    }
    fn encode_onto(self, w: &mut Vec<u8>);
}

impl RelayMsg {
    /// Return the stream command associated with this message.
    pub fn get_cmd(&self) -> StreamCmd {
        use RelayMsg::*;
        match self {
            Begin(_) => StreamCmd::BEGIN,
            Data(_) => StreamCmd::DATA,
            End(_) => StreamCmd::END,
            Connected(_) => StreamCmd::CONNECTED,
            Sendme(_) => StreamCmd::SENDME,
            Extend(_) => StreamCmd::EXTEND,
            Extended(_) => StreamCmd::EXTENDED,
            Extend2(_) => StreamCmd::EXTEND2,
            Extended2(_) => StreamCmd::EXTENDED2,
            Truncate(_) => StreamCmd::TRUNCATE,
            Truncated(_) => StreamCmd::TRUNCATED,
            Drop => StreamCmd::DROP,
            Resolve(_) => StreamCmd::RESOLVE,
            Resolved(_) => StreamCmd::RESOLVED,
            BeginDir => StreamCmd::BEGIN_DIR,
            Unrecognized(u) => u.get_cmd(),
        }
    }
    /// Extract the body of this message from `r`
    pub fn decode_from_reader(c: StreamCmd, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match c {
            StreamCmd::BEGIN => RelayMsg::Begin(Begin::decode_from_reader(r)?),
            StreamCmd::DATA => RelayMsg::Data(Data::decode_from_reader(r)?),
            StreamCmd::END => RelayMsg::End(End::decode_from_reader(r)?),
            StreamCmd::CONNECTED => RelayMsg::Connected(Connected::decode_from_reader(r)?),
            StreamCmd::SENDME => RelayMsg::Sendme(Sendme::decode_from_reader(r)?),
            StreamCmd::EXTEND => RelayMsg::Extend(Extend::decode_from_reader(r)?),
            StreamCmd::EXTENDED => RelayMsg::Extended(Extended::decode_from_reader(r)?),
            StreamCmd::EXTEND2 => RelayMsg::Extend2(Extend2::decode_from_reader(r)?),
            StreamCmd::EXTENDED2 => RelayMsg::Extended2(Extended2::decode_from_reader(r)?),
            StreamCmd::TRUNCATE => RelayMsg::Truncate(Truncate::decode_from_reader(r)?),
            StreamCmd::TRUNCATED => RelayMsg::Truncated(Truncated::decode_from_reader(r)?),
            StreamCmd::DROP => RelayMsg::Drop,
            StreamCmd::RESOLVE => RelayMsg::Resolve(Resolve::decode_from_reader(r)?),
            StreamCmd::RESOLVED => RelayMsg::Resolved(Resolved::decode_from_reader(r)?),
            StreamCmd::BEGIN_DIR => RelayMsg::BeginDir,

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
            Truncate(b) => b.encode_onto(w),
            Truncated(b) => b.encode_onto(w),
            Drop => (),
            Resolve(b) => b.encode_onto(w),
            Resolved(b) => b.encode_onto(w),
            BeginDir => (),
            Unrecognized(b) => b.encode_onto(w),
        }
    }
}

/// Message to create a enw stream
pub struct Begin {
    addr: Vec<u8>,
    port: u16,
    flags: u32,
}

impl Body for Begin {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.take_until(b':')?;
        let port = r.take_until(0)?;
        let flags = if r.remaining() >= 4 { r.take_u32()? } else { 0 };

        if !addr.is_ascii() {
            return Err(Error::BadMessage("XX"));
        }

        let port = std::str::from_utf8(port).map_err(|_| Error::BadMessage("XX"))?;

        let port = u16::from_str_radix(port, 10).map_err(|_| Error::BadMessage("XX"))?;

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
        w.write_u32(self.flags);
    }
}

/// Data on a stream
pub struct Data {
    body: Vec<u8>,
}

impl Body for Data {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Data {
            body: r.take(r.remaining())?.into(),
        })
    }
    fn decode(body: Vec<u8>) -> Result<Self> {
        Ok(Data { body })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.body);
    }
}

/// Closing a stream
pub struct End {
    reason: u8,
    addr: Option<(IpAddr, u32)>,
}
const REASON_MISC: u8 = 1;
const REASON_EXITPOLICY: u8 = 4;
impl Body for End {
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
                0 => {
                    return Ok(End { reason, addr: None });
                }
                8 => IpAddr::V4(r.extract()?),
                20 => IpAddr::V6(r.extract()?),
                _ => {
                    return Err(Error::BadMessage("XX"));
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
pub struct Connected {
    addr: Option<(IpAddr, u32)>,
}
impl Body for Connected {
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
pub struct Sendme {
    digest: Option<Vec<u8>>,
}

impl Body for Sendme {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Sendme {
            digest: Some(r.take(r.remaining())?.into()),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        match self.digest {
            None => (),
            Some(mut x) => w.append(&mut x),
        }
    }
}

/// A piece of information about a relay and how to connect to it.
///
/// TODO: move this. It's used in a bunch of other places.
#[non_exhaustive]
pub enum LinkSpec {
    /// The TCP address of an OR Port for a relay
    OrPort(IpAddr, u16),
    /// The RSA identity fingerprint of the relay
    RSAId(RSAIdentity),
    /// The Ed25519 identity of the relay
    Ed25519Id(ed25519::PublicKey),
    /// A link specifier that we didn't recognize
    Unrecognized(u8, Vec<u8>),
}

/// Indicates an IPv4 ORPORT link specifier.
const LSTYPE_ORPORT_V4: u8 = 0;
/// Indicates an IPv6 ORPORT link specifier.
const LSTYPE_ORPORT_V6: u8 = 1;
/// Indicates an RSA ID fingerprint link specifier
const LSTYPE_RSAID: u8 = 2;
/// Indicates an Ed25519 link specifier
const LSTYPE_ED25519ID: u8 = 3;

impl Readable for LinkSpec {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        fn lstype_len(tp: u8) -> Option<usize> {
            match tp {
                LSTYPE_ORPORT_V4 => Some(6),
                LSTYPE_ORPORT_V6 => Some(18),
                LSTYPE_RSAID => Some(20),
                LSTYPE_ED25519ID => Some(32),
                _ => None,
            }
        }
        let lstype = r.take_u8()?;
        let lslen = r.take_u8()? as usize;
        if let Some(wantlen) = lstype_len(lstype) {
            if wantlen != lslen {
                return Err(Error::BadMessage("XX"));
            }
        }
        Ok(match lstype {
            LSTYPE_ORPORT_V4 => {
                let addr = IpAddr::V4(r.extract()?);
                LinkSpec::OrPort(addr, r.take_u16()?)
            }
            LSTYPE_ORPORT_V6 => {
                let addr = IpAddr::V6(r.extract()?);
                LinkSpec::OrPort(addr, r.take_u16()?)
            }
            LSTYPE_RSAID => LinkSpec::RSAId(r.extract()?),
            LSTYPE_ED25519ID => LinkSpec::Ed25519Id(r.extract()?),
            _ => LinkSpec::Unrecognized(lstype, r.take(lslen)?.into()),
        })
    }
}
impl Writeable for LinkSpec {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) {
        use LinkSpec::*;
        match self {
            OrPort(IpAddr::V4(v4), port) => {
                w.write_u8(LSTYPE_ORPORT_V4);
                w.write_u8(6); // Length
                w.write(v4);
                w.write_u16(*port);
            }
            OrPort(IpAddr::V6(v6), port) => {
                w.write_u8(LSTYPE_ORPORT_V6);
                w.write_u8(18); // Length
                w.write(v6);
                w.write_u16(*port);
            }
            RSAId(r) => {
                w.write_u8(LSTYPE_RSAID);
                w.write_u8(20); // Length
                w.write(r);
            }
            Ed25519Id(e) => {
                w.write_u8(LSTYPE_ED25519ID);
                w.write_u8(32); // Length
                w.write(e);
            }
            Unrecognized(tp, vec) => {
                w.write_u8(*tp);
                w.write_u8(vec.len() as u8); // XXX overflow
                w.write_all(&vec[..]);
            }
        }
    }
}

/// Obsolete circuit extension message
pub struct Extend {
    addr: Ipv4Addr,
    port: u16,
    handshake: Vec<u8>,
    rsaid: RSAIdentity,
}

impl Body for Extend {
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
pub struct Extended {
    handshake: Vec<u8>,
}

impl Body for Extended {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake = r.take(TAP_S_HANDSHAKE_LEN)?.into();
        Ok(Extended { handshake })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.handshake)
    }
}

/// Extend the circuit to a new hop
pub struct Extend2 {
    ls: Vec<LinkSpec>,
    handshake_type: u16,
    handshake: Vec<u8>,
}

impl Body for Extend2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let ls = r.extract_n(n as usize)?;
        let handshake_type = r.take_u16()?;
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Extend2 {
            ls,
            handshake_type,
            handshake,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u8(self.ls.len() as u8); // overflow XXX
        for ls in self.ls.iter() {
            w.write(ls);
        }
        w.write_u16(self.handshake_type);
        w.write_all(&self.handshake[..]);
    }
}

/// Successful reply to an Extend2
pub struct Extended2 {
    handshake: Vec<u8>,
}

impl Body for Extended2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?;
        Ok(Extended2 {
            handshake: handshake.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u16(self.handshake.len() as u16); // XXXX overflow
        w.write_all(&self.handshake[..]);
    }
}

/// End the circuit after this hop
pub struct Truncate {}

impl Body for Truncate {
    fn decode_from_reader(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(Truncate {})
    }
    fn encode_onto(self, _w: &mut Vec<u8>) {}
}

/// The remaining hops of this circuit have gone away
pub struct Truncated {
    reason: u8,
}

impl Body for Truncated {
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
pub struct Resolve {
    query: Vec<u8>,
}

impl Body for Resolve {
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
                return Err(Error::BadMessage("XX"));
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
                w.write_u8(h.len() as u8); // XXXX overflow
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
                w.write_u8(v.len() as u8); // XXXX overflow
                w.write_all(&v[..]);
            }
        }
    }
}

/// Response to a Resolve message
pub struct Resolved {
    answers: Vec<(ResolvedVal, u32)>,
}

impl Body for Resolved {
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
pub struct Unrecognized {
    cmd: StreamCmd,
    body: Vec<u8>,
}

impl Unrecognized {
    /// Return the command associated with this message
    pub fn get_cmd(&self) -> StreamCmd {
        self.cmd
    }
    /// Decode this message, using a provided command.
    pub fn decode_with_cmd(cmd: StreamCmd, r: &mut Reader<'_>) -> Result<Self> {
        let mut r = Unrecognized::decode_from_reader(r)?;
        r.cmd = cmd;
        Ok(r)
    }
}

impl Body for Unrecognized {
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
