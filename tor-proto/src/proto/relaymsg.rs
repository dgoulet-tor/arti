use super::StreamCmd;
use super::StreamID;
use crate::chancell::msg::{TAP_C_HANDSHAKE_LEN, TAP_S_HANDSHAKE_LEN};
use std::net::{IpAddr, Ipv4Addr};
use tor_bytes::{Error, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::rsa::RSAIdentity;

use arrayref::array_mut_ref;

pub struct RelayCell {
    streamid: StreamID,
    body: RelayCellBody,
}

impl RelayCell {
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
        let body = RelayCellBody::decode_from_reader(cmd, r)?;
        Ok(RelayCell { streamid, body })
    }
}

pub enum RelayCellBody {
    Begin(BeginCellBody),
    Data(DataCellBody),
    End(EndCellBody),
    Connected(ConnectedCellBody),
    Sendme(SendmeCellBody),
    Extend(ExtendCellBody),
    Extended(ExtendedCellBody),
    Extend2(Extend2CellBody),
    Extended2(Extended2CellBody),
    Truncate(TruncateCellBody),
    Truncated(TruncatedCellBody),
    Drop,
    Resolve(ResolveCellBody),
    Resolved(ResolvedCellBody),
    BeginDir,

    Unrecognized(StreamCmd, UnrecognizedCellBody),
    // No hs for now.
}

trait Body: Sized {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self>;
    fn decode(body: Vec<u8>) -> Result<Self> {
        let mut reader = Reader::from_slice(&body[..]);
        Self::decode_from_reader(&mut reader)
    }
    fn encode_onto(self, w: &mut Vec<u8>);
}

impl RelayCellBody {
    pub fn get_cmd(&self) -> StreamCmd {
        use RelayCellBody::*;
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
            Unrecognized(cmd, _) => *cmd,
        }
    }
    pub fn decode_from_reader(c: StreamCmd, r: &mut Reader<'_>) -> Result<Self> {
        use RelayCellBody::*;
        Ok(match c {
            StreamCmd::BEGIN => Begin(BeginCellBody::decode_from_reader(r)?),
            StreamCmd::DATA => Data(DataCellBody::decode_from_reader(r)?),
            StreamCmd::END => End(EndCellBody::decode_from_reader(r)?),
            StreamCmd::CONNECTED => Connected(ConnectedCellBody::decode_from_reader(r)?),
            StreamCmd::SENDME => Sendme(SendmeCellBody::decode_from_reader(r)?),
            StreamCmd::EXTEND => Extend(ExtendCellBody::decode_from_reader(r)?),
            StreamCmd::EXTENDED => Extended(ExtendedCellBody::decode_from_reader(r)?),
            StreamCmd::EXTEND2 => Extend2(Extend2CellBody::decode_from_reader(r)?),
            StreamCmd::EXTENDED2 => Extended2(Extended2CellBody::decode_from_reader(r)?),
            StreamCmd::TRUNCATE => Truncate(TruncateCellBody::decode_from_reader(r)?),
            StreamCmd::TRUNCATED => Truncated(TruncatedCellBody::decode_from_reader(r)?),
            StreamCmd::DROP => Drop,
            StreamCmd::RESOLVE => Resolve(ResolveCellBody::decode_from_reader(r)?),
            StreamCmd::RESOLVED => Resolved(ResolvedCellBody::decode_from_reader(r)?),
            StreamCmd::BEGIN_DIR => BeginDir,

            _ => Unrecognized(c, UnrecognizedCellBody::decode_from_reader(r)?),
        })
    }
    pub fn encode_onto(self, w: &mut Vec<u8>) {
        use RelayCellBody::*;
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
            Unrecognized(_, b) => b.encode_onto(w),
        }
    }
}

pub struct BeginCellBody {
    addr: Vec<u8>,
    port: u16,
    flags: u32,
}

impl Body for BeginCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.take_until(b':')?;
        let port = r.take_until(0)?;
        let flags = if r.remaining() >= 4 { r.take_u32()? } else { 0 };

        if !addr.is_ascii() {
            return Err(Error::BadMessage("XX"));
        }

        let port = std::str::from_utf8(port).map_err(|_| Error::BadMessage("XX"))?;

        let port = u16::from_str_radix(port, 10).map_err(|_| Error::BadMessage("XX"))?;

        Ok(BeginCellBody {
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

pub struct DataCellBody {
    body: Vec<u8>,
}

impl Body for DataCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(DataCellBody {
            body: r.take(r.remaining())?.into(),
        })
    }
    fn decode(body: Vec<u8>) -> Result<Self> {
        Ok(DataCellBody { body })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.body);
    }
}

pub struct EndCellBody {
    reason: u8,
    addr: Option<(IpAddr, u32)>,
}
const REASON_MISC: u8 = 1;
const REASON_EXITPOLICY: u8 = 4;
impl Body for EndCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(EndCellBody {
                reason: REASON_MISC,
                addr: None,
            });
        }
        let reason = r.take_u8()?;
        if reason == REASON_EXITPOLICY {
            let addr = match r.remaining() {
                0 => {
                    return Ok(EndCellBody { reason, addr: None });
                }
                8 => IpAddr::V4(r.extract()?),
                20 => IpAddr::V6(r.extract()?),
                _ => {
                    return Err(Error::BadMessage("XX"));
                }
            };
            let ttl = r.take_u32()?;
            Ok(EndCellBody {
                reason,
                addr: Some((addr, ttl)),
            })
        } else {
            Ok(EndCellBody { reason, addr: None })
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

pub struct ConnectedCellBody {
    addr: Option<(IpAddr, u32)>,
}
impl Body for ConnectedCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(ConnectedCellBody { addr: None });
        }
        let ipv4 = r.take_u32()?;
        let addr = if ipv4 == 0 {
            if r.take_u8()? != 6 {
                return Ok(ConnectedCellBody { addr: None });
            }
            IpAddr::V6(r.extract()?)
        } else {
            IpAddr::V4(ipv4.into())
        };
        let ttl = r.take_u32()?;

        Ok(ConnectedCellBody {
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

pub struct SendmeCellBody {
    digest: Option<Vec<u8>>,
}

impl Body for SendmeCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(SendmeCellBody {
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

#[non_exhaustive]
pub enum LinkSpec {
    OrPort(IpAddr, u16),
    RSAId(RSAIdentity),
    Ed25519Id(ed25519::PublicKey),
    Unrecognized(u8, Vec<u8>),
}

const LSTYPE_ORPORT_V4: u8 = 0;
const LSTYPE_ORPORT_V6: u8 = 1;
const LSTYPE_RSAID: u8 = 2;
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

pub struct ExtendCellBody {
    addr: Ipv4Addr,
    port: u16,
    handshake: Vec<u8>,
    rsaid: RSAIdentity,
}

impl Body for ExtendCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.extract()?;
        let port = r.take_u16()?;
        let handshake = r.take(TAP_C_HANDSHAKE_LEN)?.into();
        let rsaid = r.extract()?;
        Ok(ExtendCellBody {
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

pub struct ExtendedCellBody {
    handshake: Vec<u8>,
}

impl Body for ExtendedCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake = r.take(TAP_S_HANDSHAKE_LEN)?.into();
        Ok(ExtendedCellBody { handshake })
    }
    fn encode_onto(mut self, w: &mut Vec<u8>) {
        w.append(&mut self.handshake)
    }
}

pub struct Extend2CellBody {
    ls: Vec<LinkSpec>,
    handshake_type: u16,
    handshake: Vec<u8>,
}

impl Body for Extend2CellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let ls = r.extract_n(n as usize)?;
        let handshake_type = r.take_u16()?;
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Extend2CellBody {
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

pub struct Extended2CellBody {
    handshake: Vec<u8>,
}

impl Body for Extended2CellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?;
        Ok(Extended2CellBody {
            handshake: handshake.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u16(self.handshake.len() as u16); // XXXX overflow
        w.write_all(&self.handshake[..]);
    }
}

pub struct TruncateCellBody {}

impl Body for TruncateCellBody {
    fn decode_from_reader(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(TruncateCellBody {})
    }
    fn encode_onto(self, _w: &mut Vec<u8>) {}
}

pub struct TruncatedCellBody {
    reason: u8,
}

impl Body for TruncatedCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TruncatedCellBody {
            reason: r.take_u8()?,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_u8(self.reason);
    }
}

pub struct ResolveCellBody {
    query: Vec<u8>,
}

impl Body for ResolveCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let query = r.take_until(0)?;
        Ok(ResolveCellBody {
            query: query.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_all(&self.query[..]);
        w.write_u8(0);
    }
}

pub enum ResolvedVal {
    Ip(IpAddr),
    Hostname(Vec<u8>),
    TransientError,
    NontransientError,
    Unrecognized(u8, Vec<u8>),
}
const RES_HOSTNAME: u8 = 0;
const RES_IPV4: u8 = 4;
const RES_IPV6: u8 = 6;
const RES_ERR_TRANSIENT: u8 = 0xF0;
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

pub struct ResolvedCellBody {
    answers: Vec<(ResolvedVal, u32)>,
}

impl Body for ResolvedCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let mut answers = Vec::new();
        while r.remaining() > 0 {
            let rv = r.extract()?;
            let ttl = r.take_u32()?;
            answers.push((rv, ttl));
        }
        Ok(ResolvedCellBody { answers })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        for (rv, ttl) in self.answers.iter() {
            w.write(rv);
            w.write_u32(*ttl);
        }
    }
}

pub struct UnrecognizedCellBody {
    body: Vec<u8>,
}

impl Body for UnrecognizedCellBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(UnrecognizedCellBody {
            body: r.take(r.remaining())?.into(),
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) {
        w.write_all(&self.body[..])
    }
}
