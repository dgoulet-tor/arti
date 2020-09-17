use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};

use tor_bytes::{Error, Readable, Reader, Result, Writeable, Writer};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::rsa::RSAIdentity;

/// A piece of information about a relay and how to connect to it.
///
/// TODO: move this. It's used in a bunch of other places.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
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
                return Err(Error::BadMessage("Wrong length for link specifier"));
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
                assert!(vec.len() < std::u8::MAX as usize);
                w.write_u8(vec.len() as u8);
                w.write_all(&vec[..]);
            }
        }
    }
}

impl From<&SocketAddr> for LinkSpec {
    fn from(sa: &SocketAddr) -> Self {
        LinkSpec::OrPort(sa.ip(), sa.port())
    }
}
impl From<RSAIdentity> for LinkSpec {
    fn from(id: RSAIdentity) -> Self {
        LinkSpec::RSAId(id)
    }
}
impl From<ed25519::PublicKey> for LinkSpec {
    fn from(id: ed25519::PublicKey) -> Self {
        LinkSpec::Ed25519Id(id)
    }
}

/// Helper for partial_cmd: return the position in the list of identifiers
/// in which a given linkspec should occur
impl LinkSpec {
    fn sort_pos(&self) -> u8 {
        use LinkSpec::*;
        match self {
            OrPort(IpAddr::V4(_), _) => 0,
            RSAId(_) => 1,
            Ed25519Id(_) => 2,
            OrPort(IpAddr::V6(_), _) => 3,
            Unrecognized(n, _) => *n,
        }
    }
}

impl PartialOrd for LinkSpec {
    fn partial_cmp(&self, other: &LinkSpec) -> Option<Ordering> {
        Some(self.sort_pos().cmp(&other.sort_pos()))
    }
}
