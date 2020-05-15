use crate::crypto::cell::{RawCellBody, CELL_BODY_LEN};
use tor_bytes::{Error, Reader, Result, Writer};

use super::{CellData, CellRef, ChanCell, ChanCmd, CircID};

use std::net::{IpAddr, Ipv4Addr};

pub struct ChannelCell {
    circid: CircID,
    body: ChannelCellBody,
}

impl ChannelCell {
    fn get_circid(&self) -> CircID {
        self.circid
    }
    fn get_cmd(&self) -> ChanCmd {
        self.body.get_cmd()
    }
    fn encode(self) -> ChanCell {
        let cmd = self.get_cmd();
        let circ = self.get_circid();
        let body = self.body.encode();
        ChanCell { cmd, circ, body }
    }
    fn decode(c: ChanCell) -> Result<Self> {
        let circid = c.get_circid();
        let cmd = c.get_cmd();
        let body = ChannelCellBody::decode(cmd, c.body)?;
        Ok(ChannelCell { circid, body })
    }
    fn decode_ref(c: &CellRef<'_>) -> Result<Self> {
        let circid = c.get_circid();
        let cmd = c.get_cmd();
        let mut r = Reader::from_slice(c.body);
        let body = ChannelCellBody::decode_from_reader(cmd, &mut r)?;
        Ok(ChannelCell { circid, body })
    }
}

#[non_exhaustive]
pub enum ChannelCellBody {
    Padding(PaddingBody),
    VPadding(VPaddingBody),
    Create(CreateBody),
    CreateFast(CreateFastBody),
    Create2(Create2Body),
    Created(CreatedBody),
    CreatedFast(CreatedFastBody),
    Created2(Created2Body),
    Relay(RelayBody),
    RelayEarly(RelayBody),
    Destroy(DestroyBody),
    Netinfo(NetinfoBody),
    Versions(VersionsBody),
    PaddingNegotiate(PaddingNegotiateBody),
    Certs(CertsBody),
    AuthChallenge(AuthChallengeBody),
    Authenticate(AuthenticateBody),
    Authorize(AuthorizeBody),
    Unrecognized(ChanCmd, UnrecognizedBody),
}

impl ChannelCellBody {
    pub fn get_cmd(&self) -> ChanCmd {
        use ChannelCellBody::*;
        match self {
            Padding(_) => ChanCmd::PADDING,
            VPadding(_) => ChanCmd::VPADDING,
            Create(_) => ChanCmd::CREATE,
            CreateFast(_) => ChanCmd::CREATE_FAST,
            Create2(_) => ChanCmd::CREATE2,
            Created(_) => ChanCmd::CREATED,
            CreatedFast(_) => ChanCmd::CREATED_FAST,
            Created2(_) => ChanCmd::CREATED2,
            Relay(_) => ChanCmd::RELAY,
            RelayEarly(_) => ChanCmd::RELAY_EARLY,
            Destroy(_) => ChanCmd::DESTROY,
            Netinfo(_) => ChanCmd::NETINFO,
            Versions(_) => ChanCmd::VERSIONS,
            PaddingNegotiate(_) => ChanCmd::PADDING_NEGOTIATE,
            Certs(_) => ChanCmd::CERTS,
            AuthChallenge(_) => ChanCmd::AUTH_CHALLENGE,
            Authenticate(_) => ChanCmd::AUTHENTICATE,
            Authorize(_) => ChanCmd::AUTHORIZE,
            Unrecognized(c, _) => *c,
        }
    }

    fn encode(self) -> Vec<u8> {
        use ChannelCellBody::*;
        match self {
            Padding(b) => b.encode(),
            VPadding(b) => b.encode(),
            Create(b) => b.encode(),
            CreateFast(b) => b.encode(),
            Create2(b) => b.encode(),
            Created(b) => b.encode(),
            CreatedFast(b) => b.encode(),
            Created2(b) => b.encode(),
            Relay(b) => b.encode(),
            RelayEarly(b) => b.encode(),
            Destroy(b) => b.encode(),
            Netinfo(b) => b.encode(),
            Versions(b) => b.encode(),
            PaddingNegotiate(b) => b.encode(),
            Certs(b) => b.encode(),
            AuthChallenge(b) => b.encode(),
            Authenticate(b) => b.encode(),
            Authorize(b) => b.encode(),
            Unrecognized(_, b) => b.encode(),
        }
    }

    fn decode(cmd: ChanCmd, b: Vec<u8>) -> Result<Self> {
        use ChannelCellBody::*;
        Ok(match cmd {
            ChanCmd::PADDING => Padding(PaddingBody::decode(b)?),
            ChanCmd::VPADDING => VPadding(VPaddingBody::decode(b)?),
            ChanCmd::CREATE => Create(CreateBody::decode(b)?),
            ChanCmd::CREATE_FAST => CreateFast(CreateFastBody::decode(b)?),
            ChanCmd::CREATE2 => Create2(Create2Body::decode(b)?),
            ChanCmd::CREATED => Created(CreatedBody::decode(b)?),
            ChanCmd::CREATED_FAST => CreatedFast(CreatedFastBody::decode(b)?),
            ChanCmd::CREATED2 => Created2(Created2Body::decode(b)?),
            ChanCmd::RELAY => Relay(RelayBody::decode(b)?),
            ChanCmd::RELAY_EARLY => RelayEarly(RelayBody::decode(b)?),
            ChanCmd::DESTROY => Destroy(DestroyBody::decode(b)?),
            ChanCmd::NETINFO => Netinfo(NetinfoBody::decode(b)?),
            ChanCmd::VERSIONS => Versions(VersionsBody::decode(b)?),
            ChanCmd::PADDING_NEGOTIATE => PaddingNegotiate(PaddingNegotiateBody::decode(b)?),
            ChanCmd::CERTS => Certs(CertsBody::decode(b)?),
            ChanCmd::AUTH_CHALLENGE => AuthChallenge(AuthChallengeBody::decode(b)?),
            ChanCmd::AUTHENTICATE => Authenticate(AuthenticateBody::decode(b)?),
            ChanCmd::AUTHORIZE => Authorize(AuthorizeBody::decode(b)?),
            _ => Unrecognized(cmd, UnrecognizedBody::decode(b)?),
        })
    }

    fn decode_from_reader(cmd: ChanCmd, r: &mut Reader<'_>) -> Result<Self> {
        use ChannelCellBody::*;
        Ok(match cmd {
            ChanCmd::PADDING => Padding(PaddingBody::decode_from_reader(r)?),
            ChanCmd::VPADDING => VPadding(VPaddingBody::decode_from_reader(r)?),
            ChanCmd::CREATE => Create(CreateBody::decode_from_reader(r)?),
            ChanCmd::CREATE_FAST => CreateFast(CreateFastBody::decode_from_reader(r)?),
            ChanCmd::CREATE2 => Create2(Create2Body::decode_from_reader(r)?),
            ChanCmd::CREATED => Created(CreatedBody::decode_from_reader(r)?),
            ChanCmd::CREATED_FAST => CreatedFast(CreatedFastBody::decode_from_reader(r)?),
            ChanCmd::CREATED2 => Created2(Created2Body::decode_from_reader(r)?),
            ChanCmd::RELAY => Relay(RelayBody::decode_from_reader(r)?),
            ChanCmd::RELAY_EARLY => RelayEarly(RelayBody::decode_from_reader(r)?),
            ChanCmd::DESTROY => Destroy(DestroyBody::decode_from_reader(r)?),
            ChanCmd::NETINFO => Netinfo(NetinfoBody::decode_from_reader(r)?),
            ChanCmd::VERSIONS => Versions(VersionsBody::decode_from_reader(r)?),
            ChanCmd::PADDING_NEGOTIATE => {
                PaddingNegotiate(PaddingNegotiateBody::decode_from_reader(r)?)
            }
            ChanCmd::CERTS => Certs(CertsBody::decode_from_reader(r)?),
            ChanCmd::AUTH_CHALLENGE => AuthChallenge(AuthChallengeBody::decode_from_reader(r)?),
            ChanCmd::AUTHENTICATE => Authenticate(AuthenticateBody::decode_from_reader(r)?),
            ChanCmd::AUTHORIZE => Authorize(AuthorizeBody::decode_from_reader(r)?),
            _ => Unrecognized(cmd, UnrecognizedBody::decode_from_reader(r)?),
        })
    }
}

trait Body: Sized {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self>;
    fn decode(body: Vec<u8>) -> Result<Self> {
        let mut reader = Reader::from_slice(&body[..]);
        Self::decode_from_reader(&mut reader)
    }
    fn encode(self) -> Vec<u8>;
}

pub struct PaddingBody {}
impl Body for PaddingBody {
    fn decode_from_reader(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(PaddingBody {})
    }
    fn encode(self) -> Vec<u8> {
        Vec::new()
    }
}

pub struct VPaddingBody {
    len: u16,
}
impl Body for VPaddingBody {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() > std::u16::MAX as usize {
            return Err(Error::BadMessage("XX"));
        }
        Ok(VPaddingBody {
            len: r.remaining() as u16,
        }) // XXXX overflow?
    }
    fn encode(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.resize(self.len as usize, 0);
        res
    }
}

// XXXX MOVE THESE
pub const TAP_C_HANDSHAKE_LEN: usize = 128 * 2 + 42;
pub const TAP_S_HANDSHAKE_LEN: usize = 128 + 20;

const FAST_C_HANDSHAKE_LEN: usize = 20;
const FAST_S_HANDSHAKE_LEN: usize = 20 * 2;

pub struct CreateBody {
    handshake: Vec<u8>,
}

impl Body for CreateBody {
    fn encode(self) -> Vec<u8> {
        self.handshake
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreateBody {
            handshake: r.take(TAP_C_HANDSHAKE_LEN)?.into(),
        })
    }
}

pub struct CreateFastBody {
    handshake: Vec<u8>,
}

impl Body for CreateFastBody {
    fn encode(self) -> Vec<u8> {
        self.handshake
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreateFastBody {
            handshake: r.take(FAST_C_HANDSHAKE_LEN)?.into(),
        })
    }
}

pub struct Create2Body {
    handshake_type: u16,
    handshake: Vec<u8>,
}

impl Body for Create2Body {
    fn encode(mut self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u16(self.handshake_type);
        body.write_u16(self.handshake.len() as u16); // XXXX overflow?
        body.append(&mut self.handshake);
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake_type = r.take_u16()?;
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Create2Body {
            handshake_type,
            handshake,
        })
    }
}

pub struct CreatedBody {
    handshake: Vec<u8>,
}
impl Body for CreatedBody {
    fn encode(self) -> Vec<u8> {
        self.handshake
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreatedBody {
            handshake: r.take(TAP_S_HANDSHAKE_LEN)?.into(),
        })
    }
}

pub struct CreatedFastBody {
    handshake: Vec<u8>,
}
impl Body for CreatedFastBody {
    fn encode(self) -> Vec<u8> {
        self.handshake
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreatedFastBody {
            handshake: r.take(FAST_S_HANDSHAKE_LEN)?.into(),
        })
    }
}

pub struct Created2Body {
    handshake: Vec<u8>,
}
impl Body for Created2Body {
    fn encode(mut self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u16(self.handshake.len() as u16); // XXX overflow?
        body.append(&mut self.handshake);
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Created2Body { handshake })
    }
}

pub struct RelayBody {
    body: Box<RawCellBody>,
}

impl Body for RelayBody {
    fn encode(self) -> Vec<u8> {
        // Avoids copy.
        (self.body as Box<[_]>).into_vec()
    }

    fn decode(body: Vec<u8>) -> Result<Self> {
        if body.len() != CELL_BODY_LEN {
            return Err(Error::BadMessage("XX"));
        }
        // Once rust has const generics this should be doable safely. XXXX
        // Till then, I'll avoid the unsafe.
        /*
        let boxed_slice = body.into_boxed_slice();
        let boxed_array = unsafe {
            Box::from_raw(Box::into_raw(boxed_slice) as *mut RawCellBody)
        };
         */
        let mut boxed_array = Box::new([0u8; CELL_BODY_LEN]);
        (&mut boxed_array[..]).copy_from_slice(&body[..]);
        Ok(RelayBody { body: boxed_array })
    }

    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Self::decode(r.take(CELL_BODY_LEN)?.into())
    }
}

pub struct DestroyBody {}
impl Body for DestroyBody {
    fn encode(self) -> Vec<u8> {
        Vec::new()
    }
    fn decode_from_reader(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(DestroyBody {})
    }
}

pub struct NetinfoBody {
    timestamp: u32,
    their_addr: IpAddr,
    my_addr: Vec<IpAddr>,
}
fn enc_one_netinfo_addr(w: &mut Vec<u8>, addr: &IpAddr) {
    match addr {
        IpAddr::V4(ipv4) => {
            w.write_u8(0x04); // type.
            w.write_u8(4); // length.
            w.write_all(&ipv4.octets()[..]);
        }
        IpAddr::V6(ipv6) => {
            w.write_u8(0x06); // type.
            w.write_u8(16); // length.
            w.write_all(&ipv6.octets()[..]);
        }
    }
}
fn take_one_netinfo_addr(r: &mut Reader<'_>) -> Result<Option<IpAddr>> {
    let atype = r.take_u8()?;
    let alen = r.take_u8()?;
    let abody = r.take(alen as usize)?;
    match (atype, alen) {
        (0x04, 4) => {
            let bytes = [abody[0], abody[1], abody[2], abody[3]];
            Ok(Some(IpAddr::V4(bytes.into())))
        }
        (0x06, 16) => {
            // XXXX is there a better way?
            let mut bytes = [0u8; 16];
            (&mut bytes[..]).copy_from_slice(abody);
            Ok(Some(IpAddr::V6(bytes.into())))
        }
        (0x04, _) => Err(Error::BadMessage("XX")),
        (0x06, _) => Err(Error::BadMessage("XX")),
        (_, _) => Ok(None),
    }
}
impl Body for NetinfoBody {
    fn encode(self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u32(self.timestamp);
        enc_one_netinfo_addr(&mut body, &self.their_addr);
        body.write_u8(self.my_addr.len() as u8); // XXXX overflow?
        for addr in self.my_addr {
            enc_one_netinfo_addr(&mut body, &addr);
        }
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let timestamp = r.take_u32()?;
        let their_addr = take_one_netinfo_addr(r)?.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let mut my_addr = Vec::new();
        let my_n_addrs = r.take_u8()?;
        for _ in 0..my_n_addrs {
            if let Some(a) = take_one_netinfo_addr(r)? {
                my_addr.push(a);
            }
        }
        Ok(NetinfoBody {
            timestamp,
            their_addr,
            my_addr,
        })
    }
}

pub struct VersionsBody {
    versions: Vec<u16>,
}
impl Body for VersionsBody {
    fn encode(self) -> Vec<u8> {
        let mut body = Vec::new();
        for v in self.versions {
            body.write_u16(v);
        }
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let mut versions = Vec::new();
        while r.remaining() > 0 {
            versions.push(r.take_u16()?);
        }
        Ok(VersionsBody { versions })
    }
}

pub struct PaddingNegotiateBody {
    command: u8,
    ito_low_ms: u16,
    ito_high_ms: u16,
}
impl Body for PaddingNegotiateBody {
    fn encode(self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u8(0); // version
        body.write_u8(self.command);
        body.write_u16(self.ito_low_ms);
        body.write_u16(self.ito_high_ms);
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let v = r.take_u8()?;
        if v != 0 {
            return Err(Error::BadMessage("XX"));
        }
        let command = r.take_u8()?;
        let ito_low_ms = r.take_u16()?;
        let ito_high_ms = r.take_u16()?;
        Ok(PaddingNegotiateBody {
            command,
            ito_low_ms,
            ito_high_ms,
        })
    }
}

struct TorCert {
    certtype: u8,
    cert: Vec<u8>,
}
fn enc_one_tor_cert(w: &mut Vec<u8>, c: &TorCert) {
    w.write_u8(c.certtype);
    w.write_u16(c.cert.len() as u16); // XXXX overflow?
    w.write_all(&c.cert[..]);
}
fn take_one_tor_cert(r: &mut Reader<'_>) -> Result<TorCert> {
    let certtype = r.take_u8()?;
    let certlen = r.take_u16()?;
    let cert = r.take(certlen as usize)?;
    Ok(TorCert {
        certtype,
        cert: cert.into(),
    })
}
pub struct CertsBody {
    certs: Vec<TorCert>,
}
impl Body for CertsBody {
    fn encode(self) -> Vec<u8> {
        // XXXX overflow.
        let mut w = Vec::new();
        w.write_u8(self.certs.len() as u8); //XXXXX overflow?
        for c in self.certs {
            enc_one_tor_cert(&mut w, &c)
        }
        w
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let mut certs = Vec::new();
        for _ in 0..n {
            certs.push(take_one_tor_cert(r)?);
        }
        Ok(CertsBody { certs })
    }
}

pub struct AuthChallengeBody {
    challenge: Vec<u8>,
    methods: Vec<u16>,
}
const CHALLENGE_LEN: usize = 32;
impl Body for AuthChallengeBody {
    fn encode(self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_all(&self.challenge[..]);
        body.write_u16(self.methods.len() as u16); // XXXXX overflow
        for m in self.methods {
            body.write_u16(m);
        }
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let challenge = r.take(CHALLENGE_LEN)?.into();
        let n_methods = r.take_u16()?;
        let mut methods = Vec::new();
        for _ in 0..n_methods {
            methods.push(r.take_u16()?);
        }
        Ok(AuthChallengeBody { challenge, methods })
    }
}

pub struct AuthenticateBody {
    authtype: u16,
    auth: Vec<u8>,
}

impl Body for AuthenticateBody {
    fn encode(self) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u16(self.authtype);
        body.write_u16(self.auth.len() as u16); // XXXX overflow
        body.write_all(&self.auth[..]);
        body
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let authtype = r.take_u16()?;
        let authlen = r.take_u16()?;
        let auth = r.take(authlen as usize)?.into();
        Ok(AuthenticateBody { authtype, auth })
    }
}

pub struct AuthorizeBody {
    content: Vec<u8>,
}

impl Body for AuthorizeBody {
    fn encode(self) -> Vec<u8> {
        self.content
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(AuthorizeBody {
            content: r.take(r.remaining())?.into(),
        })
    }
}

pub struct UnrecognizedBody {
    content: Vec<u8>,
}

impl Body for UnrecognizedBody {
    fn encode(self) -> Vec<u8> {
        self.content
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(UnrecognizedBody {
            content: r.take(r.remaining())?.into(),
        })
    }
}
