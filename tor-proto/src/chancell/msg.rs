/// A channel message is a decoded channel cell.
use crate::crypto::cell::{RawCellBody, CELL_BODY_LEN};
use tor_bytes::{self, Error, Readable, Reader, Result, Writer};

use super::ChanCmd;

use std::net::{IpAddr, Ipv4Addr};

pub trait ChanMsg: Readable {
    fn as_message(self) -> ChannelMessage;
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W);
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum ChannelMessage {
    Padding(Padding),
    VPadding(VPadding),
    Create(Create),
    CreateFast(CreateFast),
    Create2(Create2),
    Created(Created),
    CreatedFast(CreatedFast),
    Created2(Created2),
    Relay(Relay),
    RelayEarly(Relay),
    Destroy(Destroy),
    Netinfo(Netinfo),
    Versions(Versions),
    PaddingNegotiate(PaddingNegotiate),
    Certs(Certs),
    AuthChallenge(AuthChallenge),
    Authenticate(Authenticate),
    Authorize(Authorize),
    Unrecognized(Unrecognized),
}

impl ChannelMessage {
    pub fn get_cmd(&self) -> ChanCmd {
        use ChannelMessage::*;
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
            Unrecognized(c) => c.get_cmd(),
        }
    }
}

impl ChanMsg for ChannelMessage {
    fn as_message(self) -> Self {
        self
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        use ChannelMessage::*;
        match self {
            Padding(b) => b.write_body_onto(w),
            VPadding(b) => b.write_body_onto(w),
            Create(b) => b.write_body_onto(w),
            CreateFast(b) => b.write_body_onto(w),
            Create2(b) => b.write_body_onto(w),
            Created(b) => b.write_body_onto(w),
            CreatedFast(b) => b.write_body_onto(w),
            Created2(b) => b.write_body_onto(w),
            Relay(b) => b.write_body_onto(w),
            RelayEarly(b) => b.write_body_onto(w),
            Destroy(b) => b.write_body_onto(w),
            Netinfo(b) => b.write_body_onto(w),
            Versions(b) => b.write_body_onto(w),
            PaddingNegotiate(b) => b.write_body_onto(w),
            Certs(b) => b.write_body_onto(w),
            AuthChallenge(b) => b.write_body_onto(w),
            Authenticate(b) => b.write_body_onto(w),
            Authorize(b) => b.write_body_onto(w),
            Unrecognized(b) => b.write_body_onto(w),
        }
    }
}

impl Readable for ChannelMessage {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let cmd = r.take_u8()?.into();
        use ChannelMessage::*;
        Ok(match cmd {
            ChanCmd::PADDING => Padding(r.extract()?),
            ChanCmd::VPADDING => VPadding(r.extract()?),
            ChanCmd::CREATE => Create(r.extract()?),
            ChanCmd::CREATE_FAST => CreateFast(r.extract()?),
            ChanCmd::CREATE2 => Create2(r.extract()?),
            ChanCmd::CREATED => Created(r.extract()?),
            ChanCmd::CREATED_FAST => CreatedFast(r.extract()?),
            ChanCmd::CREATED2 => Created2(r.extract()?),
            ChanCmd::RELAY => Relay(r.extract()?),
            ChanCmd::RELAY_EARLY => RelayEarly(r.extract()?),
            ChanCmd::DESTROY => Destroy(r.extract()?),
            ChanCmd::NETINFO => Netinfo(r.extract()?),
            ChanCmd::VERSIONS => Versions(r.extract()?),
            ChanCmd::PADDING_NEGOTIATE => PaddingNegotiate(r.extract()?),
            ChanCmd::CERTS => Certs(r.extract()?),
            ChanCmd::AUTH_CHALLENGE => AuthChallenge(r.extract()?),
            ChanCmd::AUTHENTICATE => Authenticate(r.extract()?),
            ChanCmd::AUTHORIZE => Authorize(r.extract()?),
            _ => Unrecognized(unrecognized_with_cmd(cmd, r)?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Padding {}
impl ChanMsg for Padding {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Padding(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, _w: &mut W) {}
}
impl Readable for Padding {
    fn take_from(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(Padding {})
    }
}

#[derive(Clone, Debug)]
pub struct VPadding {
    len: u16,
}
impl ChanMsg for VPadding {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::VPadding(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_zeros(self.len as usize);
    }
}
impl Readable for VPadding {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() > std::u16::MAX as usize {
            return Err(Error::BadMessage("Too many bytes in VPADDING cell".into()));
        }
        Ok(VPadding {
            len: r.remaining() as u16,
        })
    }
}

macro_rules! fixed_len {
    {
        $name:ident , $cmd:ident, $len:ident
    } => {
        #[derive(Clone,Debug)]
        pub struct $name {
            handshake: Vec<u8>
        }
        impl ChanMsg for $name {
            fn as_message(self) -> ChannelMessage {
                ChannelMessage::$name(self)
            }
            fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
                w.write_all(&self.handshake[..])
            }
        }
        impl Readable for $name {
            fn take_from(r: &mut Reader<'_>) -> Result<Self> {
                Ok($name {
                    handshake: r.take($len)?.into(),
                })
            }
        }
    }
}

// XXXX MOVE THESE
pub const TAP_C_HANDSHAKE_LEN: usize = 128 * 2 + 42;
pub const TAP_S_HANDSHAKE_LEN: usize = 128 + 20;

const FAST_C_HANDSHAKE_LEN: usize = 20;
const FAST_S_HANDSHAKE_LEN: usize = 20 * 2;

fixed_len! { Create, CREATE, TAP_C_HANDSHAKE_LEN }
fixed_len! { Created, CREATED, TAP_S_HANDSHAKE_LEN }
fixed_len! { CreateFast, CREATE_FAST, FAST_C_HANDSHAKE_LEN }
fixed_len! { CreatedFast, CREATED_FAST, FAST_S_HANDSHAKE_LEN }

#[derive(Clone, Debug)]
pub struct Create2 {
    handshake_type: u16,
    handshake: Vec<u8>,
}
impl ChanMsg for Create2 {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Create2(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_u16(self.handshake_type);
        assert!(self.handshake.len() <= std::u16::MAX as usize);
        w.write_u16(self.handshake.len() as u16);
        w.write_all(&self.handshake[..]);
    }
}
impl Readable for Create2 {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let handshake_type = r.take_u16()?;
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Create2 {
            handshake_type,
            handshake,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Created2 {
    handshake: Vec<u8>,
}
impl ChanMsg for Created2 {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Created2(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        assert!(self.handshake.len() <= std::u16::MAX as usize);
        w.write_u16(self.handshake.len() as u16);
        w.write_all(&self.handshake[..]);
    }
}
impl Readable for Created2 {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Created2 { handshake })
    }
}

#[derive(Clone)]
pub struct Relay {
    body: Box<RawCellBody>,
}
impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay").finish()
    }
}
impl ChanMsg for Relay {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Relay(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_all(&self.body[..])
    }
}
impl Readable for Relay {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let mut body = Box::new([0u8; CELL_BODY_LEN]);
        (&mut body[..]).copy_from_slice(r.take(CELL_BODY_LEN)?);
        Ok(Relay { body })
    }
}

#[derive(Clone, Debug)]
pub struct Destroy {}
impl ChanMsg for Destroy {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Destroy(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, _w: &mut W) {}
}
impl Readable for Destroy {
    fn take_from(_r: &mut Reader<'_>) -> Result<Self> {
        Ok(Destroy {})
    }
}

#[derive(Clone, Debug)]
pub struct Netinfo {
    timestamp: u32,
    their_addr: IpAddr,
    my_addr: Vec<IpAddr>,
}
fn enc_one_netinfo_addr<W: Writer + ?Sized>(w: &mut W, addr: &IpAddr) {
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
        (0x04, _) => Ok(None), // ignore
        (0x06, _) => Ok(None), // ignore
        (_, _) => Ok(None),
    }
}
impl ChanMsg for Netinfo {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Netinfo(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_u32(self.timestamp);
        enc_one_netinfo_addr(w, &self.their_addr);
        w.write_u8(self.my_addr.len() as u8); // XXXX overflow?
        for addr in self.my_addr.iter() {
            enc_one_netinfo_addr(w, &addr);
        }
    }
}
impl Readable for Netinfo {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let timestamp = r.take_u32()?;
        let their_addr = take_one_netinfo_addr(r)?.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let mut my_addr = Vec::new();
        let my_n_addrs = r.take_u8()?;
        for _ in 0..my_n_addrs {
            if let Some(a) = take_one_netinfo_addr(r)? {
                my_addr.push(a);
            }
        }
        Ok(Netinfo {
            timestamp,
            their_addr,
            my_addr,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Versions {
    versions: Vec<u16>,
}
impl ChanMsg for Versions {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Versions(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        for v in self.versions.iter() {
            w.write_u16(*v);
        }
    }
}
impl Readable for Versions {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let mut versions = Vec::new();
        while r.remaining() > 0 {
            versions.push(r.take_u16()?);
        }
        Ok(Versions { versions })
    }
}

#[derive(Clone, Debug)]
pub struct PaddingNegotiate {
    command: u8,
    ito_low_ms: u16,
    ito_high_ms: u16,
}
impl ChanMsg for PaddingNegotiate {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::PaddingNegotiate(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_u8(0); // version
        w.write_u8(self.command);
        w.write_u16(self.ito_low_ms);
        w.write_u16(self.ito_high_ms);
    }
}
impl Readable for PaddingNegotiate {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let v = r.take_u8()?;
        if v != 0 {
            return Err(Error::BadMessage(
                "Unrecognized padding negotiation version",
            ));
        }
        let command = r.take_u8()?;
        let ito_low_ms = r.take_u16()?;
        let ito_high_ms = r.take_u16()?;
        Ok(PaddingNegotiate {
            command,
            ito_low_ms,
            ito_high_ms,
        })
    }
}

#[derive(Clone, Debug)]
struct TorCert {
    certtype: u8,
    cert: Vec<u8>,
}
fn enc_one_tor_cert<W: Writer + ?Sized>(w: &mut W, c: &TorCert) {
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
#[derive(Clone, Debug)]
pub struct Certs {
    certs: Vec<TorCert>,
}
impl ChanMsg for Certs {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Certs(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_u8(self.certs.len() as u8); //XXXXX overflow?
        for c in self.certs.iter() {
            enc_one_tor_cert(w, &c)
        }
    }
}
impl Readable for Certs {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let mut certs = Vec::new();
        for _ in 0..n {
            certs.push(take_one_tor_cert(r)?);
        }
        Ok(Certs { certs })
    }
}

#[derive(Clone, Debug)]
pub struct AuthChallenge {
    challenge: Vec<u8>,
    methods: Vec<u16>,
}
const CHALLENGE_LEN: usize = 32;
impl ChanMsg for AuthChallenge {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::AuthChallenge(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_all(&self.challenge[..]);
        w.write_u16(self.methods.len() as u16); // XXXXX overflow
        for m in self.methods.iter() {
            w.write_u16(*m);
        }
    }
}
impl Readable for AuthChallenge {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let challenge = r.take(CHALLENGE_LEN)?.into();
        let n_methods = r.take_u16()?;
        let mut methods = Vec::new();
        for _ in 0..n_methods {
            methods.push(r.take_u16()?);
        }
        Ok(AuthChallenge { challenge, methods })
    }
}

#[derive(Clone, Debug)]
pub struct Authenticate {
    authtype: u16,
    auth: Vec<u8>,
}
impl ChanMsg for Authenticate {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Authenticate(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_u16(self.authtype);
        w.write_u16(self.auth.len() as u16); // XXXX overflow
        w.write_all(&self.auth[..]);
    }
}
impl Readable for Authenticate {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let authtype = r.take_u16()?;
        let authlen = r.take_u16()?;
        let auth = r.take(authlen as usize)?.into();
        Ok(Authenticate { authtype, auth })
    }
}

#[derive(Clone, Debug)]
pub struct Authorize {
    content: Vec<u8>,
}
impl ChanMsg for Authorize {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Authorize(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_all(&self.content[..])
    }
}
impl Readable for Authorize {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Authorize {
            content: r.take(r.remaining())?.into(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Unrecognized {
    cmd: ChanCmd,
    content: Vec<u8>,
}
fn unrecognized_with_cmd(cmd: ChanCmd, r: &mut Reader<'_>) -> Result<Unrecognized> {
    let mut u = Unrecognized::take_from(r)?;
    u.cmd = cmd;
    Ok(u)
}
impl Unrecognized {
    fn get_cmd(&self) -> ChanCmd {
        self.cmd
    }
}
impl ChanMsg for Unrecognized {
    fn as_message(self) -> ChannelMessage {
        ChannelMessage::Unrecognized(self)
    }
    fn write_body_onto<W: Writer + ?Sized>(self, w: &mut W) {
        w.write_all(&self.content[..])
    }
}
impl Readable for Unrecognized {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Unrecognized {
            cmd: 0.into(),
            content: r.take(r.remaining())?.into(),
        })
    }
}
