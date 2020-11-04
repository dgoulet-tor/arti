use crate::msg::{SocksAddr, SocksAuth, SocksCmd, SocksRequest, SocksStatus};
use crate::{Error, Result};

use tor_bytes::Error as BytesError;
use tor_bytes::Result as BytesResult;
use tor_bytes::{Readable, Reader, Writeable, Writer};

use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct SocksHandshake {
    state: State,
    socks5_auth: Option<SocksAuth>,
    handshake: Option<SocksRequest>,
}

#[derive(Clone, Debug, Copy, PartialEq)]
enum State {
    Initial,
    Socks5Username,
    Socks5Wait,
    Done,
}

#[derive(Clone, Debug)]
pub struct Action {
    pub drain: usize,
    pub reply: Vec<u8>,
    pub finished: bool,
}

impl SocksHandshake {
    pub fn new() -> Self {
        SocksHandshake {
            state: State::Initial,
            socks5_auth: None,
            handshake: None,
        }
    }

    pub fn handshake(&mut self, input: &[u8]) -> Result<Action> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        match (self.state, input[0]) {
            (State::Initial, 4) => self.s4(input),
            (State::Initial, 5) => self.s5_initial(input),
            (State::Initial, v) => Err(Error::BadProtocol(v)),
            (State::Socks5Username, 1) => self.s5_uname(input),
            (State::Socks5Wait, 5) => self.s5(input),
            (State::Done, _) => Err(Error::AlreadyFinished),
            (_, _) => Err(Error::Syntax),
        }
    }

    fn s4(&mut self, input: &[u8]) -> Result<Action> {
        let mut r = Reader::from_slice(input);
        let version = r.take_u8()?;
        assert_eq!(version, 4);

        let cmd: SocksCmd = r.take_u8()?.into();
        let port = r.take_u16()?;
        let ip = r.take_u32()?;
        let username = r.take_until(0)?.into();
        let auth = SocksAuth::Socks4(username);

        let addr = if ip != 0 && (ip >> 8) == 0 {
            // Socks4a; a hotname is given.
            let hostname = r.take_until(0)?;
            let hostname = std::str::from_utf8(hostname)
                .map_err(|_| Error::Syntax)?
                .to_string();
            SocksAddr::Hostname(hostname)
        } else {
            let ip4: std::net::Ipv4Addr = ip.into();
            SocksAddr::Ip(ip4.into())
        };

        let request = SocksRequest::new(version, cmd, addr, port, auth)?;

        self.state = State::Done;
        self.handshake = Some(request);

        Ok(Action {
            drain: r.consumed(),
            reply: Vec::new(),
            finished: true,
        })
    }

    fn s5_initial(&mut self, input: &[u8]) -> Result<Action> {
        let mut r = Reader::from_slice(input);
        let version = r.take_u8()?;
        assert_eq!(version, 5);
        const USERNAME_PASSWORD: u8 = 0x02;
        const NO_AUTHENTICATION: u8 = 0x00;

        let nmethods = r.take_u8()?;
        let methods = r.take(nmethods as usize)?;

        // Prefer username/password, then none.
        let (next, reply) = if methods.contains(&USERNAME_PASSWORD) {
            (State::Socks5Username, [5, USERNAME_PASSWORD])
        } else if methods.contains(&NO_AUTHENTICATION) {
            self.socks5_auth = Some(SocksAuth::NoAuth);
            (State::Socks5Wait, [5, NO_AUTHENTICATION])
        } else {
            // In theory we should reply with "NO ACCEPTABLE METHODS".
            return Err(Error::NoSupport);
        };

        self.state = next;
        Ok(Action {
            drain: r.consumed(),
            reply: reply.into(),
            finished: false,
        })
    }

    fn s5_uname(&mut self, input: &[u8]) -> Result<Action> {
        let mut r = Reader::from_slice(input);

        let ver = r.take_u8()?;
        if ver != 1 {
            return Err(Error::NoSupport);
        }

        let ulen = r.take_u8()?;
        let username = r.take(ulen as usize)?;
        let plen = r.take_u8()?;
        let passwd = r.take(plen as usize)?;

        self.socks5_auth = Some(SocksAuth::Username(username.into(), passwd.into()));
        self.state = State::Socks5Wait;
        Ok(Action {
            drain: r.consumed(),
            reply: vec![1, 0],
            finished: false,
        })
    }

    fn s5(&mut self, input: &[u8]) -> Result<Action> {
        let mut r = Reader::from_slice(input);

        let version = r.take_u8()?;
        if version != 5 {
            return Err(Error::Syntax);
        }
        let cmd = r.take_u8()?.into();
        let _ignore = r.take_u8()?;
        let addr = r.extract()?;
        let port = r.take_u16()?;

        let auth = self.socks5_auth.take().unwrap();

        let request = SocksRequest::new(version, cmd, addr, port, auth)?;

        self.state = State::Done;
        self.handshake = Some(request);

        Ok(Action {
            drain: r.consumed(),
            reply: Vec::new(),
            finished: true,
        })
    }

    pub fn finished(&self) -> bool {
        self.state == State::Done
    }

    pub fn into_request(self) -> Option<SocksRequest> {
        self.handshake
    }
}

impl Default for SocksHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksRequest {
    pub fn reply(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> Vec<u8> {
        match self.version() {
            4 => self.s4(status, addr),
            5 => self.s5(status, addr),
            _ => panic!(),
        }
    }

    fn s4(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_u8(0);
        w.write_u8(status.into_socks4_status());
        match addr {
            Some(SocksAddr::Ip(IpAddr::V4(ip))) => {
                w.write_u16(self.port());
                w.write(ip);
            }
            _ => {
                w.write_u16(0);
                w.write_u32(0);
            }
        }
        w
    }

    pub fn s5(&self, status: SocksStatus, addr: Option<&SocksAddr>) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_u8(5);
        w.write_u8(status.into());
        w.write_u8(0); // reserved.
        if let Some(a) = addr {
            w.write(a);
            w.write_u16(self.port());
        } else {
            // TODO: sometimes I think we want to answer with ::, not 0.0.0.0
            w.write(&SocksAddr::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()));
            w.write_u16(0);
        }
        w
    }
}

impl Readable for SocksAddr {
    fn take_from(r: &mut Reader<'_>) -> BytesResult<SocksAddr> {
        let atype = r.take_u8()?;
        match atype {
            1 => {
                let ip4: std::net::Ipv4Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip4.into()))
            }
            3 => {
                let hlen = r.take_u8()?;
                let hostname = r.take(hlen as usize)?;
                let hostname = std::str::from_utf8(hostname)
                    .map_err(|_| BytesError::BadMessage("bad utf8 on hostname"))?
                    .to_string();
                Ok(SocksAddr::Hostname(hostname))
            }
            4 => {
                let ip6: std::net::Ipv6Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip6.into()))
            }
            _ => Err(BytesError::BadMessage("unrecognized address type.")),
        }
    }
}

impl Writeable for SocksAddr {
    fn write_onto<W: Writer + ?Sized>(&self, w: &mut W) {
        match self {
            SocksAddr::Ip(IpAddr::V4(ip)) => {
                w.write_u8(1);
                w.write(ip);
            }
            SocksAddr::Ip(IpAddr::V6(ip)) => {
                w.write_u8(4);
                w.write(ip);
            }
            SocksAddr::Hostname(h) => {
                assert!(h.len() < 256); // XXXX make sure we catch this earlier!
                let hlen = h.len() as u8;
                w.write_u8(3);
                w.write_u8(hlen);
                w.write(h.as_bytes());
            }
        }
    }
}
