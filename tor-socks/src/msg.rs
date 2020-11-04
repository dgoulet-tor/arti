use crate::{Error, Result};

use caret::caret_int;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct SocksRequest {
    version: u8,
    cmd: SocksCmd,
    addr: SocksAddr,
    port: u16,
    auth: SocksAuth,
}

#[derive(Clone, Debug)]
pub enum SocksAddr {
    Hostname(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub enum SocksAuth {
    NoAuth,
    Socks4(Vec<u8>),
    Username(Vec<u8>, Vec<u8>),
}

caret_int! {
    pub struct SocksCmd(u8) {
        CONNECT = 1,
        BIND = 2,
        UDP_ASSOCIATE = 3,

        RESOLVE = 0xF0,
        RESOLVE_PTR = 0xF1,
    }
}

caret_int! {
    pub struct SocksStatus(u8) {
        SUCCEEDED = 0x00,
        GENERAL_FAILURE = 0x01,
        NOT_ALLOWED = 0x02,
        NETWORK_UNREACHABLE = 0x03,
        HOST_UNREACHABLE = 0x04,
        CONNECTION_REFUSED = 0x05,
        TTL_EXPIRED = 0x06,
        COMMAND_NOT_SUPPORTED = 0x07,
        ADDRTYPE_NOT_SUPPORTED = 0x08,
    }
}

impl SocksCmd {
    fn recognized(self) -> bool {
        match self {
            SocksCmd::CONNECT => true,
            SocksCmd::RESOLVE => true,
            SocksCmd::RESOLVE_PTR => true,
            _ => false,
        }
    }
}

impl SocksStatus {
    pub(crate) fn into_socks4_status(self) -> u8 {
        match self {
            SocksStatus::SUCCEEDED => 0x5A,
            _ => 0x5B,
        }
    }
}

impl SocksRequest {
    pub(crate) fn new(
        version: u8,
        cmd: SocksCmd,
        addr: SocksAddr,
        port: u16,
        auth: SocksAuth,
    ) -> Result<Self> {
        match version {
            4 | 5 => {}
            _ => {
                return Err(Error::NoSupport);
            }
        }
        if !cmd.recognized() {
            return Err(Error::NoSupport);
        }
        if port == 0 {
            return Err(Error::Syntax);
        }

        Ok(SocksRequest {
            version,
            cmd,
            addr,
            port,
            auth,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addr(&self) -> &SocksAddr {
        &self.addr
    }
}

impl SocksAddr {
    pub fn to_string(&self) -> String {
        match self {
            SocksAddr::Ip(a) => a.to_string(),
            SocksAddr::Hostname(h) => h.clone(),
        }
    }
}
