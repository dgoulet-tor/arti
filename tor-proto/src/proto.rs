//! Implementations for Tor's cell protocols.
//!
//! These are likely to be tremendously bad; I started them first.
//!
//! I will want to refacor them a LOT before calling this interface at
//! all stable.
//!
//! Channel-level cell types are handled in the cellmsg module;
//! relay cell messages are handled in the relaymsg module.

#![allow(missing_docs)]

use caret::caret_int;
use tor_bytes::{Error, Reader, Result, Writer};

pub mod cellmsg;
pub mod relaymsg;

pub const CELL_DATA_LEN: usize = 509;

caret_int! {
    pub struct ChanCmd(u8) {
        PADDING = 0,
        CREATE = 1,
        CREATED = 2,
        RELAY = 3,
        DESTROY = 4,
        CREATE_FAST = 5,
        CREATED_FAST = 6,
        // note gap.
        NETINFO = 8,
        RELAY_EARLY = 9,
        CREATE2 = 10,
        CREATED2 = 11,
        PADDING_NEGOTIATE = 12,

        VERSIONS = 7,
        VPADDING = 128,
        CERTS = 129,
        AUTH_CHALLENGE = 130,
        AUTHENTICATE = 131,
        AUTHORIZE = 132,
    }
}

caret_int! {
    pub struct StreamCmd(u8) {
        BEGIN = 1,
        DATA = 2,
        END = 3,
        CONNECTED = 4,
        SENDME = 5,
        EXTEND = 6,
        EXTENDED = 7,
        TRUNCATE = 8,
        TRUNCATED = 9,
        DROP = 10,
        RESOLVE = 11,
        RESOLVED = 12,
        BEGIN_DIR = 13,
        EXTEND2 = 14,
        EXTENDED2 = 15,

        // hs-related
        ESTABLISH_INTRO = 32,
        ESTABLISH_RENDEZVOUS = 33,
        INTRODUCE1 = 34,
        INTRODUCE2 = 35,
        RENDEZVOUS1 = 36,
        RENDEZVOUS2 = 37,
        INTRO_ESABLISHED = 38,
        RENDEZVOUS_ESABLISHED = 39,
        INTRODUCE_ACK = 40,
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CircID(u32);

impl From<u32> for CircID {
    fn from(item: u32) -> Self {
        Self(item)
    }
}

#[derive(Clone)]
pub struct ChanCell {
    circ: CircID,
    cmd: ChanCmd,
    body: Vec<u8>,
}

pub struct CellRef<'a> {
    pub circ: CircID,
    pub cmd: ChanCmd,
    pub body: &'a [u8],
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StreamID(u16);

pub struct RelayCellRef<'a> {
    pub stream: StreamID,
    pub cmd: StreamCmd,
    pub body: &'a [u8],
}

pub struct ChannelProto {
    link_version: u16,
    relay_early_count: Option<u8>,
}

impl ChanCmd {
    pub fn is_var_cell(self) -> bool {
        self == ChanCmd::VERSIONS || self.0 >= 128u8
    }
}

impl ChannelProto {
    fn circ_id_len(&self) -> usize {
        if self.link_version >= 4 {
            4
        } else {
            2
        }
    }
    pub fn get_cell<'a>(&self, bc: &mut Reader<'a>) -> Result<CellRef<'a>> {
        let circ = if self.circ_id_len() == 4 {
            CircID(bc.take_u32()?)
        } else {
            CircID(bc.take_u16()? as u32)
        };

        let cmd = ChanCmd(bc.take_u8()?);

        let body_len = if cmd.is_var_cell() {
            bc.take_u16()? as usize
        } else {
            CELL_DATA_LEN
        };
        let body = bc.take(body_len)?;

        Ok(CellRef { circ, cmd, body })
    }
    pub fn enc_cell<'a, W: Writer>(&self, w: &mut W, cell: &CellRef<'a>) -> Result<()> {
        if self.circ_id_len() == 4 {
            w.write_u32(cell.circ.0);
        } else {
            if cell.circ.0 > std::u16::MAX as u32 {
                return Err(Error::BadMessage("XX"));
            }
            w.write_u16(cell.circ.0 as u16);
        }

        w.write_u8(cell.cmd.0);

        if cell.cmd.is_var_cell() {
            if cell.body.len() > std::u16::MAX as usize {
                return Err(Error::BadMessage("XX"));
            }
            w.write_u16(cell.body.len() as u16);
            w.write_all(cell.body);
        } else {
            if cell.body.len() > CELL_DATA_LEN {
                return Err(Error::BadMessage("XX"));
            }
            w.write_all(cell.body);
            w.write_zeros(CELL_DATA_LEN - cell.body.len());
        }
        Ok(())
    }
}

impl<'a> CellRef<'a> {
    fn to_cell(&self) -> ChanCell {
        ChanCell {
            circ: self.circ,
            cmd: self.cmd,
            body: self.body.into(),
        }
    }
    fn reader(&self) -> Reader<'_> {
        Reader::from_slice(&self.body[..])
    }
}

impl ChanCell {
    pub fn as_ref(&self) -> CellRef<'_> {
        CellRef {
            circ: self.circ,
            cmd: self.cmd,
            body: self.get_body(),
        }
    }
}

pub trait CellData: Sized {
    fn get_circid(&self) -> CircID;
    fn get_cmd(&self) -> ChanCmd;
    fn get_body(&self) -> &[u8];
}

impl CellData for ChanCell {
    fn get_circid(&self) -> CircID {
        self.circ
    }
    fn get_cmd(&self) -> ChanCmd {
        self.cmd
    }
    fn get_body(&self) -> &[u8] {
        &self.body[..]
    }
}
impl<'a> CellData for CellRef<'a> {
    fn get_circid(&self) -> CircID {
        self.circ
    }
    fn get_cmd(&self) -> ChanCmd {
        self.cmd
    }
    fn get_body(&self) -> &[u8] {
        self.body
    }
}
