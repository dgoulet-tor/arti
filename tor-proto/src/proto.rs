use tor_bytes::{Error, Reader, Result, Writer};

pub mod cellmsg;
pub mod relaymsg;

pub const CELL_DATA_LEN: usize = 509;

type CellCmd = u8;

pub mod cellcmd {
    pub const PADDING: u8 = 0;
    pub const CREATE: u8 = 1;
    pub const CREATED: u8 = 2;
    pub const RELAY: u8 = 3;
    pub const DESTROY: u8 = 4;
    pub const CREATE_FAST: u8 = 5;
    pub const CREATED_FAST: u8 = 6;
    // note gap.
    pub const NETINFO: u8 = 8;
    pub const RELAY_EARLY: u8 = 9;
    pub const CREATE2: u8 = 10;
    pub const CREATED2: u8 = 11;
    pub const PADDING_NEGOTIATE: u8 = 12;

    pub const VERSIONS: u8 = 7;
    pub const VPADDING: u8 = 128;
    pub const CERTS: u8 = 129;
    pub const AUTH_CHALLENGE: u8 = 130;
    pub const AUTHENTICATE: u8 = 131;
    pub const AUTHORIZE: u8 = 132;
}

pub mod relaycmd {
    pub const BEGIN: u8 = 1;
    pub const DATA: u8 = 2;
    pub const END: u8 = 3;
    pub const CONNECTED: u8 = 4;
    pub const SENDME: u8 = 5;
    pub const EXTEND: u8 = 6;
    pub const EXTENDED: u8 = 7;
    pub const TRUNCATE: u8 = 8;
    pub const TRUNCATED: u8 = 9;
    pub const DROP: u8 = 10;
    pub const RESOLVE: u8 = 11;
    pub const RESOLVED: u8 = 12;
    pub const BEGIN_DIR: u8 = 13;
    pub const EXTEND2: u8 = 14;
    pub const EXTENDED2: u8 = 15;

    // hs-related
    pub const ESTABLISH_INTRO: u8 = 32;
    pub const ESTABLISH_RENDEZVOUS: u8 = 33;
    pub const INTRODUCE1: u8 = 34;
    pub const INTRODUCE2: u8 = 35;
    pub const RENDEZVOUS1: u8 = 36;
    pub const RENDEZVOUS2: u8 = 37;
    pub const INTRO_ESABLISHED: u8 = 38;
    pub const RENDEZVOUS_ESABLISHED: u8 = 39;
    pub const INTRODUCE_ACK: u8 = 40;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CircID(u32);

impl From<u32> for CircID {
    fn from(item: u32) -> Self {
        Self(item)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChanCmd(u8);

impl From<u8> for ChanCmd {
    fn from(item: u8) -> Self {
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
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StreamCmd(u8);

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
        self.0 == cellcmd::VERSIONS as u8 || self.0 >= 128
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
