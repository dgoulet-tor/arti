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

pub mod relaymsg;

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
pub struct StreamID(u16);

pub struct RelayCellRef<'a> {
    pub stream: StreamID,
    pub cmd: StreamCmd,
    pub body: &'a [u8],
}
