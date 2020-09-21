//! Implementation for parsing and encoding relay cells

use caret::caret_int;

pub mod msg;

caret_int! {
    /// A command that identifies the type of a relay cell
    pub struct RelayCmd(u8) {
        /// Start a new stream
        BEGIN = 1,
        /// Data on a stream
        DATA = 2,
        /// Close a stream
        END = 3,
        /// Acknowledge a BEGIN; stream is open
        CONNECTED = 4,
        /// Used for flow control
        SENDME = 5,
        /// Extend a circuit to a new hop; deprecated
        EXTEND = 6,
        /// Reply to EXTEND handshake; deprecated
        EXTENDED = 7,
        /// Partially close a circuit
        TRUNCATE = 8,
        /// Circuit has been partially closed
        TRUNCATED = 9,
        /// Padding cell
        DROP = 10,
        /// Start a DNS lookup
        RESOLVE = 11,
        /// Reply to a DNS lookup
        RESOLVED = 12,
        /// Start a directory stream
        BEGIN_DIR = 13,
        /// Extend a circuit to a new hop
        EXTEND2 = 14,
        /// Reply to an EXTEND2 cell.
        EXTENDED2 = 15,

        /// HS: establish an introduction point.
        ESTABLISH_INTRO = 32,
        /// HS: establish a rendezvous point.
        ESTABLISH_RENDEZVOUS = 33,
        /// HS: send introduction (client to introduction point)
        INTRODUCE1 = 34,
        /// HS: send introduction (introduction point to service)
        INTRODUCE2 = 35,
        /// HS: connect rendezvous point (service to rendezvous point)
        RENDEZVOUS1 = 36,
        /// HS: connect rendezvous point (rendezvous point to client)
        RENDEZVOUS2 = 37,
        /// HS: Response to ESTABLISH_INTRO
        INTRO_ESTABLISHED = 38,
        /// HS: Response to ESTABLISH_RENDEZVOUS
        RENDEZVOUS_ESTABLISHED = 39,
        /// HS: Response to INTRODUCE1 from introduction point to client
        INTRODUCE_ACK = 40,
    }
}

/// Possible requirements on stream IDs for a relay command.
enum StreamIDReq {
    WantZero,
    WantNonZero,
    Any,
}

impl RelayCmd {
    fn expects_streamid(self) -> StreamIDReq {
        match self {
            RelayCmd::BEGIN
            | RelayCmd::DATA
            | RelayCmd::END
            | RelayCmd::CONNECTED
            | RelayCmd::RESOLVE
            | RelayCmd::RESOLVED
            | RelayCmd::BEGIN_DIR => StreamIDReq::WantNonZero,
            RelayCmd::EXTEND
            | RelayCmd::EXTENDED
            | RelayCmd::TRUNCATE
            | RelayCmd::TRUNCATED
            | RelayCmd::DROP
            | RelayCmd::EXTEND2
            | RelayCmd::EXTENDED2
            | RelayCmd::ESTABLISH_INTRO
            | RelayCmd::ESTABLISH_RENDEZVOUS
            | RelayCmd::INTRODUCE1
            | RelayCmd::INTRODUCE2
            | RelayCmd::RENDEZVOUS1
            | RelayCmd::RENDEZVOUS2
            | RelayCmd::INTRO_ESTABLISHED
            | RelayCmd::RENDEZVOUS_ESTABLISHED
            | RelayCmd::INTRODUCE_ACK => StreamIDReq::WantZero,
            RelayCmd::SENDME => StreamIDReq::Any,
            _ => StreamIDReq::Any,
        }
    }
    /// Return true if this command is one that accepts the particular
    /// stream ID `id`
    pub fn accepts_streamid_val(self, id: StreamID) -> bool {
        match (self.expects_streamid(), id.is_zero()) {
            (StreamIDReq::WantNonZero, true) => false,
            (StreamIDReq::WantZero, false) => false,
            (_, _) => true,
        }
    }
}

/// Identify a single stream on a circuit.
///
/// These identifiers are local to each hop on a circuit
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct StreamID(u16);

impl From<u16> for StreamID {
    fn from(v: u16) -> StreamID {
        StreamID(v)
    }
}

impl Into<u16> for StreamID {
    fn into(self: StreamID) -> u16 {
        self.0
    }
}

impl std::fmt::Display for StreamID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl StreamID {
    /// Return true if this is the zero StreamID.
    ///
    /// A zero-valid circuit ID denotes a relay message that is not related to
    /// any particular stream, but which applies to the circuit as a whole.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}
