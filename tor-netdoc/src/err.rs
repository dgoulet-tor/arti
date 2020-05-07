use thiserror::Error;

use crate::policy::PolicyError;
use std::fmt;

/// A position within a directory object. Used to tell where an error
/// occurred.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Position {
    None,
    Unknown,
    Invalid(usize),
    Byte { off: usize },
    Pos { line: usize, byte: usize },
}

impl Position {
    /// Construct a Position from an offset within a slice.
    pub fn from_offset(s: &str, off: usize) -> Self {
        if off > s.len() || !s.is_char_boundary(off) {
            Position::Invalid(off)
        } else {
            let s = &s[..off];
            let last_nl = s.rfind('\n');
            match last_nl {
                Some(pos) => {
                    let newlines = s.bytes().filter(|b| *b == b'\n').count();
                    Position::Pos {
                        line: newlines + 1,
                        byte: off - pos,
                    }
                }
                None => Position::Pos { line: 1, byte: off },
            }
        }
    }
    pub fn from_byte(off: usize) -> Self {
        Position::Byte { off }
    }
    pub fn within(self, s: &str) -> Self {
        match self {
            Position::Byte { off } => Self::from_offset(s, off),
            _ => self,
        }
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Position::*;
        match self {
            None => write!(f, ""),
            Unknown => write!(f, " at unknown position"),
            Invalid(off) => write!(f, " at invalid offset at index {}", off),
            Byte { off } => write!(f, " at byte {}", off),
            Pos { line, byte } => write!(f, " on line {}, byte {}", line, byte),
        }
    }
}

#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error("internal error{0}")]
    Internal(Position),
    #[error("no keyword for entry{0}")]
    MissingKeyword(Position),
    #[error("line truncated before newline{0}")]
    TruncatedLine(Position),
    #[error("invalid keyword{0}")]
    BadKeyword(Position),
    #[error("invalid PEM BEGIN tag{0}")]
    BadObjectBeginTag(Position),
    #[error("invalid PEM END tag{0}")]
    BadObjectEndTag(Position),
    #[error("mismatched PEM tags{0}")]
    BadObjectMismatchedTag(Position),
    #[error("invalid base64 in object around byte {0}")]
    BadObjectBase64(Position),
    #[error("duplicate entry for {0}{1}")]
    DuplicateToken(&'static str, Position),
    #[error("entry {0} unexpected{1}")]
    UnexpectedToken(&'static str, Position),
    #[error("didn't find required entry {0}")]
    MissingToken(&'static str),
    #[error("too many arguments for {0}{1}")]
    TooManyArguments(&'static str, Position),
    #[error("too few arguments for {0}{1}")]
    TooFewArguments(&'static str, Position),
    #[error("unexpected object for {0}{1}")]
    UnexpectedObject(&'static str, Position),
    #[error("missing object for {0}{1}")]
    MissingObject(&'static str, Position),
    #[error("wrong object type for entry{0}")]
    WrongObject(Position),
    #[error("missing argument for entry{0}")]
    MissingArgument(Position),
    #[error("bad argument {0} for entry{1}: {2}")]
    BadArgument(usize, Position, String), // converting to a string doesn't sit well with me. XXXX
    #[error("bad object for entry{0}: {1}")]
    BadObjectVal(Position, String), // converting to a string doesn't sit well with me. XXXX
    #[error("couldn't validate signature{0}")]
    BadSignature(Position),
    #[error("couldn't parse Tor version{0}")]
    BadVersion(Position),
    #[error("invalid policy entry{0}: {1}")]
    BadPolicy(Position, #[source] PolicyError),
}

impl Error {
    pub fn within(self, s: &str) -> Error {
        use Error::*;
        match self {
            Internal(p) => Internal(p.within(s)),
            MissingKeyword(p) => MissingKeyword(p.within(s)),
            TruncatedLine(p) => TruncatedLine(p.within(s)),
            BadKeyword(p) => BadKeyword(p.within(s)),
            BadObjectBeginTag(p) => BadObjectBeginTag(p.within(s)),
            BadObjectEndTag(p) => BadObjectEndTag(p.within(s)),
            BadObjectMismatchedTag(p) => BadObjectMismatchedTag(p.within(s)),
            BadObjectBase64(p) => BadObjectBase64(p.within(s)),
            DuplicateToken(s2, p) => DuplicateToken(s2, p.within(s)),
            UnexpectedToken(s2, p) => UnexpectedToken(s2, p.within(s)),
            MissingToken(s2) => MissingToken(s2),
            TooManyArguments(s2, p) => TooManyArguments(s2, p.within(s)),
            TooFewArguments(s2, p) => TooFewArguments(s2, p.within(s)),
            UnexpectedObject(s2, p) => UnexpectedObject(s2, p.within(s)),
            MissingObject(s2, p) => MissingObject(s2, p.within(s)),
            WrongObject(p) => WrongObject(p.within(s)),
            MissingArgument(p) => MissingArgument(p.within(s)),
            BadArgument(n, p, s2) => BadArgument(n, p.within(s), s2),
            BadObjectVal(p, s2) => BadObjectVal(p.within(s), s2),
            BadSignature(p) => BadSignature(p.within(s)),
            BadVersion(p) => BadVersion(p.within(s)),
            BadPolicy(p, e) => BadPolicy(p.within(s), e),
        }
    }
}
