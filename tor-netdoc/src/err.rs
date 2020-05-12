//! Error type from parsing a document, and the position where it occurred
use thiserror::Error;

use crate::policy::PolicyError;
use std::fmt;

/// A position within a directory object. Used to tell where an error
/// occurred.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Position {
    /// The error did not occur at any particular position.
    ///
    /// This can happen when the error is something like a missing entry:
    /// the entry is supposed to go _somewhere_, but we can't say where.
    None,
    /// The error occurred at an unknown position.
    ///
    /// We should avoid using this case.
    Unknown,
    /// The error occurred at an invalid offset within the string, or
    /// outside the string entirely.
    ///
    /// This can only occur because of an internal error of some kind.
    Invalid(usize),
    /// The error occurred at a particular byte within the string.
    ///
    /// We try to conver these to a Pos before displaying them to the user.
    Byte {
        /// Byte offset within a string.
        off: usize,
    },
    /// The error occurred at a particular line (and possibly at a
    /// particular byte within the line.)
    Pos {
        /// Line offset within a string.
        line: usize,
        /// Byte offset within the line.
        byte: usize,
    },
}

impl Position {
    /// Construct a Position from an offset within a &str slice.
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
    /// Construct a position from a byte offset.
    pub fn from_byte(off: usize) -> Self {
        Position::Byte { off }
    }
    /// Given a position, if it was at a byte offset, convert it to a
    /// line-and-byte position within `s`.
    ///
    /// Requires that this position was actually generated from `s`.
    /// If it was not, the results here may be nonsensical.
    ///
    /// TODO: I wish I knew an efficient safe way to do this that
    /// guaranteed that we we always talking about the right string.
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

/// An error that occurred while parsing a directory object of some kind.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An internal error in the parser: these should never happen.
    #[error("internal error{0}")]
    Internal(Position), // TODO string.
    /// An entry was found with no keyword.
    #[error("no keyword for entry{0}")]
    MissingKeyword(Position),
    /// An entry was found with no newline at the end.
    #[error("line truncated before newline{0}")]
    TruncatedLine(Position),
    /// A bad string was found in the keyword position.
    #[error("invalid keyword{0}")]
    BadKeyword(Position),
    /// We found an ill-formed "BEGIN FOO" tag.
    #[error("invalid PEM BEGIN tag{0}")]
    BadObjectBeginTag(Position),
    /// We found an ill-formed "END FOO" tag.
    #[error("invalid PEM END tag{0}")]
    BadObjectEndTag(Position),
    /// We found a "BEGIN FOO" tag with an "END FOO" tag that didn't match.
    #[error("mismatched PEM tags{0}")]
    BadObjectMismatchedTag(Position),
    /// We found a base64 object with an invalid base64 encoding.
    #[error("invalid base64 in object around byte {0}")]
    BadObjectBase64(Position),
    /// The document is not supposed to contain more than one of some
    /// kind of entry, but we found one anyway.
    #[error("duplicate entry for {0}{1}")]
    DuplicateToken(&'static str, Position),
    /// The document is not supposed to contain any of some particular kind
    /// of entry, but we found one anyway.
    #[error("entry {0} unexpected{1}")]
    UnexpectedToken(&'static str, Position),
    /// The document is supposed to contain any of some particular kind
    /// of entry, but we didn't find one one anyway.
    #[error("didn't find required entry {0}")]
    MissingToken(&'static str),
    /// The document was supposed to have one of these, but not where we
    /// found it.
    #[error("found {0} out of place{1}")]
    MisplacedToken(&'static str, Position),
    /// We found more arguments on an entry than it is allowed to hav.e
    #[error("too many arguments for {0}{1}")]
    TooManyArguments(&'static str, Position),
    /// We didn't fine enough arguments for some entry.
    #[error("too few arguments for {0}{1}")]
    TooFewArguments(&'static str, Position),
    /// We found an object attached to an entry that isn't supposed to
    /// have one.
    #[error("unexpected object for {0}{1}")]
    UnexpectedObject(&'static str, Position),
    /// An entry was supposed to have an object, but it didn't.
    #[error("missing object for {0}{1}")]
    MissingObject(&'static str, Position),
    /// We found an object on an entry, but the type was wrong.
    #[error("wrong object type for entry{0}")]
    WrongObject(Position),
    /// We tried to find an argument that we were sure would be there,
    /// but it wasn't!
    ///
    /// This error should never occur in correct code; it should be
    /// caught earlier by TooFewArguments.
    #[error("missing argument for entry{0}")]
    MissingArgument(Position),
    /// We found an argument that couldn't be parsed.
    #[error("bad argument {0} for entry{1}: {2}")]
    BadArgument(usize, Position, String), // converting to a string doesn't sit well with me. XXXX
    /// We found an object that couldn't be parsed after it was decoded.
    #[error("bad object for entry{0}: {1}")]
    BadObjectVal(Position, String), // converting to a string doesn't sit well with me. XXXX
    /// There was some signature that we couldn't validate.
    #[error("couldn't validate signature{0}")]
    BadSignature(Position), // say which kind of signature. TODO
    /// There was a tor version we couldn't parse.
    #[error("couldn't parse Tor version{0}")]
    BadVersion(Position), // collapse into something else.
    /// There was an ipv4 or ipv6 policy entry that we couldn't parse.
    #[error("invalid policy entry{0}: {1}")]
    BadPolicy(Position, #[source] PolicyError),
}

impl Error {
    /// Helper: return a mutable reference to this error's position (if any)
    fn pos_mut(&mut self) -> Option<&mut Position> {
        use Error::*;
        match self {
            Internal(p) => Some(p),
            MissingKeyword(p) => Some(p),
            TruncatedLine(p) => Some(p),
            BadKeyword(p) => Some(p),
            BadObjectBeginTag(p) => Some(p),
            BadObjectEndTag(p) => Some(p),
            BadObjectMismatchedTag(p) => Some(p),
            BadObjectBase64(p) => Some(p),
            DuplicateToken(_, p) => Some(p),
            UnexpectedToken(_, p) => Some(p),
            MissingToken(_) => None,
            MisplacedToken(_, p) => Some(p),
            TooManyArguments(_, p) => Some(p),
            TooFewArguments(_, p) => Some(p),
            UnexpectedObject(_, p) => Some(p),
            MissingObject(_, p) => Some(p),
            WrongObject(p) => Some(p),
            MissingArgument(p) => Some(p),
            BadArgument(_, p, _) => Some(p),
            BadObjectVal(p, _) => Some(p),
            BadSignature(p) => Some(p),
            BadVersion(p) => Some(p),
            BadPolicy(p, _) => Some(p),
        }
    }

    /// Return a new error based on this one, with any byte-based
    /// position mapped to some line within a string.
    pub fn within(mut self, s: &str) -> Error {
        if let Some(p) = self.pos_mut() {
            *p = p.within(s);
        }
        self
    }
}
