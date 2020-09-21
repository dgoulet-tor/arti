//! Utilities to decode/encode things into bytes.
//!
//! We use these to build and handle all the byte-encoded objects from
//! the Tor protocol.  For textual directory items, see the tor-netdoc
//! crate.
//!
//! These tools are generally unsuitable for handling anything bigger
//! than a few kilobytes in size.
//!
//! # Alternatives
//!
//! The Reader/Writer traits in std::io are more appropriate for
//! operations that can fail because of some IO problem.  These can't;
//! they are for handling things that are already in memory.
//!
//! TODO: There are other crates that try the "bytes" crate that can
//! handle stuff like this, but it's rather bigger than I need. They
//! seem to be optimized for working with things that are split across
//! multiple chunks.
//!
//! TODO: The "untrusted" crate is designed for parsing untrusted
//! inputs in a way that can never panic.  We might want to look into
//! using that as a backend instead.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod err;
mod impls;
mod reader;
mod writer;

pub use err::Error;
pub use reader::Reader;
pub use writer::Writer;

use arrayref::array_ref;

/// Result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for an object that can be encoded onto a Writer by reference.
///
/// Implement this trait in order to make an object writeable.
///
/// Most code won't need to call this directly, but will instead use
/// it implicitly via the Writer::write() method.
///
/// # Example
///
/// ```
/// use tor_bytes::{Writeable, Writer};
/// #[derive(Debug, Eq, PartialEq)]
/// struct Message {
///   flags: u32,
///   cmd: u8
/// }
///
/// impl Writeable for Message {
///     fn write_onto<B:Writer+?Sized>(&self, b: &mut B) {
///         // We'll say that a "Message" is encoded as flags, then command.
///         b.write_u32(self.flags);
///         b.write_u8(self.cmd);
///     }
/// }
///
/// let msg = Message { flags: 0x43, cmd: 0x07 };
/// let mut writer: Vec<u8> = Vec::new();
/// writer.write(&msg);
/// assert_eq!(writer, &[0x00, 0x00, 0x00, 0x43, 0x07 ]);
/// ```
pub trait Writeable {
    /// Encode this object into the writer `b`.
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B);
}

/// Trait for an object that can be encoded and consumed by a Writer.
///
/// Implement this trait in order to make an object that can be
/// written more efficiently by absorbing it into the writer.
///
/// Most code won't need to call this directly, but will instead use
/// it implicitly via the Writer::write_and_consume() method.
pub trait WriteableOnce {
    /// Encode this object into the writer `b`, and consume it.
    fn write_into<B: Writer + ?Sized>(self, b: &mut B);
}

impl<W: Writeable> WriteableOnce for W {
    fn write_into<B: Writer + ?Sized>(self, b: &mut B) {
        self.write_onto(b);
    }
}

// ----------------------------------------------------------------------

/// Trait for an object that can be extracted from a Reader.
///
/// Implement this trait in order to make an object that can (maybe)
/// be decoded from a reader.
//
/// Most code won't need to call this directly, but will instead use
/// it implicitly via the Reader::extract() method.
///
/// # Example
///
/// ```
/// use tor_bytes::{Readable,Reader,Result};
/// #[derive(Debug, Eq, PartialEq)]
/// struct Message {
///   flags: u32,
///   cmd: u8
/// }
///
/// impl Readable for Message {
///     fn take_from(r: &mut Reader<'_>) -> Result<Self> {
///         // A "Message" is encoded as flags, then command.
///         let flags = r.take_u32()?;
///         let cmd = r.take_u8()?;
///         Ok(Message{ flags, cmd })
///     }
/// }
///
/// let encoded = [0x00, 0x00, 0x00, 0x43, 0x07 ];
/// let mut reader = Reader::from_slice(&encoded);
/// let m: Message = reader.extract()?;
/// assert_eq!(m, Message { flags: 0x43, cmd: 0x07 });
/// reader.should_be_exhausted()?; // make sure there are no bytes left over
/// # Result::Ok(())
/// ```
pub trait Readable: Sized {
    /// Try to extract an object of this type from a Reader.
    ///
    /// Implementations should generally try to be efficient: this is
    /// not the right place to check signatures or perform expensive
    /// operations.  If you have an object that must not be used until
    /// it is finally validated, consider making this function return
    /// a wrapped type that can be unwrapped later on once it gets
    /// checked.
    fn take_from(b: &mut Reader<'_>) -> Result<Self>;
}

// ----------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn writer() {
        let mut v: Vec<u8> = Vec::new();
        v.write_u8(0x57);
        v.write_u16(0x6520);
        v.write_u32(0x68617665);
        v.write_u64(0x2061206d61636869);
        v.write_all(b"ne in a plexiglass dome");
        v.write_zeros(3);
        assert_eq!(&v[..], &b"We have a machine in a plexiglass dome\0\0\0"[..]);
    }
}
