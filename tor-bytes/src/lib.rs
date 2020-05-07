//! Utilities to decode/encode things into bytes.
//!
//! We use these to build and handle all the byte-encoded objects from
//! the Tor protocol.  For textual directory items, see the tor-netdoc
//! crate.
//!
//! These tools are generally unsuitable for handling anything bigger
//! than a few kilobytes in size.

// TODO: There are other crates that try the "bytes" crate that can
// handle stuff like this, but it's rather bigger than I need. This is
// for encoding stuff less than 1-2K.
//
// TODO: The "untrusted" crate is designed for parsing untrusted
// inputs in a way that can never panic.  We might want to look into
// using that as a backend instead.

mod err;
mod impls;
mod reader;
mod writer;

pub use err::Error;
pub use reader::Reader;
pub use writer::Writer;

use arrayref::array_ref;

/// Result type returned byt his crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for an object that can be encoded onto a Writer by reference.
pub trait Writeable {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B);
}

/// Trait for an object that can be encoded onto a Writer in a way that
/// consumes the original object.
pub trait WriteableOnce {
    fn write_into<B: Writer + ?Sized>(self, b: &mut B);
}

// ----------------------------------------------------------------------

/// Trait for an object that can be extracted from a Reader.
pub trait Readable: Sized {
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
