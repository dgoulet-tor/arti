use crate::Writeable;
use crate::WriteableOnce;

/// A byte-oriented trait for writing to small arrays.
///
/// Unlike std::io::Write, this trait's methods are not allowed to
/// fail.  It's not for IO.
///
/// Most code will want to use the fact that Vec<u8> implements this trait.
/// To define a new implementation, just define the write_all method.
///
/// # Examples
///
/// You can use a Writer to add bytes explicitly:
/// ```
/// use tor_bytes::Writer;
/// let mut w: Vec<u8> = Vec::new(); // Vec<u8> implements Writer.
/// w.write_u32(0x12345);
/// w.write_u8(0x22);
/// w.write_zeros(3);
/// assert_eq!(w, &[0x00, 0x01, 0x23, 0x45, 0x22, 0x00, 0x00, 0x00]);
/// ```
///
/// You can also use a Writer to encode things that implement the
/// Writeable trait:
///
/// ```
/// use tor_bytes::{Writer,Writeable};
/// let mut w: Vec<u8> = Vec::new();
/// w.write(&4u16); // The unsigned types all implement Writeable.
///
/// // We also provide Writeable implementations for several important types.
/// use std::net::Ipv4Addr;
/// let ip = Ipv4Addr::new(127, 0, 0, 1);
/// w.write(&ip);
///
/// assert_eq!(w, &[0x00, 0x04, 0x7f, 0x00, 0x00, 0x01]);
/// ```
pub trait Writer {
    /// Append a slice to the end of this writer.
    fn write_all(&mut self, b: &[u8]);

    /// Append a single u8 to this writer.
    fn write_u8(&mut self, x: u8) {
        self.write_all(&[x])
    }
    /// Append a single u16 to this writer, encoded in big-endian order.
    fn write_u16(&mut self, x: u16) {
        self.write_all(&x.to_be_bytes())
    }
    /// Append a single u32 to this writer, encoded in big-endian order.
    fn write_u32(&mut self, x: u32) {
        self.write_all(&x.to_be_bytes())
    }
    /// Append a single u64 to this writer, encoded in big-endian order.
    fn write_u64(&mut self, x: u64) {
        self.write_all(&x.to_be_bytes())
    }
    /// Append a single u128 to this writer, encoded in big-endian order.
    fn write_u128(&mut self, x: u128) {
        self.write_all(&x.to_be_bytes())
    }
    /// Write n bytes to this writer, all with the value zero.
    ///
    /// NOTE: This implementation is somewhat inefficient, since it allocates
    /// a vector.  You should probably replace it if you can.
    fn write_zeros(&mut self, n: usize) {
        let v = vec![0u8; n];
        self.write_all(&v[..])
    }
    /// Encode a Writeable object onto this writer, using its
    /// write_onto method.
    fn write<E: Writeable + ?Sized>(&mut self, e: &E) {
        e.write_onto(self)
    }
    /// Encode a WriteableOnce object onto this writer, using its
    /// write_into method.
    fn write_and_consume<E: WriteableOnce>(&mut self, e: E) {
        e.write_into(self)
    }
}
