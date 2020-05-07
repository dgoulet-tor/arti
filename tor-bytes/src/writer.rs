use crate::Writeable;
use crate::WriteableOnce;

/// A byte-oriented trait for writing to small arrays.
///
/// Unlike std::io::Write, this trait's methods are not allowed to
/// fail.  It's not for IO.
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
    /// Write n bytes to this buffer, all with the value zero.
    fn write_zeros(&mut self, n: usize) {
        // NOTE: This implementation is inefficient. Why do we need to
        // allocate it then copy it in?  Implementations should specialize.
        let v = vec![0u8; n];
        self.write_all(&v[..])
    }
    /// Encode a Writeable object onto this buffer, using its
    /// write_onto method.
    fn write<E: Writeable + ?Sized>(&mut self, e: &E) {
        e.write_onto(self)
    }
    /// Encode a WriteableOnce object onto this buffer, using its
    /// write_into method.
    fn write_and_consume<E: WriteableOnce>(&mut self, e: E) {
        e.write_into(self)
    }
}
