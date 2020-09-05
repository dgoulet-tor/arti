//! Implementations of Writeable and Readable for several items that
//! we use in Tor.
//!
//! These don't need to be in a separate module, but for convenience
//! this is where I'm putting them.

use super::*;
use bytes;
use generic_array::GenericArray;

// ----------------------------------------------------------------------

/// Vec<u8> is the main type that implements Writer.
impl Writer for Vec<u8> {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn write_u8(&mut self, byte: u8) {
        // specialize for performance
        self.push(byte);
    }
    fn write_zeros(&mut self, n: usize) {
        // specialize for performance
        let new_len = self.len() + n;
        self.resize(new_len, 0);
    }
}

impl Writer for bytes::BytesMut {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

// ----------------------------------------------------------------------

impl<'a> Writeable for [u8] {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(self)
    }
}

impl Writeable for Vec<u8> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(&self[..])
    }
}

/* There is no specialization in Rust yet, or we would make an implementation
   for this.

impl<N> Readable for GenericArray<u8, N>
where
    N: generic_array::ArrayLength<u8>,
{
    fn take_from(b: &mut Reader) -> Result<Self> {
        // safety -- "take" returns the requested bytes or error.
        Ok(Self::from_slice(b.take(N::to_usize())?).clone())
    }
}

impl<N> Writeable for GenericArray<u8, N>
where
    N: generic_array::ArrayLength<u8>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(self.as_slice())
    }
}
*/

/// The GenericArray type is defined to work around a limitation in Rust's
/// typesystem.
impl<T, N> Readable for GenericArray<T, N>
where
    T: Readable + Clone,
    N: generic_array::ArrayLength<T>,
{
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let mut v: Vec<T> = Vec::new();
        for _ in 0..N::to_usize() {
            v.push(T::take_from(b)?);
        }
        // XXXX I wish I didn't have to clone this.
        Ok(Self::from_slice(v.as_slice()).clone())
    }
}

impl<T, N> Writeable for GenericArray<T, N>
where
    T: Writeable,
    N: generic_array::ArrayLength<T>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        for item in self {
            item.write_onto(b)
        }
    }
}

// Implementations for reading and writing the unsigned types.
macro_rules! impl_u {
    ( $t:ty, $wrfn:ident, $rdfn:ident ) => {
        impl Writeable for $t {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
                b.$wrfn(*self)
            }
        }
        impl Readable for $t {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                b.$rdfn()
            }
        }
    };
}

impl_u!(u8, write_u8, take_u8);
impl_u!(u16, write_u16, take_u16);
impl_u!(u32, write_u32, take_u32);
impl_u!(u64, write_u64, take_u64);
impl_u!(u128, write_u128, take_u128);

// ----------------------------------------------------------------------

/// Implement Readable and Writerable for IPv4 and IPv6 addresses.
///
/// These are encoded as a sequence of octets, not as strings.
mod net_impls {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl Writeable for Ipv4Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.octets()[..])
        }
    }

    impl Readable for Ipv4Addr {
        fn take_from(r: &mut Reader<'_>) -> Result<Self> {
            Ok(r.take_u32()?.into())
        }
    }

    impl Writeable for Ipv6Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.octets()[..])
        }
    }
    impl Readable for Ipv6Addr {
        fn take_from(r: &mut Reader<'_>) -> Result<Self> {
            Ok(r.take_u128()?.into())
        }
    }
}

/// Implement Readable and Writeable for Ed25519 types.
mod ed25519_impls {
    use super::*;
    use signature::Signature;
    use tor_llcrypto::pk::ed25519;

    impl Writeable for ed25519::PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for ed25519::PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(32)?;
            Self::from_bytes(array_ref![bytes, 0, 32])
                .map_err(|_| Error::BadMessage("Couldn't decode Ed25519 public key"))
        }
    }
    impl Writeable for ed25519::Signature {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.to_bytes()[..])
        }
    }
    impl Readable for ed25519::Signature {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(64)?;
            Self::from_bytes(array_ref![bytes, 0, 64])
                .map_err(|_| Error::BadMessage("Couldn't decode Ed25519 signature."))
        }
    }
}

/// Implement Readable and Writeable for Curve25519 types.
mod curve25519_impls {
    use super::*;
    use tor_llcrypto::pk::curve25519::{PublicKey, SharedSecret};

    impl Writeable for PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(32)?;
            Ok((*array_ref![bytes, 0, 32]).into())
        }
    }
    impl Writeable for SharedSecret {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
}

/// Implement readable and writeable for the the RSAIdentity type.
mod rsa_impls {
    use super::*;
    use tor_llcrypto::pk::rsa::*;

    impl Writeable for RSAIdentity {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for RSAIdentity {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let m = b.take(RSA_ID_LEN)?;
            Ok(RSAIdentity::from_bytes(m).expect("take gave wrong length"))
        }
    }
}

/// Implement readable and writeable for the crypto_mac::Output type.
mod mac_impls {
    use super::*;
    use crypto_mac::{Mac, Output};
    impl<M: Mac> WriteableOnce for Output<M> {
        fn write_into<B: Writer + ?Sized>(self, b: &mut B) {
            let code = self.into_bytes();
            b.write(&code[..])
        }
    }
    impl<M: Mac> Readable for Output<M> {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let array = GenericArray::take_from(b)?;
            Ok(Output::new(array))
        }
    }
}

/// Implement readable and writeable for common sizes of u8 arrays.
mod u8_array_impls {
    use super::*;
    macro_rules! impl_array {
        ($n:literal) => {
            impl Writeable for [u8; $n] {
                fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
                    b.write_all(&self[..])
                }
            }
            impl Readable for [u8; $n] {
                fn take_from(r: &mut Reader<'_>) -> Result<Self> {
                    let bytes = r.take($n)?;
                    Ok(array_ref!(bytes, 0, $n).clone())
                }
            }
        };
    }
    // These are the lengths we know we need right now.
    impl_array! {16}
    impl_array! {20}
    impl_array! {32}
}
