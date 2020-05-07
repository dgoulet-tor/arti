//! Digests and XOFs used to implement the Tor protocol.
//!
//! In various places, for legacy reasons, Tor uses SHA1, SHA2,
//! SHA3, and SHAKE.  We re-export them all here, implementing
//! the Digest trait.

// These implement Digest, so we can just use them as-is.
pub use sha2::{Sha256, Sha512};
pub use sha3::{Sha3_256, Shake128, Shake256};

// The Sha1 crate, OTOH, doesn't expose Digest. I'll do it myself.
/// Wrapper for Sha1 that implements the Digest trait.
#[derive(Clone, Default)]
pub struct Sha1(sha1::Sha1);

use generic_array::GenericArray;

impl digest::Digest for Sha1 {
    type OutputSize = typenum::U20;

    fn new() -> Self {
        Sha1(sha1::Sha1::new())
    }
    fn output_size() -> usize {
        sha1::DIGEST_LENGTH
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data.as_ref())
    }

    fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self {
        self.0.update(data.as_ref());
        self
    }
    fn reset(&mut self) {
        self.0.reset();
    }
    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.0.digest().bytes().into()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let res = self.0.digest().bytes();
        self.0.reset();
        res.into()
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        sha1::Sha1::from(data).digest().bytes().into()
    }
}
