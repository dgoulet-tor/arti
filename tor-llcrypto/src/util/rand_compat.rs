//! Compatibility utilities for working with libraries that consume
//! older versions of rand_core.
//!
//! The dalek-crypto libraries are currently stuck on rand_core 0.5.1,
//! but everywhere else we want to use the latest rand_core (0.6.2 as
//! of this writing).

use old_rand_core::{CryptoRng as OldCryptoRng, Error as OldError, RngCore as OldRngCore};
use rand_core::{CryptoRng, Error, RngCore};

use std::convert::TryInto;

/// Extension trait for current versions of RngCore; adds a
/// compatibility-wrappper function.
pub trait RngCompatExt: RngCore {
    /// Wrapper type returned by this trait.
    type Wrapper: RngCore + OldRngCore;
    /// Return a version of this Rng that can be used with older versions
    /// of the rand_core and rand libraries.
    fn rng_compat(self) -> Self::Wrapper;
}

impl<T: RngCore + Sized> RngCompatExt for T {
    type Wrapper = RngWrapper<T>;
    fn rng_compat(self) -> RngWrapper<Self> {
        self.into()
    }
}

/// A new-style Rng, wrapped for backward compatibility.
pub struct RngWrapper<T>(T);

impl<T: RngCore> From<T> for RngWrapper<T> {
    fn from(rng: T) -> RngWrapper<T> {
        RngWrapper(rng)
    }
}

impl<T: RngCore> OldRngCore for RngWrapper<T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), OldError> {
        self.0.try_fill_bytes(dest).map_err(err_to_old)
    }
}

impl<T: RngCore> RngCore for RngWrapper<T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<T: CryptoRng> OldCryptoRng for RngWrapper<T> {}
impl<T: CryptoRng> CryptoRng for RngWrapper<T> {}

/// Convert a new-ish Rng error into the type that rng_core 0.5.1
/// would deliver.
fn err_to_old(e: Error) -> OldError {
    use std::num::NonZeroU32;
    if let Some(code) = e.code() {
        code.into()
    } else {
        let nz: NonZeroU32 = OldError::CUSTOM_START.try_into().unwrap();
        nz.into()
    }
}
