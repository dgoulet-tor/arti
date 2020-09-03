//! Convenience implementation of a SelfSigned object.

use tor_llcrypto::pk::ValidatableSignature;

/// A SignatureGated object is a self-signed object that's well-signed
/// when one or more ValidatableSignature objects are correct.
pub struct SignatureGated<T> {
    obj: T,
    signatures: Vec<Box<dyn ValidatableSignature>>,
}

impl<T> SignatureGated<T> {
    /// Return a new SignatureGated object that will be treated as
    /// correct if every one if the given set of signatures is valid.
    pub fn new(obj: T, signatures: Vec<Box<dyn ValidatableSignature>>) -> Self {
        SignatureGated { obj, signatures }
    }
}

impl<T> super::SelfSigned<T> for SignatureGated<T> {
    type Error = signature::Error;
    fn dangerously_assume_wellsigned(self) -> T {
        self.obj
    }
    fn is_well_signed(&self) -> Result<(), Self::Error> {
        if self.signatures.iter().all(|b| b.is_valid()) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}
