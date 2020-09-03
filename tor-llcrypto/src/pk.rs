//! Public-key cryptography for Tor.
//!
//! In old places, Tor uses RSA; newer Tor public-key cryptography is
//! basd on curve25519 and ed25519.

pub mod keymanip;
pub mod rsa;

/// Re-exporting Curve25519 implementations.
///
/// Eventually there should probably be a key-agreement trait or two
/// that this implements, but for now I'm just re-using the API from
/// x25519-dalek.
pub mod curve25519 {
    pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
}

/// Re-exporting Ed25519 implementations.
///
/// Eventually this should probably be replaced with a wrapper that
/// uses the ed25519 trait and the Signature trait.
pub mod ed25519 {
    pub use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature};

    /// An ed25519 signature, plus the document that it signs and its
    /// public key.
    pub struct ValidatableEd25159Signature {
        key: PublicKey,
        sig: Signature,
        // TODO: It's not so good to have this included here; it would
        // be better to have a patch to ed25519_dalek to pre-hash this.
        entire_text_of_signed_thing: Vec<u8>,
    }

    impl ValidatableEd25159Signature {
        /// Create a new ValidatableEd25519Signature
        pub fn new(key: PublicKey, sig: &[u8], text: &[u8]) -> Result<Self, signature::Error> {
            use std::convert::TryInto;
            Ok(ValidatableEd25159Signature {
                key,
                sig: sig.try_into()?,
                entire_text_of_signed_thing: text.into(),
            })
        }
    }

    impl super::ValidatableSignature for ValidatableEd25159Signature {
        fn is_valid(&self) -> bool {
            use signature::Verifier;
            self.key
                .verify(&self.entire_text_of_signed_thing[..], &self.sig)
                .is_ok()
        }
    }
}

/// Type for a validatable signature.
///
/// It necessarily includes the signature, the public key, and (a hash
/// of?) the document being checked.
pub trait ValidatableSignature {
    /// Check whether this signature is a correct signature for the document.
    fn is_valid(&self) -> bool;
}
