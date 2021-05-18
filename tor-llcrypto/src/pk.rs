//! Public-key cryptography for Tor.
//!
//! In old places, Tor uses RSA; newer Tor public-key cryptography is
//! basd on curve25519 and ed25519.

pub mod ed25519;
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

/// Type for a validatable signature.
///
/// It necessarily includes the signature, the public key, and (a hash
/// of?) the document being checked.
pub trait ValidatableSignature {
    /// Check whether this signature is a correct signature for the document.
    fn is_valid(&self) -> bool;

    /// Return this value as a validatable Ed25519 signature, if it is one.
    fn as_ed25519(&self) -> Option<&ed25519::ValidatableEd25519Signature> {
        None
    }
}

/// Check whether all of the signatures in this Vec are valid.
///
/// (Having a separate implementation here enables us to use
/// batch-verification when available.)
pub fn validate_all_sigs(v: &[Box<dyn ValidatableSignature>]) -> bool {
    // First we break out the ed25519 signatures (if any) so we can do
    // a batch-verification on them.
    let mut ed_sigs = Vec::new();
    let mut non_ed_sigs = Vec::new();
    for sig in v.iter() {
        match sig.as_ed25519() {
            Some(ed_sig) => ed_sigs.push(ed_sig),
            None => non_ed_sigs.push(sig),
        }
    }

    // Find out if the ed25519 batch is valid.
    let ed_batch_is_valid = crate::pk::ed25519::validate_batch(&ed_sigs[..]);

    // if so, verify the rest.
    ed_batch_is_valid && non_ed_sigs.iter().all(|b| b.is_valid())
}

#[cfg(test)]
mod test {
    #[test]
    fn validatable_ed_sig() {
        use super::ed25519::{PublicKey, Signature, ValidatableEd25519Signature};
        use super::ValidatableSignature;
        use hex_literal::hex;
        let pk = PublicKey::from_bytes(&hex!(
            "fc51cd8e6218a1a38da47ed00230f058
             0816ed13ba3303ac5deb911548908025"
        ))
        .unwrap();
        let sig: Signature = hex!(
            "6291d657deec24024827e69c3abe01a3
             0ce548a284743a445e3680d7db5ac3ac
             18ff9b538d16f290ae67f760984dc659
             4a7c15e9716ed28dc027beceea1ec40a"
        )
        .into();

        let valid = ValidatableEd25519Signature::new(pk.clone(), sig.clone(), &hex!("af82"));
        let invalid = ValidatableEd25519Signature::new(pk, sig, &hex!("af83"));

        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }
}
