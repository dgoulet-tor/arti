//! Re-exporting Ed25519 implementations.
//!
//! Eventually this should probably be replaced with a wrapper that
//! uses the ed25519 trait and the Signature trait.

pub use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature};

/// An ed25519 signature, plus the document that it signs and its
/// public key.
pub struct ValidatableEd25519Signature {
    /// The key that allegedly produced the signature
    key: PublicKey,
    /// The alleged signature
    sig: Signature,
    /// The entire body of text that is allegedly signed here.
    ///
    /// TODO: It's not so good to have this included here; it
    /// would be better to have a patch to ed25519_dalek to allow
    /// us to pre-hash the signed thing, and just store a digest.
    /// We can't use that with the 'prehash' variant of ed25519,
    /// since that has different constants.
    entire_text_of_signed_thing: Vec<u8>,
}

impl ValidatableEd25519Signature {
    /// Create a new ValidatableEd25519Signature
    pub fn new(key: PublicKey, sig: Signature, text: &[u8]) -> Self {
        ValidatableEd25519Signature {
            key,
            sig,
            entire_text_of_signed_thing: text.into(),
        }
    }

    /// View the interior of this signature object.
    pub(crate) fn as_parts(&self) -> (&PublicKey, &Signature, &[u8]) {
        (&self.key, &self.sig, &self.entire_text_of_signed_thing[..])
    }
}

impl super::ValidatableSignature for ValidatableEd25519Signature {
    fn is_valid(&self) -> bool {
        use signature::Verifier;
        self.key
            .verify(&self.entire_text_of_signed_thing[..], &self.sig)
            .is_ok()
    }

    fn as_ed25519(&self) -> Option<&ValidatableEd25519Signature> {
        Some(self)
    }
}

/// Perform a batch verification operation on the provided signatures
pub fn validate_batch(sigs: &[&ValidatableEd25519Signature]) -> bool {
    use crate::pk::ValidatableSignature;
    if sigs.is_empty() {
        true
    } else if sigs.len() == 1 {
        sigs[0].is_valid()
    } else {
        let mut ed_msgs = Vec::new();
        let mut ed_sigs = Vec::new();
        let mut ed_pks = Vec::new();
        for ed_sig in sigs {
            let (pk, sig, msg) = ed_sig.as_parts();
            ed_sigs.push(*sig);
            ed_pks.push(*pk);
            ed_msgs.push(msg);
        }
        ed25519_dalek::verify_batch(&ed_msgs[..], &ed_sigs[..], &ed_pks[..]).is_ok()
    }
}
