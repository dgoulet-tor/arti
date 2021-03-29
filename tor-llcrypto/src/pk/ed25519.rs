//! Re-exporting Ed25519 implementations.
//!
//! Eventually this should probably be replaced with a wrapper that
//! uses the ed25519 trait and the Signature trait.

use arrayref::array_ref;
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Display, Formatter};
use subtle::*;
use thiserror::Error;

pub use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature};

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

/// A relay's identity, as an unchecked, unvalidated Ed25519 key.
#[derive(Clone, Copy, Hash)]
#[allow(clippy::derive_hash_xor_eq)]
pub struct Ed25519Identity {
    /// A raw unchecked Ed25519 public key.
    id: [u8; 32],
}

impl Ed25519Identity {
    /// Construct a new Ed25519 identity from a 32-byte sequence.
    ///
    /// This might or might not actually be a valid Ed25519 public key.
    ///
    /// ```
    /// use tor_llcrypto::pk::ed25519::{Ed25519Identity, PublicKey};
    /// use std::convert::TryInto;
    ///
    /// let bytes = b"klsadjfkladsfjklsdafkljasdfsdsd!";
    /// let id = Ed25519Identity::new(*bytes);
    /// let pk: Result<PublicKey,_> = (&id).try_into();
    /// assert!(pk.is_ok());
    ///
    /// let bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// let id = Ed25519Identity::new(*bytes);
    /// let pk: Result<PublicKey,_> = (&id).try_into();
    /// assert!(pk.is_err());
    /// ```
    pub fn new(id: [u8; 32]) -> Self {
        Ed25519Identity { id }
    }
    /// If `id` is of the correct length, wrap it in an Ed25519Identity.
    pub fn from_bytes(id: &[u8]) -> Option<Self> {
        if id.len() == 32 {
            Some(Ed25519Identity::new(*array_ref!(id, 0, 32)))
        } else {
            None
        }
    }
    /// Return a reference to the bytes in this key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.id[..]
    }
}

impl From<[u8; 32]> for Ed25519Identity {
    fn from(id: [u8; 32]) -> Self {
        Ed25519Identity::new(id)
    }
}

impl From<PublicKey> for Ed25519Identity {
    fn from(pk: PublicKey) -> Self {
        (&pk).into()
    }
}

impl From<&PublicKey> for Ed25519Identity {
    fn from(pk: &PublicKey) -> Self {
        // This unwrap is safe because the public key is always 32 bytes
        // long.
        Ed25519Identity::from_bytes(pk.as_bytes()).expect("Ed25519 public key had wrong length?")
    }
}

impl TryFrom<&Ed25519Identity> for PublicKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_from(id: &Ed25519Identity) -> Result<PublicKey, Self::Error> {
        PublicKey::from_bytes(&id.id[..])
    }
}

impl TryFrom<Ed25519Identity> for PublicKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_from(id: Ed25519Identity) -> Result<PublicKey, Self::Error> {
        (&id).try_into()
    }
}

impl PartialEq<Ed25519Identity> for Ed25519Identity {
    fn eq(&self, rhs: &Ed25519Identity) -> bool {
        self.id.ct_eq(&rhs.id).unwrap_u8() == 1
    }
}

impl Eq for Ed25519Identity {}

impl Display for Ed25519Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_config(self.id, base64::STANDARD_NO_PAD)
        )
    }
}

impl Debug for Ed25519Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Identity {{ {} }}", self)
    }
}

impl serde::Serialize for Ed25519Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::encode_config(self.id, base64::STANDARD_NO_PAD))
        } else {
            serializer.serialize_bytes(&self.id[..])
        }
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            /// Helper for deserialization
            struct EdIdentityVisitor;
            impl<'de> serde::de::Visitor<'de> for EdIdentityVisitor {
                type Value = Ed25519Identity;
                fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                    fmt.write_str("base64-encoded Ed25519 public key")
                }
                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let bytes =
                        base64::decode_config(s, base64::STANDARD_NO_PAD).map_err(E::custom)?;
                    Ed25519Identity::from_bytes(&bytes)
                        .ok_or_else(|| E::custom("wrong length for Ed25519 public key"))
                }
            }

            deserializer.deserialize_str(EdIdentityVisitor)
        } else {
            /// Helper for deserialization
            struct EdIdentityVisitor;
            impl<'de> serde::de::Visitor<'de> for EdIdentityVisitor {
                type Value = Ed25519Identity;
                fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                    fmt.write_str("ed25519 public key")
                }
                fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ed25519Identity::from_bytes(&bytes)
                        .ok_or_else(|| E::custom("wrong length for ed25519 public key"))
                }
            }
            deserializer.deserialize_bytes(EdIdentityVisitor)
        }
    }
}

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

/// An error during our blinding operation
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlindingError {
    /// A bad public key was provided for blinding
    #[error("Bad pubkey provided")]
    BadPubkey,
    /// Dalek failed the scalar multiplication
    #[error("Key blinding Failed")]
    BlindingFailed,
}

// Convert this dalek error to a Blinding Error
impl From<ed25519_dalek::SignatureError> for BlindingError {
    fn from(_: ed25519_dalek::SignatureError) -> BlindingError {
        BlindingError::BlindingFailed
    }
}

/// Blind the ed25519 public key 'pk' using the blinding parameter 'param' and
/// return the blinded public key.
pub fn blind_pubkey(pk: &PublicKey, mut param: [u8; 32]) -> Result<PublicKey, BlindingError> {
    // Clamp the blinding parameter
    param[0] &= 248;
    param[31] &= 63;
    param[31] |= 64;

    // Transform it into a scalar so that we can do scalar mult
    let blinding_factor = Scalar::from_bytes_mod_order(param);

    // Convert the public key to a point on the curve
    let pubkey_point = CompressedEdwardsY(pk.to_bytes())
        .decompress()
        .ok_or_else(|| BlindingError::BadPubkey)?;

    // Do the scalar multiplication and get a point back
    let blinded_pubkey_point = (blinding_factor * pubkey_point).compress();
    // Turn the point back into bytes and return it
    return Ok(PublicKey::from_bytes(&blinded_pubkey_point.0)?);
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn blinding() {
        // Test the ed25519 blinding function.
        //
        // These test vectors are from our ed25519 implementation and related
        // functions. These were automatically generated by the
        // ed25519_exts_ref.py script in little-t-tor and they are also used by
        // little-t-tor and onionbalance:
        let pubkeys = vec![
            b"c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
            b"1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
            b"081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
            b"73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
            b"66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
            b"d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
            b"c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
        ];
        let params = vec![
            "54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823",
            "831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347",
            "ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760",
            "f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc",
            "b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f",
            "81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084",
            "97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818",
            "3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ];
        let blinded_pubkeys = vec![
            "1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41",
            "1cbbd4a88ce8f165447f159d9f628ada18674158c4f7c5ead44ce8eb0fa6eb7e",
            "c5419ad133ffde7e0ac882055d942f582054132b092de377d587435722deb028",
            "3e08d0dc291066272e313014bfac4d39ad84aa93c038478a58011f431648105f",
            "59381f06acb6bf1389ba305f70874eed3e0f2ab57cdb7bc69ed59a9b8899ff4d",
            "2b946a484344eb1c17c89dd8b04196a84f3b7222c876a07a4cece85f676f87d9",
            "c6b585129b135f8769df2eba987e76e089e80ba3a2a6729134d3b28008ac098e",
            "0eefdc795b59cabbc194c6174e34ba9451e8355108520554ec285acabebb34ac",
            "312404d06a0a9de489904b18d5233e83a50b225977fa8734f2c897a73c067952",
            "952a908a4a9e0e5176a2549f8f328955aca6817a9fdc59e3acec5dec50838108",
        ];

        for i in 0..pubkeys.len() {
            let pk = PublicKey::from_bytes(&hex::decode(pubkeys[i]).unwrap()).unwrap();

            let blinded_pk = blind_pubkey(&pk, hex::decode(params[i]).unwrap().try_into().unwrap());

            assert_eq!(
                hex::encode(blinded_pk.unwrap().to_bytes()),
                blinded_pubkeys[i]
            );
        }
    }
}
