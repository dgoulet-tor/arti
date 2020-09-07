//! Re-exporting RSA implementations.
//!
//! This module can currently handle public keys and signature
//! verification used in the Tor directory protocol and
//! similar places.
//!
//! Currently, that means supporting validating PKCSv1
//! signatures, and encoding and decoding keys from DER.
//!
//! Currently missing is signing and RSA-OEAP.
use arrayref::array_ref;
use subtle::*;
use zeroize::Zeroize;
use std::fmt;
use hex;

/// How many bytes are in an "RSA ID"?  (This is a legacy tor
/// concept, and refers to identifying a relay by a SHA1 digest
/// of its public key.)
pub const RSA_ID_LEN: usize = 20;

/// An identifier for a Tor relay, based on its legacy RSA
/// identity key.  These are used all over the Tor protocol.
#[derive(Clone, Zeroize)]
pub struct RSAIdentity {
    id: [u8; RSA_ID_LEN],
}

impl PartialEq<RSAIdentity> for RSAIdentity {
    fn eq(&self, rhs: &RSAIdentity) -> bool {
        self.id.ct_eq(&rhs.id).unwrap_u8() == 1
    }
}

impl std::hash::Hash for RSAIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Eq for RSAIdentity {}

impl fmt::Display for RSAIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}", hex::encode(&self.id[..]))
    }
}
impl fmt::Debug for RSAIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RSAIdentity {{ ${} }}", hex::encode(&self.id[..]))
    }
}

impl RSAIdentity {
    /// Expose and RSAIdentity as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.id[..]
    }
    /// Construct an RSAIdentity from a slice of bytes.
    ///
    /// Returns None if the input is not of the correct length.
    ///
    /// ```
    /// use tor_llcrypto::pk::rsa::RSAIdentity;
    ///
    /// let bytes = b"xyzzyxyzzyxyzzyxyzzy";
    /// let id = RSAIdentity::from_bytes(bytes);
    /// assert_eq!(id.unwrap().as_bytes(), bytes);
    ///
    /// let truncated = b"xyzzy";
    /// let id = RSAIdentity::from_bytes(truncated);
    /// assert_eq!(id, None);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == RSA_ID_LEN {
            Some(RSAIdentity {
                id: *array_ref![bytes, 0, RSA_ID_LEN],
            })
        } else {
            None
        }
    }
}

/// An RSA public key.
///
/// This implementation is a simple wrapper so that we can define new
/// methods and traits on the type.
#[derive(Clone)]
pub struct PublicKey(rsa::RSAPublicKey);
/// An RSA private key.
pub struct PrivateKey(rsa::RSAPrivateKey);

impl PrivateKey {
    /// Return the public component of this key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.to_public_key())
    }
    // ....
}
impl PublicKey {
    /// Return true iff the exponent for this key is the same
    /// number as 'e'.
    pub fn exponent_is(&self, e: u32) -> bool {
        use rsa::PublicKeyParts;
        *self.0.e() == rsa::BigUint::new(vec![e])
    }
    /// Return the number of bits in the modulus for this key.
    pub fn bits(&self) -> usize {
        use rsa::PublicKeyParts;
        self.0.n().bits()
    }
    /// Try to check a signature (as used in Tor.)  The signed hash
    /// should be in 'hashed', and the alleged signature in 'sig'.
    ///
    /// Tor uses RSA-PKCSv1 signatures, with hash algorithm OIDs
    /// omitted.
    ///
    /// ## Issues
    ///
    /// XXXX We probably shouldn't be exposing rsa::errors::Result().
    ///
    pub fn verify(&self, hashed: &[u8], sig: &[u8]) -> rsa::errors::Result<()> {
        use rsa::PublicKey;
        let padding = rsa::PaddingScheme::new_pkcs1v15_sign(None);
        self.0.verify(padding, hashed, sig)
    }
    /// Decode an alleged DER byte string into a PublicKey.
    ///
    /// Return None  if the DER string does not have a valid PublicKey.
    ///
    /// (This function expects an RSAPublicKey, as used by Tor.  It
    /// does not expect or accept a PublicKeyInfo.)
    pub fn from_der(der: &[u8]) -> Option<Self> {
        // We can't use the rsa-der crate, since it expects to find the
        // key inside of a bitstring inside of another asn1 object.
        // Also it doesn't seem to check for negative values.
        let blocks = simple_asn1::from_der(der).ok()?;
        if blocks.len() != 1 {
            return None;
        }
        let block = &blocks[0];
        use simple_asn1::ASN1Block::*;
        let (n, e) = match block {
            Sequence(_, v) => match &v[..] {
                [Integer(_, n), Integer(_, e)] => (n, e),
                _ => return None,
            },
            _ => return None,
        };
        use num_traits::sign::Signed;
        if n.is_negative() || e.is_negative() {
            return None;
        }
        let (_, nbytes) = n.to_bytes_be();
        let (_, ebytes) = e.to_bytes_be();
        let pk = PublicKey(
            rsa::RSAPublicKey::new(
                rsa::BigUint::from_bytes_be(&nbytes),
                rsa::BigUint::from_bytes_be(&ebytes),
            )
            .ok()?,
        );

        // assert_eq!(der, &pk.to_der()[..]);

        Some(pk)
    }
    /// Encode this public key into the DER format as used by Tor.
    ///
    /// The result is an RSAPublicKey, not a PublicKeyInfo.
    pub fn to_der(&self) -> Vec<u8> {
        // There seem to be version issues with these two versions of
        // bigint. XXXX
        use rsa::BigUint; // not the same as the one in simple_asn1.
        use rsa::PublicKeyParts;
        use simple_asn1::{ASN1Block, BigInt};
        fn to_asn1_int(x: &BigUint) -> ASN1Block {
            let mut bytes = vec![0];
            bytes.extend(x.to_bytes_be());
            let bigint = BigInt::from_signed_bytes_be(&bytes);
            ASN1Block::Integer(0, bigint)
        }

        let asn1 = ASN1Block::Sequence(0, vec![to_asn1_int(self.0.n()), to_asn1_int(self.0.e())]);
        simple_asn1::to_der(&asn1).unwrap()
    }

    /// Compute the RSAIdentity for this public key.
    pub fn to_rsa_identity(&self) -> RSAIdentity {
        use crate::d::Sha1;
        use digest::Digest;
        let id = Sha1::digest(&self.to_der()).into();
        RSAIdentity { id }
    }
}

/// blah blah
pub struct ValidatableRSASignature {
    key: PublicKey,
    sig: Vec<u8>,
    expected_hash: Vec<u8>,
}

impl ValidatableRSASignature {
    /// klasjdkljsd
    pub fn new(key: &PublicKey, sig: &[u8], expected_hash: &[u8]) -> Self {
        ValidatableRSASignature {
            key: key.clone(),
            sig: sig.into(),
            expected_hash: expected_hash.into(),
        }
    }
}

impl super::ValidatableSignature for ValidatableRSASignature {
    fn is_valid(&self) -> bool {
        self.key
            .verify(&self.expected_hash[..], &self.sig[..])
            .is_ok()
    }
}
