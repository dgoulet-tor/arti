//! Key manipulation functions for use with public keys.
//!
//! Tor does some interesting and not-really-standard things with its
//! curve25519 and ed25519 keys, for several reasons.
//!
//! In order to prove ownership of a curve25519 private key, Tor
//! converts it into an ed25519 key, and then uses that ed25519 key to
//! sign its identity key.
//!
//! TODO: This is also where we would put the key-derivation code that
//! Tor uses in the hsv3 onion services protocol.

use crate::pk;
use digest::Digest;
use zeroize::Zeroizing;

/// Convert a curve25519 public key (with sign bit) to an ed25519
/// public key, for use in ntor key cross-certification.
///
/// Note that this formula is not terribly standardized; don't use
/// it for anything besides cross-certification.
///
pub fn convert_curve25519_to_ed25519_public(
    pubkey: &pk::curve25519::PublicKey,
    signbit: u8,
) -> Option<pk::ed25519::PublicKey> {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    let point = MontgomeryPoint(*pubkey.as_bytes());
    let edpoint = point.to_edwards(signbit)?;

    // TODO: This is inefficient; we shouldn't have to re-compress
    // this point to get the public key we wanted.  But there's no way
    // with the current API that I can to construct an ed25519 public
    // key from a compressed point.
    let compressed_y = edpoint.compress();
    pk::ed25519::PublicKey::from_bytes(compressed_y.as_bytes()).ok()
}

/// Convert a curve25519 private key to an ed25519 public key (and
/// give a sign bit) to use with it, for use in ntor key cross-certification.
///
/// Note that this formula is not terribly standardized; don't use
/// it for anything besides cross-certification.
pub fn convert_curve25519_to_ed25519_private(
    privkey: &pk::curve25519::StaticSecret,
) -> Option<(pk::ed25519::ExpandedSecretKey, u8)> {
    use crate::d::Sha512;

    let h = Sha512::new()
        .chain(privkey.to_bytes())
        .chain(&b"Derive high part of ed25519 key from curve25519 key"[..])
        .finalize();

    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes[0..32].clone_from_slice(&privkey.to_bytes());
    bytes[32..64].clone_from_slice(&h[0..32]);

    let result = pk::ed25519::ExpandedSecretKey::from_bytes(&bytes[..]).ok()?;

    let signbit = result.to_bytes()[31] >> 7;

    #[cfg(debug_assertions)]
    {
        let curve_pubkey1 = pk::curve25519::PublicKey::from(privkey);
        let ed_pubkey1 = convert_curve25519_to_ed25519_public(&curve_pubkey1, signbit).unwrap();
        let ed_pubkey2 = (&result).into();
        assert_eq!(ed_pubkey1, ed_pubkey2);
    }

    Some((result, signbit))
}
