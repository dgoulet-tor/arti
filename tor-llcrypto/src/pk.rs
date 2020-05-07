//! Re-exporting public-key cryptography.

pub mod keymanip;
pub mod rsa;

/// Re-exporting Curve25519 implementations.
///
/// Eventually there should probably be a key-agreement trait or two
/// that this implements, but for now I'm just using the API from
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
}
