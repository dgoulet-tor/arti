//! This crate wraps other crates that implement lower-level
//! cryptographic functionality that Tor does not implement itself.
//! In some cases the functionality is just re-exported; in others, it
//! is wrapped to present a conseistent interface.
//!
//! Encryption is implemented in `cipher`, digests are in `d`, and
//! public key cryptography (including signatures, encryption, and key
//! agreement) are in `pk`.
//!
//! When possible, everything here should be accessed via traits from
//! the rust-crypto project, as re-exported from the traits module.

// TODO -- the long-term intention here is that this functionality
// should be replaceable at compile time with other implementations.

pub mod cipher;
pub mod d;
pub mod pk;
pub mod traits;
