//! Low-level crypto implementations for Tor.
//!
//! This crate doesn't have much of interest: for the most part it
//! just wraps other crates that implement lower-level cryptographic
//! functionality.  In some cases the functionality is just
//! re-exported; in others, it is wrapped to present a conseistent
//! interface.
//!
//! Encryption is implemented in `cipher`, digests are in `d`, and
//! public key cryptography (including signatures, encryption, and key
//! agreement) are in `pk`.

#![deny(missing_docs)]

pub mod cipher;
pub mod d;
pub mod pk;
