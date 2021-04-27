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
//!

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]

pub mod cipher;
pub mod d;
pub mod pk;
pub mod util;
