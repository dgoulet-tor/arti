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
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::rc_buffer)]

pub mod cipher;
pub mod d;
pub mod pk;
pub mod util;
