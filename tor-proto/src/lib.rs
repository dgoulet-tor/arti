//! Coding, decoding, handshakes, and cryptography for the core Tor protocol
//!
//! In this crate you'll find code to encode and decode tor cells, an
//! implementation of the ntor handshake, and an implementation of relay
//! cryptography.
//!
//! This is all a work in progress, and will need severe refactoring
//! before we're done.
//!
//! # Limitations
//!
//! There aren't any tests.
//!
//! There isn't enough documentation.
//!
//! This crate probably has far too many things in it, and could stand
//! to get split up!
//!
//! This is the first part of the project I started working on, and
//! probably reflects the most naive understranding of Rust.
//!

#![deny(missing_docs)]

pub mod chancell;
pub mod channel;
pub mod circuit;
mod crypto;
pub mod relaycell;
pub mod stream;
mod util;

pub use util::err::Error;

use zeroize::Zeroizing;

/// A vector of bytes that gets cleared when it's dropped.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
