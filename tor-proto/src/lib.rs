//! Implementations for the core Tor protocol
//!
//! This crate has implementation of the ntor handshake, and an
//! implementation of relay cryptography.  It's also got a somewhat
//! dodgy client-only implementation of channels, circuits, and
//! streams.
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
//! This crate was my first attempt to use async in rust, and is probably
//! pretty kludgy.

#![deny(missing_docs)]

pub mod channel;
pub mod circuit;
mod crypto;
pub mod stream;
mod util;

pub use util::err::Error;

/// A vector of bytes that gets cleared when it's dropped.
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
