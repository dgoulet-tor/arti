//! Coding, and decoding for the cells that make up Tor's protocol
//!
//! In this crate you'll find code to encode and decode Tor cells.
//!
//! This is all a work in progress, and will need severe refactoring
//! before we're done.
//!
//! TODO: Explain what cells are.
//!
//! # Limitations
//!
//! There aren't any tests.
//!
//! There isn't enough documentation.
//!
//! This is the first part of the project I started working on, and
//! probably reflects the most naive understranding of Rust.

#![deny(missing_docs)]

pub mod chancell;
mod err;
pub mod relaycell;

pub use err::Error;

/// An error type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
