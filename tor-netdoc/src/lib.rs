//! Parse and represent directory objects used in Tor.
//!
//! Tor has several "directory objects" that it uses to convey
//! information about relays on the network. They are documented in
//! dir-spec.txt.
//!
//! This crate has common code to parse and validate these documents.
//! Currently, it can handle the metaformat, along with certain parts
//! of the router descriptor type. We will eventually need to handle
//! more types.
//!
//! # Caveat haxxor: limitations and infelicities
//!
//! TODO: This crate requires that all of its inputs be valid UTF-8.
//!
//! TODO: This crate has several pieces that should probably be split out
//! into other smaller cases, including handling for version numbers
//! and exit policies.
//!
//! TODO: Many parts of this crate that should be public aren't.
//!
//! TODO: this crate needs far more tests!

#![allow(dead_code)]
//#![warn(missing_docs)]

mod argtype;
mod err;
mod parse;
mod rules;
mod tokenize;
mod util;
#[macro_use]
mod macros;
pub mod policy;
pub mod routerdesc;
pub mod version;

pub use err::{Error, Position};
/// Alias for the Result type returned by most objects in this module.
pub type Result<T> = std::result::Result<T, Error>;
