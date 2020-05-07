//! Parse and  represent directory objects used in Tor.
//!
//! Tor has several "directory objects" that it uses to convey
//! information about relays on the network. They are documented in
//! dir-spec.txt.
//!
//! TODO: Currently, this crate can handle the metaformat, along with
//! certain parts of the router descriptor type. We will eventually
//! need to handle more types.
//!
//! TODO: This crate requires that all of its inputs be valid UTF-8.

#![allow(dead_code)]

mod argtype;
mod err;
mod parse;
mod rules;
mod tokenize;
mod util;
#[macro_use]
mod macros; // xxxx
mod policy;
mod routerdesc;
mod version;

pub use err::{Error, Position};
pub type Result<T> = std::result::Result<T, Error>;
