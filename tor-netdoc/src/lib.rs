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

#![deny(missing_docs)]

#[macro_use]
pub(crate) mod parse;
pub mod doc;
mod err;
pub mod types;
mod util;

pub use err::{Error, Pos};

/// Alias for the Result type returned by most objects in this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Indicates whether we should parse an annotated list of objects or a
/// non-annotated list.
#[derive(PartialEq, Debug)]
pub enum AllowAnnotations {
    /// Parsing a document where items might be annotated.
    ///
    /// Annotations are a list of zero or more items with keywords
    /// beginning with @ that precede the items that are actually part
    /// of the document.
    AnnotationsAllowed,
    /// Parsing a document where annotations are not allowed.
    AnnotationsNotAllowed,
}
