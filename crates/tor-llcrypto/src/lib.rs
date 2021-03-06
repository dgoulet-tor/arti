//! `tor-llcrypto`: Low-level cryptographic implementations for Tor.
//!
//! # Overview
//!
//! The `tor-llcrypto` crate wraps lower-level cryptographic
//! primitives that Tor needs, and provides a few smaller pieces of
//! cryptographic functionality that are commonly required to
//! implement Tor correctly.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Many other crates in Arti depend on it.
//!
//! You probably wouldn't want to use this crate for implementing
//! non-Tor-based protocols; instead you should probably use the other
//! crates that it depends on if you have a low-level protocol to
//! implement, or a higher-level cryptographic system if you want to
//! add security to something else.  It is easy to accidentally put
//! these functions together in ways that are unsafe.
//!
//! ## Why a separate crate?
//!
//! Why do we collect and re-export our cryptography here in
//! `tor-llcrypto`, instead of having the different crates in Arti use
//! underlying cryptographic crates directly?
//!
//! By wrapping our cryptography in this crate, we ensure that we're
//! using the same implementations across our ecosystem, and provide
//! a single place to upgrade and test our cryptography.
//!
//! ## Adding to `tor-llcrypto`
//!
//! Any low-level cryptographic algorithm that is used by at least two
//! other crates in Arti is a candidate for inclusion in
//! `tor-llcrypto`, especially if that algorithm's purpose is not
//! specific to any single piece of the Tor algorithm.
//!
//! Cryptographic _traits_ (like those from RustCrypto) don't have to
//! go in `tor-llcrypto`, since they are interfaces rather than
//! implementations.
//!
//! # Contents
//!
//! Encryption is implemented in [`cipher`]: Currently only AES is
//! exposed or needed.
//!
//! Cryptographic digests are in [`d`]: The Tor protocol uses several
//! digests in different places, and these are all collected here.
//!
//! Public key cryptography (including signatures, encryption, and key
//! agreement) are in [`pk`].  Older parts of the Tor protocol require
//! RSA; newer parts are based on Curve25519 and Ed25519. There is
//! also functionality here for _key manipulation_ for the keys used
//! in these symmetric algorithms.
//!
//! The [`util`] module has some miscellaneous compatibility utilities
//! for manipulating cryptography-related objects and code.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

pub mod cipher;
pub mod d;
pub mod pk;
pub mod util;
