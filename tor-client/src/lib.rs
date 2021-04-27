//! High-level functionality for accessing the Tor network as a client.
//!
//! Eventually, this should be the API that 99% of client-only Tor users
//! will rely on.
//!
//! NOTE: Like the rest of Arti, these APIs are not the least bit stable.

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

mod client;

pub use client::{ConnectPrefs, TorClient};
