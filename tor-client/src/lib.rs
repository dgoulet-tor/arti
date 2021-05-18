//! High-level functionality for accessing the Tor network as a client.
//!
//! Eventually, this should be the API that 99% of client-only Tor users
//! will rely on.
//!
//! NOTE: Like the rest of Arti, these APIs are not the least bit stable.

#![deny(missing_docs)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

mod client;

pub use client::{ConnectPrefs, TorClient};
