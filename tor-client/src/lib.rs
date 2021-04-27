//! High-level functionality for accessing the Tor network as a client.
//!
//! Eventually, this should be the API that 99% of client-only Tor users
//! will rely on.
//!
//! NOTE: Like the rest of Arti, these APIs are not the least bit stable.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]

mod client;

pub use client::{ConnectPrefs, TorClient};
