//! Tools for configuration management.
//!
//! Arti's configuration is handled using `serde` and `config` crates,
//! plus extra features defined here for convenience.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod cmdline;
pub use cmdline::CmdLine;
