//! Support for mocking with runtimes.
//!
//! This crate should should only be used for writing tests.
//!
//! Currently, we support mocking the passage of time, making fake
//! stream pairs, and impersonating the Internet.

pub mod io;
pub mod net;
pub mod time;

mod net_runtime;
mod sleep_runtime;
pub use net_runtime::MockNetRuntime;
pub use sleep_runtime::MockSleepRuntime;
