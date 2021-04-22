//! Support for mocking with runtimes.
//!
//! This should only be used for writing tests.
//!
//! Currently, we support mocking the passage of time and making fake
//! stream pairs.

pub mod io;
pub mod time;

mod sleep_runtime;
pub use sleep_runtime::MockSleepRuntime;
