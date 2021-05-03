//! Support for mocking with runtimes.
//!
//! This crate should should only be used for writing tests.
//!
//! Currently, we support mocking the passage of time, making fake
//! stream pairs, and impersonating the Internet.

#![deny(missing_docs)]
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
#![warn(clippy::unseparated_literal_suffix)]

pub mod io;
pub mod net;
pub mod time;

mod net_runtime;
mod sleep_runtime;
pub use net_runtime::MockNetRuntime;
pub use sleep_runtime::MockSleepRuntime;
