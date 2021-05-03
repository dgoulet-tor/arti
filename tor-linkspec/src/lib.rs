//! Descriptions of Tor relays as used to connect to and extend to them.
//!
//! This is a separate module so that it can be shared as a dependency
//! by tor-netdir (which exposes these), and tor-proto (which consumes
//! these).

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

mod ls;
mod traits;

pub use ls::LinkSpec;
pub use traits::{ChanTarget, CircTarget};
