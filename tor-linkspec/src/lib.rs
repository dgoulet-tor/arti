//! Descriptions of Tor relays as used to connect to and extend to them.
//!
//! This is a separate module so that it can be shared as a dependency
//! by tor-netdir (which exposes these), and tor-proto (which consumes
//! these).

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]

mod ls;
mod traits;

pub use ls::LinkSpec;
pub use traits::{ChanTarget, CircTarget};
