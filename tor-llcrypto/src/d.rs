//! Digests and XOFs used to implement the Tor protocol.
//!
//! In various places, for legacy reasons, Tor uses SHA1, SHA2,
//! SHA3, and SHAKE.  We re-export them all here, implementing
//! the Digest trait.
//!
//! Other code should access these digests via the traits in the
//! [digest](https://docs.rs/digest/0.8.1/digest/) crate.

pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};
pub use sha3::{Sha3_256, Shake128, Shake256};
