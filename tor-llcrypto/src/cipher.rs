//! Ciphers used to implement the Tor protocols.
//!
//! Fortunately, Tor has managed not to proliferate ciphers.  It only
//! uses AES, and (so far) only uses AES in counter mode.

/// Re-exports implementations of counter-mode AES
pub mod aes {
    // These implement StreamCipher.
    pub use aes_ctr::{Aes128Ctr, Aes256Ctr};
}
