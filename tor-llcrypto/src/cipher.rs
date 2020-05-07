//! Ciphers used to implement the Tor protocols.

/// Re-exports implementations of counter-mode AES
pub mod aes {
    // These implement StreamCipher.
    pub use aes_ctr::{Aes128Ctr, Aes256Ctr};
}
