//! Ciphers used to implement the Tor protocols.
//!
//! Fortunately, Tor has managed not to proliferate ciphers.  It only
//! uses AES, and (so far) only uses AES in counter mode.

/// Re-exports implementations of counter-mode AES
///
/// These ciphers implement the
/// [StreamCipher](https://docs.rs/cipher/0.2.1/cipher/stream/trait.StreamCipher.html)
/// trait, so use the
/// [cipher](https://docs.rs/cipher/0.2.1/cipher/) crate to access them.
pub mod aes {
    // These implement StreamCipher.
    pub use ::aes::{Aes128Ctr, Aes256Ctr};
}
