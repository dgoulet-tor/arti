//! Ciphers used to implement the Tor protocols.
//!
//! Fortunately, Tor has managed not to proliferate ciphers.  It only
//! uses AES, and (so far) only uses AES in counter mode.

/// Re-exports implementations of counter-mode AES
///
/// These ciphers implement the
/// [StreamCipher](https://docs.rs/stream-cipher/0.3.2/stream_cipher/trait.StreamCipher.html)
/// trait, so use the
/// [stream-cipher](https://docs.rs/stream-cipher/0.3.2/stream_cipher/) crate to access them.
pub mod aes {
    // These implement StreamCipher.
    pub use aes_ctr::{Aes128Ctr, Aes256Ctr};
}
