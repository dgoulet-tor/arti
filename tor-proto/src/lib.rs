//! Implementations for the core Tor protocol
//!
//! At its essence, Tor makes connections called "channels" to other
//! Tor instances.  These channels are implemented using TLS.  Each of
//! these channels multiplexes a number of anonymized multihop
//! "circuits" that act as reliable transports for "relay messages"
//! that are sent between clients and the different relays on the
//! circuits.  Finally, each circuit multiplexes a number of "streams",
//! each corresponding roughly to an application-level request.
//!
//! This crate implements the logic, protocols, and cryptography that
//! implement these [channel::Channel]s, [circuit::ClientCirc]s, and
//! [stream::TorStream]s.  It uses rust async code and future-related
//! traits, and is intended to work with (nearly) any executor
//! implementation that complies with the futures API.  It should also
//! work with nearly any TLS implementation that exposes AsyncRead and
//! AsyncWrite traits.
//!
//! This crate does _not_ implement higher level protocols, like onion
//! services or the Tor directory protocol, that are based on the Tor
//! protocol here.  Nor does it decide _when_, _how_, or _where_ to
//! build channels and circuits: that's the role of a future
//! "tor-client" crate, or possibly a related "circmanager" crate or
//! something.
//!
//! In order to create channels and circuits, you'll need to know
//! about some Tor relays, and expose their information via
//! [tor_linkspec::ChanTarget] and [tor_linkspec::CircTarget].
//! Currently, the [tor-netdir] crate is
//! the easiest way to do so.
//!
//! For an example of this crate in action, see the [tor-client]
//! program.
//!
//! # Limitations
//!
//! This is all a work in progress, and will need severe refactoring
//! before we're done.
//!
//! This is a client-only implementation for now.
//!
//! There are too many missing features to list.
//!
//! There isn't enough documentation.
//!
//! This crate was my first attempt to use async in rust, and is probably
//! pretty kludgy.
//!
//! I bet that there are deadlocks somewhere in this code.  I fixed
//! all the ones I could find or think of, but it would be great to
//! find a good way to eliminate every lock that we have.
//!
//! This doesn't work with rusttls because of a limitation in the
//! webpki crate.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(clippy::unknown_clippy_lints)]
#![allow(clippy::unnecessary_wraps)]

pub mod channel;
pub mod circuit;
mod crypto;
pub mod stream;
mod util;

pub use util::err::Error;

/// A vector of bytes that gets cleared when it's dropped.
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
