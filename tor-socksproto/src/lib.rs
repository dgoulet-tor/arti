//! Implements SOCKS in the flavors provided by Tor.
//!
//! SOCKS is an old and somewhat janky protocol for telling a TCP
//! proxy where to connect.  Versions 4, 4a, and 5 are sometimes
//! encountered in the wild.
//!
//! This crate tries to hide the actual details of the protocol, and
//! expose a stateful handshake type that eventually provides a [SocksRequest]
//! or an error.
//!
//! For more information about SOCKS:
//!
//!   * SOCKS5 (which is preferred) is specified in
//!     [RFC 1928](https://tools.ietf.org/html/rfc1928), and see also
//!     [RFC 1929](https://tools.ietf.org/html/rfc1929) for
//!     Username/Password authentication in SOCKS5.
//!   * [The wikipedia article](https://en.wikipedia.org/wiki/SOCKS)
//!     is the best surviving documentation for SOCKS4 and SOCKS4a.
//!   * See
//!     [socks-extensions.txt](https://spec.torproject.org/socks-extensions)
//!     for a description of Tor's extensions and restrictions on the
//!     SOCKS protocol.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]

mod err;
mod handshake;
mod msg;

pub use err::Error;
pub use handshake::{Action, SocksHandshake};
pub use msg::{SocksAddr, SocksAuth, SocksCmd, SocksRequest, SocksStatus};

/// A Result type for the tor_socksproto crate.
pub type Result<T> = std::result::Result<T, Error>;
