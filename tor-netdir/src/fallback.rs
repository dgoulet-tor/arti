//! List of directories that ships with Tor, for initial directory
//! operations.
//!
//! From time to time, we regenerate the list of fallbacks, and
//! replace it in the pregen module.

use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RSAIdentity;

use lazy_static::lazy_static;
use std::net::SocketAddr;

mod pregen;

/// A directory whose location ships with Tor (or arti), and which we
/// can use for bootstrapping when we don't know anything else about
/// the network.
pub struct FallbackDir {
    /// RSA identity for the directory relay
    rsa_identity: RSAIdentity,
    /// Ed25519 identity for the directory relay
    ed_identity: Ed25519Identity,
    /// List of ORPorts for the directory relay
    orports: Vec<SocketAddr>,
}

impl tor_linkspec::ChanTarget for FallbackDir {
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
    }
    fn ed_identity(&self) -> &Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &RSAIdentity {
        &self.rsa_identity
    }
}

/// Return a slice of all of the built-in fallbacks that we know.
pub fn fallbacks() -> &'static [FallbackDir] {
    &FALLBACK_DIRS
}

lazy_static! {
    /// A list of all the built-in fallbacks that we know.
    static ref FALLBACK_DIRS: Vec<FallbackDir> =
        pregen::FALLBACKS.iter().map(FallbackDir::from).collect();
}
