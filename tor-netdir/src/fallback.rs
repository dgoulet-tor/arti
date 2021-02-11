//! List of directories that ships with Tor, for initial directory
//! operations.
//!
//! When a client doesn't have directory information yet, it uses a
//! "Fallback Directory" to retreive its initial information about the
//! network.
//!
//! From time to time, the Tor maintainers regenerate the list of
//! fallbacks, and replace it in the fallback::pregen module.

use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RSAIdentity;

use serde::Deserialize;
use std::net::SocketAddr;

/// A directory whose location ships with Tor (or arti), and which we
/// can use for bootstrapping when we don't know anything else about
/// the network.
#[derive(Debug, Clone, Deserialize)]
pub struct FallbackDir {
    /// RSA identity for the directory relay
    rsa_identity: RSAIdentity,
    /// Ed25519 identity for the directory relay
    ed_identity: Ed25519Identity,
    /// List of ORPorts for the directory relay
    orports: Vec<SocketAddr>,
}

impl FallbackDir {
    /// Construct a new FallbackDir
    pub fn new(
        rsa_identity: RSAIdentity,
        ed_identity: Ed25519Identity,
        orports: Vec<SocketAddr>,
    ) -> Self {
        FallbackDir {
            rsa_identity,
            ed_identity,
            orports,
        }
    }
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
