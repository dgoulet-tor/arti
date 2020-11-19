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

use lazy_static::lazy_static;
use std::net::SocketAddr;

mod pregen;

/// A directory whose location ships with Tor (or arti), and which we
/// can use for bootstrapping when we don't know anything else about
/// the network.
#[derive(Debug, Clone)]
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

lazy_static! {
    /// A list of all the built-in fallbacks that we know.
    static ref FALLBACK_DIRS: Vec<FallbackDir> =
        pregen::FALLBACKS.iter().map(FallbackDir::from).collect();
}

/// A set of fallback directories.
///
/// This can either be the default set, or a set provided at runtime.
#[derive(Debug, Clone)]
pub struct FallbackSet {
    /// If present a list of all our fallback directories.  If absent,
    /// we use the default list.
    fallbacks: Option<Vec<FallbackDir>>,
}

impl FallbackSet {
    /// Construct the default set of fallback directories.
    pub fn new() -> Self {
        FallbackSet { fallbacks: None }
    }
    /// Construct a set of caller-provided fallback directories
    pub fn from_fallbacks<T>(fallbacks: T) -> Self
    where
        T: IntoIterator<Item = FallbackDir>,
    {
        let fallbacks = fallbacks.into_iter().collect();
        FallbackSet {
            fallbacks: Some(fallbacks),
        }
    }
    /// Choose a fallback directory at random.
    ///
    /// TODO: In theory, it would be a good idea to have weights for these.
    pub fn pick<'a, R>(&'a self, rng: &mut R) -> Option<&'a FallbackDir>
    where
        R: rand::RngCore,
    {
        use rand::seq::SliceRandom;
        let slice = self.as_ref();
        slice.choose(rng)
    }
}

impl Default for FallbackSet {
    fn default() -> Self {
        FallbackSet::new()
    }
}

impl AsRef<[FallbackDir]> for FallbackSet {
    fn as_ref(&self) -> &[FallbackDir] {
        self.fallbacks.as_ref().unwrap_or(&FALLBACK_DIRS)
    }
}
