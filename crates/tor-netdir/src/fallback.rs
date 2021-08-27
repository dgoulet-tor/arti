//! List of directories that ships with Tor, for initial directory
//! operations.
//!
//! When a client doesn't have directory information yet, it uses a
//! "Fallback Directory" to retrieve its initial information about the
//! network.

use crate::{Error, Result};

use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::Deserialize;
use std::net::SocketAddr;

/// A directory whose location ships with Tor (or arti), and which we
/// can use for bootstrapping when we don't know anything else about
/// the network.
//
// Note that we do *not* set serde(deny_unknown_fields)] on this structure:
// we want our authorities format to be future-proof against adding new info
// about each authority.
#[derive(Debug, Clone, Deserialize)]
pub struct FallbackDir {
    /// RSA identity for the directory relay
    rsa_identity: RsaIdentity,
    /// Ed25519 identity for the directory relay
    ed_identity: Ed25519Identity,
    /// List of ORPorts for the directory relay
    orports: Vec<SocketAddr>,
}

/// A Builder object for constructing a [`FallbackDir`].
#[derive(Debug, Clone, Default)]
pub struct FallbackDirBuilder {
    /// See [`FallbackDir::rsa_identity`]
    rsa_identity: Option<RsaIdentity>,
    /// See [`FallbackDir::ed_identity`]
    ed_identity: Option<Ed25519Identity>,
    /// See [`FallbackDir::orports`]
    orports: Vec<SocketAddr>,
}

impl FallbackDir {
    /// Return a builder that can be used to make a `FallbackDir`.
    pub fn builder() -> FallbackDirBuilder {
        FallbackDirBuilder::new()
    }
}

impl FallbackDirBuilder {
    /// Make a new FallbackDirBuilder.
    ///
    /// You only need to use this if you're using a non-default set of
    /// fallback directories.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the RSA identity for this fallback directory.
    ///
    /// This field is required.
    pub fn rsa_identity(&mut self, rsa_identity: RsaIdentity) -> &mut Self {
        self.rsa_identity = Some(rsa_identity);
        self
    }
    /// Set the Ed25519 identity for this fallback directory.
    ///
    /// This field is required.
    pub fn ed_identity(&mut self, ed_identity: Ed25519Identity) -> &mut Self {
        self.ed_identity = Some(ed_identity);
        self
    }
    /// Add a single OR port for this fallback directory.
    ///
    /// This field is required, and may be called more than once.
    pub fn orport(&mut self, orport: SocketAddr) -> &mut Self {
        self.orports.push(orport);
        self
    }
    /// Try to construct a [`FallbackDir`] from this builder.
    pub fn build(&self) -> Result<FallbackDir> {
        let rsa_identity = self.rsa_identity.as_ref().ok_or(Error::BadArgument(
            "Missing RSA identity on fallback directory",
        ))?;
        let ed_identity = self.ed_identity.as_ref().ok_or(Error::BadArgument(
            "Missing ed25519 identity on fallback directory",
        ))?;
        let orports = self.orports.clone();
        if orports.is_empty() {
            return Err(Error::BadArgument("No OR ports on fallback directory"));
        }

        Ok(FallbackDir {
            rsa_identity: *rsa_identity,
            ed_identity: *ed_identity,
            orports,
        })
    }
}

impl tor_linkspec::ChanTarget for FallbackDir {
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
    }
    fn ed_identity(&self) -> &Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rsa_identity
    }
}
