//! Provide builder functionality for routerstatuses.

use super::{GenericRouterStatus, MdConsensusRouterStatus, NsConsensusRouterStatus};
use crate::doc::microdesc::MdDigest;
use crate::doc::netstatus::{ConsensusBuilder, RouterFlags, RouterWeight};
use crate::doc::routerdesc::RdDigest;
use crate::{Error, Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;
use std::time::SystemTime;

/// A Builder object for creating a RouterStatus and adding it to a
/// consensus.
pub struct RouterStatusBuilder<D> {
    /// See [`GenericRouterStatus::nickname`].
    nickname: Option<String>,
    /// See [`GenericRouterStatus::identity`].
    identity: Option<RsaIdentity>,
    /// See [`GenericRouterStatus::published`].
    published: Option<SystemTime>,
    /// See [`GenericRouterStatus::addrs`].
    addrs: Vec<SocketAddr>,
    /// See [`GenericRouterStatus::dir_port`].
    dir_port: u16, // never used, I think? XXXX
    /// See [`GenericRouterStatus::doc_digest`].
    doc_digest: Option<D>,
    /// See [`GenericRouterStatus::flags`].
    flags: RouterFlags,
    /// See [`GenericRouterStatus::version`].
    version: Option<String>,
    /// See [`GenericRouterStatus::protos`].
    protos: Option<Protocols>,
    /// See [`GenericRouterStatus::weight`].
    weight: Option<RouterWeight>,
}

impl<D: Clone> RouterStatusBuilder<D> {
    /// Construct a new RouterStatusBuilder.
    pub(crate) fn new() -> Self {
        RouterStatusBuilder {
            nickname: None,
            identity: None,
            published: None,
            addrs: Vec::new(),
            dir_port: 0,
            doc_digest: None,
            flags: RouterFlags::empty(),
            version: None,
            protos: None,
            weight: None,
        }
    }

    /// Set the nickname for this router.
    ///
    /// This value defaults to "Unnamed".
    pub fn nickname(&mut self, nickname: String) -> &mut Self {
        self.nickname = Some(nickname);
        self
    }

    /// Set the RSA identity for this router.
    ///
    /// (The Ed25519 identity is in the microdescriptor).
    ///
    /// This value is required.
    pub fn identity(&mut self, identity: RsaIdentity) -> &mut Self {
        self.identity = Some(identity);
        self
    }
    /// Set the publication time for this router.
    ///
    /// This value is optional, and does nothing (TODO).
    pub fn published(&mut self, published: SystemTime) -> &mut Self {
        self.published = Some(published);
        self
    }
    /// Add an OrPort at `addr` to this router.
    ///
    /// At least one value here is required.
    pub fn add_or_port(&mut self, addr: SocketAddr) -> &mut Self {
        self.addrs.push(addr);
        self
    }
    /// Set a directory port for this router.
    ///
    /// Nothing in Arti uses this value; it defaults to 0.
    pub fn dir_port(&mut self, dir_port: u16) -> &mut Self {
        self.dir_port = dir_port;
        self
    }
    /// Set the document digest for this router.
    ///
    /// This value is required.
    pub fn doc_digest(&mut self, doc_digest: D) -> &mut Self {
        self.doc_digest = Some(doc_digest);
        self
    }
    /// Replace the current flags in this router with `flags`.
    pub fn set_flags(&mut self, flags: RouterFlags) -> &mut Self {
        self.flags = flags;
        self
    }
    /// Make all the flags in `flags` become set on this router,
    /// in addition to the flags already set.
    pub fn add_flags(&mut self, flags: RouterFlags) -> &mut Self {
        self.flags |= flags;
        self
    }
    /// Set the version of this router.
    ///
    /// This value is optional.
    pub fn version(&mut self, version: String) -> &mut Self {
        self.version = Some(version);
        self
    }
    /// Set the list of subprotocols supported by this router.
    ///
    /// This value is required.
    pub fn protos(&mut self, protos: Protocols) -> &mut Self {
        self.protos = Some(protos);
        self
    }
    /// Try to build a GenericRouterStatus from this builder.
    fn finish(&self) -> Result<GenericRouterStatus<D>> {
        let nickname = self.nickname.clone().unwrap_or_else(|| "Unnamed".into());
        let identity = self
            .identity
            .ok_or(Error::CannotBuild("Missing RSA identity"))?;
        let published = self.published.unwrap_or_else(SystemTime::now);
        if self.addrs.is_empty() {
            return Err(Error::CannotBuild("No addresses"));
        }
        let or_port = self.addrs[0].port();
        let doc_digest = self
            .doc_digest
            .as_ref()
            .ok_or(Error::CannotBuild("Missing document digest"))?
            .clone();
        let protos = self
            .protos
            .as_ref()
            .ok_or(Error::CannotBuild("Missing protocols"))?
            .clone();
        let weight = self.weight.unwrap_or(RouterWeight::Unmeasured(0));

        Ok(GenericRouterStatus {
            nickname,
            identity,
            published,
            addrs: self.addrs.clone(),
            or_port,
            dir_port: self.dir_port,
            doc_digest,
            version: self.version.clone(),
            protos,
            flags: self.flags,
            weight,
        })
    }
}

impl RouterStatusBuilder<RdDigest> {
    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build(&self, builder: &mut ConsensusBuilder<NsConsensusRouterStatus>) -> Result<()> {
        let rs = self.finish()?;
        builder.add_rs(rs.into());
        Ok(())
    }
}

impl RouterStatusBuilder<MdDigest> {
    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build(&self, builder: &mut ConsensusBuilder<MdConsensusRouterStatus>) -> Result<()> {
        let rs = self.finish()?;
        builder.add_rs(rs.into());
        Ok(())
    }
}
