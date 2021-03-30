//! Microdesc-consensus specific parts of networkstatus parsing.
//!
//! This is a private module; relevant pieces are re-exported by its parent.

use super::{NetstatusKwd, ParseRouterStatus, RouterFlags, RouterStatus, RouterWeight};
use crate::doc::microdesc::MdDigest;
use crate::types::misc::*;
use crate::{parse::parser::Section, util::private::Sealed};
use crate::{Error, Result};
use std::{net, time};

use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::convert::TryInto;

/// A single relay's status, as represented in a microdesc consensus.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MdConsensusRouterStatus {
    /// The nickname for this relay.
    ///
    /// Nicknames can be used for convenience purpose, but no more:
    /// there is no mechanism to enforce their uniqueness.
    nickname: String,
    /// Fingerprint of the old-style RSA identity for this relay.
    identity: RsaIdentity,
    /// Declared time at which the router descriptor for this relay
    /// was published.
    ///
    /// This value should be ignored for all purposes; see
    /// [proposal 275](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/proposals/275-md-published-time-is-silly.txt).
    published: time::SystemTime,
    /// A list of address:port values where this relay can be reached.
    addrs: Vec<net::SocketAddr>,
    /// Declared OR port for this relay.
    or_port: u16,
    /// Declared directory port for this relay.
    dir_port: u16,
    /// Digest of the microdescriptor for this relay.
    md_digest: MdDigest,
    /// Flags applied by the authorities to this relay.
    flags: RouterFlags,
    /// Version of the software that this relay is running.
    version: Option<String>,
    /// List of subprotocol versions supported by this relay.
    protos: Protocols,
    /// Information about how to weight this relay when choosing a
    /// relay at random.
    weight: RouterWeight,
}

// TODO: These methods should probably become, in whole or in part,
// methods on the RouterStatus trait.
impl MdConsensusRouterStatus {
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn md_digest(&self) -> &MdDigest {
        &self.md_digest
    }
    /// Return an iterator of ORPort addresses for this routerstatus
    pub fn orport_addrs(&self) -> impl Iterator<Item = &net::SocketAddr> {
        self.addrs.iter()
    }
    /// Return the declared weight of this routerstatus in the directory.
    pub fn weight(&self) -> &RouterWeight {
        &self.weight
    }
    /// Return the ORPort addresses of this routerstatus
    pub fn addrs(&self) -> &[net::SocketAddr] {
        &self.addrs[..]
    }
    /// Return the protovers that this routerstatus says it implements.
    pub fn protovers(&self) -> &Protocols {
        &self.protos
    }
    /// Return true if the ed25519 identity on this relay reflects a
    /// true consensus among the authorities.
    pub fn ed25519_id_is_usable(&self) -> bool {
        !self.flags.contains(RouterFlags::NO_ED_CONSENSUS)
    }
    /// Return true if this routerstatus is listed with the BadExit flag.
    pub fn is_flagged_bad_exit(&self) -> bool {
        self.flags.contains(RouterFlags::BAD_EXIT)
    }
    /// Return true if this routerstatus is listed with the v2dir flag.
    pub fn is_flagged_v2dir(&self) -> bool {
        self.flags.contains(RouterFlags::V2DIR)
    }
    /// Return true if this routerstatus is listed with the Exit flag.
    pub fn is_flagged_exit(&self) -> bool {
        self.flags.contains(RouterFlags::EXIT)
    }
    /// Return true if this routerstatus is listed with the Guard flag.
    pub fn is_flagged_guard(&self) -> bool {
        self.flags.contains(RouterFlags::GUARD)
    }
}

impl Sealed for MdConsensusRouterStatus {}

impl RouterStatus for MdConsensusRouterStatus {
    type DocumentDigest = MdDigest;

    /// Return the expected microdescriptor digest for this routerstatus
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.identity
    }

    fn doc_digest(&self) -> &MdDigest {
        self.md_digest()
    }
}

impl ParseRouterStatus for MdConsensusRouterStatus {
    fn flavor_name() -> &'static str {
        "microdesc"
    }

    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<MdConsensusRouterStatus> {
        use NetstatusKwd::*;
        // R line
        let r_item = sec.required(RS_R)?;
        let nickname = r_item.required_arg(0)?.to_string();
        let ident = r_item.required_arg(1)?.parse::<B64>()?;
        let identity = RsaIdentity::from_bytes(ident.as_bytes())
            .ok_or_else(|| Error::BadArgument(r_item.pos(), "Wrong identity length".to_string()))?;
        let published: time::SystemTime = {
            // TODO: It's annoying to have to do this allocation, since we
            // already have a slice that contains both of these arguments.
            // Instead, we could get a slice of arguments: we'd have to add
            // a feature for that.
            let mut p = r_item.required_arg(2)?.to_string();
            p.push(' ');
            p.push_str(r_item.required_arg(3)?);
            p.parse::<Iso8601TimeSp>()?.into()
        };
        let ipv4addr = r_item.required_arg(4)?.parse::<net::Ipv4Addr>()?;
        let or_port = r_item.required_arg(5)?.parse::<u16>()?;
        let dir_port = r_item.required_arg(6)?.parse::<u16>()?;

        let mut addrs: Vec<net::SocketAddr> = vec![net::SocketAddr::V4(net::SocketAddrV4::new(
            ipv4addr, or_port,
        ))];

        // A lines
        for a_item in sec.slice(RS_A) {
            addrs.push(a_item.required_arg(0)?.parse::<net::SocketAddr>()?);
        }

        // S line
        let flags = RouterFlags::from_item(sec.required(RS_S)?)?;

        // V line
        let version = sec.maybe(RS_V).args_as_str().map(str::to_string);

        // PR line
        let protos = {
            let tok = sec.required(RS_PR)?;
            tok.args_as_str()
                .parse::<Protocols>()
                .map_err(|e| Error::BadArgument(tok.pos(), e.to_string()))?
        };

        // W line
        let weight = sec
            .get(RS_W)
            .map(RouterWeight::from_item)
            .transpose()?
            .unwrap_or_else(Default::default);

        // No p line
        // no ID line

        // M line
        let md_digest: [u8; 32] = {
            let m_item = sec.required(RS_M)?;
            m_item
                .required_arg(0)?
                .parse::<B64>()?
                .check_len(32..=32)?
                .as_bytes()
                .try_into()
                .map_err(|_| Error::Internal(m_item.pos()))?
        };

        Ok(MdConsensusRouterStatus {
            nickname,
            identity,
            published,
            addrs,
            or_port,
            dir_port,
            md_digest,
            flags,
            version,
            protos,
            weight,
        })
    }
}
