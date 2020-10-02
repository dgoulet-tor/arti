//! Parsing implementation for networkstatus documents.
//!
//! In Tor, a networkstatus documents describes a complete view of the
//! relays in the network: how many there are, how to contact them,
//! and so forth.
//!
//! A networkstatus document can either be a "votes" -- an authority's
//! view of the network, used as input to the voting process -- or a
//! "consensus" -- a combined view of the network based on multiple
//! authorities' votes, and signed by multiple authorities.
//!
//! A consensus document can itself come in two different flavors: a
//! "ns"-flavored consensus has references to router descriptors, and
//! a "microdesc"-flavored consensus has references to
//! microdescriptors.
//!
//! To keep an up-to-date view of the network, clients download
//! microdescriptor-flavored consensuses periodically, and then
//! download whatever microdescriptors the consensus lists that the
//! client doesn't already have.
//!
//! For full information about the network status format, see
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! # Limitations
//!
//! NOTE: The consensus format has changes time, using a
//! "consensus-method" mechanism.  This module is does not yet handle all
//! all historical consensus-methods.
//!
//! NOTE: This module _does_ parse some fields that are not in current
//! use, like relay nicknames, and the "published" times on
//! microdescriptors. We should probably decide whether we actually
//! want to do this.
//!
//! TODO: This module doesn't implement vote parsing at all yet.
//!
//! TODO: This module doesn't implement ns-flavored consensuses.
//!
//! TODO: More testing is needed!
//!
//! TODO: There should be accessor functions for most of the fields here.
//! As with the other tor-netdoc types, I'm deferring those till I know what
//! they should be.

use crate::doc::authcert::AuthCert;
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules};
use crate::parse::tokenize::{Item, ItemResult, NetDocReader};
use crate::types::misc::*;
use crate::{Error, Pos, Result};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::{net, result, time};
use tor_protover::Protocols;

use digest::Digest;
use tor_checkable::{timed::TimerangeBound, ExternallySigned};
use tor_llcrypto as ll;
use tor_llcrypto::pk::rsa::RSAIdentity;

use lazy_static::lazy_static;

/// The lifetime of a networkstatus document.
///
/// In a consensus, this type describes when the consensus may safely
/// be used.  In a vote, this type describes the proposed lifetime for a
/// consensus.
#[allow(dead_code)]
#[derive(Clone)]
pub struct Lifetime {
    valid_after: time::SystemTime,
    fresh_until: time::SystemTime,
    valid_until: time::SystemTime,
}

/// A set of named network parameters.
#[allow(dead_code)]
pub struct NetParams<T> {
    params: HashMap<String, T>,
}

/// A list of subprotocol versions that implementors should/must provide.
#[allow(dead_code)]
pub struct ProtoStatus {
    recommended: Protocols,
    required: Protocols,
}

/// The signature of a single directory authority on a networkstatus document.
#[allow(dead_code)]
pub struct Signature {
    digestname: String,
    id_fingerprint: RSAIdentity,
    sk_fingerprint: RSAIdentity,
    signature: Vec<u8>,
}

/// A collection of signatures that can be checked on a networkstatus document
#[allow(dead_code)]
pub struct SignatureGroup {
    sha256: [u8; 32],
    signatures: Vec<Signature>,
}

/// A shared-random value produced by the directory authorities.
#[allow(dead_code)]
struct SharedRandVal {
    n_reveals: u8,
    value: Vec<u8>,
}

/// Parts of the networkstatus header that are present in every networkstatus.
///
/// NOTE: this type is separate from the header parts that are only in
/// votes or only in consensuses, even though we don't implement votes yet.
#[allow(dead_code)]
struct CommonHeader {
    flavor: Option<String>,
    lifetime: Lifetime,
    client_versions: Vec<String>,
    relay_versions: Vec<String>,
    client_protos: ProtoStatus,
    relay_protos: ProtoStatus,
    params: NetParams<u32>,
    voting_delay: Option<(u32, u32)>,
}

/// The header of a consensus networkstatus.
#[allow(dead_code)]
struct ConsensusHeader {
    hdr: CommonHeader,
    consensus_method: u32,
    shared_rand_prev: Option<SharedRandVal>,
    shared_rand_cur: Option<SharedRandVal>,
}

/// Description of an authority's identity and address.
///
/// (Corresponds to a dir-source line.)
#[allow(dead_code)]
struct DirSource {
    nickname: String,
    identity: RSAIdentity,
    address: String,
    ip: net::IpAddr,
    dir_port: u16,
    or_port: u16,
}

/// A set of known flags on a single router.
///
/// TODO: This should have a more compact representation.  Right now it's
/// using 8 bits per boolean.
#[allow(dead_code)]
struct RouterFlags {
    authority: bool,
    bad_exit: bool,
    exit: bool,
    fast: bool,
    guard: bool,
    hsdir: bool,
    no_ed_consensus: bool,
    stable: bool,
    stale_desc: bool,
    running: bool,
    valid: bool,
    v2dir: bool,
}

/// Recognized weight fields on a single relay in a consensus
#[allow(dead_code)]
pub enum RouterWeight {
    // TODO SPEC: Document that these are u32 in dir-spec.txt
    /// An unmeasured weight for a router.
    Unmeasured(u32),
    /// An measured weight for a router.
    Measured(u32),
}

impl RouterWeight {
    /// Return true if this weight is the result of a successful measurement
    pub fn is_measured(&self) -> bool {
        matches!(self,
                 RouterWeight::Measured(x) if x > &0)
    }
    /// Return true if this weight is nonzero
    pub fn is_nonzero(&self) -> bool {
        match self {
            RouterWeight::Unmeasured(0) => false,
            RouterWeight::Measured(0) => false,
            _ => true,
        }
    }
}

/// A single relay's status as represented in a microdesc consensus.
#[allow(dead_code)]
pub struct MDConsensusRouterStatus {
    nickname: String,
    identity: RSAIdentity,
    published: time::SystemTime,
    addrs: Vec<net::SocketAddr>,
    or_port: u16,
    dir_port: u16,
    md_digest: crate::doc::microdesc::MDDigest,
    flags: RouterFlags,
    version: Option<String>,
    protos: Option<Protocols>,
    weight: RouterWeight,
}

// TODO: These methods should probably become, in whole or in part,
// methods on a RouterStatus trait.
impl MDConsensusRouterStatus {
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn md_digest(&self) -> &crate::doc::microdesc::MDDigest {
        &self.md_digest
    }
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn rsa_identity(&self) -> &RSAIdentity {
        &self.identity
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
    pub fn protovers(&self) -> &Option<Protocols> {
        &self.protos
    }
}

/// All information about a single authority, as represented in a consensus
#[allow(dead_code)]
struct ConsensusVoterInfo {
    dir_source: DirSource,
    contact: String,
    vote_digest: Vec<u8>,
}

/// The signed footer of a consensus netstatus.
#[allow(dead_code)]
struct Footer {
    weights: NetParams<i32>,
}

/// A single microdescriptor consensus netstatus
///
/// TODO: This should possibly turn into a parameterized type, to represent
/// votes and ns consensuses.
#[allow(dead_code)]
pub struct MDConsensus {
    header: ConsensusHeader,
    voters: Vec<ConsensusVoterInfo>,
    routers: Vec<MDConsensusRouterStatus>,
    footer: Footer,
}

impl MDConsensus {
    /// Return a slice of all the routerstatus entries in this consensus.
    pub fn routers(&self) -> &[MDConsensusRouterStatus] {
        &self.routers[..]
    }
}

decl_keyword! {
    /// Keywords that can be used in votes and consensuses.
    NetstatusKW {
        // Header
        "network-status-version" => NETWORK_STATUS_VERSION,
        "vote-status" => VOTE_STATUS,
        "consensus-methods" => CONSENSUS_METHODS,
        "consensus-method" => CONSENSUS_METHOD,
        "published" => PUBLISHED,
        "valid-after" => VALID_AFTER,
        "fresh-until" => FRESH_UNTIL,
        "valid-until" => VALID_UNTIL,
        "voting-delay" => VOTING_DELAY,
        "client-versions" => CLIENT_VERSIONS,
        "server-versions" => SERVER_VERSIONS,
        "known-flags" => KNOWN_FLAGS,
        "flag-thresholds" => FLAG_THRESHOLDS,
        "recommended-client-protocols" => RECOMMENDED_CLIENT_PROTOCOLS,
        "required-client-protocols" => REQUIRED_CLIENT_PROTOCOLS,
        "recommended-relay-protocols" => RECOMMENDED_RELAY_PROTOCOLS,
        "required-relay-protocols" => REQUIRED_RELAY_PROTOCOLS,
        "params" => PARAMS,
        "bandwidth-file-headers" => BANDWIDTH_FILE_HEADERS,
        "bandwidth-file-digest" => BANDWIDTH_FILE_DIGEST,
        // "package" is now ignored.

        // header in consensus, voter section in vote?
        "shared-rand-previous-value" => SHARED_RAND_PREVIOUS_VALUE,
        "shared-rand-current-value" => SHARED_RAND_CURRENT_VALUE,

        // Voter section (both)
        "dir-source" => DIR_SOURCE,
        "contact" => CONTACT,

        // voter section (vote, but not consensus)
        "legacy-dir-key" => LEGACY_DIR_KEY,
        "shared-rand-participate" => SHARED_RAND_PARTICIPATE,
        "shared-rand-commit" => SHARED_RAND_COMMIT,

        // voter section (consensus, but not vote)
        "vote-digest" => VOTE_DIGEST,

        // voter cert beginning (but only the beginning)
        "dir-key-certificate-version" => DIR_KEY_CERTIFICATE_VERSION,

        // routerstatus
        "r" => RS_R,
        "a" => RS_A,
        "s" => RS_S,
        "v" => RS_V,
        "pr" => RS_PR,
        "w" => RS_W,
        "p" => RS_P,
        "m" => RS_M,
        "id" => RS_ID,

        // footer
        "directory-footer" => DIRECTORY_FOOTER,
        "bandwidth-weights" => BANDWIDTH_WEIGHTS,
        "directory-signature" => DIRECTORY_SIGNATURE,
    }
}

lazy_static! {
    /// Shared parts of rules for all kinds of netstatus headers
    static ref NS_HEADER_RULES_COMMON_: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = SectionRules::new();
        rules.add(NETWORK_STATUS_VERSION.rule().required().args(1..=2));
        rules.add(VOTE_STATUS.rule().required().args(1..));
        rules.add(VALID_AFTER.rule().required());
        rules.add(FRESH_UNTIL.rule().required());
        rules.add(VALID_UNTIL.rule().required());
        rules.add(VOTING_DELAY.rule().args(2..));
        rules.add(CLIENT_VERSIONS.rule());
        rules.add(SERVER_VERSIONS.rule());
        rules.add(KNOWN_FLAGS.rule().required());
        rules.add(RECOMMENDED_CLIENT_PROTOCOLS.rule().args(1..));
        rules.add(RECOMMENDED_RELAY_PROTOCOLS.rule().args(1..));
        rules.add(REQUIRED_CLIENT_PROTOCOLS.rule().args(1..));
        rules.add(REQUIRED_RELAY_PROTOCOLS.rule().args(1..));
        rules.add(PARAMS.rule());
        rules
    };
    /// Rules for parsing the header of a consensus.
    static ref NS_HEADER_RULES_CONSENSUS: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = NS_HEADER_RULES_COMMON_.clone();
        rules.add(CONSENSUS_METHOD.rule().args(1..=1));
        rules.add(SHARED_RAND_PREVIOUS_VALUE.rule().args(2..));
        rules.add(SHARED_RAND_CURRENT_VALUE.rule().args(2..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
    /*
    /// Rules for parsing the header of a vote.
    static ref NS_HEADER_RULES_VOTE: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = NS_HEADER_RULES_COMMON_.clone();
        rules.add(CONSENSUS_METHODS.rule().args(1..));
        rules.add(FLAG_THRESHOLDS.rule());
        rules.add(BANDWIDTH_FILE_HEADERS.rule());
        rules.add(BANDWIDTH_FILE_DIGEST.rule().args(1..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
    /// Rules for parsing a single voter's information in a vote.
    static ref NS_VOTERINFO_RULES_VOTE: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = SectionRules::new();
        rules.add(DIR_SOURCE.rule().required().args(6..));
        rules.add(CONTACT.rule().required());
        rules.add(LEGACY_DIR_KEY.rule().args(1..));
        rules.add(SHARED_RAND_PARTICIPATE.rule().no_args());
        rules.add(SHARED_RAND_COMMIT.rule().may_repeat().args(4..));
        rules.add(SHARED_RAND_PREVIOUS_VALUE.rule().args(2..));
        rules.add(SHARED_RAND_CURRENT_VALUE.rule().args(2..));
        // then comes an entire cert: When we implement vote parsing,
        // we should use the authcert code for handling that.
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
     */
    /// Rules for parsing a single voter's information in a consensus
    static ref NS_VOTERINFO_RULES_CONSENSUS: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = SectionRules::new();
        rules.add(DIR_SOURCE.rule().required().args(6..));
        rules.add(CONTACT.rule().required());
        rules.add(VOTE_DIGEST.rule().required());
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
    /// Shared rules for parsing a single routerstatus
    static ref NS_ROUTERSTATUS_RULES_COMMON_: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = SectionRules::new();
        rules.add(RS_A.rule().may_repeat().args(1..));
        rules.add(RS_S.rule().required());
        rules.add(RS_V.rule());
        rules.add(RS_PR.rule().args(0..));
        rules.add(RS_W.rule());
        rules.add(RS_P.rule().args(2..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
    /// Rules for parsing a single routerstatus in an NS consensus
    static ref NS_ROUTERSTATUS_RULES_NSCON: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
        rules.add(RS_R.rule().required().args(8..));
        rules
    };
    /*
    /// Rules for parsing a single routerstatus in a vote
    static ref NS_ROUTERSTATUS_RULES_VOTE: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
        rules.add(RS_R.rule().required().args(8..));
        rules.add(RS_M.rule().may_repeat().args(2..));
        rules.add(RS_ID.rule().may_repeat().args(2..)); // may-repeat?
        rules
    };
*/
    /// Rules for parsing a single routerstatus in a microdesc consensus
    static ref NS_ROUTERSTATUS_RULES_MDCON: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
        rules.add(RS_R.rule().required().args(6..));
        rules.add(RS_M.rule().required().args(1..));
        rules
    };
    /// Rules for parsing consensus fields from a footer.
    static ref NS_FOOTER_RULES: SectionRules<NetstatusKW> = {
        use NetstatusKW::*;
        let mut rules = SectionRules::new();
        rules.add(DIRECTORY_FOOTER.rule().required().no_args());
        // consensus only
        rules.add(BANDWIDTH_WEIGHTS.rule());
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
}

impl ProtoStatus {
    fn from_section(
        sec: &Section<'_, NetstatusKW>,
        recommend_token: NetstatusKW,
        required_token: NetstatusKW,
    ) -> Result<ProtoStatus> {
        fn parse(t: Option<&Item<'_, NetstatusKW>>) -> Result<Protocols> {
            if let Some(item) = t {
                item.args_as_str()
                    .parse::<Protocols>()
                    .map_err(|e| Error::BadArgument(item.pos(), e.to_string()))
            } else {
                Ok(Protocols::new())
            }
        }

        let recommended = parse(sec.get(recommend_token))?;
        let required = parse(sec.get(required_token))?;
        Ok(ProtoStatus {
            recommended,
            required,
        })
    }
}

impl<T> std::str::FromStr for NetParams<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error,
{
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        fn parse_pair<U>(p: &str) -> Result<(String, U)>
        where
            U: std::str::FromStr,
            U::Err: std::error::Error,
        {
            let parts: Vec<_> = p.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(Error::BadArgument(
                    Pos::at(p),
                    "Missing = in key=value list".to_string(),
                ));
            }
            let num = parts[1]
                .parse::<U>()
                .map_err(|e| Error::BadArgument(Pos::at(parts[1]), e.to_string()))?;
            Ok((parts[0].to_string(), num))
        }

        let params = s
            .split(' ')
            .filter(|p| !p.is_empty())
            .map(parse_pair)
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(NetParams { params })
    }
}

impl CommonHeader {
    fn from_section(sec: &Section<'_, NetstatusKW>) -> Result<CommonHeader> {
        use NetstatusKW::*;

        {
            // this unwrap is safe because if there is not at least one
            // token in the section, the section is unparseable.
            let first = sec.first_item().unwrap();
            if first.kwd() != NETWORK_STATUS_VERSION {
                return Err(Error::UnexpectedToken(first.kwd().to_str(), first.pos()));
            }
        }

        let ver_item = sec.required(NETWORK_STATUS_VERSION)?;

        let version: u32 = ver_item.parse_arg(0)?;
        if version != 3 {
            return Err(Error::BadDocumentVersion(version));
        }
        let flavor = ver_item.arg(1).map(str::to_string);

        let valid_after = sec
            .required(VALID_AFTER)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();
        let fresh_until = sec
            .required(FRESH_UNTIL)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();
        let valid_until = sec
            .required(VALID_UNTIL)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();
        let lifetime = Lifetime {
            valid_after,
            fresh_until,
            valid_until,
        };

        let client_versions = sec
            .maybe(CLIENT_VERSIONS)
            .args_as_str()
            .unwrap_or("")
            .split(',')
            .map(str::to_string)
            .collect();
        let relay_versions = sec
            .maybe(SERVER_VERSIONS)
            .args_as_str()
            .unwrap_or("")
            .split(',')
            .map(str::to_string)
            .collect();

        let client_protos = ProtoStatus::from_section(
            sec,
            RECOMMENDED_CLIENT_PROTOCOLS,
            REQUIRED_CLIENT_PROTOCOLS,
        )?;
        let relay_protos =
            ProtoStatus::from_section(sec, RECOMMENDED_RELAY_PROTOCOLS, REQUIRED_RELAY_PROTOCOLS)?;

        let params = sec.maybe(PARAMS).args_as_str().unwrap_or("").parse()?;

        let voting_delay = if let Some(tok) = sec.get(VOTING_DELAY) {
            let n1 = tok.parse_arg(0)?;
            let n2 = tok.parse_arg(1)?;
            Some((n1, n2))
        } else {
            None
        };

        Ok(CommonHeader {
            flavor,
            lifetime,
            client_versions,
            relay_versions,
            client_protos,
            relay_protos,
            params,
            voting_delay,
        })
    }
}

impl SharedRandVal {
    fn from_item(item: &Item<'_, NetstatusKW>) -> Result<Self> {
        match item.kwd() {
            NetstatusKW::SHARED_RAND_PREVIOUS_VALUE | NetstatusKW::SHARED_RAND_CURRENT_VALUE => (),
            _ => return Err(Error::Internal(item.pos())),
        }
        let n_reveals: u8 = item.parse_arg(0)?;
        let val: B64 = item.parse_arg(1)?;
        let value = val.into();
        Ok(SharedRandVal { n_reveals, value })
    }
}

impl ConsensusHeader {
    fn from_section(sec: &Section<'_, NetstatusKW>) -> Result<ConsensusHeader> {
        use NetstatusKW::*;

        let status: &str = sec.required(VOTE_STATUS)?.arg(0).unwrap_or("");
        if status != "consensus" {
            return Err(Error::BadDocumentType);
        }

        // We're ignoring KNOWN_FLAGS in the consensus.

        let hdr = CommonHeader::from_section(sec)?;

        let consensus_method: u32 = sec.required(CONSENSUS_METHOD)?.parse_arg(0)?;

        let shared_rand_prev = sec
            .get(SHARED_RAND_PREVIOUS_VALUE)
            .map(|i| SharedRandVal::from_item(i))
            .transpose()?;

        let shared_rand_cur = sec
            .get(SHARED_RAND_CURRENT_VALUE)
            .map(|i| SharedRandVal::from_item(i))
            .transpose()?;

        Ok(ConsensusHeader {
            hdr,
            consensus_method,
            shared_rand_prev,
            shared_rand_cur,
        })
    }
}

impl DirSource {
    fn from_item(item: &Item<'_, NetstatusKW>) -> Result<Self> {
        if item.kwd() != NetstatusKW::DIR_SOURCE {
            return Err(Error::Internal(item.pos()));
        }
        let nickname = item.required_arg(0)?.to_string();
        let identity = item.parse_arg::<Fingerprint>(1)?.into();
        let address = item.required_arg(2)?.to_string();
        let ip = item.parse_arg(3)?;
        let dir_port = item.parse_arg(4)?;
        let or_port = item.parse_arg(5)?;

        Ok(DirSource {
            nickname,
            identity,
            address,
            ip,
            dir_port,
            or_port,
        })
    }
}

impl ConsensusVoterInfo {
    fn from_section(sec: &Section<'_, NetstatusKW>) -> Result<ConsensusVoterInfo> {
        use NetstatusKW::*;
        if sec.first_item().unwrap().kwd() != DIR_SOURCE {
            return Err(Error::Internal(sec.first_item().unwrap().pos()));
        }
        let dir_source = DirSource::from_item(sec.required(DIR_SOURCE)?)?;

        let contact = sec.required(CONTACT)?.args_as_str().to_string();

        let vote_digest = sec.required(VOTE_DIGEST)?.parse_arg::<B16>(0)?.into();

        Ok(ConsensusVoterInfo {
            dir_source,
            contact,
            vote_digest,
        })
    }
}

impl RouterFlags {
    fn from_item(item: &Item<'_, NetstatusKW>) -> Result<RouterFlags> {
        if item.kwd() != NetstatusKW::RS_S {
            return Err(Error::Internal(item.pos()));
        }
        let mut authority = false;
        let mut bad_exit = false;
        let mut exit = false;
        let mut fast = false;
        let mut guard = false;
        let mut hsdir = false;
        let mut no_ed_consensus = false;
        let mut stable = false;
        let mut stale_desc = false;
        let mut running = true; // 'Running' is implicit.
        let mut valid = true; // 'Valid' is implicit.
        let mut v2dir = false;

        let mut prev: Option<&str> = None;
        for s in item.args() {
            if let Some(p) = prev {
                if p >= s {
                    // Arguments out of order.
                    return Err(Error::BadArgument(
                        item.pos(),
                        "Flags out of order".to_string(),
                    ));
                }
            }
            match s {
                "Authority" => authority = true,
                "BadExit" => bad_exit = true,
                "Exit" => exit = true,
                "Fast" => fast = true,
                "Guard" => guard = true,
                "HSDir" => hsdir = true,
                "NoEdConsensus" => no_ed_consensus = true,
                "Stable" => stable = true,
                "StaleDesc" => stale_desc = true,
                "Running" => running = true,
                "Valid" => valid = true,
                "V2Dir" => v2dir = true,
                _ => (),
            }
            prev = Some(s);
        }

        Ok(RouterFlags {
            authority,
            bad_exit,
            exit,
            fast,
            guard,
            hsdir,
            no_ed_consensus,
            stable,
            stale_desc,
            running,
            valid,
            v2dir,
        })
    }
}

impl Default for RouterWeight {
    fn default() -> RouterWeight {
        RouterWeight::Unmeasured(0)
    }
}

impl RouterWeight {
    fn from_item(item: &Item<'_, NetstatusKW>) -> Result<RouterWeight> {
        if item.kwd() != NetstatusKW::RS_W {
            return Err(Error::Internal(item.pos()));
        }

        let params: NetParams<u32> = item.args_as_str().parse()?;

        let bw = params.params.get("Bandwidth");
        let unmeas = params.params.get("Unmeasured");

        let bw = match bw {
            None => return Ok(RouterWeight::Unmeasured(0)),
            Some(b) => *b,
        };

        match unmeas {
            None | Some(0) => Ok(RouterWeight::Measured(bw)),
            Some(1) => Ok(RouterWeight::Unmeasured(bw)),
            _ => Err(Error::BadArgument(
                item.pos(),
                "unmeasured value".to_string(),
            )),
        }
    }
}

impl MDConsensusRouterStatus {
    fn from_section(sec: &Section<'_, NetstatusKW>) -> Result<MDConsensusRouterStatus> {
        use NetstatusKW::*;
        // R line
        let r_item = sec.required(RS_R)?;
        let nickname = r_item.required_arg(0)?.to_string();
        let ident = r_item.required_arg(1)?.parse::<B64>()?;
        let identity = RSAIdentity::from_bytes(ident.as_bytes())
            .ok_or_else(|| Error::BadArgument(r_item.pos(), "Wrong identity length".to_string()))?;
        let published: time::SystemTime = {
            // TODO: It's annoying to have to do this allocation, since we
            // already have a slice that contains both of these arguments.
            // Instead, we could get a slice of arguments: we'd have to add
            // a feature for that.
            let mut p = r_item.required_arg(2)?.to_string();
            p.push(' ');
            p.push_str(r_item.required_arg(3)?);
            p.parse::<ISO8601TimeSp>()?.into()
        };
        let ipv4addr = r_item.required_arg(4)?.parse::<net::Ipv4Addr>()?;
        let or_port = r_item.required_arg(5)?.parse::<u16>()?;
        let dir_port = r_item.required_arg(6)?.parse::<u16>()?;

        let mut addrs: Vec<net::SocketAddr> = Vec::new();
        addrs.push(net::SocketAddr::V4(net::SocketAddrV4::new(
            ipv4addr, or_port,
        )));

        // A lines
        for a_item in sec.slice(RS_A) {
            addrs.push(a_item.required_arg(0)?.parse::<net::SocketAddr>()?);
        }

        // S line
        let flags = RouterFlags::from_item(sec.required(RS_S)?)?;

        // V line
        let version = sec.maybe(RS_V).args_as_str().map(str::to_string);

        // PR line
        let protos = if let Some(tok) = sec.get(RS_PR) {
            Some(
                tok.args_as_str()
                    .parse::<Protocols>()
                    .map_err(|e| Error::BadArgument(tok.pos(), e.to_string()))?,
            )
        } else {
            None
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

        Ok(MDConsensusRouterStatus {
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

impl Footer {
    fn from_section(sec: &Section<'_, NetstatusKW>) -> Result<Footer> {
        use NetstatusKW::*;
        sec.required(DIRECTORY_FOOTER)?;

        let weights = sec
            .maybe(BANDWIDTH_WEIGHTS)
            .args_as_str()
            .unwrap_or("")
            .parse()?;

        Ok(Footer { weights })
    }
}

/// Result of checking a single authority signature.
enum SigCheckResult {
    Valid,
    Invalid,
    MissingCert,
}

impl Signature {
    fn from_item(item: &Item<'_, NetstatusKW>) -> Result<Signature> {
        if item.kwd() != NetstatusKW::DIRECTORY_SIGNATURE {
            return Err(Error::Internal(item.pos()));
        }

        let (alg, id_fp, sk_fp) = if item.n_args() > 2 {
            (
                item.required_arg(0)?,
                item.required_arg(1)?,
                item.required_arg(2)?,
            )
        } else {
            ("sha1", item.required_arg(0)?, item.required_arg(1)?)
        };

        let digestname = alg.to_string();
        let id_fingerprint = id_fp.parse::<Fingerprint>()?.into();
        let sk_fingerprint = sk_fp.parse::<Fingerprint>()?.into();
        let signature = item.obj("SIGNATURE")?;

        Ok(Signature {
            digestname,
            id_fingerprint,
            sk_fingerprint,
            signature,
        })
    }

    fn matches_cert(&self, cert: &AuthCert) -> bool {
        cert.id_fingerprint() == &self.id_fingerprint
            && cert.sk_fingerprint() == &self.sk_fingerprint
    }

    fn find_cert<'a>(&self, certs: &'a [AuthCert]) -> Option<&'a AuthCert> {
        for c in certs {
            if self.matches_cert(c) {
                return Some(c);
            }
        }
        None
    }

    fn check_signature(&self, signed_digest: &[u8], certs: &[AuthCert]) -> SigCheckResult {
        match self.find_cert(certs) {
            None => SigCheckResult::MissingCert,
            Some(cert) => {
                let key = cert.signing_key();
                match key.verify(signed_digest, &self.signature[..]) {
                    Ok(()) => SigCheckResult::Valid,
                    Err(_) => SigCheckResult::Invalid,
                }
            }
        }
    }
}

/// A MDConsensus object that has been parsed, but not checked for signatures
/// and time.
pub type UncheckedMDConsensus = TimerangeBound<UnvalidatedMDConsensus>;

impl MDConsensus {
    /// Try to parse a single networkstatus document from a string.
    pub fn parse(s: &str) -> Result<UncheckedMDConsensus> {
        let mut reader = NetDocReader::new(s);
        Self::parse_from_reader(&mut reader).map_err(|e| e.within(s))
    }
    fn take_voterinfo(r: &mut NetDocReader<'_, NetstatusKW>) -> Result<Option<ConsensusVoterInfo>> {
        use NetstatusKW::*;

        match r.iter().peek() {
            None => return Ok(None),
            Some(e) if e.is_ok_with_kwd_in(&[RS_R, DIRECTORY_FOOTER]) => return Ok(None),
            _ => (),
        };

        let mut first_dir_source = true;
        // TODO: Extract this pattern into a "parse at second"???
        // Pause at the first 'r', or the second 'dir-source'.
        let mut p = r.pause_at(|i| match i {
            Err(_) => false,
            Ok(item) => {
                item.kwd() == RS_R
                    || if item.kwd() == DIR_SOURCE {
                        let was_first = first_dir_source;
                        first_dir_source = false;
                        !was_first
                    } else {
                        false
                    }
            }
        });

        let voter_sec = NS_VOTERINFO_RULES_CONSENSUS.parse(&mut p)?;
        let voter = ConsensusVoterInfo::from_section(&voter_sec)?;

        Ok(Some(voter))
    }

    fn take_footer(r: &mut NetDocReader<'_, NetstatusKW>) -> Result<Footer> {
        use NetstatusKW::*;
        let mut p = r.pause_at(|i| i.is_ok_with_kwd_in(&[DIRECTORY_SIGNATURE]));
        let footer_sec = NS_FOOTER_RULES.parse(&mut p)?;
        let footer = Footer::from_section(&footer_sec)?;
        Ok(footer)
    }

    fn take_routerstatus(
        r: &mut NetDocReader<'_, NetstatusKW>,
    ) -> Result<Option<MDConsensusRouterStatus>> {
        use NetstatusKW::*;
        match r.iter().peek() {
            None => return Ok(None),
            Some(e) if e.is_ok_with_kwd_in(&[DIRECTORY_FOOTER]) => return Ok(None),
            _ => (),
        };

        let mut first_r = true;
        let mut p = r.pause_at(|i| match i {
            Err(_) => false,
            Ok(item) => {
                item.kwd() == DIRECTORY_FOOTER
                    || if item.kwd() == RS_R {
                        let was_first = first_r;
                        first_r = false;
                        !was_first
                    } else {
                        false
                    }
            }
        });

        let rs_sec = NS_ROUTERSTATUS_RULES_MDCON.parse(&mut p)?;
        let rs = MDConsensusRouterStatus::from_section(&rs_sec)?;
        Ok(Some(rs))
    }

    fn parse_from_reader(r: &mut NetDocReader<'_, NetstatusKW>) -> Result<UncheckedMDConsensus> {
        use NetstatusKW::*;
        let (header, start_pos) = {
            let mut h = r.pause_at(|i| i.is_ok_with_kwd_in(&[DIR_SOURCE]));
            let header_sec = NS_HEADER_RULES_CONSENSUS.parse(&mut h)?;
            let pos = header_sec.first_item().unwrap().offset_in(r.str());
            (ConsensusHeader::from_section(&header_sec)?, pos.unwrap())
        };
        match header.hdr.flavor {
            Some(ref s) if s == "microdesc" => (),
            _ => return Err(Error::BadDocumentType),
        };

        let mut voters = Vec::new();

        while let Some(voter) = MDConsensus::take_voterinfo(r)? {
            voters.push(voter);
        }

        let mut routers = Vec::new();
        while let Some(router) = MDConsensus::take_routerstatus(r)? {
            routers.push(router);
        }

        let footer = MDConsensus::take_footer(r)?;

        let consensus = MDConsensus {
            header,
            voters,
            routers,
            footer,
        };

        // Find the signatures.
        let mut first_sig: Option<Item<'_, NetstatusKW>> = None;
        let mut signatures = Vec::new();
        for item in r.iter() {
            let item = item?;
            if item.kwd() != DIRECTORY_SIGNATURE {
                return Err(Error::UnexpectedToken(item.kwd().to_str(), item.pos()));
            }

            let sig = Signature::from_item(&item)?;
            if first_sig.is_none() {
                first_sig = Some(item);
            }
            signatures.push(sig);
        }

        if first_sig.is_none() {
            return Err(Error::MissingToken("directory-signature"));
        }

        let end_pos = first_sig.unwrap().offset_in(r.str()).unwrap() + "directory-signature ".len();

        // Find the sha256 digest.
        let signed_str = &r.str()[start_pos..end_pos];
        let sha256 = ll::d::Sha256::digest(signed_str.as_bytes()).into();
        let siggroup = SignatureGroup { sha256, signatures };

        let unval = UnvalidatedMDConsensus {
            consensus,
            siggroup,
            n_authorities: None,
        };
        let lifetime = unval.consensus.header.hdr.lifetime.clone();
        let delay = unval.consensus.header.hdr.voting_delay.unwrap_or((0, 0));
        let dist_interval = time::Duration::from_secs(delay.1.into());
        let starting_time = lifetime.valid_after - dist_interval;
        let timebound = TimerangeBound::new(unval, starting_time..lifetime.valid_until);
        Ok(timebound)
    }
}

/// A Microdesc consensus whose signatures have not yet been checked.
pub struct UnvalidatedMDConsensus {
    consensus: MDConsensus,
    siggroup: SignatureGroup,
    n_authorities: Option<u16>,
}

impl UnvalidatedMDConsensus {
    /// Tell the unvalidated consensus how many authorities we believe in.
    ///
    /// Without knowing this number, we can't validate the signature.
    pub fn set_n_authorities(self, n_authorities: u16) -> Self {
        UnvalidatedMDConsensus {
            n_authorities: Some(n_authorities),
            ..self
        }
    }
}

impl ExternallySigned<MDConsensus> for UnvalidatedMDConsensus {
    type Key = [AuthCert];
    type KeyHint = Vec<(RSAIdentity, RSAIdentity)>;
    type Error = Error;

    fn key_is_correct(&self, k: &Self::Key) -> result::Result<(), Self::KeyHint> {
        let (n_ok, missing) = self.siggroup.list_missing(&k[..]);
        match self.n_authorities {
            Some(n) if n_ok > (n / 2) as usize => Ok(()),
            _ => Err(missing
                .iter()
                .map(|cert| (cert.id_fingerprint.clone(), cert.sk_fingerprint.clone()))
                .collect()),
        }
    }
    fn is_well_signed(&self, k: &Self::Key) -> result::Result<(), Self::Error> {
        if self.n_authorities.is_none() {
            return Err(Error::Internal(Pos::None));
        }
        if self.siggroup.validate(self.n_authorities.unwrap(), &k[..]) {
            Ok(())
        } else {
            Err(Error::BadSignature(Pos::None))
        }
    }
    fn dangerously_assume_wellsigned(self) -> MDConsensus {
        self.consensus
    }
}

impl SignatureGroup {
    /// Helper: Return a pair of the number of possible authorities
    /// signatures in this object for which we _could_ find certs, and
    /// a list of the signatures we couldn't find certificates for.
    fn list_missing(&self, certs: &[AuthCert]) -> (usize, Vec<&Signature>) {
        let mut ok: HashSet<RSAIdentity> = HashSet::new();
        let mut missing = Vec::new();
        for sig in self.signatures.iter() {
            if ok.contains(&sig.id_fingerprint) {
                continue;
            }
            if sig.find_cert(certs).is_some() {
                ok.insert(sig.id_fingerprint.clone());
                continue;
            }

            missing.push(sig);
        }
        (ok.len(), missing)
    }

    /// Return true if the signature group defines a valid signature.
    ///
    /// A signature is valid if it signed by more than half of the
    /// authorities.  This API requires that `n_authorities` is the number of
    /// authorities we believe in, and that every cert in `certs` belongs
    /// to a real authority.
    fn validate(&self, n_authorities: u16, certs: &[AuthCert]) -> bool {
        let mut ok: HashSet<RSAIdentity> = HashSet::new();

        for sig in self.signatures.iter() {
            if ok.contains(&sig.id_fingerprint) {
                // We already checked at least one signature using this
                // authority's identity fingerprint.
                continue;
            }

            if &sig.digestname != "sha256" {
                // We don't support sha1 digests here yet. Maybe we never
                // will.
                continue;
            }

            match sig.check_signature(&self.sha256, certs) {
                SigCheckResult::Valid => {
                    ok.insert(sig.id_fingerprint.clone());
                }
                _ => continue,
            }
        }

        ok.len() > (n_authorities / 2) as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CERTS: &str = include_str!("../../testdata/authcerts2.txt");
    const CONSENSUS: &str = include_str!("../../testdata/mdconsensus1.txt");

    #[test]
    fn parse_and_validate() -> Result<()> {
        use tor_checkable::{SelfSigned, Timebound};
        let mut certs = Vec::new();
        for cert in AuthCert::parse_multiple(CERTS) {
            let cert = cert?.check_signature()?.dangerously_assume_timely();
            certs.push(cert);
        }

        assert_eq!(certs.len(), 3);

        let _consensus = MDConsensus::parse(CONSENSUS)?
            .dangerously_assume_timely()
            .set_n_authorities(3)
            .check_signature(&certs)?;

        Ok(())
    }
}
