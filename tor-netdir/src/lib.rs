//! Represents a clients'-eye view of the Tor network.
//!
//! The tor-netdir crate wraps objects from tor-netdoc, and combines
//! them to provide a unified view of the relays on the network.
//! It is responsible for representing a client's knowledge of the
//! network's state and who is on it.
//!
//! # Limitations
//!
//! Right now, this code doesn't fetch network information: instead,
//! it looks in a local Tor cache directory.
//!
//! Only modern consensus methods and microdescriptor consensuses are
//! supported.
//!
//! TODO: Eventually, there should be the ability to download
//! directory information and store it, but that should probably be
//! another module.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod err;
pub mod fallback;
pub mod params;
mod pick;
mod weight;

use ll::pk::rsa::RsaIdentity;
use tor_llcrypto as ll;
use tor_netdoc::doc::microdesc::{MdDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MdConsensus, RouterStatus};
use tor_netdoc::types::policy::PortPolicy;

use log::warn;
use std::collections::HashSet;
use std::sync::Arc;

pub use err::Error;
pub use weight::WeightRole;
/// A Result using the Error type from the tor-netdir crate
pub type Result<T> = std::result::Result<T, Error>;

use params::{NetParameters, Param};

/// Internal type: either a microdescriptor, or the digest for a
/// microdescriptor that we want.
///
/// This is a separate type so we can use a HashSet instead of
/// HashMap.
#[derive(Clone, Debug)]
enum MdEntry {
    /// The digest for a microdescriptor that is wanted
    /// but not present.
    // TODO: I'd like to make thtis a reference, but that's nontrivial.
    Absent(MdDigest),
    /// A microdescriptor that we have.
    Present(Arc<Microdesc>),
}

impl std::borrow::Borrow<MdDigest> for MdEntry {
    fn borrow(&self) -> &MdDigest {
        self.digest()
    }
}

impl MdEntry {
    /// Return the digest for this entry.
    fn digest(&self) -> &MdDigest {
        match self {
            MdEntry::Absent(d) => d,
            MdEntry::Present(md) => md.digest(),
        }
    }
}

impl From<Microdesc> for MdEntry {
    fn from(md: Microdesc) -> MdEntry {
        MdEntry::Present(Arc::new(md))
    }
}
impl From<MdDigest> for MdEntry {
    fn from(d: MdDigest) -> MdEntry {
        MdEntry::Absent(d)
    }
}

impl PartialEq for MdEntry {
    fn eq(&self, rhs: &MdEntry) -> bool {
        self.digest() == rhs.digest()
    }
}
impl Eq for MdEntry {}

impl std::hash::Hash for MdEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest().hash(state);
    }
}

/// A view of the Tor directory, suitable for use in building
/// circuits.
#[derive(Debug, Clone)]
pub struct NetDir {
    /// A microdescriptor consensus that lists the members of the network,
    /// and maps each one to a 'microdescriptor' that has more information
    /// about it
    consensus: Arc<MdConsensus>,
    /// A map from keys to integer values, distributed in the consensus,
    /// and clamped to certain defaults.
    params: NetParameters,
    /// Map from SHA256 digest of microdescriptors to the
    /// microdescriptors themselves.
    mds: HashSet<MdEntry>,
    /// Weight values to apply to a given relay when deciding how frequently
    /// to choose it for a given role.
    weights: weight::WeightSet,
}

/// A partially build NetDir -- it can't be unwrapped until it has
/// enough information to build safe paths.
#[derive(Debug, Clone)]
pub struct PartialNetDir {
    /// The netdir that's under construction.
    netdir: NetDir,
}

/// A view of a relay on the Tor network, suitable for building circuits.
// TODO: This should probably be a more specific struct, with a trait
// that implements it.
pub struct Relay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MdConsensusRouterStatus,
    /// A microdescriptor for this relay.
    md: &'a Microdesc,
}

/// A relay that we haven't checked for validity or usability in
/// routing.
struct UncheckedRelay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MdConsensusRouterStatus,
    /// A microdescriptor for this relay, if there is one.
    md: Option<&'a Microdesc>,
}

/// A partial or full network directory that we can download
/// microdescriptors for.
pub trait MdReceiver {
    /// Return an iterator over the digests for all of the microdescriptors
    /// that this netdir is missing.
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_>;
    /// Add a microdescriptor to this netdir, if it was wanted.
    ///
    /// Return true if it was indeed wanted.
    fn add_microdesc(&mut self, md: Microdesc) -> bool;
}

impl PartialNetDir {
    /// Create a new PartialNetDir with a given consensus, and no
    /// microdecriptors loaded.
    ///
    /// If `replacement_params` is provided, override network parameters from
    /// the consensus with those from `replacement_params`.
    pub fn new(
        consensus: MdConsensus,
        replacement_params: Option<&netstatus::NetParams<i32>>,
    ) -> Self {
        let mut params = NetParameters::default();
        params.update(consensus.params());
        // We have to do this now, or else changes won't be reflected in our
        // weights.
        if let Some(replacement) = replacement_params {
            let unrecognized = params.update(replacement);
            for u in unrecognized {
                warn!("Unrecognized option: override_net_params.{}", u);
            }
        }

        // Compute the weights we'll want to use for these routers.
        let weights = weight::WeightSet::from_consensus(&consensus, &params);

        let mut netdir = NetDir {
            consensus: Arc::new(consensus),
            params,
            mds: HashSet::new(),
            weights,
        };

        for rs in netdir.consensus.routers().iter() {
            netdir.mds.insert(MdEntry::Absent(*rs.md_digest()));
        }
        PartialNetDir { netdir }
    }

    /// Return the declared lifetime of this PartialNetDir.
    pub fn lifetime(&self) -> &netstatus::Lifetime {
        self.netdir.lifetime()
    }
    /// Fill in as many missing microdescriptors as possible in this
    /// netdir, using the microdescriptors from the previous netdir.
    pub fn fill_from_previous_netdir<'a>(&mut self, prev: &'a NetDir) -> Vec<&'a MdDigest> {
        let mut loaded = Vec::new();
        for ent in prev.mds.iter() {
            if let MdEntry::Present(md) = ent {
                if self.netdir.mds.contains(md.digest()) {
                    loaded.push(md.digest());
                    self.netdir.mds.replace(ent.clone());
                }
            }
        }
        loaded
    }
    /// Return true if this are enough information in this directory
    /// to build multihop paths.
    pub fn have_enough_paths(&self) -> bool {
        self.netdir.have_enough_paths()
    }
    /// If this directory has enough information to build multihop
    /// circuits, return it.
    pub fn unwrap_if_sufficient(self) -> std::result::Result<NetDir, PartialNetDir> {
        if self.netdir.have_enough_paths() {
            Ok(self.netdir)
        } else {
            Err(self)
        }
    }
}

impl MdReceiver for PartialNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        self.netdir.missing_microdescs()
    }
    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        self.netdir.add_microdesc(md)
    }
}

impl NetDir {
    /// Return the declared lifetime of this NetDir.
    pub fn lifetime(&self) -> &netstatus::Lifetime {
        &self.consensus.lifetime()
    }

    /// Construct a (possibly invalid) Relay object from a routerstatus and its
    /// microdescriptor (if any).
    fn relay_from_rs<'a>(
        &'a self,
        rs: &'a netstatus::MdConsensusRouterStatus,
    ) -> UncheckedRelay<'a> {
        let md = match self.mds.get(rs.md_digest()) {
            Some(MdEntry::Present(md)) => Some(Arc::as_ref(md)),
            _ => None,
        };
        UncheckedRelay { rs, md }
    }
    /// Return an iterator over all Relay objects, including invalid ones
    /// that we can't use.
    fn all_relays(&self) -> impl Iterator<Item = UncheckedRelay<'_>> {
        // TODO: I'd like if if we could memoize this so we don't have to
        // do so many hashtable lookups.
        self.consensus
            .routers()
            .iter()
            .map(move |rs| self.relay_from_rs(rs))
    }
    /// Return an iterator over all usable Relays.
    pub fn relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.all_relays().filter_map(UncheckedRelay::into_relay)
    }
    /// Return the parameters from the consensus, clamped to the
    /// correct ranges, with defaults filled in.
    ///
    /// NOTE: that unsupported parameters aren't returned here; only those
    /// values configured in the `params` module are available.
    pub fn params(&self) -> &NetParameters {
        &self.params
    }
    /// Return the fraction of total bandwidth weight for a given role
    /// that we have available information for in this NetDir.
    fn frac_for_role(&self, role: WeightRole) -> f64 {
        let mut total_weight = 0_u64;
        let mut have_weight = 0_u64;

        for r in self.all_relays() {
            let w = self.weights.weight_rs_for_role(&r.rs, role);
            total_weight += w;
            if r.is_usable() {
                have_weight += w
            }
        }

        (have_weight as f64) / (total_weight as f64)
    }
    /// Return true if there is enough information in this NetDir to build
    /// multihop circuits.
    fn have_enough_paths(&self) -> bool {
        // If we can build a randomly chosen path with at least this
        // probability, we know enough information to participate
        // on the network.
        let min_pct = self.params().get(Param::MinPathsForCircsPct);
        let min_frac_paths = (min_pct as f64) / 100.0;

        // What fraction of paths can we build?
        let available = self.frac_for_role(WeightRole::Guard)
            * self.frac_for_role(WeightRole::Middle)
            * self.frac_for_role(WeightRole::Exit);

        available >= min_frac_paths
    }
    /// Chose a relay at random.
    ///
    /// Each relay is chosen with probability proportional to its weight
    /// in the role `role`, and is only selected if the predicate `usable`
    /// returns true for it.
    ///
    /// This function returns None if (and only if) there are no relays
    /// with nonzero weight where `usable` returned true.
    pub fn pick_relay<'a, R, P>(
        &'a self,
        rng: &mut R,
        role: WeightRole,
        usable: P,
    ) -> Option<Relay<'a>>
    where
        R: rand::Rng,
        P: Fn(&Relay<'a>) -> bool,
    {
        pick::pick_weighted(rng, self.relays(), |r| {
            if usable(r) {
                self.weights.weight_rs_for_role(&r.rs, role)
            } else {
                0
            }
        })
    }

    /// Add the provided microdescriptors to this netdir, doing as
    /// little copying as possible.  May return a new netdir, or may
    /// return the same one if there was only one references.
    pub fn extend<I>(self: Arc<NetDir>, mds: I) -> NetDir
    where
        I: IntoIterator<Item = Microdesc>,
    {
        // Get a version of self that we have exclusive access to, either
        // by unwrapping or cloning.
        let mut exclusive = match Arc::try_unwrap(self) {
            Ok(ex) => ex,
            Err(t) => NetDir::clone(&t),
        };
        for md in mds.into_iter() {
            exclusive.add_microdesc(md);
        }
        exclusive
    }
}

impl MdReceiver for NetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        Box::new(self.consensus.routers().iter().filter_map(move |rs| {
            let d = rs.md_digest();
            match self.mds.get(d) {
                Some(MdEntry::Absent(d)) => Some(d),
                _ => None,
            }
        }))
    }
    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        let ent = md.into();
        if self.mds.remove(&ent) {
            self.mds.insert(ent);
            true
        } else {
            false
        }
    }
}

impl<'a> UncheckedRelay<'a> {
    /// Return true if this relay is valid and usable.
    ///
    /// This function should return `true` for every Relay we expose
    /// to the user.
    fn is_usable(&self) -> bool {
        // No need to check for 'valid' or 'running': they are implicit.
        self.md.is_some() && self.rs.ed25519_id_is_usable()
    }
    /// If this is usable, return a corresponding Relay object.
    fn into_relay(self) -> Option<Relay<'a>> {
        if self.is_usable() {
            Some(Relay {
                rs: self.rs,
                md: self.md?,
            })
        } else {
            None
        }
    }
}

impl<'a> Relay<'a> {
    /// Return the Ed25519 ID for this relay.
    pub fn id(&self) -> &ll::pk::ed25519::Ed25519Identity {
        self.md.ed25519_id()
    }
    /// Return the RsaIdentity for this relay.
    pub fn rsa_id(&self) -> &RsaIdentity {
        self.rs.rsa_identity()
    }
    /// Return true if this relay and `other` seem to be the same relay.
    ///
    /// (Two relays are the same if they have the same identity.)
    pub fn same_relay<'b>(&self, other: &Relay<'b>) -> bool {
        self.id() == other.id() && self.rsa_id() == other.rsa_id()
    }
    /// Return true if this relay allows exiting to `port` on IPv4.
    pub fn supports_exit_port_ipv4(&self, port: u16) -> bool {
        !self.rs.is_flagged_bad_exit() && self.md.ipv4_policy().allows_port(port)
    }
    /// Return true if this relay allows exiting to `port` on IPv6.
    pub fn supports_exit_port_ipv6(&self, port: u16) -> bool {
        !self.rs.is_flagged_bad_exit() && self.md.ipv6_policy().allows_port(port)
    }
    /// Return true if this relay is suitable for use as a directory
    /// cache.
    pub fn is_dir_cache(&self) -> bool {
        use tor_protover::ProtoKind;
        self.rs.is_flagged_v2dir()
            && self
                .rs
                .protovers()
                .supports_known_subver(ProtoKind::DirCache, 2)
    }
    /// Return true if both relays are in the same family.
    ///
    /// (Every relay is considered to be in the same family as itself.)
    pub fn in_same_family<'b>(&self, other: &Relay<'b>) -> bool {
        // XXX: features missing from original implementation:
        // - option EnforceDistinctSubnets
        // - option NodeFamilySets
        // see: src/feature/nodelist/nodelist.c:nodes_in_same_family()
        if self.same_relay(other) {
            return true;
        }
        self.md.family().contains(other.rsa_id()) && other.md.family().contains(self.rsa_id())
    }

    /// Return the IPv4 exit policy for this relay.
    pub fn ipv4_policy(&self) -> &Arc<PortPolicy> {
        self.md.ipv4_policy()
    }

    /// Return the IPv6 exit policy for this relay.
    pub fn ipv6_policy(&self) -> &Arc<PortPolicy> {
        self.md.ipv6_policy()
    }
}

impl<'a> tor_linkspec::ChanTarget for Relay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.addrs()
    }
    fn ed_identity(&self) -> &ll::pk::ed25519::Ed25519Identity {
        self.id()
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        self.rsa_id()
    }
}

impl<'a> tor_linkspec::CircTarget for Relay<'a> {
    fn ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        self.md.ntor_key()
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        self.rs.protovers()
    }
}
