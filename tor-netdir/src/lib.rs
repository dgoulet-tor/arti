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
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

mod err;
pub mod fallback;
pub mod params;
mod pick;
mod weight;

use tor_llcrypto as ll;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
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
#[derive(Debug)]
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
    /// Return a relay matching a given Ed25519 identity, if we have a
    /// usable relay with that key.
    #[cfg(test)]
    pub fn by_id(&self, id: &Ed25519Identity) -> Option<Relay<'_>> {
        // TODO This is O(n); we will probably want to fix that if we use
        // this function for anything besides testing.
        self.relays().find(|r| r.id() == id)
    }
    /// Return the parameters from the consensus, clamped to the
    /// correct ranges, with defaults filled in.
    ///
    /// NOTE: that unsupported parameters aren't returned here; only those
    /// values configured in the `params` module are available.
    pub fn params(&self) -> &NetParameters {
        &self.params
    }
    /// Return weighted the fraction of routers we can use.  We only
    /// consider routers that match the predicate `usable`.  We weight
    /// this bandwidth according to the provided `role`.
    ///
    /// Note that this function can return NaN if the consensus contains
    /// no relays that match the predicate, or if those relays have
    /// no weighted bandwidth.
    fn frac_for_role<'a, F>(&'a self, role: WeightRole, usable: F) -> f64
    where
        F: Fn(&UncheckedRelay<'a>) -> bool,
    {
        let mut total_weight = 0_u64;
        let mut have_weight = 0_u64;

        for r in self.all_relays() {
            if !usable(&r) {
                continue;
            }
            let w = self.weights.weight_rs_for_role(&r.rs, role);
            total_weight += w;
            if r.is_usable() {
                have_weight += w
            }
        }

        (have_weight as f64) / (total_weight as f64)
    }
    /// Return the estimated fraction of possible paths that we have
    /// enough microdescriptors to build.
    ///
    /// NOTE: This function can return NaN if the consensus contained
    /// zero bandwidth for some type of router we need.
    fn frac_usable_paths(&self) -> f64 {
        self.frac_for_role(WeightRole::Guard, |u| u.rs.is_flagged_guard())
            * self.frac_for_role(WeightRole::Middle, |_| true)
            * self.frac_for_role(WeightRole::Exit, |u| u.rs.is_flagged_exit())
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
        let available = self.frac_usable_paths();

        // TODO: `available` could be NaN if the consensus is sufficiently
        // messed-up.  If so it's not 100% clear what to fall back on.
        // What does C Tor do? XXXX-SPEC

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
    pub fn id(&self) -> &Ed25519Identity {
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
    /// Return a reference to this relay's "router status" entry in
    /// the consensus.
    ///
    /// The router status entry contains information about the relay
    /// that the authorities voted on directly.  For most use cases,
    /// you shouldn't need them.
    ///
    /// This function is only available if the crate was built with
    /// its `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn rs(&self) -> &netstatus::MdConsensusRouterStatus {
        self.rs
    }
    /// Return a reference to this relay's "microdescriptor" entry in
    /// the consensus.
    ///
    /// A "microdescriptor" is a synopsis of the information about a relay,
    /// used to determine its capabilities and route traffic through it.
    /// For most use cases, you shouldn't need it.
    ///
    /// This function is only available if the crate was built with
    /// its `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn md(&self) -> &Microdesc {
        self.md
    }
}

impl<'a> tor_linkspec::ChanTarget for Relay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.addrs()
    }
    fn ed_identity(&self) -> &Ed25519Identity {
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

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime};
    use tor_llcrypto::pk::rsa;
    use tor_netdoc::doc::netstatus::{Lifetime, RouterFlags, RouterWeight};

    fn rsa_example() -> rsa::PublicKey {
        let der = hex!("30818902818100d527b6c63d6e81d39c328a94ce157dccdc044eb1ad8c210c9c9e22487b4cfade6d4041bd10469a657e3d82bc00cf62ac3b6a99247e573b54c10c47f5dc849b0accda031eca6f6e5dc85677f76dec49ff24d2fcb2b5887fb125aa204744119bb6417f45ee696f8dfc1c2fc21b2bae8e9e37a19dc2518a2c24e7d8fd7fac0f46950203010001");
        rsa::PublicKey::from_der(&der).unwrap()
    }

    // Build a fake network with enough information to enable some basic
    // tests.
    fn construct_network() -> (MdConsensus, Vec<Microdesc>) {
        let f = RouterFlags::RUNNING | RouterFlags::VALID | RouterFlags::V2DIR;
        // define 4 groups of flags
        let flags = [
            f,
            f | RouterFlags::EXIT,
            f | RouterFlags::GUARD,
            f | RouterFlags::EXIT | RouterFlags::GUARD,
        ];

        let now = SystemTime::now();
        let one_day = Duration::new(86400, 0);
        let mut bld = MdConsensus::builder();
        bld.consensus_method(34)
            .lifetime(Lifetime::new(now, now + one_day / 2, now + one_day).unwrap())
            .param("bwweightscale", 1)
            .weights("".parse().unwrap());

        let mut microdescs = Vec::new();
        for idx in 0..40_u8 {
            // Each relay gets a couple of no-good onion keys.
            // Its identity fingerprints are set to `idx`, repeating.
            // They all get the same address.
            let flags = flags[(idx / 10) as usize];
            let policy = if flags.contains(RouterFlags::EXIT) {
                "accept 80,443"
            } else {
                "reject 1-65535"
            };
            // everybody is family with the adjacent relay.
            let fam_id = [idx ^ 1; 20];
            let family = hex::encode(&fam_id);

            let md = Microdesc::builder()
                .tap_key(rsa_example())
                .ntor_key((*b"----nothing in dirmgr uses this-").into())
                .ed25519_id([idx; 32].into())
                .family(family.parse().unwrap())
                .parse_ipv4_policy(policy)
                .unwrap()
                .testing_md()
                .unwrap();
            let protocols = if idx % 2 == 0 {
                // even-numbered routers are dircaches.
                "DirCache=2".parse().unwrap()
            } else {
                "".parse().unwrap()
            };
            let weight = RouterWeight::Measured(1000 * (idx % 10 + 1) as u32);
            bld.rs()
                .identity([idx; 20].into())
                .add_or_port("127.0.0.1:9001".parse().unwrap())
                .doc_digest(*md.digest())
                .protos(protocols)
                .set_flags(flags)
                .weight(weight)
                .build_into(&mut bld)
                .unwrap();
            microdescs.push(md);
        }

        let consensus = bld.testing_consensus().unwrap();

        (consensus, microdescs)
    }

    // Basic functionality for a partial netdir: Add microdescriptors,
    // then you have a netdir.
    #[test]
    fn partial_netdir() {
        let (consensus, microdescs) = construct_network();
        let dir = PartialNetDir::new(consensus, None);

        // Check the lifetime
        let lifetime = dir.lifetime();
        assert_eq!(
            lifetime
                .valid_until()
                .duration_since(lifetime.valid_after())
                .unwrap(),
            Duration::new(86400, 0)
        );

        // No microdescriptors, so we don't have enough paths, and can't
        // advance.
        assert_eq!(dir.have_enough_paths(), false);
        let mut dir = match dir.unwrap_if_sufficient() {
            Ok(_) => panic!(),
            Err(d) => d,
        };

        let missing: HashSet<_> = dir.missing_microdescs().collect();
        assert_eq!(missing.len(), 40);
        assert_eq!(missing.len(), dir.netdir.consensus.routers().len());
        for md in microdescs.iter() {
            assert!(missing.contains(md.digest()));
        }

        // Now add all the mds and try again.
        for md in microdescs {
            let wanted = dir.add_microdesc(md);
            assert!(wanted);
        }

        let missing: HashSet<_> = dir.missing_microdescs().collect();
        assert!(missing.is_empty());
        assert!(dir.have_enough_paths());
        let _complete = match dir.unwrap_if_sufficient() {
            Ok(d) => d,
            Err(_) => panic!(),
        };
    }

    #[test]
    fn override_params() {
        let (consensus, _microdescs) = construct_network();
        let override_p = "bwweightscale=2 doesnotexist=77 circwindow=500"
            .parse()
            .unwrap();
        let dir = PartialNetDir::new(consensus.clone(), Some(&override_p));
        let params = &dir.netdir.params;
        assert_eq!(params.get(Param::BwWeightScale), 2);
        assert_eq!(params.get(Param::CircWindow), 500);

        // try again without the override.
        let dir = PartialNetDir::new(consensus, None);
        let params = &dir.netdir.params;
        assert_eq!(params.get(Param::BwWeightScale), 1);
        assert_eq!(params.get(Param::CircWindow), 1000);
    }

    #[test]
    fn fill_from_previous() {
        let (consensus, microdescs) = construct_network();

        let mut dir = PartialNetDir::new(consensus.clone(), None);
        for md in microdescs.iter().skip(2) {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir1 = dir.unwrap_if_sufficient().unwrap();
        assert_eq!(dir1.missing_microdescs().count(), 2);

        let mut dir = PartialNetDir::new(consensus, None);
        assert_eq!(dir.missing_microdescs().count(), 40);
        dir.fill_from_previous_netdir(&dir1);
        assert_eq!(dir.missing_microdescs().count(), 2);
    }

    #[test]
    fn path_count() {
        let low_threshold = "min_paths_for_circs_pct=64".parse().unwrap();
        let high_threshold = "min_paths_for_circs_pct=65".parse().unwrap();

        let (consensus, microdescs) = construct_network();

        let mut dir = PartialNetDir::new(consensus.clone(), Some(&low_threshold));
        for (idx, md) in microdescs.iter().enumerate() {
            if idx % 7 == 2 {
                continue; // skip a few relays.
            }
            dir.add_microdesc(md.clone());
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        // We  have 40 relays that we know about from the consensus.
        assert_eq!(dir.all_relays().count(), 40);

        // But only 34 are usable.
        assert_eq!(dir.relays().count(), 34);

        // For guards: mds 20..=39 correspond to Guard relays.
        // Their bandwidth is 2*(1000+2000+...10000) = 110_000.
        // We skipped 23, 30, and 37.  They have bandwidth
        // 4000 + 1000 + 8000 = 13_000.  So our fractional bandwidth
        // should be (110-13)/110.
        let f = dir.frac_for_role(WeightRole::Guard, |u| u.rs.is_flagged_guard());
        assert!(((97.0 / 110.0) - f).abs() < 0.000001);

        // For exits: mds 10..=19 and 30..=39 correspond to Exit relays.
        // We skipped 16, 30,  and 37. Per above our fractional bandwidth is
        // (110-16)/110.
        let f = dir.frac_for_role(WeightRole::Exit, |u| u.rs.is_flagged_exit());
        assert!(((94.0 / 110.0) - f).abs() < 0.000001);

        // For middles: all relays are middles. We skipped 2, 9, 16,
        // 23, 30, and 37. Per above our fractional bandwidth is
        // (220-33)/220
        let f = dir.frac_for_role(WeightRole::Middle, |_| true);
        assert!(((187.0 / 220.0) - f).abs() < 0.000001);

        // Multiplying those together, we get the fraction of paths we can
        // build at ~0.64052066, which is above the threshold we set above for
        // MinPathsForCircsPct.
        let f = dir.frac_usable_paths();
        assert!((f - 0.64052066).abs() < 0.000001);

        // But if we try again with a slightly higher threshold...
        let mut dir = PartialNetDir::new(consensus, Some(&high_threshold));
        for (idx, md) in microdescs.into_iter().enumerate() {
            if idx % 7 == 2 {
                continue; // skip a few relays.
            }
            dir.add_microdesc(md);
        }
        assert!(dir.unwrap_if_sufficient().is_err());
    }

    #[test]
    fn test_pick() {
        use crate::pick::test::*; // for stochastic testing
        use tor_linkspec::ChanTarget;

        let (consensus, microdescs) = construct_network();
        let mut dir = PartialNetDir::new(consensus.clone(), None);
        for md in microdescs.into_iter() {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        let total = get_iters() as isize;
        let mut picked = [0_isize; 40];
        let mut rng = get_rng();
        for _ in 0..get_iters() {
            let r = dir.pick_relay(&mut rng, WeightRole::Middle, |r| {
                r.supports_exit_port_ipv4(80)
            });
            let r = r.unwrap();
            let id_byte = r.rsa_identity().as_bytes()[0];
            picked[id_byte as usize] += 1;
        }
        // non-exits should never get picked.
        for idx in 0..10 {
            assert_eq!(picked[idx], 0);
        }
        for idx in 20..30 {
            assert_eq!(picked[idx], 0);
        }
        // We didn't we any non-default weights, so the other routers get
        // weighted proportional to their bandwidth.
        check_close(picked[19], (total * 10) / 110);
        check_close(picked[38], (total * 9) / 110);
        check_close(picked[39], (total * 10) / 110);
    }

    #[test]
    fn relay_funcs() {
        let (consensus, microdescs) = construct_network();
        let mut dir = PartialNetDir::new(consensus.clone(), None);
        for md in microdescs.into_iter() {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        // Pick out a few relays by ID.
        let r0 = dir.by_id(&[0; 32].into()).unwrap();
        let r1 = dir.by_id(&[1; 32].into()).unwrap();
        let r2 = dir.by_id(&[2; 32].into()).unwrap();
        let r3 = dir.by_id(&[3; 32].into()).unwrap();

        assert_eq!(r0.id(), &[0; 32].into());
        assert_eq!(r0.rsa_id(), &[0; 20].into());
        assert_eq!(r1.id(), &[1; 32].into());
        assert_eq!(r1.rsa_id(), &[1; 20].into());

        assert!(r0.same_relay(&r0));
        assert!(r1.same_relay(&r1));
        assert!(!r1.same_relay(&r0));

        assert!(r0.is_dir_cache());
        assert!(!r1.is_dir_cache());
        assert!(r2.is_dir_cache());
        assert!(!r3.is_dir_cache());

        assert!(!r0.supports_exit_port_ipv4(80));
        assert!(!r1.supports_exit_port_ipv4(80));
        assert!(!r2.supports_exit_port_ipv4(80));
        assert!(!r3.supports_exit_port_ipv4(80));

        assert!(r0.in_same_family(&r0));
        assert!(r0.in_same_family(&r1));
        assert!(r1.in_same_family(&r0));
        assert!(r1.in_same_family(&r1));
        assert!(!r0.in_same_family(&r2));
        assert!(!r2.in_same_family(&r0));
        assert!(r2.in_same_family(&r2));
        assert!(r2.in_same_family(&r3));
    }
}
