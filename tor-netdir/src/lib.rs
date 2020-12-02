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
mod pick;
mod weight;

use ll::pk::rsa::RSAIdentity;
use tor_llcrypto as ll;
use tor_netdoc::doc::microdesc::{MDDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MDConsensus};

use std::collections::HashMap;

pub use err::Error;
pub use weight::WeightRole;
/// A Result using the Error type from the tor-netdir crate
pub type Result<T> = std::result::Result<T, Error>;

/// Internal type: wraps Option<Microdesc> to prevent confusion.
///
/// (Having an Option type be the value of a HashMap makes things a
/// bit confused IMO.)
#[derive(Clone, Debug, Default)]
struct MDEntry {
    /// The microdescriptor in this entry, or None if a microdescriptor
    /// is wanted but not present.
    md: Option<Microdesc>,
}

/// A view of the Tor directory, suitable for use in building
/// circuits.
#[derive(Debug, Clone)]
pub struct NetDir {
    /// A microdescriptor consensus that lists the members of the network,
    /// and maps each one to a 'microdescriptor' that has more information
    /// about it
    consensus: MDConsensus,
    /// Map from SHA256 digest of microdescriptors to the
    /// microdescriptors themselves.
    mds: HashMap<MDDigest, MDEntry>,
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
    rs: &'a netstatus::MDConsensusRouterStatus,
    /// A microdescriptor for this relay.
    md: &'a Microdesc,
}

/// A relay that we haven't checked for validity or usability in
/// routing.
struct UncheckedRelay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MDConsensusRouterStatus,
    /// A microdescriptor for this relay, if there is one.
    md: Option<&'a Microdesc>,
}

/// A partial or full network directory that we can download
/// microdescriptors for.
pub trait MDReceiver {
    /// Return an iterator over the digests for all of the microdescriptors
    /// that this netdir is missing.
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MDDigest> + '_>;
    /// Add a microdescriptor to this netdir, if it was wanted.
    ///
    /// Return true if it was indeed wanted.
    fn add_microdesc(&mut self, md: Microdesc) -> bool;
}

impl PartialNetDir {
    /// Create a new PartialNetDir with a given consensus, and no
    /// microdecriptors loaded.
    pub fn new(consensus: MDConsensus) -> Self {
        // Compute the weights we'll want to use for these routers.
        let weights = weight::WeightSet::from_consensus(&consensus);

        let mut netdir = NetDir {
            consensus,
            mds: HashMap::new(),
            weights,
        };

        for rs in netdir.consensus.routers().iter() {
            netdir.mds.insert(*rs.md_digest(), MDEntry::default());
        }
        PartialNetDir { netdir }
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

impl MDReceiver for PartialNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MDDigest> + '_> {
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
        rs: &'a netstatus::MDConsensusRouterStatus,
    ) -> UncheckedRelay<'a> {
        let md = match self.mds.get(rs.md_digest()) {
            Some(MDEntry { md: Some(md) }) => Some(md),
            _ => None,
        };
        UncheckedRelay { rs, md }
    }
    /// Return an iterator over all Relay objects, including invalid ones
    /// that we can't use.
    fn all_relays(&self) -> impl Iterator<Item = UncheckedRelay<'_>> {
        self.consensus
            .routers()
            .iter()
            .map(move |rs| self.relay_from_rs(rs))
    }
    /// Return an iterator over all usable Relays.
    pub fn relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.all_relays().filter_map(UncheckedRelay::into_relay)
    }
    /// Return true if there is enough information in this NetDir to build
    /// multihop circuits.
    fn have_enough_paths(&self) -> bool {
        // TODO: Implement the real path-based algorithm.
        let mut total_bw = 0_u64;
        let mut have_bw = 0_u64;
        for r in self.all_relays() {
            let w = self.weights.weight_rs_for_role(&r.rs, WeightRole::Middle);
            total_bw += w;
            if r.is_usable() {
                have_bw += w;
            }
        }

        // TODO: Do a real calculation here.
        have_bw > (total_bw / 2)
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

impl MDReceiver for NetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MDDigest> + '_> {
        Box::new(self.consensus.routers().iter().filter_map(move |rs| {
            let d = rs.md_digest();
            match self.mds.get(d) {
                Some(MDEntry { md: Some(_) }) => None,
                _ => Some(d),
            }
        }))
    }
    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        if let Some(entry) = self.mds.get_mut(md.digest()) {
            entry.md = Some(md);
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
                md: self.md.unwrap(),
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
    /// Return the RSAIdentity for this relay.
    pub fn rsa_id(&self) -> &RSAIdentity {
        self.rs.rsa_identity()
    }
    /// Return true if this relay and `other` seem to be the same relay.
    ///
    /// (Two relays are the same if they have the same identity.)
    pub fn same_relay<'b>(&self, other: &Relay<'b>) -> bool {
        self.id() == other.id() && self.rsa_id() == other.rsa_id()
    }
    /// Return true if this relay allows exiting to `port` on IPv4.
    // XXXX ipv4/ipv6
    pub fn supports_exit_port(&self, port: u16) -> bool {
        !self.rs.is_flagged_bad_exit() && self.md.ipv4_policy().allows_port(port)
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
}

impl<'a> tor_linkspec::ChanTarget for Relay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.addrs()
    }
    fn ed_identity(&self) -> &ll::pk::ed25519::Ed25519Identity {
        self.id()
    }
    fn rsa_identity(&self) -> &RSAIdentity {
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
