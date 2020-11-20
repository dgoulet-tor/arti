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

mod authority;
pub mod docmeta;
mod err;
pub mod fallback;
mod pick;
pub mod storage;

use crate::storage::legacy::LegacyStore;

use ll::pk::rsa::RSAIdentity;
use tor_llcrypto as ll;
use tor_netdoc::doc::microdesc::{MDDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MDConsensus};

use log::warn;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub use err::Error;
/// A Result using the Error type from the tor-netdir crate
pub type Result<T> = std::result::Result<T, Error>;

pub use authority::Authority;

/// Configuration object for reading directory information from disk.
///
/// To read a directory, create one of these, configure it, then call
/// its load() function.
#[derive(Debug, Clone)]
pub struct NetDirConfig {
    /// A list of authorities to trust.
    ///
    /// A consensus document is considered valid if it signed by more
    /// than half of these authorities.
    authorities: Vec<Authority>,
    /// The directory from which to read legacy directory information.
    ///
    /// This has to be the directory used by a Tor instance
    /// that downloads microdesc info, and has been running fairly
    /// recently.
    legacy_cache_path: Option<PathBuf>,
}

/// Internal: how should we find the base weight of each relay?  This
/// value is global over a whole directory, and depends on the bandwidth
/// weights in the consensus.
#[derive(Copy, Clone, Debug)]
enum WeightFn {
    /// There are no weights at all in the consensus: weight every
    /// relay as 1.
    Uniform,
    /// There are no measured weights in the consensus: count
    /// unmeasured weights as the weights for relays.
    IncludeUnmeasured,
    /// There are measured relays in the consensus; only use those.
    MeasuredOnly,
}

impl WeightFn {
    /// Apply this weight function to the measured or unmeasured bandwidth
    /// of a single router.
    fn apply(&self, w: &netstatus::RouterWeight) -> u32 {
        use netstatus::RouterWeight::*;
        use WeightFn::*;
        match (self, w) {
            (Uniform, _) => 1,
            (IncludeUnmeasured, Unmeasured(u)) => *u,
            (IncludeUnmeasured, Measured(u)) => *u,
            (MeasuredOnly, Unmeasured(_)) => 0,
            (MeasuredOnly, Measured(u)) => *u,
        }
    }
}

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
    /// Value describing how to find the weight to use when picking a
    /// router by weight.
    weight_fn: WeightFn,
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
#[allow(unused)]
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

impl NetDirConfig {
    /// Construct a new NetDirConfig.
    ///
    /// To use this, call at least one method to configure directory
    /// authorities, then call load().
    pub fn new() -> Self {
        NetDirConfig {
            authorities: Vec::new(),
            legacy_cache_path: None,
        }
    }

    /// Add a single directory authority to this configuration.
    ///
    /// The authority's name is `name`; its identity is given as a
    /// hex-encoded RSA identity fingrprint in `ident`.
    pub fn add_authority(&mut self, name: &str, ident: &str) -> Result<()> {
        let ident: Vec<u8> =
            hex::decode(ident).map_err(|_| Error::BadArgument("bad hex identity"))?;
        let v3ident =
            RSAIdentity::from_bytes(&ident).ok_or(Error::BadArgument("wrong identity length"))?;
        self.authorities
            .push(Authority::new(name.to_string(), v3ident));

        Ok(())
    }

    /// Add the default Tor network directory authorities to this
    /// configuration.
    ///
    /// This list is added by default if you try to load() without having
    /// configured any authorities.
    ///
    /// (List generated August 2020.)
    pub fn add_default_authorities(&mut self) {
        self.add_authority("moria1", "D586D18309DED4CD6D57C18FDB97EFA96D330566")
            .unwrap();
        self.add_authority("tor26", "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4")
            .unwrap();
        self.add_authority("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58")
            .unwrap();
        self.add_authority("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226")
            .unwrap();
        self.add_authority("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E")
            .unwrap();
        self.add_authority("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B")
            .unwrap();
        self.add_authority("Faravahar", "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97")
            .unwrap();
        self.add_authority("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66")
            .unwrap();
        self.add_authority("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21")
            .unwrap();
    }

    /// Consume this configuration and return its authority list
    /// TODO: get rid of this function,, or refactor it, or something.
    pub fn into_authorities(self) -> Vec<Authority> {
        self.authorities
    }

    /// Read the authorities from a torrc file in a Chutney directory.
    ///
    /// # Limitations
    ///
    /// This function can handle the format for DirAuthority lines
    /// that chutney generates now, but that's it.  It isn't careful
    /// about line continuations.
    pub fn add_authorities_from_chutney(&mut self, path: &Path) -> Result<()> {
        use std::io::{self, BufRead};
        let pb = path.join("torrc");
        let f = fs::File::open(pb)?;
        for line in io::BufReader::new(f).lines() {
            let line = line?;
            let line = line.trim();
            if !line.starts_with("DirAuthority") {
                continue;
            }
            let elts: Vec<_> = line.split_ascii_whitespace().collect();
            let name = elts[1];
            let v3ident = elts[4];
            if !v3ident.starts_with("v3ident=") {
                warn!("Chutney torrc not in expected format.");
            }
            self.add_authority(name, &v3ident[8..])?;
        }
        Ok(())
    }

    /// Use `path` as the directory to search for directory files.
    ///
    /// This path must contain `cached-certs`, `cached-microdesc-consensus`,
    /// and at least one of `cached-microdescs` and `cached-microdescs.new`.
    pub fn set_legacy_cache_path(&mut self, path: &Path) {
        self.legacy_cache_path = Some(path.to_path_buf());
    }

    // DOCDOC
    fn fill_defaults(&mut self) {
        if self.legacy_cache_path.is_none() {
            let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
            pb.push(".tor");
            self.legacy_cache_path = Some(pb);
        };

        if self.authorities.is_empty() {
            self.add_default_authorities();
        }
    }

    /// Read directory information from the configured storage location.
    pub fn load(&mut self) -> Result<PartialNetDir> {
        self.fill_defaults();
        let store = LegacyStore::new(self.legacy_cache_path.as_ref().unwrap().clone());
        store.load_legacy(&self.authorities[..])
    }
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

impl Default for NetDirConfig {
    fn default() -> Self {
        NetDirConfig::new()
    }
}

impl PartialNetDir {
    /// Create a new PartialNetDir with a given consensus, and no
    /// microdecriptors loaded.
    pub fn new(consensus: MDConsensus) -> Self {
        let weight_fn = pick_weight_fn(&consensus);
        let mut netdir = NetDir {
            consensus,
            mds: HashMap::new(),
            weight_fn,
        };

        for rs in netdir.consensus.routers().iter() {
            netdir.mds.insert(*rs.md_digest(), MDEntry::default());
        }
        PartialNetDir { netdir }
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
            let w = self.weight_fn.apply(r.rs.weight());
            total_bw += w as u64;
            if r.is_usable() {
                have_bw += w as u64;
            }
        }

        // TODO: Do a real calculation here.
        have_bw > (total_bw / 2)
    }
    /// Chose a relay at random.
    ///
    /// Each relay is chosen with probability proportional to a function
    /// `reweight` of the relay and its weight in the consensus.
    ///
    /// This function returns None if (and only if) there are no relays
    /// with nonzero weight.
    //
    // TODO: This API is powerful but tricky; there should be wrappers.
    pub fn pick_relay<'a, R, F>(&'a self, rng: &mut R, reweight: F) -> Option<Relay<'a>>
    where
        R: rand::Rng,
        F: Fn(&Relay<'a>, u32) -> u32,
    {
        pick::pick_weighted(rng, self.relays(), |r| {
            reweight(r, r.weight(self.weight_fn)) as u64
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

/// Helper: Calculate the function we should use to find
/// initial relay weights.
fn pick_weight_fn(consensus: &MDConsensus) -> WeightFn {
    let routers = consensus.routers();
    let has_measured = routers.iter().any(|rs| rs.weight().is_measured());
    let has_nonzero = routers.iter().any(|rs| rs.weight().is_nonzero());
    if !has_nonzero {
        WeightFn::Uniform
    } else if !has_measured {
        WeightFn::IncludeUnmeasured
    } else {
        WeightFn::MeasuredOnly
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
    /// Return the weight of this Relay, according to `wf`.
    fn weight(&self, wf: WeightFn) -> u32 {
        wf.apply(self.rs.weight())
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
