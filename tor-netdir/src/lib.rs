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

pub mod docmeta;
mod err;
pub mod fallback;
mod pick;
mod storage;

use crate::storage::legacy::LegacyStore;

use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::{self, MDDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MDConsensus};
use tor_netdoc::AllowAnnotations;

use ll::pk::rsa::RSAIdentity;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time;
use tor_llcrypto as ll;

pub use err::Error;
/// A Result using the Error type from the tor-netdir crate
pub type Result<T> = std::result::Result<T, Error>;

/// A single authority that signs a consensus directory.
#[derive(Debug)]
pub struct Authority {
    /// A memorable nickname for this authority.
    name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    v3ident: RSAIdentity,
}

/// Configuration object for reading directory information from disk.
///
/// To read a directory, create one of these, configure it, then call
/// its load() function.
pub struct NetDirConfig {
    /// A list of authorities to trust.
    ///
    /// A consensus document is considered valid if it signed by more
    /// than half of these authorities.
    authorities: Vec<Authority>,
    /// The directory from which to read directory information.
    ///
    /// Right now, this has to be the directory used by a Tor instance
    /// that downloads microdesc info, and has been running fairly
    /// recently.
    cache_path: Option<PathBuf>,
}

/// Internal: how should we find the base weight of each relay?  This
/// value is global over a whole directory, and depends on the bandwidth
/// weights in the consensus.
#[derive(Copy, Clone)]
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

/// A view of the Tor directory, suitable for use in building
/// circuits.
pub struct NetDir {
    /// A microdescriptor consensus that lists the members of the network,
    /// and maps each one to a 'microdescriptor' that has more information
    /// about it
    consensus: MDConsensus,
    /// Map from SHA256 digest of microdescriptors to the
    /// microdescriptors themselves.  May include microdescriptors not
    /// used in the consensus: if so, they need to be ignored.
    mds: HashMap<MDDigest, Microdesc>,
    /// Value describing how to find the weight to use when picking a
    /// router by weight.
    weight_fn: Option<WeightFn>,
}

/// A partially build NetDir -- it can't be unwrapped until it has
/// enough information to build safe paths.
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
            cache_path: None,
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
        self.authorities.push(Authority {
            name: name.to_string(),
            v3ident,
        });

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
    pub fn set_cache_path(&mut self, path: &Path) {
        self.cache_path = Some(path.to_path_buf());
    }

    /// Helper: Load the authority certificates from a store.
    ///
    /// Only loads the certificates that match identity keys for
    /// authorities that we believe in.
    ///
    /// Warn about invalid certs, but don't give an error unless there
    /// is a complete failure.
    fn load_certs(&self, store: &LegacyStore) -> Result<Vec<AuthCert>> {
        let mut res = Vec::new();
        for input in store.authcerts().filter_map(Result::ok) {
            let text = input.as_str()?;

            for cert in AuthCert::parse_multiple(text) {
                let r = (|| {
                    let cert = cert?.check_signature()?.check_valid_now()?;

                    let found = self
                        .authorities
                        .iter()
                        .any(|a| &a.v3ident == cert.id_fingerprint());
                    if !found {
                        return Err(Error::Unwanted("no such authority"));
                    }
                    Ok(cert)
                })();

                match r {
                    Err(e) => warn!("unwanted certificate: {}", e),
                    Ok(cert) => {
                        debug!(
                            "adding cert for {} (SK={})",
                            cert.id_fingerprint(),
                            cert.sk_fingerprint()
                        );
                        res.push(cert);
                    }
                }
            }
        }

        info!("Loaded {} certs", res.len());
        Ok(res)
    }

    /// Read the consensus from a provided store, and check it
    /// with a list of authcerts.
    fn load_consensus(&self, store: &LegacyStore, certs: &[AuthCert]) -> Result<MDConsensus> {
        let input = store.latest_consensus()?;
        let text = input.as_str()?;
        let (_, consensus) = MDConsensus::parse(text)?;
        let consensus = consensus
            .extend_tolerance(time::Duration::new(86400, 0))
            .check_valid_now()?
            .set_n_authorities(self.authorities.len() as u16)
            .check_signature(certs)?;

        Ok(consensus)
    }

    /// Read a list of microdescriptors from a provided store, and check it
    /// with a list of authcerts.
    ///
    /// Warn about invalid microdescs, but don't give an error unless there
    /// is a complete failure.
    fn load_mds(&self, store: &LegacyStore, res: &mut HashMap<MDDigest, Microdesc>) -> Result<()> {
        for input in store.microdescs().filter_map(Result::ok) {
            let text = input.as_str()?;
            for annotated in
                microdesc::MicrodescReader::new(&text, AllowAnnotations::AnnotationsAllowed)
            {
                let r = annotated.map(microdesc::AnnotatedMicrodesc::into_microdesc);
                match r {
                    Err(e) => warn!("bad microdesc: {}", e),
                    Ok(md) => {
                        res.insert(*md.digest(), md);
                    }
                }
            }
        }
        Ok(())
    }

    /// Load and validate an entire network directory.
    pub fn load(&mut self) -> Result<PartialNetDir> {
        let cachedir = match &self.cache_path {
            Some(pb) => pb.clone(),
            None => {
                let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
                pb.push(".tor");
                pb
            }
        };
        let store = LegacyStore::new(cachedir);

        if self.authorities.is_empty() {
            self.add_default_authorities();
        }

        let certs = self.load_certs(&store)?;
        let consensus = self.load_consensus(&store, &certs)?;
        info!("Loaded consensus");
        let mut mds = HashMap::new();
        self.load_mds(&store, &mut mds)?;
        info!("Loaded {} microdescriptors", mds.len());

        let mut dir = NetDir {
            consensus,
            mds,
            weight_fn: None,
        };
        dir.set_weight_fn();
        Ok(PartialNetDir { netdir: dir })
    }
}

impl Default for NetDirConfig {
    fn default() -> Self {
        NetDirConfig::new()
    }
}

impl PartialNetDir {
    /// If this directory has enough information to build multihop
    /// circuits, return it.
    pub fn unwrap_if_sufficient(self) -> Result<NetDir> {
        if self.netdir.have_enough_paths() {
            Ok(self.netdir)
        } else {
            Err(Error::NotEnoughInfo)
        }
    }
    /// Return an iterator over the digests for all of the microdescriptors
    /// that this netdir is missing.
    pub fn missing_microdescs(&self) -> impl Iterator<Item = &MDDigest> {
        self.netdir.missing_microdescs()
    }
    /// Add a microdescriptor to this netdir.
    pub fn add_microdesc(&mut self, md: Microdesc) {
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
        let md = self.mds.get(rs.md_digest());
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
    /// Return an iterator over the digests for all of the microdescriptors
    /// that this netdir is missing.
    pub fn missing_microdescs(&self) -> impl Iterator<Item = &MDDigest> {
        self.consensus.routers().iter().filter_map(move |rs| {
            let d = rs.md_digest();
            if self.mds.contains_key(d) {
                None
            } else {
                Some(d)
            }
        })
    }
    /// Add a microdescriptor to this netdir.
    pub fn add_microdesc(&mut self, md: Microdesc) {
        self.mds.insert(*md.digest(), md);
    }
    /// Return true if there is enough information in this NetDir to build
    /// multihop circuits.
    fn have_enough_paths(&self) -> bool {
        // TODO: Implement the real path-based algorithm.
        let mut total_bw = 0_u64;
        let mut have_bw = 0_u64;
        let weight_fn = self.weight_fn.unwrap(); // XXXXX unwrap
        for r in self.all_relays() {
            let w = weight_fn.apply(r.rs.weight());
            total_bw += w as u64;
            if r.is_usable() {
                have_bw += w as u64;
            }
        }

        // TODO: Do a real calculation here.
        have_bw > (total_bw / 2)
    }
    /// Helper: Calculate the function we should use to find
    /// initial relay weights.
    fn pick_weight_fn(&self) -> WeightFn {
        let has_measured = self.relays().any(|r| r.rs.weight().is_measured());
        let has_nonzero = self.relays().any(|r| r.rs.weight().is_nonzero());
        if !has_nonzero {
            WeightFn::Uniform
        } else if !has_measured {
            WeightFn::IncludeUnmeasured
        } else {
            WeightFn::MeasuredOnly
        }
    }
    /// Cache the correct weighting function to use for this directory
    pub fn set_weight_fn(&mut self) {
        self.weight_fn = Some(self.pick_weight_fn())
    }
    /// Return the value of self.weight_fn that we should use.
    fn get_weight_fn(&self) -> WeightFn {
        self.weight_fn.unwrap_or_else(|| self.pick_weight_fn())
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
        let weight_fn = self.get_weight_fn();
        pick::pick_weighted(rng, self.relays(), |r| {
            reweight(r, r.weight(weight_fn)) as u64
        })
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
    /// Return the subprotocols implemented by this relay.
    fn protovers(&self) -> &tor_protover::Protocols {
        self.rs.protovers()
    }
}
