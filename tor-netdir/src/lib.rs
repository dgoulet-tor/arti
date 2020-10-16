//! Represents a clients' eye view of the Tor network.
//!
//! The tor-netdir crate wraps objects from tor-netdoc, and combines
//! them to provide a unified view of the relays on the network.
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
mod pick;

use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::{self, MDDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MDConsensus};
use tor_netdoc::AllowAnnotations;

use ll::pk::rsa::RSAIdentity;
use log::{debug, info, warn};
use std::cell::Cell;
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

/// A view of the Tor directory, suitable for use in building
/// circuits.
pub struct NetDir {
    /// A microdescriptor consensus that lists the members of the network,
    /// and maps each one to a 'microdescriptor' that has more information
    /// about it
    consensus: MDConsensus,
    /// Map from SHA256 digest of microdescriptors to the
    /// microdescriptors themselves.  May include microdescriptors not
    /// used int the consensus: if so, they need to be ignored.
    mds: HashMap<MDDigest, Microdesc>,
    /// Value describing how to find the weight to use when picking a
    /// router by weight.
    weight_fn: Cell<Option<WeightFn>>,
}

/// A view of a relay on the Tor network, suitable for building circuits.
// TODO: This should probably be a more specific struct, with a trait
// that implements it.
//
// XXXX: invalid instances of this object are possible.  Some Relay
// functions will panic if it has no ed25519 key, or if its md is None.
// We should clean that up so that we never construct invalid
// instances of this.
#[allow(unused)]
pub struct Relay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MDConsensusRouterStatus,
    /// A microdescriptor for this relay.
    md: Option<&'a Microdesc>,
    /// Memoized expanded Ed25519 public key.
    ed_identity: Option<ll::pk::ed25519::PublicKey>,
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

    /// Helper: Load the authority certificates from cached-certs.
    ///
    /// Only loads the certificates that match identity keys for
    /// authorities that we believe in.
    ///
    /// Warn about invalid certs, but don't give an error unless there
    /// is a complete failure.
    fn load_certs(&self, path: &Path) -> Result<Vec<AuthCert>> {
        let mut res = Vec::new();
        let text = fs::read_to_string(path)?;
        for cert in AuthCert::parse_multiple(&text) {
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

        info!("Loaded {} certs", res.len());
        Ok(res)
    }

    /// Read the consensus from a provided file, and check it
    /// with a list of authcerts.
    fn load_consensus(&self, path: &Path, certs: &[AuthCert]) -> Result<MDConsensus> {
        let text = fs::read_to_string(path)?;
        let consensus = MDConsensus::parse(&text)?
            .extend_tolerance(time::Duration::new(86400, 0))
            .check_valid_now()?
            .set_n_authorities(self.authorities.len() as u16)
            .check_signature(certs)?;

        Ok(consensus)
    }

    /// Read a list of microdescriptors from a provided file, and check it
    /// with a list of authcerts.
    ///
    /// Warn about invalid microdescs, but don't give an error unless there
    /// is a complete failure.
    fn load_mds(&self, path: &Path, res: &mut HashMap<MDDigest, Microdesc>) -> Result<()> {
        let text = fs::read_to_string(path)?;
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
        Ok(())
    }

    /// Load and validate an entire network directory.
    pub fn load(&mut self) -> Result<NetDir> {
        let cachedir = match &self.cache_path {
            Some(pb) => pb.clone(),
            None => {
                let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
                pb.push(".tor");
                pb
            }
        };
        let certspath = cachedir.join("cached-certs");
        let conspath = cachedir.join("cached-microdesc-consensus");
        let mdpath = cachedir.join("cached-microdescs");
        let md2path = mdpath.with_extension("new");

        if self.authorities.is_empty() {
            self.add_default_authorities();
        }

        let certs = self.load_certs(&certspath)?;
        let consensus = self.load_consensus(&conspath, &certs)?;
        info!("Loaded consensus");
        let mut mds = HashMap::new();
        if mdpath.exists() {
            self.load_mds(&mdpath, &mut mds)?;
        }
        if md2path.exists() {
            self.load_mds(&md2path, &mut mds)?;
        }
        info!("Loaded {} microdescriptors", mds.len());

        Ok(NetDir {
            consensus,
            mds,
            weight_fn: Cell::new(None),
        })
    }
}

impl Default for NetDirConfig {
    fn default() -> Self {
        NetDirConfig::new()
    }
}

impl NetDir {
    /// Construct a (possibly invalid) Relay object from a routerstatus and its
    /// microdescriptor (if any).
    fn relay_from_rs<'a>(&'a self, rs: &'a netstatus::MDConsensusRouterStatus) -> Relay<'a> {
        let md = self.mds.get(rs.md_digest());
        let ed_identity = md.map(|m| m.get_opt_ed25519_id()).flatten();
        Relay {
            rs,
            md,
            ed_identity,
        }
    }
    /// Return an iterator over all Relay objects, including invalid ones
    /// that we can't use.
    fn all_relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.consensus
            .routers()
            .iter()
            .map(move |rs| self.relay_from_rs(rs))
    }
    /// Return an iterator over all usable Relays.
    pub fn relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.all_relays().filter(Relay::is_usable)
    }
    /// Heolper: Set self.weight_fn to the function we should use to find
    /// initial relay weights.
    fn pick_weight_fn(&self) {
        let has_measured = self.relays().any(|r| r.rs.weight().is_measured());
        let has_nonzero = self.relays().any(|r| r.rs.weight().is_nonzero());
        if !has_nonzero {
            self.weight_fn.set(Some(WeightFn::Uniform));
        } else if !has_measured {
            self.weight_fn.set(Some(WeightFn::IncludeUnmeasured));
        } else {
            self.weight_fn.set(Some(WeightFn::MeasuredOnly));
        }
    }
    /// Return the value of self.weight_fn, setting itif needed.
    fn get_weight_fn(&self) -> WeightFn {
        if self.weight_fn.get().is_none() {
            self.pick_weight_fn();
        }
        self.weight_fn.get().unwrap()
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

impl<'a> Relay<'a> {
    /// Return true if this relay is valid and usable.
    ///
    /// This function should return `true` for every Relay we expose
    /// to the user.
    fn is_usable(&self) -> bool {
        self.md.is_some() && self.md.unwrap().get_opt_ed25519_id().is_some()
    }
    /// Return the Ed25519 ID for this relay, assuming it has one.
    // TODO: This should always succeed.
    pub fn id(&self) -> Option<&ll::pk::ed25519::PublicKey> {
        self.ed_identity.as_ref()
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
        self.md.unwrap().ipv4_policy().allows_port(port)
    }
    /// Return the weight of this Relay, according to `wf`.
    fn weight(&self, wf: WeightFn) -> u32 {
        use netstatus::RouterWeight::*;
        use WeightFn::*;
        match (wf, self.rs.weight()) {
            (Uniform, _) => 1,
            (IncludeUnmeasured, Unmeasured(u)) => *u,
            (IncludeUnmeasured, Measured(u)) => *u,
            (MeasuredOnly, Unmeasured(_)) => 0,
            (MeasuredOnly, Measured(u)) => *u,
        }
    }
}

impl<'a> tor_linkspec::ChanTarget for Relay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.addrs()
    }
    fn ed_identity(&self) -> &ll::pk::ed25519::PublicKey {
        self.id().unwrap()
    }
    fn rsa_identity(&self) -> &RSAIdentity {
        self.rsa_id()
    }
}

impl<'a> tor_linkspec::CircTarget for Relay<'a> {
    fn ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        // XXXX unwrap might fail if is_usable is false
        self.md.unwrap().ntor_key()
    }
    /// Return the subprotocols implemented by this relay.
    fn protovers(&self) -> &tor_protover::Protocols {
        // XXXX unwrap might fail if is_usable is false
        self.rs.protovers()
    }
}
