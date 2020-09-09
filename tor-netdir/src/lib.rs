mod err;
mod pick;

use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_netdoc::authcert::AuthCert;
use tor_netdoc::microdesc::{self, MDDigest, Microdesc};
use tor_netdoc::netstatus::{self, MDConsensus};
use tor_netdoc::AllowAnnotations;

use ll::pk::rsa::RSAIdentity;
use log::{info, warn};
use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time;
use tor_llcrypto as ll;

pub use err::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Authority {
    name: String,
    v3ident: RSAIdentity,
}

pub struct NetDirConfig {
    authorities: Vec<Authority>,
    cache_path: Option<PathBuf>,
}

#[derive(Copy, Clone)]
enum WeightFn {
    Uniform,
    IncludeUnmeasured,
    MeasuredOnly,
}

#[allow(unused)]
pub struct NetDir {
    consensus: MDConsensus,
    mds: HashMap<MDDigest, Microdesc>,
    weight_fn: Cell<Option<WeightFn>>,
}

// TODO: This should probably be a more specific struct, with a trait
// that implements it.
#[allow(unused)]
pub struct Relay<'a> {
    rs: &'a netstatus::MDConsensusRouterStatus,
    md: Option<&'a Microdesc>,
}

impl NetDirConfig {
    pub fn new() -> Self {
        NetDirConfig {
            authorities: Vec::new(),
            cache_path: None,
        }
    }
    pub fn add_authority(&mut self, name: &str, ident: &str) -> Result<()> {
        let ident: Vec<u8> =
            hex::decode(ident).map_err(|_| Error::BadArgument("bad hex identity"))?;
        let v3ident = RSAIdentity::from_bytes(&ident)
            .ok_or_else(|| Error::BadArgument("wrong identity length"))?;
        self.authorities.push(Authority {
            name: name.to_string(),
            v3ident,
        });

        Ok(())
    }

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

    pub fn set_cache_path(&mut self, path: &Path) {
        self.cache_path = Some(path.to_path_buf());
    }

    fn load_certs(&self, path: &Path) -> Result<Vec<AuthCert>> {
        let mut res = Vec::new();
        let text = fs::read_to_string(path)?;
        for cert in AuthCert::parse_multiple(&text) {
            let r = (|| {
                let cert = cert?.check_signature()?.check_valid_now()?;

                let found = self
                    .authorities
                    .iter()
                    .any(|a| &a.v3ident == cert.get_id_fingerprint());
                if !found {
                    return Err(Error::Unwanted("no such authority"));
                }
                Ok(cert)
            })();

            match r {
                Err(e) => warn!("unwanted certificate: {}", e),
                Ok(cert) => {
                    info!(
                        "adding cert for {} (SK={})",
                        cert.get_id_fingerprint(),
                        cert.get_sk_fingerprint()
                    );
                    res.push(cert);
                }
            }
        }

        info!("Loaded {} certs", res.len());
        Ok(res)
    }

    pub fn load_consensus(&self, path: &Path, certs: &[AuthCert]) -> Result<MDConsensus> {
        let text = fs::read_to_string(path)?;
        let consensus = MDConsensus::parse(&text)?
            .extend_tolerance(time::Duration::new(86400, 0))
            .check_valid_now()?
            .set_n_authorities(self.authorities.len() as u16)
            .check_signature(certs)?;

        Ok(consensus)
    }

    pub fn load_mds(&self, path: &Path, res: &mut HashMap<MDDigest, Microdesc>) -> Result<()> {
        let text = fs::read_to_string(path)?;
        for annotated in
            microdesc::MicrodescReader::new(&text, AllowAnnotations::AnnotationsAllowed)
        {
            let r = annotated.map(microdesc::AnnotatedMicrodesc::into_microdesc);
            match r {
                Err(e) => warn!("bad microdesc: {}", e),
                Ok(md) => {
                    res.insert(*md.get_digest(), md);
                }
            }
        }
        Ok(())
    }

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
    pub fn relay_from_rs<'a>(&'a self, rs: &'a netstatus::MDConsensusRouterStatus) -> Relay<'a> {
        let md = self.mds.get(rs.get_md_digest());
        Relay { rs, md }
    }
    fn all_relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.consensus
            .get_routers()
            .iter()
            .map(move |rs| self.relay_from_rs(rs))
    }
    pub fn relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.all_relays().filter(Relay::is_usable)
    }
    fn pick_weight_fn(&self) {
        let has_measured = self.relays().any(|r| r.rs.get_weight().is_measured());
        let has_nonzero = self.relays().any(|r| r.rs.get_weight().is_nonzero());
        if !has_nonzero {
            self.weight_fn.set(Some(WeightFn::Uniform));
        } else if !has_measured {
            self.weight_fn.set(Some(WeightFn::IncludeUnmeasured));
        } else {
            self.weight_fn.set(Some(WeightFn::MeasuredOnly));
        }
    }
    fn get_weight_fn(&self) -> WeightFn {
        if self.weight_fn.get().is_none() {
            self.pick_weight_fn();
        }
        self.weight_fn.get().unwrap()
    }
    pub fn pick_relay<'a, R, F>(&'a self, rng: &mut R, reweight: F) -> Option<Relay<'a>>
    where
        R: rand::Rng,
        F: Fn(&Relay<'a>, u32) -> u32,
    {
        let weight_fn = self.get_weight_fn();
        pick::pick_weighted(rng, self.relays(), |r| {
            reweight(r, r.get_weight(weight_fn)) as u64
        })
    }
}

impl<'a> Relay<'a> {
    pub fn is_usable(&self) -> bool {
        self.md.is_some() && self.md.unwrap().get_opt_ed25519_id().is_some()
    }
    pub fn get_id(&self) -> Option<&ll::pk::ed25519::PublicKey> {
        self.md?.get_opt_ed25519_id().as_ref()
    }
    pub fn get_rsa_id(&self) -> &RSAIdentity {
        self.rs.get_rsa_identity()
    }

    fn get_weight(&self, wf: WeightFn) -> u32 {
        use netstatus::RouterWeight::*;
        use WeightFn::*;
        match (wf, self.rs.get_weight()) {
            (Uniform, _) => 1,
            (IncludeUnmeasured, Unmeasured(u)) => *u,
            (IncludeUnmeasured, Measured(u)) => *u,
            (MeasuredOnly, Unmeasured(_)) => 0,
            (MeasuredOnly, Measured(u)) => *u,
        }
    }
}

impl<'a> tor_linkspec::ChanTarget for Relay<'a> {
    fn get_addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.get_addrs()
    }
    fn get_ed_identity(&self) -> &ll::pk::ed25519::PublicKey {
        self.get_id().unwrap()
    }
    fn get_rsa_identity(&self) -> &RSAIdentity {
        self.get_rsa_id()
    }
}

impl<'a> tor_linkspec::ExtendTarget for Relay<'a> {
    fn get_ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        // XXXX unwrap might fail if is_usable is false
        self.md.unwrap().get_ntor_key()
    }
    /// Return the subprotocols implemented by this relay.
    fn get_protovers(&self) -> &tor_protover::Protocols {
        // XXXX unwrap might fail if is_usable is false
        self.rs.get_protovers().as_ref().unwrap()
    }
}
