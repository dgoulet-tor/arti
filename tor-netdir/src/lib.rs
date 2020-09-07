mod err;

use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_netdoc::authcert::AuthCert;
use tor_netdoc::microdesc::{self, MDDigest, Microdesc};
use tor_netdoc::netstatus::MDConsensus;
use tor_netdoc::AllowAnnotations;

use ll::pk::rsa::RSAIdentity;
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
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

pub struct NetDir {}

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

    pub fn set_cache_path(&mut self, path: &Path) {
        self.cache_path = Some(path.to_path_buf());
    }

    fn load_certs(&self, path: &Path) -> Result<Vec<AuthCert>> {
        let mut res = Vec::new();
        let text = fs::read_to_string(path)?;
        for cert in AuthCert::parse_multiple(&text) {
            let r = (|| {
                let cert = cert?.check_signature()?.check_valid_now()?; // warn instead.

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
                        "adding cert for {:?} {:?}",
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

    pub fn load_consensus(&self, path: &Path, certs: &Vec<AuthCert>) -> Result<MDConsensus> {
        let text = fs::read_to_string(path)?;
        let consensus = MDConsensus::parse(&text)?
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
            let r = annotated.map(microdesc::AnnotatedMicrodesc::to_microdesc);
            match r {
                Err(e) => warn!("bad microdesc: {}", e),
                Ok(md) => {
                    res.insert(md.get_digest().clone(), md);
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
        let md2path = mdpath.with_extension(".new");

        let certs = self.load_certs(&certspath)?;
        let _consensus = self.load_consensus(&conspath, &certs)?;
        let mut mds = HashMap::new();
        if mdpath.exists() {
            self.load_mds(&mdpath, &mut mds)?;
        }
        if md2path.exists() {
            self.load_mds(&md2path, &mut mds)?;
        }
        info!("Loaded {} microdescriptors", mds.len());

        Ok(NetDir {})
    }
}
