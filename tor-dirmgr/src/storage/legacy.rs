use log::{debug, info, warn};
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::{AnnotatedMicrodesc, Microdesc, MicrodescReader};
use tor_netdoc::doc::netstatus::MDConsensus;
use tor_netdoc::AllowAnnotations;

use std::path::{Path, PathBuf};
use std::time;

use super::InputString;
use crate::{Authority, Error, MDReceiver, PartialNetDir, Result};

pub(crate) struct LegacyStore {
    dir: PathBuf,
}

impl LegacyStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        LegacyStore {
            dir: path.as_ref().into(),
        }
    }

    fn relative_path<P: AsRef<Path>>(&self, relpath: P) -> PathBuf {
        let mut pb = self.dir.to_path_buf();
        pb.push(relpath);
        pb
    }

    pub fn latest_consensus(&self) -> Result<InputString> {
        let p = self.relative_path("cached-microdesc-consensus");
        Ok(InputString::load(p)?)
    }

    pub fn microdescs(&self) -> impl Iterator<Item = Result<InputString>> {
        // impl Iterator<Item=Result<InputString,Self::Error>> {
        let paths = vec![
            self.relative_path("cached-microdescs"),
            self.relative_path("cached-microdescs.new"),
        ];
        Box::new(paths.into_iter().map(InputString::load))
    }

    pub fn authcerts(&self) -> impl Iterator<Item = Result<InputString>> {
        // impl Iterator<Item=Result<InputString,Self::Error>> {
        let paths = vec![self.relative_path("cached-certs")];
        Box::new(paths.into_iter().map(InputString::load))
    }

    /// Helper: Load the authority certificates from a store.
    ///
    /// Only loads the certificates that match identity keys for
    /// authorities that we believe in.
    ///
    /// Warn about invalid certs, but don't give an error unless there
    /// is a complete failure.
    fn load_certs(&self, authorities: &[Authority]) -> Result<Vec<AuthCert>> {
        let mut res = Vec::new();
        for input in self.authcerts().filter_map(Result::ok) {
            let text = input.as_str()?;

            for cert in AuthCert::parse_multiple(text) {
                let r: Result<_> = (|| {
                    let cert = cert?.check_signature()?.check_valid_now()?;

                    let found = authorities.iter().any(|a| a.matches_cert(&cert));
                    if !found {
                        return Err(Error::Unwanted("no such authority").into());
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
    fn load_consensus(&self, certs: &[AuthCert], authorities: &[Authority]) -> Result<MDConsensus> {
        let input = self.latest_consensus()?;
        let text = input.as_str()?;
        let (_, consensus) = MDConsensus::parse(text)?;
        let consensus = consensus
            .extend_tolerance(time::Duration::new(86400, 0))
            .check_valid_now()?
            .set_n_authorities(authorities.len() as u16)
            .check_signature(certs)?;

        Ok(consensus)
    }

    /// Read a list of microdescriptors from a provided store.
    ///
    /// Warn about invalid microdescs, but don't give an error unless there
    /// is a complete failure.
    fn load_mds(&self) -> Result<Vec<Microdesc>> {
        let mut res = Vec::new();
        for input in self.microdescs().filter_map(Result::ok) {
            let text = input.as_str()?;
            for annotated in MicrodescReader::new(&text, AllowAnnotations::AnnotationsAllowed) {
                let r = annotated.map(AnnotatedMicrodesc::into_microdesc);
                match r {
                    Err(e) => warn!("bad microdesc: {}", e),
                    Ok(md) => res.push(md),
                }
            }
        }
        Ok(res)
    }

    /// Load and validate an entire network directory from a legacy Tor cache.
    pub fn load_legacy(&self, authorities: &[Authority]) -> Result<PartialNetDir> {
        let certs = self.load_certs(authorities)?;
        let consensus = self.load_consensus(&certs, authorities)?;
        info!("Loaded consensus");
        let mut partial = PartialNetDir::new(consensus);

        let mds = self.load_mds()?;
        info!("Loaded {} microdescriptors", mds.len());
        let mut n_added = 0_usize;
        for md in mds {
            if partial.add_microdesc(md) {
                n_added += 1;
            }
        }
        info!("Used {} microdescriptors", n_added);

        Ok(partial)
    }
}
