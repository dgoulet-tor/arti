//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information ,where to fetch it from, and how to validate it.

use crate::fallback::FallbackSet;
use crate::storage::legacy::LegacyStore;
use crate::Authority;
use crate::PartialNetDir;
use crate::{Error, Result};

use tor_llcrypto::pk::rsa::RSAIdentity;

use log::warn;
use std::fs;
use std::path::{Path, PathBuf};

/// Builder for a NetDirConfig.
///
/// To create a directory configuration, create one of these,
/// configure it, then call its finalize function.
#[derive(Debug, Clone)]
pub struct NetDirConfigBuilder {
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

    /// The fallback directories to use when downloading directory
    /// information
    fallbacks: Option<FallbackSet>,
}

/// Configuration type for network directory operations.
///
/// This type is immutable once constructed.
///
/// To create an object of this type, use NetDirConfigBuilder.
// XXXX Right now this has the same members as NetDirConfigBuilder, but I
// expect them to diverge.
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

    /// A set of directories to use for fetching directory info when we
    /// don't have any directories yet.
    fallbacks: FallbackSet,
}

impl NetDirConfigBuilder {
    /// Construct a new NetDirConfig.
    ///
    /// To use this, call at least one method to configure directory
    /// authorities, then call load().
    pub fn new() -> Self {
        NetDirConfigBuilder {
            authorities: Vec::new(),
            legacy_cache_path: None,
            fallbacks: None,
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

    /// Configure the set of fallback directories to be `fallbacks`, instead
    /// of the defaults.
    pub fn set_fallback_list(&mut self, fallbacks: FallbackSet) {
        self.fallbacks = Some(fallbacks);
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
    pub fn set_legacy_cache_path(&mut self, path: &Path) {
        self.legacy_cache_path = Some(path.to_path_buf());
    }

    /// Consume this builder and return a NetDirConfig that can be used
    /// to load directories
    pub fn finalize(mut self) -> NetDirConfig {
        if self.legacy_cache_path.is_none() {
            let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
            pb.push(".tor");
            self.legacy_cache_path = Some(pb);
        };

        if self.authorities.is_empty() {
            self.add_default_authorities();
        }

        let fallbacks = self.fallbacks.unwrap_or_else(FallbackSet::default);

        NetDirConfig {
            authorities: self.authorities,
            legacy_cache_path: self.legacy_cache_path,
            fallbacks,
        }
    }
}

impl Default for NetDirConfigBuilder {
    fn default() -> Self {
        NetDirConfigBuilder::new()
    }
}

impl NetDirConfig {
    /// Read directory information from the configured storage location.
    pub fn load(&self) -> Result<PartialNetDir> {
        let store = LegacyStore::new(self.legacy_cache_path.as_ref().unwrap().clone());
        store.load_legacy(&self.authorities[..])
    }

    /// Consume this configuration and return its authority list
    /// TODO: get rid of this function,, or refactor it, or something.
    pub fn into_authorities(self) -> Vec<Authority> {
        self.authorities
    }

    /// Return a slice of the configured authorities
    pub fn authorities(&self) -> &[Authority] {
        &self.authorities[..]
    }

    /// Return the configured set of fallback directories
    pub fn fallbacks(&self) -> &FallbackSet {
        &self.fallbacks
    }
}

impl From<NetDirConfigBuilder> for NetDirConfig {
    fn from(builder: NetDirConfigBuilder) -> NetDirConfig {
        builder.finalize()
    }
}
