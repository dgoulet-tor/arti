//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.

#[cfg(feature = "legacy-storage")]
use crate::storage::legacy::LegacyStore;
use crate::storage::sqlite::SqliteStore;
use crate::Authority;
use crate::{Error, Result};
use tor_netdir::fallback::{FallbackDir, FallbackSet};

use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RSAIdentity;

use log::warn;
use std::fs;
use std::net::SocketAddr;
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

    /// Path to use for current (sqlite) directory information.
    cache_path: Option<PathBuf>,

    /// The fallback directories to use when downloading directory
    /// information
    fallbacks: Option<FallbackSet>,
}

/// Configuration type for network directory operations.
///
/// This type is immutable once constructed.
///
/// To create an object of this type, use NetDirConfigBuilder.
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

    /// Location to use for storing and reading current-format
    /// directory information.
    cache_path: PathBuf,

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
            cache_path: None,
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
    pub fn configure_from_chutney<P>(&mut self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        use std::io::{self, BufRead};
        let pb = path.as_ref().join("000a/torrc"); // Any node directory will do.
        let f = fs::File::open(pb)?;

        let mut fbinfo: Vec<(SocketAddr, RSAIdentity)> = Vec::new();
        // Find the authorities.  These will also be the fallbacks.
        for line in io::BufReader::new(f).lines() {
            let line = line?;
            let line = line.trim();
            if !line.starts_with("DirAuthority") {
                continue;
            }
            let elts: Vec<_> = line.split_ascii_whitespace().collect();
            let name = elts[1];
            let orport = elts[2];
            let v3ident = elts[4];
            if !v3ident.starts_with("v3ident=") || !orport.starts_with("orport=") {
                warn!("Chutney torrc not in expected format.");
            }
            self.add_authority(name, &v3ident[8..])?;

            // XXXX These unwraps should turn into errors.
            let dir_addr: SocketAddr = elts[5].parse().unwrap();
            let port: u16 = orport[7..].parse().unwrap();
            let sockaddr = SocketAddr::new(dir_addr.ip(), port);
            let rsaident = hex::decode(elts[6]).unwrap();
            let rsaident = RSAIdentity::from_bytes(&rsaident[..]).unwrap();

            fbinfo.push((sockaddr, rsaident));
        }

        // Now find the ed identities so we can configure the fallbacks.
        let mut fallbacks = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.metadata()?.is_dir() {
                continue;
            }
            let path = entry.path();
            let rsapath = path.join("fingerprint");
            let edpath = path.join("fingerprint-ed25519");

            if !rsapath.exists() || !edpath.exists() {
                continue;
            }

            // XXXX this is ugly
            // XXXX These unwraps can be crashy.
            let rsa = std::fs::read_to_string(rsapath)?;
            let ed = std::fs::read_to_string(edpath)?;
            let rsa = rsa.split_ascii_whitespace().nth(1).unwrap();
            let ed = ed.split_ascii_whitespace().nth(1).unwrap();
            let rsa = hex::decode(rsa).unwrap();
            let ed = base64::decode(ed).unwrap();
            let rsa = RSAIdentity::from_bytes(&rsa).unwrap();
            let ed = Ed25519Identity::from_bytes(&ed).unwrap();

            if let Some((sa, _)) = fbinfo.iter().find(|(_, rsaid)| rsaid == &rsa) {
                fallbacks.push(FallbackDir::new(rsa, ed, vec![*sa]));
            }
        }

        let fallbacks = FallbackSet::from_fallbacks(fallbacks);
        self.set_fallback_list(fallbacks);

        Ok(())
    }

    /// Use `path` as the directory to search for legacy directory files.
    ///
    /// This path must contain `cached-certs`, `cached-microdesc-consensus`,
    /// and at least one of `cached-microdescs` and `cached-microdescs.new`.
    pub fn set_legacy_cache_path(&mut self, path: &Path) {
        self.legacy_cache_path = Some(path.to_path_buf());
    }

    /// Use `path` as the directory to use for current directory files.
    pub fn set_cache_path(&mut self, path: &Path) {
        self.cache_path = Some(path.to_path_buf());
    }

    /// Consume this builder and return a NetDirConfig that can be used
    /// to load directories
    pub fn finalize(mut self) -> NetDirConfig {
        if self.legacy_cache_path.is_none() {
            // XXXX use dirs crate?
            let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
            pb.push(".tor");
            self.legacy_cache_path = Some(pb);
        };

        if self.cache_path.is_none() {
            // XXXX use dirs crate?
            let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
            pb.push(".arti/cache");
            self.cache_path = Some(pb);
        }

        if self.authorities.is_empty() {
            self.add_default_authorities();
        }

        let fallbacks = self.fallbacks.unwrap_or_else(FallbackSet::default);

        NetDirConfig {
            authorities: self.authorities,
            legacy_cache_path: self.legacy_cache_path,
            cache_path: self.cache_path.unwrap(),
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
    #[cfg(feature = "legacy-storage")]
    /// Read directory information from the configured storage location.
    pub fn load_legacy(&self) -> Result<tor_netdir::PartialNetDir> {
        let store = LegacyStore::new(self.legacy_cache_path.as_ref().unwrap().clone());
        store.load_legacy(&self.authorities[..])
    }

    /// Create a SqliteStore from this configuration.
    ///
    /// Note that each time this is called, a new store object will be
    /// created: you probably only want to call this once.
    pub(crate) fn open_sqlite_store(&self) -> Result<SqliteStore> {
        SqliteStore::from_path(&self.cache_path)
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
