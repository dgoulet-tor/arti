//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.

#[cfg(feature = "legacy-storage")]
use crate::storage::legacy::LegacyStore;
use crate::storage::sqlite::SqliteStore;
use crate::Authority;
use crate::{Error, Result};
use tor_netdir::fallback::FallbackDir;

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Configuration information about the Tor network; used as part of
/// Arti's configuration.
// TODO: move this?
#[derive(Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information,
    /// if we don't actually have a directory yet.
    ///
    /// (If we do have a chached directory, we use directory caches
    /// listed there instead.)
    fallback_cache: Vec<FallbackDir>,

    /// List of directory authorities which we expect to sign
    /// consensus documents.
    authority: Vec<Authority>,
}

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
    fallbacks: Vec<FallbackDir>,
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
    fallbacks: Vec<FallbackDir>,
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
            fallbacks: Vec::new(),
        }
    }

    /// Set the network information (authorities and fallbacks) from `config`.
    pub fn set_network_config(&mut self, config: NetworkConfig) {
        self.authorities = config.authority;
        self.fallbacks = config.fallback_cache;
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
    pub fn finalize(mut self) -> Result<NetDirConfig> {
        if self.legacy_cache_path.is_none() {
            // XXXX use dirs crate?
            let mut pb: PathBuf = std::env::var_os("HOME").unwrap().into();
            pb.push(".tor");
            self.legacy_cache_path = Some(pb);
        };

        if self.cache_path.is_none() {
            return Err(Error::BadNetworkConfig("No cache path configured").into());
        }
        if self.authorities.is_empty() {
            return Err(Error::BadNetworkConfig("No authorities configured").into());
        }
        if self.fallbacks.is_empty() {
            return Err(Error::BadNetworkConfig("No fallback caches configured").into());
        }

        Ok(NetDirConfig {
            authorities: self.authorities,
            legacy_cache_path: self.legacy_cache_path,
            cache_path: self.cache_path.unwrap(),
            fallbacks: self.fallbacks,
        })
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
    pub fn fallbacks(&self) -> &[FallbackDir] {
        &self.fallbacks[..]
    }
}
