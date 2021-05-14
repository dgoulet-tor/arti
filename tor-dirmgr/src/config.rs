//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.

use crate::retry::RetryConfig;
use crate::storage::sqlite::SqliteStore;
use crate::Authority;
use crate::{Error, Result};
use tor_netdir::fallback::FallbackDir;
use tor_netdoc::doc::netstatus;

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Configuration information about the Tor network iteslf; used as
/// part of Arti's configuration.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information,
    /// if we don't actually have a directory yet.
    ///
    /// (If we do have a chached directory, we use directory caches
    /// listed there instead.)
    #[serde(default = "fallbacks::default_fallbacks")]
    fallback_cache: Vec<FallbackDir>,

    /// List of directory authorities which we expect to sign
    /// consensus documents.
    #[serde(default = "crate::authority::default_authorities")]
    authority: Vec<Authority>,

    /// A map of network parameters that we're overriding from their
    /// setttings in the consensus.
    // TODO: move this?
    #[serde(default)]
    override_net_params: netstatus::NetParams<i32>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            fallback_cache: fallbacks::default_fallbacks(),
            authority: crate::authority::default_authorities(),
            override_net_params: Default::default(),
        }
    }
}

/// An object used to build a network configuration.  You shouldn't
/// need to use one of these directly for working on the standard Tor
/// network; the defaults are correct for use there.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfigBuilder {
    /// See [`NetworkConfig::fallback_cache`].  This is an option because
    /// we need to distinguish "no fallback directories" from "default
    /// fallback directories".
    fallbacks: Option<Vec<FallbackDir>>,
    /// See [`NetworkConfig::authority`].  This is an option because
    /// we need to distinguish "no fallback directories" from "default
    /// fallback authorities".
    authorities: Option<Vec<Authority>>,
    /// See [`NetworkConfig::override_net_params`].
    override_net_params: netstatus::NetParams<i32>,
}

impl NetworkConfigBuilder {
    /// Return a new NetworkConfigBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `fallback` as a fallback directory.
    ///
    /// Fallback directories are used to reach the Tor network if the
    /// client has not yet retrieved any other directory information.
    ///
    /// By default, if we are using the default set of authorities, we
    /// use a hardcoded set of fallback directories chosen from the
    /// Tor network.  Using this function or the `authority()`
    /// function means that we will not be using the default set of
    /// fallback directories.
    pub fn fallback(&mut self, fallback: FallbackDir) -> &mut Self {
        self.fallbacks.get_or_insert_with(Vec::new).push(fallback);
        self
    }

    /// Add `authority` as a directory authority.
    ///
    /// Directory authorites are a trusted set of servers that
    /// periodically sign documents attesting to the state of the Tor
    /// network.
    ///
    /// By default, we use the set of authorities that maintains the real
    /// Tor network.  Calling this function opts out of using that set.
    pub fn authority(&mut self, auth: Authority) -> &mut Self {
        self.authorities.get_or_insert_with(Vec::new).push(auth);
        self
    }

    /// Overrides the
    ///
    /// By default no parameters will be overridden.
    pub fn override_param(&mut self, param: &str, value: i32) -> &mut Self {
        self.override_net_params.set(param.to_owned(), value);
        self
    }

    /// Try to build a network configuration corresponding to the
    /// information in this builder.
    pub fn build(&self) -> Result<NetworkConfig> {
        let using_default_authorities = self.authorities.is_none();
        let authority = self
            .authorities
            .clone()
            .unwrap_or_else(crate::authority::default_authorities);
        let fallback_cache = if using_default_authorities {
            self.fallbacks
                .clone()
                .unwrap_or_else(fallbacks::default_fallbacks)
        } else {
            self.fallbacks.clone().unwrap_or_else(Vec::new)
        };

        Ok(NetworkConfig {
            fallback_cache,
            authority,
            override_net_params: self.override_net_params.clone(),
        })
    }
}

/// Configuration information for how exactly we download things from the
/// Tor directory caches.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DownloadScheduleConfig {
    /// Top-level configuration for how to retry our initial bootstrap attempt.
    #[serde(default = "default_retry_bootstrap")]
    retry_bootstrap: RetryConfig,

    /// Configuration for how to retry a consensus download.
    #[serde(default)]
    retry_consensus: RetryConfig,

    /// Configuration for how to retry an authority cert download.
    #[serde(default)]
    retry_certs: RetryConfig,

    /// Configuration for how to retry a microdescriptor download.
    #[serde(default)]
    retry_microdescs: RetryConfig,

    /// Number of microdescriptor downloads to attempt in parallel
    #[serde(default = "default_microdesc_parallelism")]
    microdesc_parallelism: u8,
}

/// Default value for retry_bootstrap in DownloadScheduleConfig.
fn default_retry_bootstrap() -> RetryConfig {
    RetryConfig::new(128, std::time::Duration::new(1, 0))
}
/// Default value for microdesc_parallelism in DownloadScheduleConfig.
fn default_microdesc_parallelism() -> u8 {
    4
}

impl Default for DownloadScheduleConfig {
    fn default() -> Self {
        DownloadScheduleConfig {
            retry_bootstrap: default_retry_bootstrap(),
            retry_consensus: Default::default(),
            retry_certs: Default::default(),
            retry_microdescs: Default::default(),
            microdesc_parallelism: default_microdesc_parallelism(),
        }
    }
}

/// Builder for a [`DownloadScheduleConfig`].
#[derive(Debug, Clone, Default)]
pub struct DownloadScheduleConfigBuilder {
    /// The DownloadScheduleConfig we're building.
    ///
    /// (There aren't currently any inconsistent partially constructed
    /// states for this object, so we can just use an internal object.
    /// We don't precisely need a builder here, but let's keep it for
    /// consistency.)
    inner: DownloadScheduleConfig,
}

impl DownloadScheduleConfigBuilder {
    /// Construct a new builder to make a [`DownloadScheduleConfig`].
    ///
    /// All fields are optional, and are set to reasonable defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the configuration for retrying our initial bootstrap attempt.
    ///
    /// Unlike other retry configurations, this should have a higher number
    /// of attempts: if we were to 'give up' here, we would never get a
    /// usable directory.
    pub fn retry_bootstrap(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_bootstrap = sched;
        self
    }

    /// Configure the schedule for retrying a consensus download.
    pub fn retry_consensus(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_consensus = sched;
        self
    }

    /// Configure the schedule for retrying an authority certificate
    /// download.
    pub fn retry_certs(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_certs = sched;
        self
    }

    /// Configure the schedule for retrying a microdescriptor download.
    pub fn retry_microdescs(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_microdescs = sched;
        self
    }

    /// Set the number of microdescriptor downloads that we should be
    /// allowed to launch in parallel.
    ///
    /// The default value is 4.
    pub fn microdesc_parallelism(&mut self, parallelism: u8) -> &mut Self {
        self.inner.microdesc_parallelism = parallelism;
        self
    }

    /// Construct a download schedule configuration from this building.
    pub fn build(&self) -> DownloadScheduleConfig {
        self.inner.clone()
    }
}

/// Builder for a [`NetDirConfig`]
///
/// To create a directory configuration, create one of these,
/// configure it, then call its finalize function.
///
/// # Examples
///
/// ```
/// # use tor_dirmgr::*;
/// # fn x() -> anyhow::Result<()> {
/// let mut builder = NetDirConfigBuilder::new();
/// builder.use_default_cache_path()?;
/// let config: NetDirConfig = builder.finalize()?;
/// # Ok(()) }
/// # x().unwrap()
/// ```
#[derive(Debug, Clone, Default)]
pub struct NetDirConfigBuilder {
    /// Path to use for current (sqlite) directory information.
    cache_path: Option<PathBuf>,

    /// Configuration information about the network.
    network: NetworkConfig,

    /// Configuration information about when to download stuff.
    timing: DownloadScheduleConfig,
}

/// Configuration type for network directory operations.
///
/// This type is immutable once constructed.
///
/// To create an object of this type, use NetDirConfigBuilder.
#[derive(Debug, Clone)]
pub struct NetDirConfig {
    /// Location to use for storing and reading current-format
    /// directory information.
    cache_path: PathBuf,

    /// Configuration information about the network.
    network: NetworkConfig,

    /// Configuration information about when we download things.
    timing: DownloadScheduleConfig,
}

impl NetDirConfigBuilder {
    /// Construct a new NetDirConfig.
    ///
    /// To use this, call at least one method to set a cache directory,
    /// then call load().
    pub fn new() -> Self {
        NetDirConfigBuilder::default()
    }

    /// Set the network information (authorities and fallbacks) from `config`.
    ///
    /// (You shouldn't need to replace the defaults unless you are
    /// using a private Tor network, a testing-only Tor network, or a
    /// network that is otherwise nonstandard.)
    pub fn set_network_config(&mut self, config: NetworkConfig) -> &mut Self {
        self.network = config;
        self
    }

    /// Set the timining information that we use for deciding when to
    /// attempt and retry downloads.
    ///
    /// (The defaults should be reasonable for most use cases.)
    pub fn set_timing_config(&mut self, timing: DownloadScheduleConfig) -> &mut Self {
        self.timing = timing;
        self
    }

    /// Use `path` as the directory to use for current directory files.
    pub fn set_cache_path(&mut self, path: &Path) -> &mut Self {
        self.cache_path = Some(path.to_path_buf());
        self
    }

    /// Try to use the default cache path.
    ///
    /// This will be ~/.cache/arti on unix, and in other suitable
    /// locations on other platforms.
    pub fn use_default_cache_path(&mut self) -> Result<&mut Self> {
        let pd = directories::ProjectDirs::from("org", "torproject", "Arti")
            .ok_or(Error::DirectoryNotPresent)?;

        self.cache_path = Some(pd.cache_dir().into());

        Ok(self)
    }

    /// Use this builder to produce a NetDirConfig that can be used
    /// to load directories
    pub fn finalize(&self) -> Result<NetDirConfig> {
        let cache_path = self
            .cache_path
            .as_ref()
            .ok_or(Error::BadNetworkConfig("No cache path configured"))?;

        if self.network.authority.is_empty() {
            return Err(Error::BadNetworkConfig("No authorities configured").into());
        }
        if self.network.fallback_cache.is_empty() {
            return Err(Error::BadNetworkConfig("No fallback caches configured").into());
        }

        Ok(NetDirConfig {
            cache_path: cache_path.clone(),
            network: self.network.clone(),
            timing: self.timing.clone(),
        })
    }
}

impl NetDirConfig {
    /// Create a SqliteStore from this configuration.
    ///
    /// Note that each time this is called, a new store object will be
    /// created: you probably only want to call this once.
    ///
    /// The `readonly` argument is as for [`SqliteStore::from_path`]
    pub(crate) fn open_sqlite_store(&self, readonly: bool) -> Result<SqliteStore> {
        SqliteStore::from_path(&self.cache_path, readonly)
    }

    /// Return a slice of the configured authorities
    pub fn authorities(&self) -> &[Authority] {
        &self.network.authority[..]
    }

    /// Return the configured set of fallback directories
    pub fn fallbacks(&self) -> &[FallbackDir] {
        &self.network.fallback_cache[..]
    }

    /// Return set of configured networkstatus parameter overrides.
    pub fn override_net_params(&self) -> &netstatus::NetParams<i32> {
        &self.network.override_net_params
    }

    /// Return the timing configuration we should use to decide when to
    /// attemppt and retry downloads.
    pub fn timing(&self) -> &DownloadScheduleConfig {
        &self.timing
    }
}

impl DownloadScheduleConfig {
    /// Return configuration for retrying our entire bootstrap
    /// operation at startup.
    pub fn retry_bootstrap(&self) -> &RetryConfig {
        &self.retry_bootstrap
    }

    /// Return configuration for retrying a consensus download.
    pub fn retry_consensus(&self) -> &RetryConfig {
        &self.retry_consensus
    }

    /// Return configuration for retrying an authority certificate download
    pub fn retry_certs(&self) -> &RetryConfig {
        &self.retry_certs
    }

    /// Return configuration for retrying an authority certificate download
    pub fn retry_microdescs(&self) -> &RetryConfig {
        &self.retry_microdescs
    }

    /// Number of microdescriptor fetches to attempt in parallel
    pub fn microdesc_parallelism(&self) -> usize {
        self.microdesc_parallelism.max(1).into()
    }
}

/// Helpers for initializing the fallback list.
mod fallbacks {
    use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
    use tor_netdir::fallback::FallbackDir;
    /// Return a list of the default fallback directories shipped with
    /// arti.
    pub(crate) fn default_fallbacks() -> Vec<super::FallbackDir> {
        /// Build a fallback directory; panic if input is bad.
        fn fallback(rsa: &str, ed: &str, ports: Vec<&str>) -> FallbackDir {
            let rsa = hex::decode(rsa).expect("Bad hex in built-in fallback list");
            let rsa =
                RsaIdentity::from_bytes(&rsa).expect("Wrong length in built-in fallback list");
            let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
                .expect("Bad hex in built-in fallback list");
            let ed =
                Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
            let mut bld = FallbackDir::builder();
            bld.rsa_identity(rsa).ed_identity(ed);

            ports
                .iter()
                .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
                .for_each(|p| {
                    bld.orport(p);
                });

            bld.build()
                .expect("Unable to build default fallback directory!?")
        }
        include!("fallback_dirs.inc")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn simplest_config() -> Result<()> {
        let tmp = TempDir::new("arti-config").unwrap();

        let dir = NetDirConfigBuilder::new()
            .set_cache_path(tmp.path())
            .finalize()?;

        assert!(dir.authorities().len() >= 3);
        assert!(dir.fallbacks().len() >= 3);

        // TODO: verify other defaults.

        Ok(())
    }
}
