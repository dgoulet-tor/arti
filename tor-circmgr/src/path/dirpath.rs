//! Code to construct paths to a directory for non-anonymous downloads
use super::*;
use crate::{DirInfo, Error};
use tor_netdir::{Relay, WeightRole};

/// A PathBuilder that can connect to a directory.
pub struct DirPathBuilder {}

impl Default for DirPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DirPathBuilder {
    /// Create a new DirPathBuilder.
    pub fn new() -> Self {
        DirPathBuilder {}
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: DirInfo<'a>) -> Result<TorPath<'a>> {
        // TODO: this will need to learn about directory guards.
        match netdir {
            DirInfo::Fallbacks(f) => {
                let relay = f.pick(rng);
                if let Some(r) = relay {
                    return Ok(TorPath::FallbackOneHop(r));
                }
            }
            DirInfo::Directory(netdir) => {
                let relay = netdir.pick_relay(rng, WeightRole::BeginDir, Relay::is_dir_cache);
                if let Some(r) = relay {
                    return Ok(TorPath::OneHop(r));
                }
            }
        }
        Err(Error::NoRelays("No relays found for use as directory cache".into()).into())
    }
}
