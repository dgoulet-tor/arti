//! Code for building paths to an exit relay.

use super::*;
use crate::{DirInfo, Error};
use tor_netdir::WeightRole;

/// A PathBuilder that builds a path to an exit node supporting a given
/// set of ports.
///
/// TODO: IPv6 support
pub struct ExitPathBuilder {
    /// List of ports that the exit needs to support
    wantports: Vec<u16>,
}

impl ExitPathBuilder {
    /// Create a new builder that will try to get an exit node
    /// containing all the ports in `ports`.
    pub fn new<P: Into<Vec<u16>>>(ports: P) -> Self {
        let wantports = ports.into();
        ExitPathBuilder { wantports }
    }

    /// Return true if `r` supports every port in `self.wantports`
    fn ports_supported_by(&self, r: &Relay<'_>) -> bool {
        self.wantports.iter().all(|p| r.supports_exit_port(*p))
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: DirInfo<'a>) -> Result<TorPath<'a>> {
        // TODO: implement families
        // TODO: implement guards
        let netdir = match netdir {
            DirInfo::Fallbacks(_) => return Err(Error::NeedConsensus.into()),
            DirInfo::Directory(d) => d,
        };
        let exit = netdir
            .pick_relay(rng, WeightRole::Exit, |r| self.ports_supported_by(r))
            .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?;

        let middle = netdir
            .pick_relay(rng, WeightRole::Middle, |r| !r.same_relay(&exit))
            .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?;

        let entry = netdir
            .pick_relay(rng, WeightRole::Guard, |r| {
                !(r.same_relay(&exit) || r.same_relay(&middle))
            })
            .ok_or_else(|| Error::NoRelays("No entry relay found".into()))?;

        Ok(TorPath::Path(vec![entry, middle, exit]))
    }
}
