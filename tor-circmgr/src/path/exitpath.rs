//! Code for building paths to an exit relay.

use super::*;
use crate::{DirInfo, Error, TargetPort};
use tor_netdir::{NetDir, WeightRole};

/// Internal representation of PathBuilder.
enum ExitPathBuilderInner<'a> {
    /// Request a path that allows exit to the given TargetPort's.
    WantsPorts(Vec<TargetPort>),

    /// Request a path that uses a given relay as exit node.
    ChosenExit(Relay<'a>),
}

/// A PathBuilder that builds a path to an exit relay supporting a given
/// set of ports.
pub struct ExitPathBuilder<'a> {
    /// The inner ExitPathBuilder state.
    inner: ExitPathBuilderInner<'a>,
}

impl<'a> ExitPathBuilder<'a> {
    /// Create a new builder that will try to get an exit relay
    /// containing all the ports in `ports`.
    pub fn from_target_ports(wantports: Vec<TargetPort>) -> Self {
        Self {
            inner: ExitPathBuilderInner::WantsPorts(wantports),
        }
    }

    /// Create a new builder that will try to build a path with the given exit
    /// relay as the last hop.
    pub fn from_chosen_exit(exit_relay: Relay<'a>) -> Self {
        Self {
            inner: ExitPathBuilderInner::ChosenExit(exit_relay),
        }
    }

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    fn pick_exit<R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<Relay<'a>> {
        match &self.inner {
            ExitPathBuilderInner::WantsPorts(wantports) => Ok(netdir
                .pick_relay(rng, WeightRole::Exit, |r| {
                    wantports.iter().all(|p| p.is_supported_by(r))
                })
                .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?),

            ExitPathBuilderInner::ChosenExit(exit_relay) => Ok(exit_relay.clone()),
        }
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<R: Rng>(&self, rng: &mut R, netdir: DirInfo<'a>) -> Result<TorPath<'a>> {
        // TODO: implement guards
        let netdir = match netdir {
            DirInfo::Fallbacks(_) => return Err(Error::NeedConsensus.into()),
            DirInfo::Directory(d) => d,
        };
        let exit = self.pick_exit(rng, &netdir)?;

        let middle = netdir
            .pick_relay(rng, WeightRole::Middle, |r| !r.in_same_family(&exit))
            .ok_or_else(|| Error::NoRelays("No middle relay found".into()))?;

        let entry = netdir
            .pick_relay(rng, WeightRole::Guard, |r| {
                !r.in_same_family(&middle) && !r.in_same_family(&exit)
            })
            .ok_or_else(|| Error::NoRelays("No entry relay found".into()))?;

        Ok(TorPath::new_multihop(vec![entry, middle, exit]))
    }
}
