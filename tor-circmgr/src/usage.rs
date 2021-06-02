//! Code related to tracking what activities a circuit can be used for.

use rand::Rng;
use std::sync::Arc;

use tor_netdir::Relay;
use tor_netdoc::types::policy::PortPolicy;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, TorPath};

use crate::Result;

/// An exit policy, as supported by the last hop of a circuit.
#[derive(Clone, Debug)]
pub(crate) struct ExitPolicy {
    /// Permitted IPv4 ports.
    v4: Arc<PortPolicy>,
    /// Permitted IPv6 ports.
    v6: Arc<PortPolicy>,
}

/// A port that we want to connect to as a client.
///
/// Ordinarily, this is a TCP port, plus a flag to indicate whether we
/// must support IPv4 or IPv6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPort {
    /// True if this is a request to connect to an IPv6 address
    ipv6: bool,
    /// The port that the client wants to connect to
    port: u16,
}

impl TargetPort {
    /// Create a request to make sure that a circuit supports a given
    /// ipv4 exit port.
    pub fn ipv4(port: u16) -> TargetPort {
        TargetPort { ipv6: false, port }
    }

    /// Create a request to make sure that a circuit supports a given
    /// ipv6 exit port.
    pub fn ipv6(port: u16) -> TargetPort {
        TargetPort { ipv6: true, port }
    }

    /// Return true if this port is supported by the provided Relay.
    pub fn is_supported_by(&self, r: &tor_netdir::Relay<'_>) -> bool {
        if self.ipv6 {
            r.supports_exit_port_ipv6(self.port)
        } else {
            r.supports_exit_port_ipv4(self.port)
        }
    }
}

impl ExitPolicy {
    /// Make a new exit policy from a given Relay.
    pub(crate) fn from_relay(relay: &Relay<'_>) -> Self {
        Self {
            v4: Arc::clone(relay.ipv4_policy()),
            v6: Arc::clone(relay.ipv6_policy()),
        }
    }

    /// Return true if a given port is contained in this ExitPolicy.
    fn allows_port(&self, p: TargetPort) -> bool {
        let policy = if p.ipv6 { &self.v6 } else { &self.v4 };
        policy.allows_port(p.port)
    }
}

/// The purpose for which a circuit is being created.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug)]
pub(crate) enum TargetCircUsage {
    /// Use for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Use to exit to one or more ports.
    Exit(Vec<TargetPort>),
}

/// The purposes for which a circuit is usable.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug)]
pub(crate) enum SupportedCircUsage {
    /// Useable for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Usable to exit to to a set of ports.
    Exit(ExitPolicy),
}

impl TargetCircUsage {
    /// Construct path for a given circuit purpose; return it and the
    /// usage that it _actually_ supports.
    pub(crate) fn build_path<'a, R: Rng>(
        &self,
        rng: &mut R,
        netdir: crate::DirInfo<'a>,
    ) -> Result<(TorPath<'a>, SupportedCircUsage)> {
        match self {
            TargetCircUsage::Dir => {
                let path = DirPathBuilder::new().pick_path(rng, netdir)?;
                Ok((path, SupportedCircUsage::Dir))
            }
            TargetCircUsage::Exit(p) => {
                let path = ExitPathBuilder::from_target_ports(p.clone()).pick_path(rng, netdir)?;
                let policy = path
                    .exit_policy()
                    .expect("ExitPathBuilder gave us a one-hop circuit?");
                Ok((path, SupportedCircUsage::Exit(policy)))
            }
        }
    }

    /// Return true if this usage "contains" `target` -- in other words,
    /// if any circuit built for this purpose is also usable for the
    /// purpose of `target`.
    pub(crate) fn contains(&self, target: &TargetCircUsage) -> bool {
        use TargetCircUsage::*;
        match (self, target) {
            (Dir, Dir) => true,
            (Exit(p1), Exit(p2)) => p2.iter().all(|p| p1.contains(p)),
            (_, _) => false,
        }
    }

    /// Return true if this usage "is compatible with" `other`.
    ///
    /// Two usages are compatible if they can share a single circuit.
    #[allow(unused)]
    pub(crate) fn compatible(&self, other: &TargetCircUsage) -> bool {
        use TargetCircUsage::*;
        match (self, other) {
            (Dir, Dir) => true,
            (Exit(_), Exit(_)) => true,
            (_, _) => false,
        }
    }
}

impl SupportedCircUsage {
    /// Return true if this usage "contains" `target` -- in other words,
    /// if any circuit built for this purpose is also usable for the
    /// purpose of `target`.
    pub(crate) fn contains(&self, target: &TargetCircUsage) -> bool {
        use SupportedCircUsage::*;
        match (self, target) {
            (Dir, TargetCircUsage::Dir) => true,
            (Exit(p1), TargetCircUsage::Exit(p2)) => p2.iter().all(|port| p1.allows_port(*port)),
            (_, _) => false,
        }
    }
}
