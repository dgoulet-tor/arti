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
            v4: relay.ipv4_policy(),
            v6: relay.ipv6_policy(),
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
}

impl crate::mgr::AbstractSpec for SupportedCircUsage {
    type Usage = TargetCircUsage;

    fn supports(&self, target: &TargetCircUsage) -> bool {
        use SupportedCircUsage::*;
        match (self, target) {
            (Dir, TargetCircUsage::Dir) => true,
            (Exit(p1), TargetCircUsage::Exit(p2)) => p2.iter().all(|port| p1.allows_port(*port)),
            (_, _) => false,
        }
    }

    fn restrict_mut(&mut self, _usage: &TargetCircUsage) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tor_netdir::testnet;

    #[test]
    fn exit_policy() {
        let network = testnet::construct_netdir();

        // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
        // exits.  Odd-numbered ones allow only ports 80 and 443;
        // even-numbered ones allow all ports.
        let id_noexit = [0x05; 32].into();
        let id_webexit = [0x11; 32].into();
        let id_fullexit = [0x20; 32].into();

        let not_exit = network.by_id(&id_noexit).unwrap();
        let web_exit = network.by_id(&id_webexit).unwrap();
        let full_exit = network.by_id(&id_fullexit).unwrap();

        let ep_none = ExitPolicy::from_relay(&not_exit);
        let ep_web = ExitPolicy::from_relay(&web_exit);
        let ep_full = ExitPolicy::from_relay(&full_exit);

        assert!(!ep_none.allows_port(TargetPort::ipv4(80)));
        assert!(!ep_none.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_web.allows_port(TargetPort::ipv4(80)));
        assert!(ep_web.allows_port(TargetPort::ipv4(443)));
        assert!(!ep_web.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_full.allows_port(TargetPort::ipv4(80)));
        assert!(ep_full.allows_port(TargetPort::ipv4(443)));
        assert!(ep_full.allows_port(TargetPort::ipv4(9999)));

        // Note that nobody in the testdir::network allows ipv6.
        assert!(!ep_none.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_web.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_full.allows_port(TargetPort::ipv6(80)));

        // Check is_supported_by while we're here.
        // TODO: Make sure that if BadExit is set, this fnuction returns no
        assert!(TargetPort::ipv4(80).is_supported_by(&web_exit));
        assert!(!TargetPort::ipv6(80).is_supported_by(&web_exit));
    }

    #[test]
    fn usage_ops() {
        use crate::mgr::AbstractSpec;
        // Make an exit-policy object that allows web on IPv4 and
        // smtp on IPv6.
        let policy = ExitPolicy {
            v4: Arc::new("accept 80,443".parse().unwrap()),
            v6: Arc::new("accept 23".parse().unwrap()),
        };

        let supp_dir = SupportedCircUsage::Dir;
        let targ_dir = TargetCircUsage::Dir;
        let supp_exit = SupportedCircUsage::Exit(policy);
        let targ_80_v4 = TargetCircUsage::Exit(vec![TargetPort::ipv4(80)]);
        let targ_80_23_v4 = TargetCircUsage::Exit(vec![TargetPort::ipv4(80), TargetPort::ipv4(23)]);
        let targ_80_23_mixed =
            TargetCircUsage::Exit(vec![TargetPort::ipv4(80), TargetPort::ipv6(23)]);
        let targ_999_v6 = TargetCircUsage::Exit(vec![TargetPort::ipv6(999)]);

        assert!(supp_dir.supports(&targ_dir));
        assert!(!supp_dir.supports(&targ_80_v4));
        assert!(!supp_exit.supports(&targ_dir));
        assert!(supp_exit.supports(&targ_80_v4));
        assert!(supp_exit.supports(&targ_80_23_mixed));
        assert!(!supp_exit.supports(&targ_80_23_v4));
        assert!(!supp_exit.supports(&targ_999_v6));
    }

    #[test]
    fn buildpath() {
        use crate::mgr::AbstractSpec;
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir();
        let di = (&netdir).into();

        // Only doing basic tests for now.  We'll test the path
        // building code a lot more closely in the tests for TorPath
        // and friends.
        let (p_dir, u_dir) = TargetCircUsage::Dir.build_path(&mut rng, di).unwrap();
        assert!(matches!(u_dir, SupportedCircUsage::Dir));
        assert_eq!(p_dir.len(), 1);

        let exit_usage = TargetCircUsage::Exit(vec![TargetPort::ipv4(995)]);
        let (p_exit, u_exit) = exit_usage.build_path(&mut rng, di).unwrap();
        assert!(matches!(u_exit, SupportedCircUsage::Exit(_)));
        assert!(u_exit.supports(&exit_usage));
        assert_eq!(p_exit.len(), 3);
    }
}
