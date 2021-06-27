//! `tor-circmgr`: circuits through the Tor network on demand.
//!
//! # Limitations
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a circuit is an encrypted multi-hop tunnel over multiple
//! relays.  This crate's purpose, long-term, is to manage a set of
//! circuits for a client.  It should construct circuits in response
//! to a client's needs, and preemptively construct circuits so as to
//! anticipate those needs.  If a client request can be satisfied with
//! an existing circuit, it should return that circuit instead of
//! constructing a new one.
//!
//! But for now, this `tor-circmgr` code is extremely preliminary; its
//! data structures are all pretty bad, and it's likely that the API
//! is wrong too.
//!
//! The path generation code in this crate is missing a colossal
//! number of features that you'd probably want in production: the
//! paths it generates should not be considered secure.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackDir, NetDir};
use tor_proto::circuit::{CircParameters, ClientCirc, UniqId};
use tor_rtcompat::Runtime;

use log::warn;
use std::sync::Arc;
use std::time::Duration;

mod err;
mod impls;
mod mgr;
pub mod path;
mod usage;

pub use err::Error;
pub use usage::TargetPort;

use usage::TargetCircUsage;

/// A Result type as returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// How long do we let a circuit be dirty before we won't hand it out any
/// more?
///
/// TODO: this should be an option.
///
/// TODO: The rules should be different for different kinds of circuits.
const MAX_CIRC_DIRTINESS: Duration = Duration::from_secs(60 * 15);

/// Represents what we know about the Tor network.
///
/// This can either be a comlete directory, or a list of fallbacks.
///
/// Not every DirInfo can be used to build every kind of circuit:
/// if you try to build a path with an inadequate DirInfo, you'll get a
/// NeedConsensus error.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DirInfo<'a> {
    /// A list of fallbacks, for use when we don't know a network directory.
    Fallbacks(&'a [FallbackDir]),
    /// A complete network directory
    Directory(&'a NetDir),
}

impl<'a> From<&'a [FallbackDir]> for DirInfo<'a> {
    fn from(v: &'a [FallbackDir]) -> DirInfo<'a> {
        DirInfo::Fallbacks(v)
    }
}
impl<'a> From<&'a NetDir> for DirInfo<'a> {
    fn from(v: &'a NetDir) -> DirInfo<'a> {
        DirInfo::Directory(v)
    }
}
impl<'a> DirInfo<'a> {
    /// Return a set of circuit parameters for this DirInfo.
    fn circ_params(&self) -> CircParameters {
        use tor_netdir::params::NetParameters;
        /// Extract a CircParameters from the NetParameters from a
        /// consensus.  We use a common function for both cases here
        /// to be sure that we look at the defaults from NetParameters
        /// code.
        fn from_netparams(inp: &NetParameters) -> CircParameters {
            let mut p = CircParameters::default();
            if let Err(e) = p.set_initial_send_window(inp.circuit_window.get() as u16) {
                warn!("Invalid parameter in directory: {}", e);
            }
            p.set_extend_by_ed25519_id(inp.extend_by_ed25519_id.into());
            p
        }

        match self {
            DirInfo::Fallbacks(_) => from_netparams(&NetParameters::default()),
            DirInfo::Directory(d) => from_netparams(d.params()),
        }
    }
}

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
#[derive(Clone)]
pub struct CircMgr<R: Runtime> {
    /// The underlying circuit manager object that implements our behavior.
    mgr: Arc<mgr::AbstractCircMgr<impls::Builder<R>, R>>,
}

impl<R: Runtime> CircMgr<R> {
    /// Construct a new circuit manager.
    pub fn new(runtime: R, chanmgr: Arc<ChanMgr<R>>) -> Self {
        let builder = impls::Builder::new(runtime.clone(), chanmgr);
        let mgr = mgr::AbstractCircMgr::new(builder, runtime);
        CircMgr { mgr: Arc::new(mgr) }
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<ClientCirc>> {
        self.expire_dirty_circuits();
        let usage = TargetCircUsage::Dir;
        self.mgr.get_or_launch(&usage, netdir).await
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    pub async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>,
        ports: &[TargetPort],
    ) -> Result<Arc<ClientCirc>> {
        self.expire_dirty_circuits();
        let ports = ports.iter().map(Clone::clone).collect();
        let usage = TargetCircUsage::Exit(ports);
        self.mgr.get_or_launch(&usage, netdir).await
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub fn retire_circ(&self, circ_id: &UniqId) {
        let _ = self.mgr.take_circ(circ_id);
    }

    /* Removed for now: just use TorPath::build_circuit instead.

    /// Construct a client circuit using a given path.
    ///
    /// Note: The returned circuit is not managed by the circuit manager and
    /// therefore won't be used by anything else.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub async fn build_path<RC: Rng + CryptoRng>(
        &self,
        rng: &mut RC,
        netdir: DirInfo<'_>,
        path: &TorPath<'_>,
    ) -> Result<Arc<ClientCirc>> {
        let params = netdir.circ_params();
        let circ = path
            .build_circuit(rng, &self.runtime, &self.chanmgr, &params)
            .await?;
        Ok(circ)
    }
     */

    /// Expire every circuit that has been dirty for too long.
    ///
    /// Expired circuits are not closed while they still have users,
    /// but they are no longer given out for new requests.
    fn expire_dirty_circuits(&self) {
        let cutoff = self.mgr.peek_runtime().now() - MAX_CIRC_DIRTINESS;
        self.mgr.expire_dirty_before(cutoff);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_params() {
        use tor_netdir::{MdReceiver, PartialNetDir};
        use tor_netdoc::doc::netstatus::NetParams;
        // If it's just fallbackdir, we get the default parameters.
        let di: DirInfo<'_> = (&[][..]).into();

        let p1 = di.circ_params();
        assert_eq!(p1.extend_by_ed25519_id(), false);
        assert_eq!(p1.initial_send_window(), 1000);

        // Now try with a directory and configured parameters.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 100);
        assert_eq!(p2.extend_by_ed25519_id(), true);

        // Now try with a bogus circwindow value.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100_000);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 1000); // Not 100_000
        assert_eq!(p2.extend_by_ed25519_id(), true);
    }
}
