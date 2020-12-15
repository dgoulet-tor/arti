//! The circuit manager creates circuits through the Tor network on demand.
//!
//! # Limitations
//!
//! This code is extremely preliminary; its data structures are all
//! pretty bad, and it's likely that the API is wrong too.
//!
//! The path generation code in this crate is missing a colossal
//! number of features that you'd probably want in production: the
//! paths it generates should not be considered secure.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackSet, NetDir};
use tor_netdoc::types::policy::PortPolicy;
use tor_proto::circuit::{ClientCirc, UniqId};
use tor_retry::RetryError;

use anyhow::Result;
use futures::lock::Mutex;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod err;
pub mod path;

pub use err::Error;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, TorPath};

/// How long do we let a circuit be dirty before we won't hand it out any
/// more?
///
/// TODO: this should be an option.
const MAX_CIRC_DIRTINESS: Duration = Duration::from_secs(60 * 15);

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
pub struct CircMgr {
    /// Reference to a channel manager that this circuit manager can
    /// use to make channels.
    chanmgr: Arc<ChanMgr>,

    /// The circuits and pending circuit creation attempts managed
    /// by this CircMgr.
    circuits: Mutex<CircSet>,
}

/// A group of pending and open circuits managed by a circuit manager.
///
/// This is a separate type so we can more easily handle functions that
/// want to hold the lock on it.
struct CircSet {
    /// Map from unique circuit identifier to an entry describing its state.
    ///
    /// Each entry is either an open circuit, or a pending circuit.
    circuits: HashMap<CircEntId, CircEntry>,
}

/// Counter for allocating unique-ish identifiers for pending circuits
static NEXT_PENDING_ID: AtomicUsize = AtomicUsize::new(0);

/// Represents what we know about the Tor network.
///
/// This can either be a comlete directory, or a list of fallbacks.
///
/// Not every DirInfo can be used to build every kind of circuit:
/// if you try to build a path with an inadequate DirInfo, you'll get a
/// NeedConsensus error.
#[derive(Debug, Copy, Clone)]
pub enum DirInfo<'a> {
    /// A list of fallbacks, for use when we don't know a network directory.
    Fallbacks(&'a FallbackSet),
    /// A complete network directory
    Directory(&'a NetDir),
}

impl<'a> Into<DirInfo<'a>> for &'a FallbackSet {
    fn into(self) -> DirInfo<'a> {
        DirInfo::Fallbacks(self)
    }
}
impl<'a> Into<DirInfo<'a>> for &'a NetDir {
    fn into(self) -> DirInfo<'a> {
        DirInfo::Directory(self)
    }
}

/// A unique identifier for a circuit in a circuit manager.
///
// TODO: I'd like to avoid dupliating the value of UniqId here, since the
// circuit already has one.  That's a waste of memory.
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
enum CircEntId {
    /// An identifier for an open circuit.
    Open(UniqId),
    /// An identifier for a pending circuit.
    Pending(usize),
}

impl From<UniqId> for CircEntId {
    fn from(id: UniqId) -> Self {
        CircEntId::Open(id)
    }
}

impl CircEntId {
    /// Make a new, hopefully unused, CircEntId for a pending circuit.
    ///
    /// Assuming that we time out pending IDs fast enough, these can't
    /// collide.
    fn new_pending() -> Self {
        let id = NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed);
        CircEntId::Pending(id)
    }
}

/// Describes the state of an entry in a circuit builder's map.
enum CircEntry {
    /// An entry for a completed circuit
    Open(OpenCircEntry),
    /// An entry for a pending circuit
    Pending(PendingCircEntry),
}

/// An entry for a completed circuit that we're managing.
struct OpenCircEntry {
    /// The usage for which this circuit is suitable.
    usage: CircUsage,
    /// When did we first yield this circuit as usable for a stream?
    ///
    /// (For now, this is always Some(_).  Later, we'll support building
    /// circuits in advance, and handing them out as needed.)
    first_used: Option<Instant>,
    /// The circuit itself
    circ: Arc<ClientCirc>,
}

/// An entry for a pending circuit that we haven't finished yet.
struct PendingCircEntry {
    /// The reason we're building the circuit.
    usage: TargetCircUsage,
    /// An event that will get notified when the circuit succeeds or fails.
    event: Arc<event_listener::Event>,
}

impl CircEntry {
    /// Return true if this CircEntry can be used for the provided
    /// target_usage.
    fn supports_target_usage(&self, target_usage: &TargetCircUsage) -> bool {
        match self {
            CircEntry::Open(ent) => ent.usage.contains(target_usage),
            CircEntry::Pending(ent) => ent.usage.contains(target_usage),
        }
    }

    /// Return true if this CircEntry is for a circuit that is closing.
    fn is_closing(&self) -> bool {
        match self {
            CircEntry::Open(ent) => ent.circ.is_closing(),
            _ => false,
        }
    }

    /// Return true if this CircEntry is too old to give to clients.
    fn is_too_old(&self, now: Instant) -> bool {
        if let CircEntry::Open(ent) = self {
            if let Some(first_used) = ent.first_used {
                return first_used + MAX_CIRC_DIRTINESS < now;
            }
        }
        false
    }
}

/// An exit policy as supported by the last hop of a circuit.
#[derive(Clone, Debug)]
struct ExitPolicy {
    /// Permitted IPv4 ports.
    v4: PortPolicy, // XXXX refcount!
    /// Permitted IPv6 ports.
    v6: PortPolicy, // XXXX refcount!
}

/// A port that we want to connect to as a client.
///
/// Ordinarliy, this is a TCP port, plus a flag to indicate whether we
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
}

impl ExitPolicy {
    /// Return true if a given port is contained in an ExitPolicy.
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
enum TargetCircUsage {
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
enum CircUsage {
    /// Useable for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Usable to exit to to a set of ports.
    Exit(ExitPolicy),
}

impl TargetCircUsage {
    /// Construct path for a given circuit purpose; return it and the
    /// usage that it _actually_ supports.
    fn build_path<'a, R: Rng>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
    ) -> Result<(TorPath<'a>, CircUsage)> {
        match self {
            TargetCircUsage::Dir => {
                let path = DirPathBuilder::new().pick_path(rng, netdir)?;
                Ok((path, CircUsage::Dir))
            }
            TargetCircUsage::Exit(p) => {
                let path = ExitPathBuilder::new(p.clone()).pick_path(rng, netdir)?;
                let policy = path
                    .exit_policy()
                    .expect("ExitPathBuilder gave us a one-hop circuit?");
                Ok((path, CircUsage::Exit(policy)))
            }
        }
    }

    /// Return true if this usage "contains" other -- in other words,
    /// if any circuit built for this purpose is also usable for the
    /// purpose of other.
    fn contains(&self, target: &TargetCircUsage) -> bool {
        use TargetCircUsage::*;
        match (self, target) {
            (Dir, Dir) => true,
            (Exit(p1), Exit(p2)) => p2.iter().all(|p| p1.contains(p)),
            (_, _) => false,
        }
    }
}

impl CircUsage {
    /// Return true if this usage "contains" other -- in other words,
    /// if any circuit built for this purpose is also usable for the
    /// purpose of other.
    fn contains(&self, target: &TargetCircUsage) -> bool {
        use CircUsage::*;
        match (self, target) {
            (Dir, TargetCircUsage::Dir) => true,
            (Exit(p1), TargetCircUsage::Exit(p2)) => p2.iter().all(|port| p1.allows_port(*port)),
            (_, _) => false,
        }
    }
}

impl CircMgr {
    /// Construct a new circuit manager.
    pub fn new(chanmgr: Arc<ChanMgr>) -> Self {
        let circuits = Mutex::new(CircSet {
            circuits: HashMap::new(),
        });

        CircMgr { chanmgr, circuits }
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<ClientCirc>> {
        self.get_or_launch_by_usage(netdir, TargetCircUsage::Dir)
            .await
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    pub async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>,
        ports: &[TargetPort],
    ) -> Result<Arc<ClientCirc>> {
        let ports = ports.iter().map(Clone::clone).collect();
        self.get_or_launch_by_usage(netdir, TargetCircUsage::Exit(ports))
            .await
    }

    /// How many circuits for this purpose should exist in parallel?
    fn parallelism(&self, usage: &TargetCircUsage) -> usize {
        // TODO parameterize?
        match usage {
            TargetCircUsage::Dir => 3,
            TargetCircUsage::Exit(_) => 1,
        }
    }

    /// Helper: return a a circuit for this usage, launching it if necessary.
    async fn get_or_launch_by_usage(
        &self,
        netdir: DirInfo<'_>,
        target_usage: TargetCircUsage,
    ) -> Result<Arc<ClientCirc>> {
        // XXXX-A1 LOG.
        // XXXX This function is huge and ugly.
        let mut rng = StdRng::from_rng(rand::thread_rng()).unwrap();

        // Check the state of our circuit list.
        let (should_launch, event, id) = {
            let mut circs = self.circuits.lock().await;
            let par = self.parallelism(&target_usage);
            assert!(par >= 1);
            circs.prune();
            let suitable = circs.find_suitable_circs(&target_usage, false);

            let result = if suitable.len() < par {
                // There aren't enough circuits of this type. Launch one.
                let event = Arc::new(event_listener::Event::new());
                let entry = CircEntry::Pending(PendingCircEntry {
                    usage: target_usage.clone(),
                    event: Arc::clone(&event),
                });
                let id = CircEntId::new_pending();
                if circs.circuits.insert(id, entry).is_some() {
                    // This should be impossible, since we would have to
                    // wrap around usize before the pending circuit expired.
                    panic!("ID collision among pending circuits.");
                }
                (true, event, id)
            } else {
                // There are enough circuits or pending circuits of this type.
                // We'll pick one.
                // unwrap ok: there is at least one member in suitable.
                let (id, entry) = suitable.choose(&mut rng).unwrap();
                match entry {
                    CircEntry::Open(c) => return Ok(Arc::clone(&c.circ)), // Found a circuit!
                    CircEntry::Pending(c) => (false, Arc::clone(&c.event), **id), // wait for this one.
                }
            };

            result
        };

        if should_launch {
            let result = self.build_by_usage(&mut rng, netdir, &target_usage).await;

            // Adjust the map and notify the others.
            let circ = {
                let mut circs = self.circuits.lock().await;
                let _old = circs.circuits.remove(&id).unwrap();
                match result {
                    Ok((circ, usage)) => {
                        let ent = CircEntry::Open(OpenCircEntry {
                            usage,
                            first_used: Some(Instant::now()),
                            circ: Arc::clone(&circ),
                        });
                        circs.circuits.insert(circ.unique_id().into(), ent);
                        Ok(circ)
                    }
                    Err(e) => Err(e),
                }
            };
            event.notify(usize::MAX);
            circ
        } else {
            // Wait on the event.
            //
            // XXXX This is actually not the right way to do this.
            // We should arrange to get notified when any circuit
            // finishes that supports (or might support) our usage.
            // As implemented now, we only are waiting for one specific
            // pending circuit, when another might finish first.
            event.listen().await;

            {
                let circs = self.circuits.lock().await;
                let suitable = circs.find_suitable_circs(&target_usage, true);
                if suitable.is_empty() {
                    // XXXX-A1 might want to retry
                    return Err(Error::PendingFailed.into());
                }

                let (_, ent) = suitable.choose(&mut rng).unwrap();
                if let CircEntry::Open(ref c) = ent {
                    Ok(Arc::clone(&c.circ))
                } else {
                    Err(Error::PendingFailed.into()) // should be impossible XXXX
                }
            }
        }
    }

    /// Actually construct a circuit for a given usage.
    async fn build_by_usage(
        &self,
        rng: &mut StdRng,
        netdir: DirInfo<'_>,
        target_usage: &TargetCircUsage,
    ) -> Result<(Arc<ClientCirc>, CircUsage)> {
        // TODO: This should probably be an option too.
        let n_tries: usize = 3;
        // TODO: This is way too long, AND it should be an option.
        let timeout = Duration::new(10, 0);

        let mut error = RetryError::new();

        for _ in 0..n_tries {
            let result = tor_rtcompat::timer::timeout(
                timeout,
                self.build_once_by_usage(rng, netdir, target_usage),
            )
            .await;

            match result {
                Ok(Ok((circ, usage))) => {
                    return Ok((circ, usage));
                }
                Ok(Err(e)) => {
                    error.push(e);
                }
                Err(_) => {
                    error.push(Error::CircTimeout);
                }
            }
        }

        Err(error.into())
    }

    /// Actually construct a circuit for a given usage.  Does not time out
    /// or retry.
    async fn build_once_by_usage(
        &self,
        rng: &mut StdRng,
        netdir: DirInfo<'_>,
        target_usage: &TargetCircUsage,
    ) -> Result<(Arc<ClientCirc>, CircUsage)> {
        let (path, usage) = target_usage.build_path(rng, netdir)?;
        let circ = path.build_circuit(rng, &self.chanmgr).await?;
        Ok((circ, usage))
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub async fn retire_circ(&self, circ_id: &UniqId) {
        let mut circs = self.circuits.lock().await;

        circs.remove(circ_id);
    }
}

impl CircSet {
    /// Remove every closed or too-dirty circuit from this set.
    ///
    /// This doesn't cause the circuits to close immediately if
    /// anybody still has a reference to them.
    fn prune(&mut self) {
        let now = Instant::now();
        let mut remove = Vec::new();
        for (id, c) in self.circuits.iter() {
            if c.is_closing() || c.is_too_old(now) {
                remove.push(*id)
            }
        }
        for id in remove {
            self.circuits.remove(&id);
        }
    }

    /// Find all the circuits in this set that implement `target_usage`.
    ///
    /// Return only the open ones, if `open_only` is true.
    //
    // XXXX This is a linear search, and that's not pretty.
    fn find_suitable_circs(
        &self,
        target_usage: &TargetCircUsage,
        open_only: bool,
    ) -> Vec<(&CircEntId, &CircEntry)> {
        let mut result = Vec::new();
        let now = Instant::now();
        for (id, c) in self.circuits.iter() {
            if open_only && !matches!(c, CircEntry::Open(_)) {
                continue;
            }
            if c.is_closing() || c.is_too_old(now) {
                continue;
            }
            if !c.supports_target_usage(target_usage) {
                continue;
            }
            result.push((id, c));
        }
        result
    }

    /// Remove the circuit with the provided unique identifier from this set.
    fn remove(&mut self, circ_id: &UniqId) {
        self.circuits.remove(&(*circ_id).into());
    }
}
