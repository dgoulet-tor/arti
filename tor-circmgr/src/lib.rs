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

use anyhow::Result;
use futures::lock::Mutex;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod err;
pub mod path;

pub use err::Error;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, TorPath};

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
// XXXX-A1 Support timing out circuits
pub struct CircMgr {
    /// Reference to a channel manager that this circuit manager can use to make
    /// channels.
    chanmgr: Arc<ChanMgr>,

    /// Map from unique circuit identifier to an entry describing its state.
    ///
    /// Each entry is either an open circuit, or a pending circuit.
    ///
    // This is an awful structure. The unique-identifier part is ad
    // hoc and probably a bad choice, whereas some of the usage logic
    // requires walking the whole map to find a suitable circuit.
    circuits: Mutex<HashMap<CircEntId, CircEntry>>,
}

/// Counter for allocating unique-ish identifiers for circuits
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

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
/// TODO: We should probably refactor not to need this.
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
struct CircEntId {
    /// Actual identifier.
    id: usize,
}
impl CircEntId {
    /// Make a new, hopefully unused, CircEntId
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        CircEntId { id }
    }
}

/// Describes the state of an entry in a circuit builder's map.
struct CircEntry {
    /// What this circuit was created for (and presumably, what it can be used for).
    usage: CircUsage, // XXXX-A1 use targetcircusage for pending
    /// The circuit, or an event to notify on its creation.
    circ: Circ,
}

#[derive(Clone, Debug)]
struct ExitPolicy {
    v4: PortPolicy, // XXXX refcount!
    v6: PortPolicy, // XXXX refcount!
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TargetPort {
    ipv6: bool,
    port: u16,
}

impl ExitPolicy {
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

impl From<TargetCircUsage> for CircUsage {
    fn from(t: TargetCircUsage) -> CircUsage {
        match t {
            TargetCircUsage::Dir => CircUsage::Dir,
            TargetCircUsage::Exit(ports) => {
                // This is ugly and wrong but only temporary. XXXX-A1 remove
                let p1 = ports[0].port;
                let v4polstr = format!("accept {}", p1);
                let v4pol = v4polstr.parse().unwrap();
                let pol = ExitPolicy {
                    v4: v4pol,
                    v6: PortPolicy::new_reject_all(),
                };
                CircUsage::Exit(pol)
            }
        }
    }
}

/// The state of a circuit: either built or waiting to be built.
enum Circ {
    /// A circuit that has been constructed and which is probably usable.
    Open(Arc<ClientCirc>),
    /// A circuit that we've started building, which could succeed or fail.
    Pending(Arc<event_listener::Event>),
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
                    .exit_usage()
                    .expect("ExitPathBuilder gave us a one-hop circuit?");
                Ok((path, CircUsage::Exit(policy)))
            }
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

impl CircEntry {
    /// Return true if this entry contains the circuit identified with c
    fn matches_id(&self, c: &UniqId) -> bool {
        match &self.circ {
            Circ::Open(x) => &x.unique_id() == c,
            Circ::Pending(_) => false,
        }
    }
}

impl CircMgr {
    /// Construct a new circuit manager.
    pub fn new(chanmgr: Arc<ChanMgr>) -> Self {
        let circuits = Mutex::new(HashMap::new());

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
        ports: &[u16],
    ) -> Result<Arc<ClientCirc>> {
        // XXXX support ipv6
        let ports = ports
            .iter()
            .map(|port| TargetPort {
                ipv6: false,
                port: *port,
            })
            .collect();
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
            let mut suitable = Vec::new();
            let par = self.parallelism(&target_usage);
            let mut remove = Vec::new();
            assert!(par >= 1);
            for (id, c) in circs.iter() {
                if !c.usage.contains(&target_usage) {
                    continue;
                }
                if let Circ::Open(ref c) = &c.circ {
                    if c.is_closing() {
                        remove.push(*id);
                        continue;
                    }
                }
                suitable.push((id, c));
            }
            let result = if suitable.len() < par {
                // There aren't enough circuits of this type. Launch one.
                let event = Arc::new(event_listener::Event::new());
                let id = CircEntId::new();
                let entry = CircEntry {
                    usage: target_usage.clone().into(), // XXXX-A1 no, remove this.
                    circ: Circ::Pending(Arc::clone(&event)),
                };
                circs.insert(id, entry);
                (true, event, id)
            } else {
                // There are enough circuits or pending circuits of this type.
                // We'll pick one.
                // unwrap ok: there is at least one member in suitable.
                let (id, entry) = suitable.choose(&mut rng).unwrap();
                match &entry.circ {
                    Circ::Open(c) => return Ok(Arc::clone(c)), // Found a circuit!
                    Circ::Pending(event) => (false, Arc::clone(&event), **id), // wait for this one.
                }
            };

            for id in remove {
                circs.remove(&id);
            }
            result
        };

        if should_launch {
            let result = self.build_by_usage(&mut rng, netdir, &target_usage).await;

            // Adjust the map and notify the others.
            let circ = {
                let mut circs = self.circuits.lock().await;
                let _old = circs.remove(&id).unwrap();
                match result {
                    Ok((circ, usage)) => {
                        let ent = CircEntry {
                            usage,
                            circ: Circ::Open(Arc::clone(&circ)),
                        };
                        circs.insert(id, ent);
                        Ok(circ)
                    }
                    Err(e) => Err(e),
                }
            };
            event.notify(usize::MAX);
            circ
        } else {
            // Wait on the event.
            event.listen().await;

            {
                let circs = self.circuits.lock().await;
                let ent = circs.get(&id).ok_or(Error::PendingFailed)?;
                if let Circ::Open(ref c) = ent.circ {
                    Ok(Arc::clone(c))
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
        let mut last_err = None;

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
                    last_err = Some(e);
                }
                Err(_) => {
                    last_err = Some(Error::CircTimeout.into());
                }
            }
        }
        // TODO: maybe don't forget all the other errors? XXXX-A1
        Err(last_err.unwrap())
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
        // XXXX This implementation is awful.  Looking over the whole pile
        // XXXX of circuits!?
        let id = {
            if let Some((id, _)) = circs.iter_mut().find(|(_, c)| c.matches_id(circ_id)) {
                *id
            } else {
                return;
            }
        };

        // We just remove this circuit from the map. Doing so will ensure
        // that it will go away when there are no other references to it.
        circs.remove(&id);
    }
}
