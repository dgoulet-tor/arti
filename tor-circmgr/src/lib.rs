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
use tor_netdir::NetDir;
use tor_proto::circuit::ClientCirc;

use anyhow::Result;
use futures::lock::Mutex;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod err;
pub mod path;

pub use err::Error;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, PathBuilder, TorPath};

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
// XXXX Support circuits that go away.
// XXXX Support timing out circuits
// XXXX Support explicitly removing circuits
pub struct CircMgr<TR>
where
    TR: tor_chanmgr::transport::Transport,
{
    /// Reference to a channel manager that this circuit manager can use to make
    /// channels.
    chanmgr: Arc<ChanMgr<TR>>,

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
#[derive(Copy, Clone, Hash, Eq, PartialEq)]

/// A unique identifier for a circuit in a circuit manager.
///
/// TODO: We should probably refactor not to need this.
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
    usage: CircUsage,
    /// The circuit, or an event to notify on its creation.
    circ: Circ,
}

/// The purpose for which a circuit was created.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Hash, Clone, Debug, PartialEq, Eq)]
enum CircUsage {
    /// Use for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Use to exit to any listed port
    Exit(Vec<u16>),
}

/// The state of a circuit: either built or waiting to be built.
enum Circ {
    /// A circuit that has been constructed and which is probably usable.
    Open(ClientCirc),
    /// A circuit that we've started building, which could succeed or fail.
    Pending(Arc<event_listener::Event>),
}

impl CircUsage {
    /// Construct path for a given circuit purpose.
    fn build_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>> {
        match self {
            CircUsage::Dir => DirPathBuilder::new().pick_path(rng, netdir),
            CircUsage::Exit(p) => ExitPathBuilder::new(p.clone()).pick_path(rng, netdir),
        }
    }

    /// Return true if this usage "contains" other -- in other words,
    /// if any circuit built for this purpose is also usable for the
    /// purpose of other.
    fn contains(&self, other: &CircUsage) -> bool {
        use CircUsage::*;
        match (self, other) {
            (Dir, Dir) => true,
            (Exit(p1), Exit(p2)) => p1.iter().all(|port| p2.contains(port)),
            (_, _) => false,
        }
    }
}

impl<TR> CircMgr<TR>
where
    TR: tor_chanmgr::transport::Transport,
{
    /// Construct a new circuit manager.
    pub fn new(chanmgr: Arc<ChanMgr<TR>>) -> Self {
        let circuits = Mutex::new(HashMap::new());

        CircMgr { chanmgr, circuits }
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: &NetDir) -> Result<ClientCirc> {
        self.get_or_launch_by_usage(netdir, CircUsage::Dir).await
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    pub async fn get_or_launch_exit(&self, netdir: &NetDir, ports: &[u16]) -> Result<ClientCirc> {
        self.get_or_launch_by_usage(netdir, CircUsage::Exit(ports.into()))
            .await
    }

    /// How many circuits for this purpose should exist in parallel?
    fn parallelism(&self, usage: &CircUsage) -> usize {
        // TODO parameterize?
        match usage {
            CircUsage::Dir => 3,
            CircUsage::Exit(_) => 1,
        }
    }

    /// Helper: return a a circuit for this usage, launching it if necessary.
    async fn get_or_launch_by_usage(
        &self,
        netdir: &NetDir,
        usage: CircUsage,
    ) -> Result<ClientCirc> {
        // XXXX LOG.
        // XXXX This function is huge and ugly.
        let mut rng = StdRng::from_rng(rand::thread_rng()).unwrap();

        // Check the state of our circuit list.
        let (should_launch, event, id) = {
            let mut circs = self.circuits.lock().await;
            let mut suitable = Vec::new();
            let par = self.parallelism(&usage);
            let mut remove = Vec::new();
            assert!(par >= 1);
            for (id, c) in circs.iter() {
                if !c.usage.contains(&usage) {
                    continue;
                }
                if let Circ::Open(ref c) = &c.circ {
                    if c.is_closing().await {
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
                    usage: usage.clone(), // TODO: Maybe expand the usage based on actual provided ports?
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
                    Circ::Open(c) => return Ok(c.new_ref()), // Found a circuit!
                    Circ::Pending(event) => (false, Arc::clone(&event), **id), // wait for this one.
                }
            };

            for id in remove {
                circs.remove(&id);
            }
            result
        };

        if should_launch {
            // TODO: Try again on failure?
            let result = self.build_by_usage(&mut rng, netdir, &usage).await;

            // Adjust the map and notify the others.
            {
                let mut circs = self.circuits.lock().await;
                if let Ok(ref circ) = result {
                    let p = circs.get_mut(&id);
                    // XXXX instead of unwrapping, should make a new entry.
                    let p = p.unwrap();
                    p.circ = Circ::Open(circ.new_ref());
                } else {
                    circs.remove(&id);
                }
            }
            event.notify(usize::MAX);
            result
        } else {
            // TODO: Try again on failure?
            // Wait on the event.
            event.listen().await;

            {
                let circs = self.circuits.lock().await;
                let ent = circs.get(&id).ok_or(Error::PendingFailed)?;
                if let Circ::Open(ref c) = ent.circ {
                    Ok(c.new_ref())
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
        netdir: &NetDir,
        usage: &CircUsage,
    ) -> Result<ClientCirc> {
        // XXXX Timeout support.
        let path = usage.build_path(rng, netdir)?;
        let circ = path.build_circuit(rng, &self.chanmgr).await?;
        Ok(circ)
    }
}
