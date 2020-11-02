use tor_chanmgr::ChanMgr;
use tor_netdir::NetDir;
use tor_proto::circuit::ClientCirc;

use futures::lock::Mutex;
use futures::task::Spawn;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod err;
pub mod path;

pub use err::Error;
pub type Result<T> = std::result::Result<T, Error>;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, PathBuilder, TorPath};

pub struct CircMgr<TR>
where
    TR: tor_chanmgr::transport::Transport,
{
    netdir: Arc<NetDir>,
    chanmgr: Arc<ChanMgr<TR>>,
    spawn: Box<dyn Spawn>,

    // This is an awful structure. XXXX
    circuits: Mutex<HashMap<CircEntId, CircEntry>>,
}

/// Counter for allocating unique-ish identifiers for channels.
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
struct CircEntId {
    id: usize,
}
impl CircEntId {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        CircEntId { id }
    }
}

struct CircEntry {
    usage: CircUsage,
    circ: Circ,
}

#[derive(Hash, Clone, Debug, PartialEq, Eq)]
enum CircUsage {
    Dir,
    Exit(Vec<u16>),
}

enum Circ {
    Open(ClientCirc),
    Pending(Arc<event_listener::Event>),
}

impl CircUsage {
    fn build_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>> {
        match self {
            CircUsage::Dir => DirPathBuilder::new().pick_path(rng, netdir),
            CircUsage::Exit(p) => ExitPathBuilder::new(p.clone()).pick_path(rng, netdir),
        }
    }

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
    pub fn new(netdir: Arc<NetDir>, chanmgr: Arc<ChanMgr<TR>>, spawn: Box<dyn Spawn>) -> Self {
        let circuits = Mutex::new(HashMap::new());

        CircMgr {
            netdir,
            chanmgr,
            spawn,
            circuits,
        }
    }

    pub async fn get_or_launch_dir(&self) -> Result<ClientCirc> {
        self.get_or_launch_by_usage(CircUsage::Dir).await
    }

    pub async fn get_or_launch_exit(&self, ports: &[u16]) -> Result<ClientCirc> {
        self.get_or_launch_by_usage(CircUsage::Exit(ports.into()))
            .await
    }

    fn parallelism(&self, usage: &CircUsage) -> usize {
        // TODO parameterize?
        match usage {
            CircUsage::Dir => 3,
            CircUsage::Exit(_) => 1,
        }
    }

    async fn get_or_launch_by_usage(&self, usage: CircUsage) -> Result<ClientCirc> {
        let mut rng = rand::thread_rng();

        // Check the state of our circuit list.
        let (should_launch, event, id) = {
            let mut circs = self.circuits.lock().await;
            let mut suitable = Vec::new();
            let par = self.parallelism(&usage);
            assert!(par >= 1);
            for (id, c) in circs.iter() {
                if c.usage.contains(&usage) {
                    suitable.push((id, c));
                }
            }
            if suitable.len() < par {
                // There aren't enough circuits of this type. Launch one.
                let event = Arc::new(event_listener::Event::new());
                let id = CircEntId::new();
                let entry = CircEntry {
                    usage: usage.clone(), // TODO: Maybe expand the usage based on actual needs?
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
            }
        };

        if should_launch {
            // TODO: Try again on failure?
            let result = self.build_by_usage(&mut rng, &usage).await;

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
                    Err(Error::PendingFailed) // should be impossible XXXX
                }
            }
        }
    }

    async fn build_by_usage<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        usage: &CircUsage,
    ) -> Result<ClientCirc> {
        let path = usage.build_path(rng, &self.netdir)?;
        let circ = path.build_circuit(rng, &self.chanmgr, &self.spawn).await?;
        Ok(circ)
    }
}
