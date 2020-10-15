//! Types and code to map circuit IDs to circuits.

// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

use crate::{Error, Result};
use tor_cell::chancell::CircID;

use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};

use futures::channel::{mpsc, oneshot};

use rand::distributions::Distribution;
use rand::Rng;
use std::collections::{hash_map::Entry, HashMap};

/// Which group of circuit IDs are we allowed to allocate in this map?
///
/// If we initiated the channel, we use High circuit ids.  If we're the
/// responder, we use low circuit ids.
#[derive(Copy, Clone)]
pub(super) enum CircIDRange {
    /// Only use circuit IDs with the MSB cleared.
    #[allow(dead_code)] // Relays will need this.
    Low,
    /// Only use circuit IDs with the MSB set.
    High,
    // Historical note: There used to be an "All" range of circuit IDs
    // available to clients only.  We stopped using "All" when we moved to link
    // protocol version 4.
}

impl rand::distributions::Distribution<CircID> for CircIDRange {
    /// Return a random circuit ID in the appropriate range.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CircID {
        // Make sure v is nonzero.
        let v = loop {
            match rng.gen() {
                0u32 => (), // zero is not a valid circuit ID
                x => break x,
            }
        };
        // Force the high bit of v to the appropriate value.
        match self {
            CircIDRange::Low => v & 0x7fff_ffff,
            CircIDRange::High => v | 0x8000_0000,
        }
        .into()
    }
}

/// An entry in the circuit map.  Right now, we only have "here's the
/// way to send cells to a given circuit", but that's likely to
/// change.
pub(super) enum CircEnt {
    /// A circuit that has not yet received a CREATED cell.
    ///
    /// For this circuit, the CREATED* cell or DESTROY cell gets sent
    /// to the oneshot sender to tell the corresponding
    /// PendingClientCirc that the handshake is done.
    ///
    /// Once that's done, the mpsc sender will be used to send subsequent
    /// cells to the circuit.
    Opening(
        oneshot::Sender<CreateResponse>,
        mpsc::Sender<ClientCircChanMsg>,
    ),

    /// A circuit that is open and can be given relay cells.
    Open(mpsc::Sender<ClientCircChanMsg>),
}

/// A map from circuit IDs to circuit entries. Each channel has one.
pub(super) struct CircMap {
    /// Map from circuit IDs to entries
    m: HashMap<CircID, CircEnt>,
    /// Rule for allocating new circuit IDs.
    range: CircIDRange,
}

impl CircMap {
    /// Make a new empty CircMap
    pub(super) fn new(idrange: CircIDRange) -> Self {
        CircMap {
            m: HashMap::new(),
            range: idrange,
        }
    }

    /// Add a new pair of elements (corresponding to a PendingClientCirc)
    /// to this map.
    ///
    /// On success return the allocated circuit ID.
    pub(super) fn add_ent<R: Rng>(
        &mut self,
        rng: &mut R,
        createdsink: oneshot::Sender<CreateResponse>,
        sink: mpsc::Sender<ClientCircChanMsg>,
    ) -> Result<CircID> {
        /// How many times do we probe for a random circuit ID before
        /// we assume that the range is fully populated?
        const N_ATTEMPTS: usize = 16;
        let iter = (&mut self.range).sample_iter(rng).take(N_ATTEMPTS);
        let circ_ent = CircEnt::Opening(createdsink, sink);
        for id in iter {
            let ent = self.m.entry(id);
            if let Entry::Vacant(_) = &ent {
                ent.or_insert(circ_ent);
                return Ok(id);
            }
        }
        Err(Error::IDRangeFull)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: CircID) -> Option<&mut CircEnt> {
        self.m.get_mut(&id)
    }

    /// See whether 'id' is an opening circuit.  If so, mark it "open" and
    /// return a oneshot::Sender that is waiting for its create cell.
    pub(super) fn advance_from_opening(
        &mut self,
        id: CircID,
    ) -> Option<oneshot::Sender<CreateResponse>> {
        // TODO: there should be a better way to do
        // this. hash_map::Entry seems like it could be better.
        let ok = matches!(self.m.get(&id), Some(CircEnt::Opening(_, _)));
        if ok {
            if let Some(CircEnt::Opening(oneshot, sink)) = self.m.remove(&id) {
                self.m.insert(id, CircEnt::Open(sink));
                Some(oneshot)
            } else {
                panic!("internal error: inconsistent circuit state");
            }
        } else {
            None
        }
    }

    /// Extract the value from this map with 'id' if any
    pub(super) fn remove(&mut self, id: CircID) -> Option<CircEnt> {
        self.m.remove(&id)
    }
    // TODO: Eventually if we want relay support, we'll need to support
    // circuit IDs chosen by somebody else. But for now, we don't need those.
}
