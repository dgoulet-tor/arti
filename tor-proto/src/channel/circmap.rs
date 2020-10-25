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
#[derive(Debug)]
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
    // XXXXM3 this should return a Result, not an option.
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

#[cfg(test)]
mod test {
    use super::*;
    use futures::channel::{mpsc, oneshot};

    #[test]
    fn circmap_basics() {
        let mut map_low = CircMap::new(CircIDRange::Low);
        let mut map_high = CircMap::new(CircIDRange::High);
        let mut ids_low: Vec<CircID> = Vec::new();
        let mut ids_high: Vec<CircID> = Vec::new();
        let mut rng = rand::thread_rng();

        assert!(map_low.get_mut(CircID::from(77)).is_none());

        for _ in 0..128 {
            let (csnd, _) = oneshot::channel();
            let (snd, _) = mpsc::channel(8);
            let id_low = map_low.add_ent(&mut rng, csnd, snd).unwrap();
            assert!(u32::from(id_low) > 0);
            assert!(u32::from(id_low) < 0x80000000);
            assert!(ids_low.iter().find(|x| **x == id_low).is_none());
            ids_low.push(id_low);

            assert!(matches!(
                map_low.get_mut(id_low),
                Some(&mut CircEnt::Opening(_, _))
            ));

            let (csnd, _) = oneshot::channel();
            let (snd, _) = mpsc::channel(8);
            let id_high = map_high.add_ent(&mut rng, csnd, snd).unwrap();
            assert!(u32::from(id_high) >= 0x80000000);
            assert!(ids_high.iter().find(|x| **x == id_high).is_none());
            ids_high.push(id_high);
        }

        // Test remove
        assert!(map_low.get_mut(ids_low[0]).is_some());
        map_low.remove(ids_low[0]);
        assert!(map_low.get_mut(ids_low[0]).is_none());

        // Test advance_from_opening.

        // Good case.
        assert!(map_high.get_mut(ids_high[0]).is_some());
        assert!(matches!(
            map_high.get_mut(ids_high[0]),
            Some(&mut CircEnt::Opening(_, _))
        ));
        let adv = map_high.advance_from_opening(ids_high[0]);
        assert!(adv.is_some());
        assert!(matches!(
            map_high.get_mut(ids_high[0]),
            Some(&mut CircEnt::Open(_))
        ));

        // Can't double-advance.
        let adv = map_high.advance_from_opening(ids_high[0]);
        assert!(adv.is_none());

        // Can't advance an entry that is not there.  We know "77"
        // can't be in map_high, since we only added high circids to
        // it.
        let adv = map_high.advance_from_opening(77.into());
        assert!(adv.is_none());
    }
}
