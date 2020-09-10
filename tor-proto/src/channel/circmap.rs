// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

use crate::chancell::msg::ChanMsg;
use crate::chancell::CircID;

use std::collections::HashMap;

//use futures::sink::Sink;
//use futures::channel::oneshot;
use futures::channel::mpsc;

use rand::Rng;

/// Which group of circuit IDs are we allowed to allocate in this map?
///
/// If we're a client, we can allocate any nonzero circid we want.  If
/// we authenticated as a relay, we can allocate Low circuit IDs if we
/// launched the channel, and High circuit IDs if we received the
/// channal.
pub(super) enum CircIDRange {
    Low,
    High,
    All,
}

impl CircIDRange {
    /// Return a random circuit ID in the appropriate range.
    fn new_id<R: Rng>(&self, rng: &mut R) -> CircID {
        // Make sure v is nonzero.
        let v = loop {
            match rng.gen() {
                0u32 => (),
                x => break x,
            }
        };
        // Force the high bit of v to the appropriate value.
        match self {
            CircIDRange::Low => v & 0x7fff_ffff,
            CircIDRange::High => v | 0x8000_0000,
            CircIDRange::All => v,
        }
        .into()
    }
}

/// An entry in the circuit map.  Right now, we only have "here's the
/// way to send cells to a given circuit", but that's likely to
/// change.
pub(super) enum CircEnt {
    Open(mpsc::Sender<ChanMsg>),
}

/// A map from circuit IDs to circuit entries. Each channel has one.
pub(super) struct CircMap {
    idrange: CircIDRange,
    m: HashMap<CircID, CircEnt>,
}

impl CircMap {
    /// Make a new empty CircMap
    pub(super) fn new(idrange: CircIDRange) -> Self {
        CircMap {
            idrange,
            m: HashMap::new(),
        }
    }

    /// Construct a new CircuitID for an outbound circuit; make sure
    /// it is unused.  This can fail if there are too many circuits on
    /// this channel.
    fn gen_id<R: Rng>(&self, rng: &mut R) -> Option<CircID> {
        // How many times to we try before giving up?
        const MAX_ATTEMPTS: usize = 16;
        for _ in 0..MAX_ATTEMPTS {
            let id = self.idrange.new_id(rng);
            if !self.m.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    fn get_ref(&self, id: CircID) -> Option<&CircEnt> {
        self.m.get(&id)
    }

    /// Remove the entry for `id` on this map, if any.
    fn remove(&mut self, id: CircID) {
        self.m.remove(&id);
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: CircID) -> Option<&mut CircEnt> {
        self.m.get_mut(&id)
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // circuit IDs chosen by somebody else. But for now, we don't need those.
}
