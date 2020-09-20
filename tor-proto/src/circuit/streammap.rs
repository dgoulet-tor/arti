// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

use crate::relaycell::{msg::RelayMsg, StreamID};
use crate::util::idmap::IdMap;
use crate::Result;

use rand::distributions::Distribution;
use rand::Rng;

use futures::channel::mpsc;

pub(super) enum StreamEnt {
    Open(mpsc::Sender<RelayMsg>),
}

struct StreamIDDist;
impl Distribution<StreamID> for StreamIDDist {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> StreamID {
        loop {
            let val: u16 = rng.gen();
            if val != 0 {
                return val.into();
            }
        }
    }
}

/// A map from stream IDs to stream entries. Each circuit has one.
pub(super) struct StreamMap {
    m: IdMap<StreamID, StreamIDDist, StreamEnt>,
}

impl StreamMap {
    /// Make a new empty StreamMap
    pub(super) fn new() -> Self {
        StreamMap {
            m: IdMap::new(StreamIDDist),
        }
    }

    pub(super) fn add_ent<R: Rng>(
        &mut self,
        rng: &mut R,
        sink: mpsc::Sender<RelayMsg>,
    ) -> Result<StreamID> {
        let ent = StreamEnt::Open(sink);
        let id = self.m.add_ent(rng, ent)?;
        Ok(id)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamID) -> Option<&mut StreamEnt> {
        self.m.get_mut(&id)
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // circuit IDs chosen by somebody else. But for now, we don't need those.
}
