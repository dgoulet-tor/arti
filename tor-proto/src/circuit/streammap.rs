/// Mapping from stream ID to streams.
// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!
use crate::relaycell::{msg::RelayMsg, StreamID};
use crate::util::idmap::IdMap;
use crate::Result;

use futures::channel::mpsc;
use std::collections::HashMap;

/// The entry for a stream.
pub(super) enum StreamEnt {
    /// An open stream: any relay cells tagged for this stream should get
    /// sent over the mpsc::Sender.
    Open(mpsc::Sender<RelayMsg>),
}

/// A map from stream IDs to stream entries. Each circuit has one for each
/// hop.
pub(super) struct StreamMap {
    m: HashMap<StreamID, StreamEnt>,
    i: std::iter::Cycle<std::ops::RangeInclusive<u16>>,
}

impl StreamMap {
    /// Make a new empty StreamMap.
    pub(super) fn new() -> Self {
        let iter = (1_u16..=65535_u16).cycle();
        StreamMap {
            m: HashMap::new(),
            i: iter,
        }
    }

    /// Add an entry to this map; return the newly allocated StreamID.
    pub(super) fn add_ent(&mut self, sink: mpsc::Sender<RelayMsg>) -> Result<StreamID> {
        let ent = StreamEnt::Open(sink);
        let mut iter = (&mut self.i).map(|x| x.into()).take(65536);
        self.m.add_ent(&mut iter, ent)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamID) -> Option<&mut StreamEnt> {
        self.m.get_mut(&id)
    }

    // TODO: need a way to remove streams.

    // TODO: Eventually if we want relay support, we'll need to support
    // circuit IDs chosen by somebody else. But for now, we don't need those.
}
