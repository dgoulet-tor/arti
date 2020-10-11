use crate::circuit::sendme;
use crate::{Error, Result};
/// Mapping from stream ID to streams.
// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!
use tor_cell::relaycell::{msg::RelayMsg, StreamID};

use futures::channel::mpsc;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use rand::Rng;

/// The entry for a stream.
pub(super) enum StreamEnt {
    /// An open stream: any relay cells tagged for this stream should get
    /// sent over the mpsc::Sender.
    Open(mpsc::Sender<RelayMsg>, sendme::StreamSendWindow),
    /// A stream for which we have received an END cell, but not yet
    /// had the stream object get dropped.
    EndReceived,
}

/// A map from stream IDs to stream entries. Each circuit has one for each
/// hop.
pub(super) struct StreamMap {
    m: HashMap<StreamID, StreamEnt>,
    next_stream_id: u16,
}

impl StreamMap {
    /// Make a new empty StreamMap.
    pub(super) fn new() -> Self {
        let mut rng = rand::thread_rng();
        let next_stream_id: u16 = loop {
            let v: u16 = rng.gen();
            if v != 0 {
                break v;
            }
        };
        StreamMap {
            m: HashMap::new(),
            next_stream_id,
        }
    }

    /// Add an entry to this map; return the newly allocated StreamID.
    pub(super) fn add_ent(
        &mut self,
        sink: mpsc::Sender<RelayMsg>,
        window: sendme::StreamSendWindow,
    ) -> Result<StreamID> {
        let stream_ent = StreamEnt::Open(sink, window);
        // This seems too aggressive, but it's what tor does
        for _ in 1..=65536 {
            let id: StreamID = self.next_stream_id.into();
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if id.is_zero() {
                continue;
            }
            let ent = self.m.entry(id);
            if let Entry::Vacant(_) = ent {
                ent.or_insert(stream_ent);
                return Ok(id);
            }
        }

        Err(Error::IDRangeFull)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamID) -> Option<&mut StreamEnt> {
        self.m.get_mut(&id)
    }

    /// Marks the stream with `id` as closing.
    ///
    /// Returns true if there was really a stream there.
    pub(super) fn mark_closing(&mut self, id: StreamID) -> bool {
        let old = self.m.insert(id, StreamEnt::EndReceived);
        match old {
            None => false,
            Some(StreamEnt::EndReceived) => false,
            Some(StreamEnt::Open(_, _)) => true,
        }
    }

    /// Remove the entry with `id`, if there is one.  Return true if the
    /// stream was open.
    pub(super) fn remove(&mut self, id: StreamID) -> bool {
        let old = self.m.remove(&id);
        match old {
            None => false,
            Some(StreamEnt::EndReceived) => false,
            Some(StreamEnt::Open(_, _)) => true,
        }
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // stream IDs chosen by somebody else. But for now, we don't need those.
}
