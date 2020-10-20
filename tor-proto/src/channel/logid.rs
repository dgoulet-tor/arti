//! Helper for logging about channels.

use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counter for allocating unique-ish identifiers for channels.
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Identifier for a channel for logging purposes.
///
/// It should be unique, but collisions are possible on 32-bit
/// architectures under certain very weird circumstances.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LogId(usize);

impl LogId {
    /// Construct a new LogId.
    pub fn new() -> Self {
        // Relaxed ordering is fine; we don't care about how this
        // is instantiated with respoect to other channels.
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        LogId(id)
    }
}

impl Display for LogId {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Chan {}", self.0)
    }
}

/// Counter for allocating circuit log ids.
///
/// We don't use circuit IDs here, because they tend are huge and
/// random and can be reused more readily.
#[derive(Debug)]
pub(crate) struct CircLogIdContext {
    /// Next value to be handed out for this channel's circuits.
    next_circ_id: usize,
}

impl CircLogIdContext {
    /// Create a new CircLogIdContext
    pub(super) fn new() -> Self {
        CircLogIdContext { next_circ_id: 0 }
    }
    /// Construct a new, unique-ish circuit LogId
    pub(super) fn next(&mut self, logid: LogId) -> crate::circuit::LogId {
        let circ_logid = self.next_circ_id;
        self.next_circ_id += 1;
        crate::circuit::LogId::new(logid.0, circ_logid)
    }
}
