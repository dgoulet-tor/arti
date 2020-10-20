//! Helper for logging about channels.

use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counter for allocating unique-ish identifiers for channels.
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Identifier for this channel for logging purposes.
///
/// It should be unique, but collisions are possible on 32-bit
/// architectures under certain very weird circumstances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        write!(f, "Chan:{}", self.0)
    }
}
