//! Logging-only identifiers for circuits

use std::fmt::{Display, Formatter};

/// Identifier for this circuit for logging purposes.
///
/// We could use channel_id.circid here, but the circid is a large
/// random number, and can be reused over time.  This is less likely
/// to repeat.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct LogId {
    /// Channel that this circuit is on.
    chan: usize,
    /// ID for the circuit on the channel
    circ: usize,
}

impl LogId {
    /// Construct a new circuit LogId from its parts
    pub(crate) fn new(chan: usize, circ: usize) -> Self {
        LogId { chan, circ }
    }
}

impl Display for LogId {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Circ {}.{}", self.chan, self.circ)
    }
}
