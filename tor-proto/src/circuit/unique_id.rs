//! Unique identifiers for circuits.

use std::fmt::{Display, Formatter};

/// Process-unique identifier for a circuit.
///
/// We could use channel_id.circid here, but the circid can be reused
/// over time.  This won't ever repeat on a 64-bit architecture, and
/// is super-unlikely to repeat on a 32-bit architecture.  (If
/// we're about to return a repeat value, we assert instead.)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct UniqId {
    /// Channel that this circuit is on.
    chan: usize,
    /// ID for the circuit on the channel
    circ: usize,
}

impl UniqId {
    /// Construct a new circuit UniqId from its parts
    pub(crate) fn new(chan: usize, circ: usize) -> Self {
        UniqId { chan, circ }
    }
}

impl Display for UniqId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circ {}.{}", self.chan, self.circ)
    }
}
