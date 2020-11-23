//! Types to describe information about other downloaded directory
//! documents, without necessarily having the full document.

use tor_llcrypto as ll;
use tor_netdoc::doc::netstatus::{Lifetime, MDConsensus, UnvalidatedMDConsensus};

use digest::Digest;

/// Information about a consensus that we have
#[derive(Debug, Clone)]
pub struct ConsensusMeta {
    /// The time over which the consensus is valid.
    lifetime: Lifetime,
    /// A sha3-256 digest of the signed portion of the consensus: used for
    /// fetching diffs.
    sha3_256: [u8; 32],
}

impl ConsensusMeta {
    /// Create a new ConsensusMeta
    pub fn new(lifetime: Lifetime, sha3_256: [u8; 32]) -> Self {
        ConsensusMeta { lifetime, sha3_256 }
    }
    /// Derive a new ConsensusMeta from an UnvalidatedMDConsensus and the
    /// text of its signed portino.
    pub fn from_unvalidated(signed_part: &str, con: &UnvalidatedMDConsensus) -> Self {
        let lifetime = con.peek_lifetime().clone();
        let sha3_256 = ll::d::Sha3_256::digest(signed_part.as_bytes()).into();
        ConsensusMeta::new(lifetime, sha3_256)
    }
    /// Derive a new ConsensusMeta from a MDConsensus and the text of its
    /// signed portion.
    #[allow(unused)]
    pub fn from_consensus(signed_part: &str, con: &MDConsensus) -> Self {
        let lifetime = con.lifetime().clone();
        let sha3_256 = ll::d::Sha3_256::digest(signed_part.as_bytes()).into();
        ConsensusMeta::new(lifetime, sha3_256)
    }
    /// Return the lifetime of this ConsensusMeta
    pub fn lifetime(&self) -> &Lifetime {
        &self.lifetime
    }
    /// Return the sha3-256 of the signed portion of this consensus.
    pub fn sha3_256_of_signed(&self) -> &[u8; 32] {
        &self.sha3_256
    }
}
