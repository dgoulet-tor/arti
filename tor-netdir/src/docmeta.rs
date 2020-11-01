#![allow(unused)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(missing_docs)]

use tor_llcrypto as ll;
use tor_netdoc::doc::netstatus::{Lifetime, MDConsensus};

use digest::Digest;

pub struct ConsensusMeta {
    lifetime: Lifetime,
    sha3_256: [u8; 32],
}

impl ConsensusMeta {
    pub fn new(lifetime: Lifetime, sha3_256: [u8; 32]) -> Self {
        ConsensusMeta { lifetime, sha3_256 }
    }
    pub fn from_consensus(signed_part: &str, con: &MDConsensus) -> Self {
        let lifetime = con.lifetime().clone();
        let sha3_256 = ll::d::Sha3_256::digest(signed_part.as_bytes()).into();
        ConsensusMeta::new(lifetime, sha3_256)
    }
    pub fn lifetime(&self) -> &Lifetime {
        &self.lifetime
    }
    pub fn sha3_256_of_signed(&self) -> &[u8; 32] {
        &self.sha3_256
    }
}
