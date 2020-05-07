pub mod ntor;

use crate::{Result, SecretBytes};
//use zeroize::Zeroizing;
use rand_core::{CryptoRng, RngCore};

pub trait ClientHandshake {
    type KeyType;
    type StateType;
    type KeyGen;
    fn client1<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &Self::KeyType,
    ) -> Result<(Self::StateType, Vec<u8>)>;
    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<Self::KeyGen>;
}

pub trait ServerHandshake {
    type KeyType;
    type KeyGen;
    fn server<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[Self::KeyType],
    ) -> Result<(Self::KeyGen, Vec<u8>)>;
}

pub trait KeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBytes>;
}

pub struct TAPKeyGenerator {
    seed: SecretBytes,
}

impl TAPKeyGenerator {
    pub fn new(seed: SecretBytes) -> Self {
        TAPKeyGenerator { seed }
    }
}

impl KeyGenerator for TAPKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBytes> {
        use crate::crypto::ll::kdf::{LegacyKDF, KDF};
        LegacyKDF::new().derive(&self.seed[..], keylen)
    }
}

pub struct ShakeKeyGenerator {
    seed: SecretBytes,
}

impl ShakeKeyGenerator {
    pub fn new(seed: SecretBytes) -> Self {
        ShakeKeyGenerator { seed }
    }
}

impl KeyGenerator for ShakeKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBytes> {
        use crate::crypto::ll::kdf::{ShakeKDF, KDF};
        ShakeKDF::new().derive(&self.seed[..], keylen)
    }
}
