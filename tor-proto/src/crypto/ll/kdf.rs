use crate::{Error, Result, SecretBytes};
use digest::{Digest, ExtendableOutput};
use tor_llcrypto::d::{Sha1, Sha256, Shake256};

use zeroize::Zeroizing;

pub trait KDF {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBytes>;
}

pub struct LegacyKDF();
pub struct Ntor1KDF<'a, 'b> {
    t_key: &'a [u8],
    m_expand: &'b [u8],
}
pub struct ShakeKDF();

impl LegacyKDF {
    pub fn new() -> Self {
        LegacyKDF()
    }
}
impl KDF for LegacyKDF {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBytes> {
        let mut result = Zeroizing::new(Vec::with_capacity(n_bytes + Sha1::output_size()));
        let mut k = 0u8;
        if n_bytes > Sha1::output_size() * 256 {
            return Err(Error::InvalidOutputLength);
        }

        while result.len() < n_bytes {
            let mut d = Sha1::new();
            d.input(seed);
            d.input(&[k]);
            result.extend(d.result());
            k += 1;
        }

        result.truncate(n_bytes);
        Ok(result)
    }
}

impl<'a, 'b> Ntor1KDF<'a, 'b> {
    pub fn new(t_key: &'a [u8], m_expand: &'b [u8]) -> Self {
        Ntor1KDF { t_key, m_expand }
    }
}

impl KDF for Ntor1KDF<'_, '_> {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBytes> {
        // XXX mark as zero-on-free?
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(self.t_key), seed);

        let mut result = Zeroizing::new(vec![0; n_bytes]);
        hkdf.expand(self.m_expand, &mut result[..])
            .map_err(|_| Error::InvalidOutputLength)?;
        Ok(result)
    }
}

impl ShakeKDF {
    pub fn new() -> Self {
        ShakeKDF()
    }
}
impl KDF for ShakeKDF {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBytes> {
        // XXX mark as zero-on-free?
        use digest::Input;
        let mut xof = Shake256::default();
        xof.input(seed);
        Ok(Zeroizing::new(xof.vec_result(n_bytes)))
    }
}
