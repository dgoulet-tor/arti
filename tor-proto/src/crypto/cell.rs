//! Relay cell cryptography
//!
//! The Tor protocol centers around "RELAY cells", which are
//! transmitted through the network along circuits.  The client that
//! creates a circuitg shares two different set of keys and state with
//! each of the relays on the circuit: one for "oubound" traffic, and
//! one for "inbound" traffic.
//!

use crate::{Error, Result};
use tor_cell::chancell::RawCellBody;

use generic_array::GenericArray;

/// Type for the body of a relay cell.
#[derive(Clone)]
pub struct RelayCellBody(RawCellBody);

impl From<RawCellBody> for RelayCellBody {
    fn from(body: RawCellBody) -> Self {
        RelayCellBody(body)
    }
}
impl From<RelayCellBody> for RawCellBody {
    fn from(cell: RelayCellBody) -> Self {
        cell.0
    }
}
impl AsRef<[u8]> for RelayCellBody {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
impl AsMut<[u8]> for RelayCellBody {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

/// Represents the ability for a circuit crypto state to be initialized
/// from a given seed.
pub(crate) trait CryptInit: Sized {
    /// Return the number of bytes that this state will require.
    fn seed_len() -> usize;
    /// Construct this state from a seed of the appropriate length.
    ///
    /// TODO: maybe this should return a Result rather than just
    /// asserting that the length is correct.
    fn initialize(seed: &[u8]) -> Self;
    /// Initialize this object from a key generator.
    fn construct<K: super::handshake::KeyGenerator>(keygen: K) -> Result<Self> {
        let seed = keygen.expand(Self::seed_len())?;
        Ok(Self::initialize(&seed))
    }
}

/// Represents a relay's view of the crypto state on a given circuit.
pub(crate) trait RelayCrypt {
    /// Prepare a RelayCellBody to be sent towards the client.
    fn originate(&mut self, cell: &mut RelayCellBody);
    /// Encrypt a RelayCellBody that is moving towards the client.
    fn encrypt_inbound(&mut self, cell: &mut RelayCellBody);
    /// Decrypt a RelayCellBody that is moving towards the client.
    ///
    /// Return true if it is addressed to us.
    fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool;
}

/// A client's view of the crypto state shared with a single relay.
pub(crate) trait ClientLayer {
    /// Prepare a RelayCellBody to be sent to the relay at this layer, and
    /// encrypt it.
    ///
    /// Return the authentication tag.
    fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8];
    /// Encrypt a RelayCellBody to be decrypted by this layer.
    fn encrypt_outbound(&mut self, cell: &mut RelayCellBody);
    /// Decrypt a CellBopdy that passed through this layer.
    ///
    /// Return an authentication tag if this layer is the originator.
    fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]>;
}

/// Type to store hop indices on a circuit.
///
/// Hop indices are zero-based: "0" denotes the first hop on the circuit.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct HopNum(u8);

impl Into<u8> for HopNum {
    fn into(self) -> u8 {
        self.0
    }
}

impl From<u8> for HopNum {
    fn from(v: u8) -> HopNum {
        HopNum(v)
    }
}

impl Into<usize> for HopNum {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for HopNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

/// A client's view of the cryptographic state for an entire
/// constructed circuit.
pub(crate) struct ClientCrypt {
    layers: Vec<Box<dyn ClientLayer + Send>>,
}

impl ClientCrypt {
    /// Return a new (empty) ClientCrypt.
    pub fn new() -> Self {
        ClientCrypt { layers: Vec::new() }
    }
    /// Prepare a cell body to sent away from the client.
    ///
    /// The cell is prepared for the `hop`th hop, and then encrypted with
    /// the appropriate keys.
    ///
    /// On success, returns a reference to tag that should be expected
    /// for an authenticated SENDME sent in response to this cell.
    pub fn encrypt(&mut self, cell: &mut RelayCellBody, hop: HopNum) -> Result<&[u8]> {
        let hop: usize = hop.into();
        if hop >= self.layers.len() {
            return Err(Error::NoSuchHop);
        }

        let mut layers = self.layers.iter_mut().take(hop + 1).rev();
        let first_layer = layers.next().unwrap();
        let tag = first_layer.originate_for(cell);
        for layer in layers {
            layer.encrypt_outbound(cell);
        }
        Ok(tag)
    }
    /// Decrypt an incoming cell that is coming to the client.
    ///
    /// On success, return which hop was the originator of the cell.
    // XXXX use real tag type
    pub fn decrypt(&mut self, cell: &mut RelayCellBody) -> Result<(HopNum, &[u8])> {
        for (hopnum, layer) in self.layers.iter_mut().enumerate() {
            if let Some(tag) = layer.decrypt_inbound(cell) {
                assert!(hopnum <= std::u8::MAX as usize);
                return Ok(((hopnum as u8).into(), tag));
            }
        }
        Err(Error::BadCellAuth)
    }
    /// Add a new layer to this ClientCrypt
    pub fn add_layer(&mut self, layer: Box<dyn ClientLayer + Send>) {
        assert!(self.layers.len() < std::u8::MAX as usize);
        self.layers.push(layer);
    }

    /// Return the number of layers configured on this ClientCrypt.
    ///
    /// TODO: use HopNum
    pub fn n_layers(&self) -> usize {
        self.layers.len()
    }
}

/// Standard Tor relay crypto, as instantiated for RELAY cells.
pub(crate) type Tor1RelayCrypto =
    tor1::CryptState<tor_llcrypto::cipher::aes::Aes128Ctr, tor_llcrypto::d::Sha1>;

/// Incomplete untested implementation of Tor's current cell crypto.
pub(crate) mod tor1 {
    use super::*;
    use digest::Digest;
    use std::convert::TryInto;
    use stream_cipher::{NewStreamCipher, StreamCipher};
    use typenum::Unsigned;

    /// A CryptState is part of a RelayCrypt or a ClientLayer.
    ///
    /// It is parameterized on a stream cipher and a digest type: most
    /// circuits will use AES-128-CTR and SHA1, but v3 onion services
    /// use AES-256-CTR and SHA-3.
    pub struct CryptState<SC: StreamCipher, D: Digest + Clone> {
        f_c: SC,
        b_c: SC,
        f_d: D,
        b_d: D,
        last_sent_digest: GenericArray<u8, D::OutputSize>,
        last_rcvd_digest: GenericArray<u8, D::OutputSize>,
    }

    impl<SC: StreamCipher + NewStreamCipher, D: Digest + Clone> CryptInit for CryptState<SC, D> {
        fn seed_len() -> usize {
            SC::KeySize::to_usize() * 2 + D::OutputSize::to_usize() * 2
        }
        fn initialize(seed: &[u8]) -> Self {
            assert!(seed.len() == Self::seed_len());
            let keylen = SC::KeySize::to_usize();
            let dlen = D::OutputSize::to_usize();
            let fdinit = &seed[0..dlen];
            let bdinit = &seed[dlen..dlen * 2];
            let fckey = &seed[dlen * 2..dlen * 2 + keylen];
            let bckey = &seed[dlen * 2 + keylen..dlen * 2 + keylen * 2];
            CryptState {
                f_c: SC::new(fckey.try_into().expect("Wrong length"), &Default::default()),
                b_c: SC::new(bckey.try_into().expect("Wrong length"), &Default::default()),
                f_d: D::new().chain(fdinit),
                b_d: D::new().chain(bdinit),
                last_sent_digest: GenericArray::default(),
                last_rcvd_digest: GenericArray::default(),
            }
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone> RelayCrypt for CryptState<SC, D> {
        fn originate(&mut self, cell: &mut RelayCellBody) {
            let mut d_ignored = GenericArray::default();
            cell.set_digest(&mut self.b_d, &mut d_ignored);
        }
        fn encrypt_inbound(&mut self, cell: &mut RelayCellBody) {
            self.b_c.encrypt(cell.as_mut());
        }
        fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool {
            self.f_c.decrypt(cell.as_mut());
            let mut d_ignored = GenericArray::default();
            cell.recognized(&mut self.f_d, &mut d_ignored)
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone> ClientLayer for CryptState<SC, D> {
        fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8] {
            cell.set_digest(&mut self.f_d, &mut self.last_sent_digest);
            self.encrypt_outbound(cell);
            &self.last_sent_digest
        }
        fn encrypt_outbound(&mut self, cell: &mut RelayCellBody) {
            self.f_c.encrypt(&mut cell.0[..])
        }
        fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]> {
            self.b_c.decrypt(&mut cell.0[..]);
            if cell.recognized(&mut self.b_d, &mut self.last_rcvd_digest) {
                Some(&self.last_rcvd_digest)
            } else {
                None
            }
        }
    }

    impl RelayCellBody {
        /// Prepare a cell body by setting its digest and recognized field.
        fn set_digest<D: Digest + Clone>(
            &mut self,
            d: &mut D,
            used_digest: &mut GenericArray<u8, D::OutputSize>,
        ) {
            self.0[1] = 0;
            self.0[2] = 0;
            self.0[5] = 0;
            self.0[6] = 0;
            self.0[7] = 0;
            self.0[8] = 0;

            d.update(&self.0[..]);
            *used_digest = d.clone().finalize(); // XXX can I avoid this clone?
            self.0[5..9].copy_from_slice(&used_digest[0..4]);
        }
        /// Check a cell to see whether its recognized field is set.
        fn recognized<D: Digest + Clone>(
            &mut self,
            d: &mut D,
            rcvd: &mut GenericArray<u8, D::OutputSize>,
        ) -> bool {
            // maybe too optimized? XXXX
            // XXXX self is only mut for an optimization.
            use crate::util::ct;
            use arrayref::{array_mut_ref, array_ref};
            let recognized = u16::from_be_bytes(*array_ref![self.0, 1, 2]);
            if recognized != 0 {
                return false;
            }

            let dval = *array_ref![self.0, 5, 4];
            {
                self.0[5] = 0;
                self.0[6] = 0;
                self.0[7] = 0;
                self.0[8] = 0;
            }

            let r = {
                let mut dtmp = d.clone();
                dtmp.update(&self.0[..]);
                dtmp.finalize()
            };

            if ct::bytes_eq(&dval[..], &r[0..4]) {
                // This is for us. We need to process the data again,
                // apparently, since digesting is destructive
                // according to the digest api.
                d.update(&self.0[..]);
                *rcvd = r;
                return true;
            }

            // This is not for us.  We need to set the digest back to
            // what it was.
            *array_mut_ref![self.0, 5, 4] = dval;
            false
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::SecretBytes;
    use rand::RngCore;

    #[test]
    fn roundtrip() {
        // Take canned keys and make sure we can do crypto correctly.
        use crate::crypto::handshake::ShakeKeyGenerator as KGen;
        fn s(seed: &[u8]) -> SecretBytes {
            let mut s: SecretBytes = SecretBytes::new(Vec::new());
            s.extend(seed);
            s
        }

        let seed1 = s(b"hidden we are free");
        let seed2 = s(b"free to speak, to free ourselves");
        let seed3 = s(b"free to hide no more");

        let mut cc = ClientCrypt::new();
        cc.add_layer(Box::new(
            Tor1RelayCrypto::construct(KGen::new(seed1.clone().into())).unwrap(),
        ));
        cc.add_layer(Box::new(
            Tor1RelayCrypto::construct(KGen::new(seed2.clone().into())).unwrap(),
        ));
        cc.add_layer(Box::new(
            Tor1RelayCrypto::construct(KGen::new(seed3.clone().into())).unwrap(),
        ));

        let mut r1 = Tor1RelayCrypto::construct(KGen::new(seed1.into())).unwrap();
        let mut r2 = Tor1RelayCrypto::construct(KGen::new(seed2.into())).unwrap();
        let mut r3 = Tor1RelayCrypto::construct(KGen::new(seed3.into())).unwrap();

        let mut rng = rand::thread_rng();
        for _ in 1..1000 {
            // outbound cell
            let mut cell = [0_u8; 509];
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig[..]);
            (&mut cell).copy_from_slice(&cell_orig[..]);
            let mut cell = cell.into();
            let _tag = cc.encrypt(&mut cell, 2.into());
            assert_ne!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);
            assert_eq!(false, r1.decrypt_outbound(&mut cell));
            assert_eq!(false, r2.decrypt_outbound(&mut cell));
            assert_eq!(true, r3.decrypt_outbound(&mut cell));

            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // inbound cell
            let mut cell = [0_u8; 509];
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig[..]);
            (&mut cell).copy_from_slice(&cell_orig[..]);
            let mut cell = cell.into();

            r3.originate(&mut cell);
            r3.encrypt_inbound(&mut cell);
            r2.encrypt_inbound(&mut cell);
            r1.encrypt_inbound(&mut cell);
            let (layer, _tag) = cc.decrypt(&mut cell).unwrap();
            assert_eq!(layer, 2.into());
            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // TODO: Test tag somehow.
        }
    }

    // TODO: Generate test vectors from Tor.
}
