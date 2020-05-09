//! Relay cell cryptography
//!
//! The Tor protocol centers around "RELAY cells", which are
//! transmitted through the network along circuits.  The client that
//! creates a circuitg shares two different set of keys and state with
//! each of the relays on the circuit: one for "oubound" traffic, and
//! one for "inbound" traffic.
//!

use crate::{Error, Result};

/// The number of bytes in the body of a cell.
///
/// TODO: This probably belongs somewhere else.
pub const CELL_BODY_LEN: usize = 509;
/// A cell body considerd as a raw array of bytes
pub type RawCellBody = [u8; CELL_BODY_LEN];
/// Type for a cell body.
#[derive(Clone)]
pub struct CellBody(pub RawCellBody);

/// Represents the ability for a circuit crypto state to be initialized
/// from a given seed.
pub trait CryptInit {
    /// Return the number of bytes that this state will require.
    fn seed_len() -> usize;
    /// Construct this state from a seed of the appropriate length.
    ///
    /// TODO: maybe this should return a Result rather than just
    /// asserting that the length is correct.
    fn initialize(seed: &[u8]) -> Self;
}

/// Represents a relay's view of the crypto state on a given circuit.
pub trait RelayCrypt {
    /// Prepare a CellBody to be sent towards the client.
    fn originate(&mut self, cell: &mut CellBody);
    /// Encrypt a CellBody that is moving towards the client.
    fn encrypt_inbound(&mut self, cell: &mut CellBody);
    /// Decrypt a CellBody that is moving towards the client.
    ///
    /// Return true if it is addressed to us.
    fn decrypt_outbound(&mut self, cell: &mut CellBody) -> bool;
}

/// A client's view of the crypto state shared with a single relay.
pub trait ClientLayer {
    /// Prepare a CellBody to be sent to the relay at this layer.
    fn originate_for(&mut self, cell: &mut CellBody);
    /// Encrypt a CellBody to be decrypted by this layer.
    fn encrypt_outbound(&mut self, cell: &mut CellBody);
    /// Decrypt a CellBopdy that passed through this layer.
    ///
    /// Return true if this layer is the originator.
    fn decrypt_inbound(&mut self, cell: &mut CellBody) -> bool;
}

/// Type to store hop indices on a circuit.
pub type HopNum = u8;

/// A client's view of the cryptographic state for an entire
/// constructed circuit.
pub struct ClientCrypt {
    layers: Vec<Box<dyn ClientLayer>>,
}

impl ClientCrypt {
    /// Prepare a cell body to sent away from the client.
    ///
    /// The cell is prepared for the `hop`th hop, and then encrypted with
    /// the appropriate keys.
    pub fn encrypt(&mut self, cell: &mut CellBody, hop: HopNum) -> Result<()> {
        let hop = hop as usize;
        if hop > self.layers.len() {
            return Err(Error::NoSuchHop);
        }

        self.layers[hop].originate_for(cell);
        for layer in self.layers.iter_mut().rev() {
            layer.encrypt_outbound(cell);
        }
        Ok(())
    }
    /// Decrypt an incoming cell that is coming to the client.
    ///
    /// On success, return which hop was the originator of the cell.
    pub fn decrypt(&mut self, cell: &mut CellBody) -> Result<HopNum> {
        for (hopnum, layer) in self.layers.iter_mut().enumerate() {
            if layer.decrypt_inbound(cell) {
                return Ok(hopnum as HopNum);
            }
        }
        Err(Error::BadCellAuth)
    }
    /// Add a new layer to this ClientCrypt
    pub fn add_layer(&mut self, layer: Box<dyn ClientLayer>) {
        assert!(self.layers.len() < HopNum::max_value() as usize);
        self.layers.push(layer);
    }
}

/// Incomplete untested implementation of Tor's current cell crypto.
mod tor1 {
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
            }
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone> RelayCrypt for CryptState<SC, D> {
        fn originate(&mut self, cell: &mut CellBody) {
            cell.set_digest(&mut self.b_d);
        }
        fn encrypt_inbound(&mut self, cell: &mut CellBody) {
            self.b_c.encrypt(&mut cell.0[..])
        }
        fn decrypt_outbound(&mut self, cell: &mut CellBody) -> bool {
            self.f_c.decrypt(&mut cell.0[..]);
            cell.recognized(&mut self.f_d)
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone> ClientLayer for CryptState<SC, D> {
        fn originate_for(&mut self, cell: &mut CellBody) {
            cell.set_digest(&mut self.f_d);
        }
        fn encrypt_outbound(&mut self, cell: &mut CellBody) {
            self.f_c.encrypt(&mut cell.0[..])
        }
        fn decrypt_inbound(&mut self, cell: &mut CellBody) -> bool {
            self.b_c.decrypt(&mut cell.0[..]);
            cell.recognized(&mut self.b_d)
        }
    }

    impl CellBody {
        /// Prepare a cell body by setting its digest and recognized field.
        fn set_digest<D: Digest + Clone>(&mut self, d: &mut D) {
            self.0[1] = 0;
            self.0[2] = 0;
            self.0[5] = 0;
            self.0[6] = 0;
            self.0[7] = 0;
            self.0[8] = 0;

            d.input(&self.0[..]);
            let r = d.clone().result(); // XXX can I avoid this clone?
            self.0[5..9].copy_from_slice(&r[0..4]);
        }
        /// Check a cell to see whether its recognized field is set.
        fn recognized<D: Digest + Clone>(&mut self, d: &mut D) -> bool {
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
                dtmp.input(&self.0[..]);
                dtmp.result()
            };

            if ct::bytes_eq(&dval[..], &r[0..4]) {
                // This is for us. We need to process the data again,
                // apparently, since digesting is destructive
                // according to the digest api.
                d.input(&self.0[..]);
                return true;
            }

            // This is not for us.  We need to set the digest back to
            // what it was.
            *array_mut_ref![self.0, 5, 4] = dval;
            false
        }
    }
}
