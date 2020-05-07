use crate::{Error, Result};

pub const CELL_BODY_LEN: usize = 509;
pub type RawCellBody = [u8; CELL_BODY_LEN];
#[derive(Clone)]
pub struct CellBody(pub RawCellBody);

pub trait CryptInit {
    fn seed_len() -> usize;
    fn initialize(seed: &[u8]) -> Self;
}

pub trait RelayCrypt {
    fn originate(&mut self, cell: &mut CellBody);
    fn encrypt_inbound(&mut self, cell: &mut CellBody);
    fn decrypt_outbound(&mut self, cell: &mut CellBody) -> bool;
}

pub trait ClientLayer {
    fn originate_for(&mut self, cell: &mut CellBody);
    fn encrypt_outbound(&mut self, cell: &mut CellBody);
    fn decrypt_inbound(&mut self, cell: &mut CellBody) -> bool;
}

pub type HopNum = u16;

pub struct ClientCrypt {
    layers: Vec<Box<dyn ClientLayer>>,
}

impl ClientCrypt {
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
    pub fn decrypt(&mut self, cell: &mut CellBody) -> Result<HopNum> {
        for (hopnum, layer) in self.layers.iter_mut().enumerate() {
            if layer.decrypt_inbound(cell) {
                return Ok(hopnum as HopNum);
            }
        }
        Err(Error::BadCellAuth)
    }
    pub fn add_layer(&mut self, layer: Box<dyn ClientLayer>) {
        assert!(self.layers.len() < HopNum::max_value() as usize);
        self.layers.push(layer);
    }
}

mod tor1 {
    use super::*;
    use digest::Digest;
    use std::convert::TryInto;
    use stream_cipher::{NewStreamCipher, StreamCipher};
    use typenum::Unsigned;

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
