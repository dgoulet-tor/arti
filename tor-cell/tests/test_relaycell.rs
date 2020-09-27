// Tests for encoding/decoding relay messags into relay cell bodies.

use tor_cell::relaycell::{msg, msg::RelayCell, msg::RelayMsg, StreamID};

const CELL_BODY_LEN: usize = 509;

struct BadRng;
impl rand::RngCore for BadRng {
    fn next_u32(&mut self) -> u32 {
        0xf0f0f0f0
    }
    fn next_u64(&mut self) -> u64 {
        0xf0f0f0f0f0f0f0f0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = 0xf0;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(self.fill_bytes(dest))
    }
}

// I won't tell if you don't.
impl rand_core::CryptoRng for BadRng {}

fn decode(body: &str) -> [u8; CELL_BODY_LEN] {
    let mut body = body.to_string();
    body.retain(|c| !c.is_whitespace());
    let mut body = hex::decode(body).unwrap();
    body.resize(CELL_BODY_LEN, 0xf0); // see BadRng

    let mut result = [0; CELL_BODY_LEN];
    (&mut result[..]).copy_from_slice(&body[..]);
    result
}

fn cell(body: &str, id: StreamID, msg: RelayMsg) {
    let body = decode(body);
    let mut bad_rng = BadRng;

    let expected = RelayCell::new(id, msg);

    let decoded = RelayCell::decode(body).unwrap();

    assert_eq!(format!("{:?}", expected), format!("{:?}", decoded));

    let encoded1 = decoded.encode(&mut bad_rng).unwrap();
    let encoded2 = expected.encode(&mut bad_rng).unwrap();

    assert_eq!(&encoded1[..], &encoded2[..]);
}

#[test]
fn test_cells() {
    cell(
        "02 0000 9999 12345678 000c 6e6565642d746f2d6b6e6f77 00000000",
        0x9999.into(),
        msg::Data::new(&b"need-to-know"[..]).into(),
    );
}
