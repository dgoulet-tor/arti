#![no_main]
use libfuzzer_sys::fuzz_target;

use tor_socksproto::SocksHandshake;

fuzz_target!(|data: Vec<Vec<u8>>| {
    let mut hs = SocksHandshake::new();
    for d in data {
        let _ = hs.handshake(&d);
    }
});
