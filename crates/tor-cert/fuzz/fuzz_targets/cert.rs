#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cert::Ed25519Cert;

fuzz_target!(|data: &[u8]| {
    let _ = Ed25519Cert::decode(data);
});
