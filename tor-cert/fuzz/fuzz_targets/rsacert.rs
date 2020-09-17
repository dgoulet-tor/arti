#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cert::rsa::RSACrosscert;

fuzz_target!(|data: &[u8]| {
    let _ = RSACrosscert::decode(data);
});
