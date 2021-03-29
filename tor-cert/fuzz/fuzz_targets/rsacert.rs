#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cert::rsa::RsaCrosscert;

fuzz_target!(|data: &[u8]| {
    let _ = RsaCrosscert::decode(data);
});
