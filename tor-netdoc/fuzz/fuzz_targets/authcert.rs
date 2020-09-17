#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::authcert::AuthCert;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = AuthCert::parse_multiple(s).count();
    }
});
