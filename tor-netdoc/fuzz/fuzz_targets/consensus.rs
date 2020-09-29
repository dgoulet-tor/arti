#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::netstatus::MDConsensus;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = MDConsensus::parse(s);
    }
});
