#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::routerdesc::RouterReader;
use tor_netdoc::AllowAnnotations;

fuzz_target!(|data: &[u8]| {
    if data.len() > 0 {
        let allow = if (data[0] & 1) == 0 {
            AllowAnnotations::AnnotationsAllowed
        } else {
            AllowAnnotations::AnnotationsNotAllowed
        };
        if let Ok(s) = std::str::from_utf8(&data[1..]) {
            let _ = RouterReader::new(s, allow).count();
        }
    }
});
