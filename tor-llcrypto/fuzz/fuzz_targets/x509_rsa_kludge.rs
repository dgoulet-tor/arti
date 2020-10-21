#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_llcrypto::util::x509_extract_rsa_subject_kludge;

fuzz_target!(|data: &[u8]| {
    let _ = x509_extract_rsa_subject_kludge(data);
});
