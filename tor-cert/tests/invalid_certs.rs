use tor_bytes::Error;
//use tor_cert::rsa::RSACrosscert;
use tor_cert::Ed25519Cert;
//use tor_checkable::{ExternallySigned, SelfSigned, Timebound};

//use std::time::{Duration, SystemTime};

use hex_literal::hex;

#[test]
fn cant_parse() {
    fn decode_err(inp: &[u8]) -> Error {
        Ed25519Cert::decode(inp).err().unwrap()
    }

    assert_eq!(
        decode_err(&hex!("03")),
        Error::BadMessage("Unrecognized certificate version")
    );

    assert_eq!(
        decode_err(&hex!(
            "
       01 04 0006CC2A 01
       F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
       01 0021 04 00
       DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF
       FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
       094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
        )),
        Error::BadMessage("wrong length on Ed25519 key")
    );

    assert_eq!(
        decode_err(&hex!(
            "
       01 04 0006CC2A 01
       F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
       01 0020 09 01
       DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9
       FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
       094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
        )),
        Error::BadMessage("unrecognized certificate extension, with 'affect_validation' flag set.")
    );
}
