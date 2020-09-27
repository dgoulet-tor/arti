// Test for encoding/decoding channel cells.
//
// Reminder: you can think of a cell as an message plus a circuitid.

use tor_cell::chancell::{codec, msg, ChanCell, CircID};
use tor_cell::Error;

use bytes::BytesMut;

const FIXED_BODY_LEN: usize = 514;

fn decode(body: &str, pad_body: bool) -> Vec<u8> {
    let mut body = body.to_string();
    body.retain(|c| !c.is_whitespace());
    let mut body = hex::decode(body).unwrap();
    if pad_body {
        body.resize(FIXED_BODY_LEN, 0);
    }
    body
}

fn cell(body: &str, msg: msg::ChanMsg, id: CircID, pad_body: bool) {
    let body = decode(body, pad_body);

    let cell = ChanCell::new(id, msg);
    let mut codec = codec::ChannelCodec::new(4);

    let decoded = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        bm.extend_from_slice(&b"next thing"[..]);
        let decoded = codec.decode_cell(&mut bm).unwrap();
        assert_eq!(bm.len(), 10);
        decoded.unwrap()
    };

    let decoded2 = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        // no extra bytes this time.
        let decoded = codec.decode_cell(&mut bm).unwrap();
        assert_eq!(bm.len(), 0);
        decoded.unwrap()
    };

    assert_eq!(format!("{:?}", decoded), format!("{:?}", cell));
    assert_eq!(format!("{:?}", decoded2), format!("{:?}", cell));

    let mut encoded1 = BytesMut::new();
    let mut encoded2 = BytesMut::new();
    codec.write_cell(cell, &mut encoded1).unwrap();
    codec.write_cell(decoded, &mut encoded2).unwrap();

    assert_eq!(encoded1, encoded2);
    assert_eq!(encoded1, body);
}

fn fcell(body: &str, msg: msg::ChanMsg, id: CircID) {
    cell(body, msg, id, true);
}

fn vcell(body: &str, msg: msg::ChanMsg, id: CircID) {
    cell(body, msg, id, false);
}

#[test]
fn test_simple_cells() {
    fcell("", msg::Padding::new().into(), 0.into());

    vcell(
        "12345678 ff 0019 7765206c697374656e20726f756e642074686520636c6f636b",
        msg::Unrecognized::new(255.into(), &b"we listen round the clock"[..]).into(),
        0x12345678.into(),
    );

    fcell(
        "20201122 03 666f72206120636f64652063616c6c656420706561636574696d65",
        msg::Relay::new(b"for a code called peacetime").into(),
        0x20201122.into(),
    );
}

fn short_cell(body: &str) {
    let body = decode(body, false);

    let mut codec = codec::ChannelCodec::new(4);

    let mut bm = BytesMut::new();
    bm.extend_from_slice(&body[..]);
    let len_orig = bm.len();
    let d = codec.decode_cell(&mut bm);
    assert!(d.unwrap().is_none()); // "Ok(None)" means truncated.
    assert_eq!(bm.len(), len_orig);
}

#[test]
fn test_truncated_cells() {
    // short relay (fixed)
    short_cell("00000001 03 1234");

    // short certs (varlen)
    short_cell("00000000 81 0003 1234");
}

fn bad_cell(body: &str, err: Error, pad_body: bool) {
    let body = decode(body, pad_body);

    let mut codec = codec::ChannelCodec::new(4);

    let decoded = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        bm.extend_from_slice(&b"next thing"[..]);
        let decoded = codec.decode_cell(&mut bm).err().unwrap();
        decoded
    };

    assert_eq!(format!("{:?}", decoded), format!("{:?}", err));
}

#[test]
fn bad_circid_cells() {
    // relay, no circid
    bad_cell(
        "00000000 03 123456",
        Error::ChanProto("Invalid circuit ID 0 for cell command RELAY".into()),
        true,
    );

    // relay, unexpected circid
    bad_cell(
        "00000010 08 123456",
        Error::ChanProto("Invalid circuit ID 16 for cell command NETINFO".into()),
        true,
    );
}
