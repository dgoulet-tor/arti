use digest::Digest;
use hex_literal::hex;
use stream_cipher::{NewStreamCipher, StreamCipher};
use tor_llcrypto as ll;

#[test]
fn tv_curve25519() {
    use ll::pk::curve25519::*;

    // Test vectors from RFC 7748
    let s1 = hex!(
        "a546e36bf0527c9d3b16154b82465edd
                   62144c0ac1fc5a18506a2244ba449ac4"
    );
    let u1 = hex!(
        "e6db6867583030db3594c1a424b15f7c
                   726624ec26b3353b10a903a6d0ab1c4c"
    );
    let o1 = hex!(
        "c3da55379de9c6908e94ea4df28d084f
                   32eccf03491c71f754b4075577a28552"
    );

    let s1 = StaticSecret::from(s1);
    let u1 = PublicKey::from(u1);
    let ss = s1.diffie_hellman(&u1);
    assert_eq!(ss.as_bytes(), &o1);

    let s2 = hex!(
        "4b66e9d4d1b4673c5ad22691957d6af5
                   c11b6421e0ea01d42ca4169e7918ba0d"
    );
    let u2 = hex!(
        "e5210f12786811d3f4b7959d0538ae2c
                   31dbe7106fc03c3efc4cd549c715a493"
    );
    let o2 = hex!(
        "95cbde9476e8907d7aade45cb4b873f8
                   8b595a68799fa152e6f8f7647aac7957"
    );

    let s2 = StaticSecret::from(s2);
    let u2 = PublicKey::from(u2);
    let ss = s2.diffie_hellman(&u2);
    assert_eq!(ss.as_bytes(), &o2);
}

#[test]
fn tv_ed25519() {
    use ll::pk::ed25519::*;
    // Test vectors from RFC 8032.

    // TEST 1
    let sk = SecretKey::from_bytes(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc4
               4449c5697b326919703bac031cae7f60"
    ))
    .expect("Bad value");

    let pk: PublicKey = (&sk).into();

    assert_eq!(
        pk.as_bytes(),
        &hex!(
            "d75a980182b10ab7d54bfed3c964073a
                      0ee172f3daa62325af021a68f707511a"
        )
    );

    let kp = Keypair {
        public: pk,
        secret: sk,
    };
    let sig = kp.sign(&b""[..]);
    assert_eq!(
        &sig.to_bytes()[..],
        &hex!(
            "e5564300c360ac729086e2cc806e828a
                      84877f1eb8e5d974d873e06522490155
                      5fb8821590a33bacc61e39701cf9b46b
                      d25bf5f0595bbe24655141438e7a100b"
        )[..]
    );

    assert!(kp.public.verify(&b""[..], &sig).is_ok());

    // TEST 3
    let sk = SecretKey::from_bytes(&hex!(
        "c5aa8df43f9f837bedb7442f31dcb7b1
               66d38535076f094b85ce3a2e0b4458f7"
    ))
    .expect("Bad value");

    let pk: PublicKey = (&sk).into();

    assert_eq!(
        pk.as_bytes(),
        &hex!(
            "fc51cd8e6218a1a38da47ed00230f058
                      0816ed13ba3303ac5deb911548908025"
        )
    );

    let kp = Keypair {
        public: pk,
        secret: sk,
    };
    let sig = kp.sign(&hex!("af82"));
    assert_eq!(
        &sig.to_bytes()[..],
        &hex!(
            "6291d657deec24024827e69c3abe01a3
                      0ce548a284743a445e3680d7db5ac3ac
                      18ff9b538d16f290ae67f760984dc659
                      4a7c15e9716ed28dc027beceea1ec40a"
        )[..]
    );

    assert!(kp.public.verify(&hex!("af82"), &sig).is_ok());

    assert!(kp.public.verify(&hex!(""), &sig).is_err());
}

#[test]
fn tv_aes128_ctr() {
    // From NIST Special Publication 800-38A.
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    use ll::cipher::aes::Aes128Ctr;

    let k1 = hex!("2b7e151628aed2a6abf7158809cf4f3c").into();
    let ctr1 = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").into();

    let mut cipher = Aes128Ctr::new(&k1, &ctr1);
    let mut data = hex!(
        "6bc1bee22e409f96e93d7e117393172a
         ae2d8a571e03ac9c9eb76fac45af8e51
         30c81c46a35ce411e5fbc1191a0a52ef
         f69f2445df4f9b17ad2b417be66c3710"
    );

    cipher.encrypt(&mut data);

    assert_eq!(
        &data[..],
        &hex!(
            "874d6191b620e3261bef6864990db6ce
             9806f66b7970fdff8617187bb9fffdff
             5ae4df3edbd5d35e5b4f09020db03eab
             1e031dda2fbe03d1792170a0f3009cee"
        )[..]
    );
}

#[test]
fn tv_aes256_ctr() {
    // From NIST Special Publication 800-38A.
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    use ll::cipher::aes::Aes256Ctr;

    let k1 = hex!(
        "603deb1015ca71be2b73aef0857d7781
         1f352c073b6108d72d9810a30914dff4"
    )
    .into();
    let ctr1 = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").into();

    let mut cipher = Aes256Ctr::new(&k1, &ctr1);
    let mut data = hex!(
        "6bc1bee22e409f96e93d7e117393172a
         ae2d8a571e03ac9c9eb76fac45af8e51
         30c81c46a35ce411e5fbc1191a0a52ef
         f69f2445df4f9b17ad2b417be66c3710"
    );

    cipher.encrypt(&mut data);

    assert_eq!(
        &data[..],
        &hex!(
            "601ec313775789a5b7a7f504bbf3d228
             f443e3ca4d62b59aca84e990cacaf5c5
             2b0930daa23de94ce87017ba2d84988d
             dfc9c58db67aada613c2dd08457941a6"
        )[..]
    );
}

#[test]
fn tv_sha1() {
    // From RFC 3174, extracted from the example C code.
    use ll::d::Sha1;

    fn run_test(inp: &[u8], repeatcount: usize, expect: &[u8]) {
        let mut d = Sha1::new();
        for _ in 0..repeatcount {
            d.input(inp);
        }
        let res = d.result();
        assert_eq!(&res[..], &expect[..]);
    }

    run_test(
        b"abc",
        1,
        &hex!(
            "A9 99 3E 36 47 06 81 6A BA 3E
             25 71 78 50 C2 6C 9C D0 D8 9D"
        )[..],
    );
    run_test(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        1,
        &hex!(
            "84 98 3E 44 1C 3B D2 6E BA AE
             4A A1 F9 51 29 E5 E5 46 70 F1"
        )[..],
    );
    run_test(
        b"a",
        1000000,
        &hex!(
            "34 AA 97 3C D4 C4 DA A4 F6 1E
             EB 2B DB AD 27 31 65 34 01 6F"
        )[..],
    );
    run_test(
        b"0123456701234567012345670123456701234567012345670123456701234567",
        10,
        &hex!(
            "DE A3 56 A2 CD DD 90 C7 A7 EC
             ED C5 EB B5 63 93 4F 46 04 52"
        )[..],
    );
}

#[test]
fn tv_sha256() {
    // From FIPS 180-3 at
    // https://csrc.nist.gov/csrc/media/publications/fips/180/3/archive/2008-10-31/documents/fips180-3_final.pdf
}
