use super::KeyGenerator;
use crate::util::ct;
use crate::{Error, Result, SecretBytes};
use tor_bytes::{Reader, Writer};
use tor_llcrypto::pk::curve25519::*;
use tor_llcrypto::pk::rsa::RSAIdentity;

use crypto_mac::MacResult;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct NtorPublicKey {
    id: RSAIdentity,
    pk: PublicKey,
}

pub struct NtorSecretKey {
    pk: NtorPublicKey,
    sk: StaticSecret,
}

use subtle::{Choice, ConstantTimeEq};
impl NtorSecretKey {
    fn matches_pk(&self, pk: PublicKey) -> Choice {
        self.pk.pk.as_bytes().ct_eq(pk.as_bytes())
    }
}

pub struct NtorHandshakeState {
    relay_public: NtorPublicKey,
    my_sk: StaticSecret, // can't use ephemeralsecret -- need to use it twice.
    my_public: PublicKey,
}

pub struct NtorHKDFKeyGenerator {
    seed: SecretBytes,
}

impl NtorHKDFKeyGenerator {
    pub fn new(seed: SecretBytes) -> Self {
        NtorHKDFKeyGenerator { seed }
    }
}

impl KeyGenerator for NtorHKDFKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBytes> {
        let ntor1_key = &b"ntor-curve25519-sha256-1:key_extract"[..];
        let ntor1_expand = &b"ntor-curve25519-sha256-1:key_expand"[..];
        use crate::crypto::ll::kdf::{Ntor1KDF, KDF};
        Ntor1KDF::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
    }
}

type Authcode = MacResult<typenum::U32>;

pub fn client_handshake_ntor_v1<R>(
    rng: &mut R,
    relay_public: &NtorPublicKey,
) -> (NtorHandshakeState, Vec<u8>)
where
    R: RngCore + CryptoRng,
{
    let my_sk = StaticSecret::new(rng);
    let my_public = PublicKey::from(&my_sk);

    client_handshake_ntor_v1_no_keygen(my_public, my_sk, relay_public)
}

fn client_handshake_ntor_v1_no_keygen(
    my_public: PublicKey,
    my_sk: StaticSecret,
    relay_public: &NtorPublicKey,
) -> (NtorHandshakeState, Vec<u8>) {
    let mut v: Vec<u8> = Vec::new();

    v.write(&relay_public.id);
    v.write(&relay_public.pk);
    v.write(&my_public);

    assert_eq!(v.len(), 20 + 32 + 32);

    let state = NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_public,
        my_sk,
    };

    (state, v)
}

pub fn client_handshake2_ntor_v1<T>(
    msg: T,
    state: NtorHandshakeState,
) -> Result<NtorHKDFKeyGenerator>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk: PublicKey = cur.extract()?;
    let auth: Authcode = cur.extract()?;

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    let (keygen, authcode) =
        ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk);

    if authcode != auth {
        return Err(Error::BadHandshake);
    }

    Ok(keygen)
}

fn ntor_derive(
    xy: &SharedSecret,
    xb: &SharedSecret,
    server_pk: &NtorPublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> (NtorHKDFKeyGenerator, Authcode) {
    let ntor1_protoid = &b"ntor-curve25519-sha256-1"[..];
    let ntor1_mac = &b"ntor-curve25519-sha256-1:mac"[..];
    let ntor1_verify = &b"ntor-curve25519-sha256-1:verify"[..];
    let server_string = &b"Server"[..];

    let mut secret_input = Zeroizing::new(Vec::new());
    secret_input.write(xy); // EXP(X,y)
    secret_input.write(xb); // EXP(X,b)
    secret_input.write(&server_pk.id); // ID
    secret_input.write(&server_pk.pk); // B
    secret_input.write(x); // X
    secret_input.write(y); // Y
    secret_input.write(ntor1_protoid); // PROTOID

    use hmac::{Hmac, Mac};
    use tor_llcrypto::d::Sha256;
    let verify = {
        let mut m = Hmac::<Sha256>::new_varkey(ntor1_verify).expect("Hmac allows keys of any size");
        m.input(&secret_input[..]);
        m.result_reset()
    };
    let mut auth_input: SecretBytes = Zeroizing::new(Vec::new());
    auth_input.write_and_consume(verify); // verify
    auth_input.write(&server_pk.id); // ID
    auth_input.write(&server_pk.pk); // B
    auth_input.write(y); // Y
    auth_input.write(x); // X
    auth_input.write(ntor1_protoid); // PROTOID
    auth_input.write(server_string); // "Server"

    let auth_mac = {
        let mut m = Hmac::<Sha256>::new_varkey(ntor1_mac).expect("Hmac allows keys of any size");
        m.input(&auth_input[..]);
        m.result_reset()
    };

    let keygen = NtorHKDFKeyGenerator::new(secret_input);
    (keygen, auth_mac)
}

pub fn server_handshake_ntor_v1<R, T>(
    rng: &mut R,
    msg: T,
    keys: &[NtorSecretKey],
) -> Result<(NtorHKDFKeyGenerator, Vec<u8>)>
where
    R: RngCore + CryptoRng,
    T: AsRef<[u8]>,
{
    // XXXX we generate this key whether or not we are actually going to
    // find our nodeid or keyid. Perhaps we should delay that till later.
    // But if we do, we'll need to refactor a bit to keep our tests working.
    let ephem = EphemeralSecret::new(rng);
    let ephem_pub = PublicKey::from(&ephem);

    server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, msg, keys)
}

fn server_handshake_ntor_v1_no_keygen<T>(
    ephem_pub: PublicKey,
    ephem: EphemeralSecret,
    msg: T,
    keys: &[NtorSecretKey],
) -> Result<(NtorHKDFKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());

    let my_id: RSAIdentity = cur.extract()?;
    let my_key: PublicKey = cur.extract()?;
    let their_pk: PublicKey = cur.extract()?;

    let keypair = ct::lookup(&my_key, keys, |a, b| b.matches_pk(*a));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(Error::MissingKey),
    };

    if my_id != keypair.pk.id {
        return Err(Error::MissingKey);
    }

    let xy = ephem.diffie_hellman(&their_pk);
    let xb = keypair.sk.diffie_hellman(&their_pk);

    let (keygen, authcode) = ntor_derive(&xy, &xb, &keypair.pk, &their_pk, &ephem_pub);

    let mut reply: Vec<u8> = Vec::new();
    reply.write(&ephem_pub);
    reply.write_and_consume(authcode);
    Ok((keygen, reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() -> Result<()> {
        let mut rng = rand_core::OsRng;
        let relay_secret = StaticSecret::new(&mut rng);
        let relay_public = PublicKey::from(&relay_secret);
        let relay_identity = RSAIdentity::from_bytes(&[12; 20]).unwrap();
        let relay_ntpk = NtorPublicKey {
            id: relay_identity,
            pk: relay_public.clone(),
        };
        let (state, cmsg) = client_handshake_ntor_v1(&mut rng, &relay_ntpk);

        let relay_ntsk = NtorSecretKey {
            pk: relay_ntpk.clone(),
            sk: relay_secret.clone(),
        };
        let relay_ntsks = [relay_ntsk];

        let (skeygen, smsg) = server_handshake_ntor_v1(&mut rng, &cmsg, &relay_ntsks)?;

        let ckeygen = client_handshake2_ntor_v1(smsg, state)?;

        let skeys = skeygen.expand(55)?;
        let ckeys = ckeygen.expand(55)?;

        assert_eq!(skeys, ckeys);

        Ok(())
    }

    struct FakePRNG<'a> {
        bytes: &'a [u8],
    }
    impl<'a> FakePRNG<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes }
        }
    }
    impl<'a> RngCore for FakePRNG<'a> {
        fn next_u32(&mut self) -> u32 {
            rand_core::impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            rand_core::impls::next_u64_via_fill(self)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            Ok(self.fill_bytes(dest))
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            assert!(dest.len() <= self.bytes.len());

            dest.copy_from_slice(&self.bytes[0..dest.len()]);
            self.bytes = &self.bytes[dest.len()..];
        }
    }
    impl rand_core::CryptoRng for FakePRNG<'_> {}
    fn make_fake_ephem_key(bytes: &[u8]) -> EphemeralSecret {
        assert_eq!(bytes.len(), 32);
        let mut rng = FakePRNG::new(bytes);
        EphemeralSecret::new(&mut rng)
    }

    #[test]
    fn testvec() -> Result<()> {
        use hex_literal::hex;

        let b_sk = hex!("4820544f4c4420594f5520444f474954204b454550532048415050454e494e47");
        let b_pk = hex!("ccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471");
        let x_sk = hex!("706f6461792069207075742e2e2e2e2e2e2e2e4a454c4c59206f6e2074686973");
        let x_pk = hex!("e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
        let y_sk = hex!("70686520737175697272656c2e2e2e2e2e2e2e2e686173206869732067616d65");
        let y_pk = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a37");
        let id = hex!("69546f6c64596f7541626f75745374616972732e");
        let client_handshake = hex!("69546f6c64596f7541626f75745374616972732eccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
        let server_handshake = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a371cbdf68b89923e1f85e8e18ee6e805ea333fe4849c790ffd2670bd80fec95cc8");
        let keys = hex!("0c62dee7f48893370d0ef896758d35729867beef1a5121df80e00f79ed349af39b51cae125719182f19d932a667dae1afbf2e336e6910e7822223e763afad0a13342157969dc6b79");

        let relay_pk = NtorPublicKey {
            id: RSAIdentity::from_bytes(&id).unwrap(),
            pk: b_pk.into(),
        };
        let relay_sk = NtorSecretKey {
            pk: relay_pk.clone(),
            sk: b_sk.into(),
        };

        let (state, create_msg) =
            client_handshake_ntor_v1_no_keygen(x_pk.into(), x_sk.into(), &relay_pk);
        assert_eq!(&create_msg[..], &client_handshake[..]);

        let ephem = make_fake_ephem_key(&y_sk[..]);
        let ephem_pub = y_pk.into();
        let (s_keygen, created_msg) =
            server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, &create_msg[..], &[relay_sk])?;
        assert_eq!(&created_msg[..], &server_handshake[..]);

        let c_keygen = client_handshake2_ntor_v1(created_msg, state)?;

        let c_keys = c_keygen.expand(keys.len())?;
        let s_keys = s_keygen.expand(keys.len())?;
        assert_eq!(&c_keys[..], &keys[..]);
        assert_eq!(&s_keys[..], &keys[..]);
        Ok(())
    }
}
