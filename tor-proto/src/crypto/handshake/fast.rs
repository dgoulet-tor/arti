//! Implementation for the (deprecated) CreateFast handshake.
//!

use crate::crypto::ll::kdf::{LegacyKDF, KDF};
use crate::util::ct::bytes_eq;
use crate::{Error, Result};

use rand::{CryptoRng, RngCore};

/// Number of bytes used for a "CREATE_FAST" handshake by the initiator.
pub const FAST_C_HANDSHAKE_LEN: usize = 20;
/// Number of bytes used for a "CREATE_FAST" handshake by the responder
pub const FAST_S_HANDSHAKE_LEN: usize = 20 * 2;

/// State for a CREATE_FAST client handshake.
pub struct CreateFastClientState([u8; FAST_C_HANDSHAKE_LEN]);

/// Client-handshake for CREATE_FAST.
///
/// See module documentation; you probably don't want to use this.
pub struct CreateFastClient;

impl super::ClientHandshake for CreateFastClient {
    type KeyType = ();
    type StateType = CreateFastClientState;
    type KeyGen = super::TAPKeyGenerator;

    fn client1<R: RngCore + CryptoRng>(
        rng: &mut R,
        _key: &Self::KeyType,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let mut state = [0u8; FAST_C_HANDSHAKE_LEN];
        rng.fill_bytes(&mut state);
        Ok((CreateFastClientState(state), state.into()))
    }

    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<Self::KeyGen> {
        let msg = msg.as_ref();
        if msg.len() != FAST_S_HANDSHAKE_LEN {
            return Err(Error::BadHandshake);
        }
        let mut inp = Vec::new();
        inp.extend(&state.0[..]);
        inp.extend(&msg[0..20]);

        let kh_expect = LegacyKDF::new(0).derive(&inp[..], 20)?;

        if !bytes_eq(&kh_expect, &msg[20..40]) {
            return Err(Error::BadHandshake);
        }

        Ok(super::TAPKeyGenerator::new(inp.into()))
    }
}

/// Relay-handshake for CREATE_FAST.
///
/// See module documentation; you probably don't want to use this.
pub struct CreateFastServer;

impl super::ServerHandshake for CreateFastServer {
    type KeyType = ();
    type KeyGen = super::TAPKeyGenerator;

    fn server<R: RngCore + CryptoRng, T: AsRef<[u8]>>(
        rng: &mut R,
        _key: &[Self::KeyType],
        msg: T,
    ) -> Result<(Self::KeyGen, Vec<u8>)> {
        let msg = msg.as_ref();
        if msg.len() != FAST_C_HANDSHAKE_LEN {
            return Err(Error::BadHandshake);
        }
        let mut reply = vec![0u8; FAST_S_HANDSHAKE_LEN];
        rng.fill_bytes(&mut reply[0..20]);

        let mut inp = Vec::new();
        inp.extend(&msg[..]);
        inp.extend(&reply[0..20]);
        let kh = LegacyKDF::new(0).derive(&inp[..], 20)?;
        reply[20..].copy_from_slice(&kh);

        Ok((super::TAPKeyGenerator::new(inp.into()), reply))
    }
}
