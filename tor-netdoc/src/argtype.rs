//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub use b64impl::*;
pub use curve25519impl::*;
pub use edcert::*;
pub use rsa::*;
pub use timeimpl::*;

pub trait FromBytes: Sized {
    fn from_bytes(b: &[u8], p: crate::Pos) -> crate::Result<Self>;
    fn from_vec(v: Vec<u8>, p: crate::Pos) -> crate::Result<Self> {
        Self::from_bytes(&v[..], p)
    }
}

mod b64impl {
    use crate::{Error, Pos, Result};

    pub struct B64(Vec<u8>);

    impl std::str::FromStr for B64 {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let bytes = base64::decode_config(s, base64::STANDARD_NO_PAD)
                .map_err(|e| Error::BadArgument(Pos::at(s), format!("Invalid base64: {}", e)))?;
            Ok(B64(bytes))
        }
    }

    impl B64 {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl From<B64> for Vec<u8> {
        fn from(w: B64) -> Vec<u8> {
            w.0
        }
    }
}

// ============================================================

mod curve25519impl {
    use super::B64;
    use crate::{Error, Pos, Result};
    use std::convert::TryInto;
    use tor_llcrypto::pk::curve25519::PublicKey;

    pub struct Curve25519Public(PublicKey);

    impl std::str::FromStr for Curve25519Public {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let b64: B64 = s.parse()?;
            let arry: [u8; 32] = b64.as_bytes().try_into().map_err(|_| {
                Error::BadArgument(Pos::at(s), "bad length for curve25519 key.".into())
            })?;
            Ok(Curve25519Public(arry.into()))
        }
    }

    impl From<Curve25519Public> for PublicKey {
        fn from(w: Curve25519Public) -> PublicKey {
            w.0
        }
    }
}

// ============================================================

mod timeimpl {
    use crate::{Error, Pos, Result};
    use std::time::SystemTime;

    pub struct ISO8601TimeSp(SystemTime);

    impl std::str::FromStr for ISO8601TimeSp {
        type Err = Error;
        fn from_str(s: &str) -> Result<ISO8601TimeSp> {
            use chrono::{DateTime, NaiveDateTime, Utc};
            let d = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| Error::BadArgument(Pos::at(s), format!("invalid time: {}", e)))?;
            let dt = DateTime::<Utc>::from_utc(d, Utc);
            Ok(ISO8601TimeSp(dt.into()))
        }
    }

    impl From<ISO8601TimeSp> for SystemTime {
        fn from(t: ISO8601TimeSp) -> SystemTime {
            t.0
        }
    }
}

mod rsa {
    use crate::{Error, Pos, Result};
    use std::ops::RangeBounds;
    use tor_llcrypto::pk::rsa::PublicKey;

    /// An RSA public key, as parsed from a base64-encoded object.
    #[allow(non_camel_case_types)]
    pub struct RSAPublic(PublicKey, Pos);

    impl From<RSAPublic> for PublicKey {
        fn from(k: RSAPublic) -> PublicKey {
            k.0
        }
    }
    impl super::FromBytes for RSAPublic {
        fn from_bytes(b: &[u8], pos: Pos) -> Result<Self> {
            let key = PublicKey::from_der(b).ok_or_else(|| {
                Error::BadObjectVal(Pos::None, "unable to decode RSA public key".into())
            })?;
            Ok(RSAPublic(key, pos))
        }
    }
    impl RSAPublic {
        /// Give an error if the exponent of this key is not 'e'
        pub fn check_exponent(self, e: u32) -> Result<Self> {
            if self.0.exponent_is(e) {
                Ok(self)
            } else {
                Err(Error::BadObjectVal(self.1, "invalid RSA exponent".into()))
            }
        }
        /// Give an error if the exponent of this key is not contained in 'bounds'
        pub fn check_len<B: RangeBounds<usize>>(self, bounds: B) -> Result<Self> {
            if bounds.contains(&self.0.bits()) {
                Ok(self)
            } else {
                Err(Error::BadObjectVal(self.1, "invalid RSA length".into()))
            }
        }
        pub fn check_len_eq(self, n: usize) -> Result<Self> {
            self.check_len(n..=n)
        }
    }
}

mod edcert {
    use crate::{Error, Pos, Result};
    use tor_cert::Ed25519Cert;
    use tor_llcrypto::pk::ed25519;

    /// An ed25519 certificate as parsed from a directory object, with
    /// signature not validated.
    pub struct UnvalidatedEdCert(Vec<u8>, Pos);

    /// An ed25519 certificate as parsed from a directory object, with
    /// checked signature.
    pub struct ValidatedEdCert(Ed25519Cert, Pos);
    impl From<ValidatedEdCert> for Ed25519Cert {
        fn from(c: ValidatedEdCert) -> Self {
            c.0
        }
    }
    impl super::FromBytes for UnvalidatedEdCert {
        fn from_bytes(b: &[u8], p: Pos) -> Result<Self> {
            Self::from_vec(b.into(), p)
        }
        fn from_vec(v: Vec<u8>, p: Pos) -> Result<Self> {
            Ok(Self(v, p))
        }
    }
    impl UnvalidatedEdCert {
        pub fn validate(self, signing_key: Option<&ed25519::PublicKey>) -> Result<ValidatedEdCert> {
            let cert = Ed25519Cert::decode_and_check(&self.0, signing_key)
                .map_err(|e| Error::BadObjectVal(self.1, e.to_string()))?;
            Ok(ValidatedEdCert(cert, self.1))
        }
    }
    impl ValidatedEdCert {
        /// Give an error if this certificate's type is not `desired_type`.
        pub fn check_cert_type(self, desired_type: u8) -> Result<Self> {
            if self.0.get_cert_type() != desired_type {
                return Err(Error::BadObjectVal(
                    self.1,
                    format!(
                        "bad certificate type {} (wanted {})",
                        self.0.get_cert_type(),
                        desired_type
                    ),
                ));
            }
            Ok(self)
        }
        /// Give an error if this certificate's subject_key is not `pk`
        pub fn check_subject_key_is(self, pk: &ed25519::PublicKey) -> Result<Self> {
            if self.0.get_subject_key().as_ed25519() != Some(pk) {
                return Err(Error::BadObjectVal(self.1, "incorrect subject key".into()));
            }
            Ok(self)
        }
    }
}
