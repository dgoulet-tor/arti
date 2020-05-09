//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub use b64impl::*;
pub use curve25519impl::*;
pub use timeimpl::*;

use thiserror::Error;

/// A problem that can occur when parsing an argument.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ArgError {
    /// Invalid base64.
    #[error("bad base64 encoding: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A time that was in the wrong form, or out of range.
    #[error("invalid time: {0}")]
    BadTime(#[from] chrono::ParseError),
    /// Some other error, represented as a string.
    #[error("{0}")]
    Generic(&'static str),
}

mod b64impl {

    use super::ArgError;

    pub struct B64(Vec<u8>);

    impl std::str::FromStr for B64 {
        type Err = ArgError;
        fn from_str(s: &str) -> Result<Self, ArgError> {
            Ok(B64(
                base64::decode_config(s, base64::STANDARD_NO_PAD).map_err(ArgError::Base64)?
            ))
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
    use super::{ArgError, B64};
    use std::convert::TryInto;
    use tor_llcrypto::pk::curve25519::PublicKey;

    pub struct Curve25519Public(PublicKey);

    impl std::str::FromStr for Curve25519Public {
        type Err = ArgError;
        fn from_str(s: &str) -> Result<Self, ArgError> {
            let b64: B64 = s.parse()?;
            let arry: [u8; 32] = b64
                .as_bytes()
                .try_into()
                .map_err(|_| ArgError::Generic("wrong length"))?;
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
    use super::ArgError;
    use std::time::SystemTime;

    pub struct ISO8601TimeSp(SystemTime);

    impl std::str::FromStr for ISO8601TimeSp {
        type Err = ArgError;
        fn from_str(s: &str) -> Result<ISO8601TimeSp, ArgError> {
            use chrono::{DateTime, NaiveDateTime, Utc};
            let d =
                NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map_err(ArgError::BadTime)?;
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
