//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub use b64impl::*;
pub use curve25519impl::*;
pub use timeimpl::*;

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
