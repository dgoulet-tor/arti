//! Implements the relay 'family' type.

use crate::argtype::LongIdent;
use crate::{Error, Result};
use tor_llcrypto::pk::rsa::RSAIdentity;

/// Information about a relay family.
///
/// Tor relays may declare that they belong to the same family, to
/// indicate that they are controlled by the same party or parties,
/// and as such should not be used in the same circuit. Two relays
/// belong to the same family if and only if each one lists the other
/// as belonging to its family.
///
/// TODO: This type probably belongs in a different crate.
pub struct RelayFamily(Vec<RSAIdentity>);

impl std::str::FromStr for RelayFamily {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v: Result<Vec<RSAIdentity>> = s
            .split(crate::tokenize::is_sp)
            .map(|e| e.parse::<LongIdent>().map(|v| v.into()))
            .collect();
        Ok(RelayFamily(v?))
    }
}
