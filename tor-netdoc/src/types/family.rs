//! Implements the relay 'family' type.

use crate::types::misc::LongIdent;
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
/// NOTE: when parsing, this type always discards incorrectly-formatted
/// entries, including entries that are only nicknames.
///
/// TODO: This type probably belongs in a different crate.
pub struct RelayFamily(Vec<RSAIdentity>);

impl RelayFamily {
    /// Return a new empty RelayFamily.
    pub fn new() -> Self {
        RelayFamily(Vec::new())
    }
}

impl Default for RelayFamily {
    fn default() -> Self {
        RelayFamily::new()
    }
}

impl std::str::FromStr for RelayFamily {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v: Result<Vec<RSAIdentity>> = s
            .split(crate::parse::tokenize::is_sp)
            .map(|e| e.parse::<LongIdent>().map(|v| v.into()))
            .filter(Result::is_ok)
            .collect();
        Ok(RelayFamily(v?))
    }
}
