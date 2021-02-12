//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to to sign the
//! consensus directory.

use serde::Deserialize;
use tor_llcrypto::pk::rsa::RSAIdentity;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};

/// A single authority that signs a consensus directory.
//
// Note that we do *not* set serde(deny_unknown_fields)] on this structure:
// we want our authorities format to be future-proof against adding new info
// about each authority.
#[derive(Deserialize, Debug, Clone)]
pub struct Authority {
    /// A memorable nickname for this authority.
    name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    v3ident: RSAIdentity,
}

impl Authority {
    /// Construct information about a new authority.
    pub fn new(name: String, v3ident: RSAIdentity) -> Self {
        Authority { name, v3ident }
    }
    /// Return the v3 identity key of this certificate.
    pub fn v3ident(&self) -> &RSAIdentity {
        &self.v3ident
    }
    /// Return true if this authority matches a given certificate.
    pub fn matches_cert(&self, cert: &AuthCert) -> bool {
        &self.v3ident == cert.id_fingerprint()
    }

    /// Return true if this authority matches a given key ID.
    pub fn matches_keyid(&self, id: &AuthCertKeyIds) -> bool {
        self.v3ident == id.id_fingerprint
    }
}
