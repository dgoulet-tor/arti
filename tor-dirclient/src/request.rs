//! Descriptions objects for different kinds of directory requests
//! that we can make.

use tor_llcrypto::pk::rsa::RSAIdentity;
use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MDDigest;

use anyhow::{Context, Result};
use std::time::SystemTime;

/// A request for an object that can be served over the Tor directory system.
pub trait ClientRequest {
    /// Consume this ClientRequest and return an [`http::Request`] if
    /// it is well-formed.
    fn into_request(self) -> Result<http::Request<()>>;

    /// Return true if partial downloads are potentially useful.  This
    /// is true for request types where we're going to be downloading
    /// multiple documents.
    fn partial_docs_ok(&self) -> bool;

    /// Return the maximum allowable response length we'll accept for this
    /// request.
    fn max_response_len(&self) -> usize {
        (16 * 1024 * 1024) - 1
    }
}

/// A Request for a consensus directory.
#[derive(Debug, Clone)]
pub struct ConsensusRequest {
    /// What flavor of consensus are we asking for?  Right now, only "microdesc"
    /// is supported.
    flavor: String,
    /// A list of the authority identities that we believe in.  We tell the
    /// directory cache only to give us a consensus if it is signed by enough
    /// of these authorities.
    authority_ids: Vec<RSAIdentity>,
    /// The publication time of the most recent consensus we have.  Used to
    /// generate an If-Modified-Since header so that we don't get a document
    /// we already have.
    last_consensus_published: Option<SystemTime>,
    /// A set of SHA3-256 digests of the _signed portion_ of consensuses we have.
    /// Used to declare what diffs we would accept.
    ///
    /// (Currently we don't send this, since we can't handle diffs.)
    last_consensus_sha3_256: Vec<[u8; 32]>,
}

impl ConsensusRequest {
    /// Create a new request for a consensus directory document.
    pub fn new() -> Self {
        ConsensusRequest {
            flavor: "microdesc".to_string(),
            authority_ids: Vec::new(),
            last_consensus_published: None,
            last_consensus_sha3_256: Vec::new(),
        }
    }

    /// Add `id` to the list of authorities that this request should
    /// say we believe in.
    pub fn push_authority_id(&mut self, id: RSAIdentity) {
        self.authority_ids.push(id);
    }

    /// Add `d` to the list of consensus digests this request should
    /// say we already haev.
    pub fn push_old_consensus_digest(&mut self, d: [u8; 32]) {
        self.last_consensus_sha3_256.push(d);
    }

    /// Set the publication time we should say we have for our last
    /// consensus to `when`.
    pub fn set_last_consensus_date(&mut self, when: SystemTime) {
        self.last_consensus_published = Some(when);
    }
}

impl Default for ConsensusRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRequest for ConsensusRequest {
    fn into_request(mut self) -> Result<http::Request<()>> {
        // Build the URL.
        let mut uri = "/tor/status-vote/current/consensus".to_string();
        if self.flavor != "ns" {
            uri.push('-');
            uri.push_str(&self.flavor);
        }
        if !self.authority_ids.is_empty() {
            self.authority_ids.sort_unstable();
            uri.push('/');
            let ids: Vec<String> = self
                .authority_ids
                .iter()
                .map(|id| hex::encode(id.as_bytes()))
                .collect();
            uri.push_str(&ids.join("+"));
        }
        uri.push_str(".z");

        let mut req = http::Request::builder().method("GET").uri(uri);
        req = add_common_headers(req);

        // Possibly, add an if-modified-since header.
        if let Some(when) = self.last_consensus_published {
            req = req.header(
                http::header::IF_MODIFIED_SINCE,
                httpdate::fmt_http_date(when),
            );
        }

        // Possibly, add an X-Or-Diff-From-Consensus header.
        if !self.last_consensus_sha3_256.is_empty() {
            self.last_consensus_sha3_256.sort_unstable();
            let digests: Vec<String> = self
                .last_consensus_sha3_256
                .iter()
                .map(hex::encode)
                .collect();
            req = req.header("X-Or-Diff-From-Consensus", &digests.join(", "));
        }

        Ok(req
            .body(())
            .context("Bug: Unable to form consensus HTTP request")?)
    }

    fn partial_docs_ok(&self) -> bool {
        false
    }
}

/// A request for one or more authority certificates.
#[derive(Debug, Clone)]
pub struct AuthCertRequest {
    /// The identity/signing keys of the certificates we want.
    ids: Vec<AuthCertKeyIds>,
}

impl AuthCertRequest {
    /// Create a new requst, asking for no authority certificates.
    pub fn new() -> Self {
        AuthCertRequest { ids: Vec::new() }
    }

    /// Add `ids` to the list of certificates we're asking for.
    pub fn push(&mut self, ids: AuthCertKeyIds) {
        self.ids.push(ids);
    }
}

impl Default for AuthCertRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRequest for AuthCertRequest {
    fn into_request(mut self) -> Result<http::Request<()>> {
        self.ids.sort_unstable();

        let ids: Vec<String> = self
            .ids
            .iter()
            .map(|id| {
                format!(
                    "{}-{}",
                    hex::encode(id.id_fingerprint.as_bytes()),
                    hex::encode(id.sk_fingerprint.as_bytes())
                )
            })
            .collect();

        let uri = format!("/tor/keys/fp-sk/{}.z", &ids.join("+"));

        let req = http::Request::builder().method("GET").uri(uri);
        let req = add_common_headers(req);

        Ok(req
            .body(())
            .context("Bug: Unable to form authority certificate HTTP request")?)
    }

    fn partial_docs_ok(&self) -> bool {
        self.ids.len() > 1
    }

    fn max_response_len(&self) -> usize {
        // TODO: Pick a more principled number; I just made this one up.
        self.ids.len().saturating_mul(16 * 1024)
    }
}

/// A request for one or more microdescriptors
#[derive(Debug, Clone)]
pub struct MicrodescRequest {
    /// The SHA256 digests of the microdescriptors we want.
    digests: Vec<MDDigest>,
}

impl MicrodescRequest {
    /// Construct a request for no microdescriptors.
    pub fn new() -> Self {
        MicrodescRequest {
            digests: Vec::new(),
        }
    }
    /// Add `d` to the list of microdescriptors we want to request.
    pub fn push(&mut self, d: MDDigest) {
        self.digests.push(d)
    }
}

impl Default for MicrodescRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRequest for MicrodescRequest {
    fn into_request(mut self) -> Result<http::Request<()>> {
        // TODO: require that self.digests is nonempty.
        self.digests.sort_unstable();

        let ids: Vec<String> = self
            .digests
            .iter()
            .map(|d| base64::encode_config(d, base64::STANDARD_NO_PAD))
            .collect();
        let uri = format!("/tor/micro/d/{}.z", &ids.join("-"));
        let req = http::Request::builder().method("GET").uri(uri);

        let req = add_common_headers(req);

        Ok(req
            .body(())
            .context("Bug: Unable to form microdescriptor HTTP request")?)
    }

    fn partial_docs_ok(&self) -> bool {
        self.digests.len() > 1
    }

    fn max_response_len(&self) -> usize {
        // TODO: Pick a more principled number; I just made this one up.
        self.digests.len().saturating_mul(8 * 1024)
    }
}

/// Add commonly used headers to the HTTP request.
///
/// (Right now, this is only Accept-Encoding.)
fn add_common_headers(req: http::request::Builder) -> http::request::Builder {
    // TODO: gzip, zstd, brotli
    req.header(
        http::header::ACCEPT_ENCODING,
        "deflate, identity, x-tor-lzma",
    )
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_md_request() -> Result<()> {
        let d1 = b"This is a testing digest. it isn";
        let d2 = b"'t actually SHA-256.............";

        let mut req = MicrodescRequest::new();
        req.push(*d1);
        req.push(*d2);

        assert!(req.partial_docs_ok());

        let req = crate::util::encode_request(req.into_request()?);

        assert_eq!(req,
                   "GET /tor/micro/d/J3QgYWN0dWFsbHkgU0hBLTI1Ni4uLi4uLi4uLi4uLi4-VGhpcyBpcyBhIHRlc3RpbmcgZGlnZXN0LiBpdCBpc24.z HTTP/1.0\r\naccept-encoding: deflate, identity, x-tor-lzma\r\n\r\n");

        Ok(())
    }

    #[test]
    fn test_cert_request() -> Result<()> {
        let d1 = b"This is a testing dn";
        let d2 = b"'t actually SHA-256.";

        let d3 = b"blah blah blah 1 2 3";
        let d4 = b"I like pizza from Na";

        let mut req = AuthCertRequest::new();
        req.push(AuthCertKeyIds {
            id_fingerprint: (*d1).into(),
            sk_fingerprint: (*d2).into(),
        });
        req.push(AuthCertKeyIds {
            id_fingerprint: (*d3).into(),
            sk_fingerprint: (*d4).into(),
        });

        assert!(req.partial_docs_ok());

        let req = crate::util::encode_request(req.into_request()?);

        assert_eq!(req,
                   "GET /tor/keys/fp-sk/5468697320697320612074657374696e6720646e-27742061637475616c6c79205348412d3235362e+626c616820626c616820626c6168203120322033-49206c696b652070697a7a612066726f6d204e61.z HTTP/1.0\r\naccept-encoding: deflate, identity, x-tor-lzma\r\n\r\n");

        Ok(())
    }
}
