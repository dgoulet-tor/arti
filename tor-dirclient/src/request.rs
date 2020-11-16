use tor_llcrypto::pk::rsa::RSAIdentity;
use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MDDigest;

use anyhow::Result;
use std::time::SystemTime;

pub trait ClientRequest {
    fn into_request(self) -> Result<http::Request<()>>;
}

#[derive(Debug, Clone)]
pub struct ConsensusRequest {
    flavor: String,
    authority_ids: Vec<RSAIdentity>,
    last_consensus_published: Option<SystemTime>,
    last_consensus_sha3_256: Vec<[u8; 32]>,
}

impl ConsensusRequest {
    pub fn new() -> Self {
        ConsensusRequest {
            flavor: "microdesc".to_string(),
            authority_ids: Vec::new(),
            last_consensus_published: None,
            last_consensus_sha3_256: Vec::new(),
        }
    }

    pub fn push_authority_id(&mut self, id: RSAIdentity) {
        self.authority_ids.push(id);
    }

    pub fn push_old_consensus_digest(&mut self, d: [u8; 32]) {
        self.last_consensus_sha3_256.push(d);
    }

    pub fn set_last_consensus_date<T>(&mut self, when: SystemTime) {
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
        if let Some(when) = self.last_consensus_published {
            req = req.header(
                http::header::IF_MODIFIED_SINCE,
                httpdate::fmt_http_date(when),
            );
        }
        if !self.last_consensus_sha3_256.is_empty() {
            self.last_consensus_sha3_256.sort_unstable();
            let digests: Vec<String> = self
                .last_consensus_sha3_256
                .iter()
                .map(hex::encode)
                .collect();
            req = req.header("X-Or-Diff-From-Consensus", &digests.join(", "));
        }

        Ok(req.body(())?)
    }
}

#[derive(Debug, Clone)]
pub struct AuthCertRequest {
    ids: Vec<AuthCertKeyIds>,
}

impl AuthCertRequest {
    pub fn new() -> Self {
        AuthCertRequest { ids: Vec::new() }
    }
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

        Ok(req.body(())?)
    }
}

#[derive(Debug, Clone)]
pub struct MicrodescRequest {
    digests: Vec<MDDigest>,
}

impl MicrodescRequest {
    pub fn new() -> Self {
        MicrodescRequest {
            digests: Vec::new(),
        }
    }
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
        self.digests.sort_unstable();

        let ids: Vec<String> = self.digests.iter().map(hex::encode).collect();
        let uri = format!("/tor/micro/d/{}.z", &ids.join("-"));

        let req = http::Request::builder().method("GET").uri(uri);

        let req = add_common_headers(req);
        Ok(req.body(())?)
    }
}

fn add_common_headers(req: http::request::Builder) -> http::request::Builder {
    // TODO: gzip, zstd, brotli, xz2
    req.header(http::header::ACCEPT_ENCODING, "deflate, identity")
}
