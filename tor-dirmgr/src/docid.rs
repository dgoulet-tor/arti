//! Declare a general purpose "document ID type" for tracking which
//! documents we want and which we have.

use std::{borrow::Borrow, collections::HashMap};

use tor_dirclient::request;
use tor_netdoc::doc::{
    authcert::AuthCertKeyIds, microdesc::MdDigest, netstatus::ConsensusFlavor, routerdesc::RdDigest,
};

/// The identity of a single document, in enough detail to load it
/// from storage.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum DocId {
    /// A request for the most recent consensus document.
    LatestConsensus {
        /// The flavor of consensus to request.
        flavor: ConsensusFlavor,
        /// Rules for loading this consensus from the cache.
        cache_usage: CacheUsage,
    },
    /// A request for an authority certificate, by the SHA1 digests of
    /// its identity key and signing key.
    AuthCert(AuthCertKeyIds),
    /// A request for a single microdescriptor, by SHA256 digest.
    Microdesc(MdDigest),
    /// A request for the router descriptor of a public relay, by SHA1
    /// digest.
    RouterDesc(RdDigest),
}

/// The underlying type of a DocId.
///
/// Documents with the same type can be grouped into the same query; others
/// cannot.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub(crate) enum DocType {
    /// A consensus document
    Consensus(ConsensusFlavor),
    /// An authority certificate
    AuthCert,
    /// A microdescriptor
    Microdesc,
    /// A router descriptor.
    RouterDesc,
}

impl DocId {
    /// Return the associated doctype of this DocId.
    pub(crate) fn doctype(&self) -> DocType {
        use DocId::*;
        use DocType as T;
        match self {
            LatestConsensus { flavor: f, .. } => T::Consensus(*f),
            AuthCert(_) => T::AuthCert,
            Microdesc(_) => T::Microdesc,
            RouterDesc(_) => T::RouterDesc,
        }
    }
}

/// A request for a specific kind of directory resource that a DirMgr can
/// request.
#[derive(Clone, Debug)]
pub(crate) enum ClientRequest {
    /// Request for a consensus
    Consensus(request::ConsensusRequest),
    /// Request for one or more authority certificates
    AuthCert(request::AuthCertRequest),
    /// Request for one or more microdescriptors
    Microdescs(request::MicrodescRequest),
    /// Request for one or more router descriptors
    RouterDescs(request::RouterDescRequest),
}

impl ClientRequest {
    /// Turn a ClientRequest into a Requestable.
    pub(crate) fn as_requestable(&self) -> &(dyn request::Requestable + Send + Sync) {
        use ClientRequest::*;
        match self {
            Consensus(a) => a,
            AuthCert(a) => a,
            Microdescs(a) => a,
            RouterDescs(a) => a,
        }
    }
}

/// Description of how to start out a given bootstrap attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CacheUsage {
    /// The bootstrap attempt will only use the cache.  Therefore, don't
    /// load a pending consensus from the cache, since we won't be able
    /// to find enough information to make it usable.
    CacheOnly,
    /// The bootstrap attempt is willing to download information or to
    /// use the cache.  Therefore, we want the latest cached
    /// consensus, whether it is pending or not.
    CacheOkay,
    /// The bootstrap attempt is trying to fetch a new consensus. Therefore,
    /// we don't want a consensus from the cache.
    MustDownload,
}

impl CacheUsage {
    /// Turn this CacheUsage into a pending field for use with
    /// SqliteStorage.
    pub(crate) fn pending_requirement(&self) -> Option<bool> {
        match self {
            CacheUsage::CacheOnly => Some(false),
            _ => None,
        }
    }
}

/// A group of DocIds that can be downloaded or loaded from the database
/// together.
///
/// TODO: Perhaps this should be the same as ClientRequest?
#[derive(Clone, Debug)]
pub(crate) enum DocQuery {
    /// A request for the latest consensus
    LatestConsensus {
        /// A desired flavor of consensus
        flavor: ConsensusFlavor,
        /// Whether we can or must use the cache
        cache_usage: CacheUsage,
    },
    /// A request for authority certificates
    AuthCert(Vec<AuthCertKeyIds>),
    /// A request for microdescriptors
    Microdesc(Vec<MdDigest>),
    /// A request for router descriptors
    RouterDesc(Vec<RdDigest>),
}

impl DocQuery {
    /// Construct an "empty" docquery from the given DocId
    pub(crate) fn empty_from_docid(id: &DocId) -> Self {
        match *id {
            DocId::LatestConsensus {
                flavor,
                cache_usage,
            } => Self::LatestConsensus {
                flavor,
                cache_usage,
            },
            DocId::AuthCert(_) => Self::AuthCert(Vec::new()),
            DocId::Microdesc(_) => Self::Microdesc(Vec::new()),
            DocId::RouterDesc(_) => Self::RouterDesc(Vec::new()),
        }
    }

    /// Add `id` to this query, if possible.
    fn push(&mut self, id: DocId) {
        match (self, id) {
            (Self::LatestConsensus { .. }, DocId::LatestConsensus { .. }) => {}
            (Self::AuthCert(ids), DocId::AuthCert(id)) => ids.push(id),
            (Self::Microdesc(ids), DocId::Microdesc(id)) => ids.push(id),
            (Self::RouterDesc(ids), DocId::RouterDesc(id)) => ids.push(id),
            (_, _) => panic!(),
        }
    }

    /// If this query contains too many documents to download with a single
    /// request, divide it up.
    pub(crate) fn split_for_download(self) -> Vec<Self> {
        use DocQuery::*;
        /// How many objects can be put in a single HTTP GET line?
        const N: usize = 500;
        match self {
            LatestConsensus { .. } => vec![self],
            AuthCert(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| AuthCert(s.to_vec())).collect()
            }
            Microdesc(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| Microdesc(s.to_vec())).collect()
            }
            RouterDesc(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| RouterDesc(s.to_vec())).collect()
            }
        }
    }
}

impl From<DocId> for DocQuery {
    fn from(d: DocId) -> DocQuery {
        let mut result = DocQuery::empty_from_docid(&d);
        result.push(d);
        result
    }
}

/// Given a list of DocId, split them up into queries, by type.
pub(crate) fn partition_by_type<T>(collection: T) -> HashMap<DocType, DocQuery>
where
    T: IntoIterator<Item = DocId>,
{
    let mut result = HashMap::new();
    for item in collection.into_iter() {
        let b = item.borrow();
        let tp = b.doctype();
        result
            .entry(tp)
            .or_insert_with(|| DocQuery::empty_from_docid(b))
            .push(item);
    }
    result
}
