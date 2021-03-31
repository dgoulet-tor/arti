//! Declare a general purpose "document ID type" for tracking which
//! documents we want and which we have.

use std::{borrow::Borrow, collections::HashMap};

use tor_netdoc::doc::{
    authcert::AuthCertKeyIds, microdesc::MdDigest, netstatus::ConsensusFlavor, routerdesc::RdDigest,
};

/// The identity of a single document, in enough detail to load it from
/// storage.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum DocId {
    /// A request for the most recent consensus document.
    LatestConsensus {
        /// The flavor of consensus to request
        flavor: ConsensusFlavor,
        /// If present, a specific pending status to request.
        ///
        /// (A "pending" consensus is one where we don't have all the
        /// certificates and/or descriptors yet.)
        pending: Option<bool>,
    },
    /// A request for an authority certificate, by the SHA1 digests of
    /// its identity key and signing key.
    AuthCert(AuthCertKeyIds),
    /// A request for a single microdescriptor, by SHA256 digest.
    Microdesc(MdDigest),
    /// A request for a router descriptor, by SHA1 digest.
    Routerdesc(RdDigest),
}

/// The underlying type of a DocId.
///
/// Documents with the same type can be grouped into the same query.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
#[allow(clippy::missing_docs_in_private_items)]
pub(crate) enum DocType {
    Consensus(ConsensusFlavor),
    AuthCert,
    Microdesc,
    Routerdesc,
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
            Routerdesc(_) => T::Routerdesc,
        }
    }
}

/// A group of DocIds that can be downloaded or loaded from the database
/// together.
#[derive(Clone, Debug)]
#[allow(clippy::missing_docs_in_private_items)]
pub(crate) enum DocQuery {
    LatestConsensus {
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    },
    AuthCert(Vec<AuthCertKeyIds>),
    Microdesc(Vec<MdDigest>),
    Routerdesc(Vec<RdDigest>),
}

impl DocQuery {
    /// Construct an "empty" docquery from the given DocId
    pub fn empty_from_docid(id: &DocId) -> Self {
        match *id {
            DocId::LatestConsensus { flavor, pending } => Self::LatestConsensus { flavor, pending },
            DocId::AuthCert(_) => Self::AuthCert(Vec::new()),
            DocId::Microdesc(_) => Self::Microdesc(Vec::new()),
            DocId::Routerdesc(_) => Self::Routerdesc(Vec::new()),
        }
    }

    /// Add `id` to this query, if possible.
    fn push(&mut self, id: DocId) {
        match (self, id) {
            (Self::LatestConsensus { .. }, DocId::LatestConsensus { .. }) => {}
            (Self::AuthCert(ids), DocId::AuthCert(id)) => ids.push(id),
            (Self::Microdesc(ids), DocId::Microdesc(id)) => ids.push(id),
            (Self::Routerdesc(ids), DocId::Routerdesc(id)) => ids.push(id),
            (_, _) => panic!(),
        }
    }

    /*
        /// How many documents of this type may be downloaded with a single
        /// download request?
        #[allow(unused)]
        pub fn max_per_request(self) -> usize {
            use DocQuery::*;
            match self {
                Consensus(_) => 1,
                AuthCert => 256, // somewhat arbitrary.
                Microdesc => 500,
                Routerdesc => 500,
            }
        }
    */
    /// If this query contains too many documents to download with a single
    /// request, divide it up.
    #[allow(unused)]
    pub fn split_for_download(self) -> Vec<Self> {
        use DocQuery::*;
        /// How many objects can be put in a single HTTP GET line?
        const N: usize = 500;
        match &self {
            LatestConsensus { .. } => vec![self],
            AuthCert(v) => v[..].chunks(N).map(|s| AuthCert(s.to_vec())).collect(),
            Microdesc(v) => v[..].chunks(N).map(|s| Microdesc(s.to_vec())).collect(),
            Routerdesc(v) => v[..].chunks(N).map(|s| Routerdesc(s.to_vec())).collect(),
            _ => Vec::new(),
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

// TODO: code to read one of these from storage.
