//! Code to fetch, store, and update directory information.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.

pub mod authority;
// TODO: make this private.
mod config;
mod docmeta;
mod err;
mod storage;

use crate::docmeta::ConsensusMeta;
use crate::storage::sqlite::SqliteStore;
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_circmgr::{CircMgr, DirInfo};
use tor_netdir::{MDReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::microdesc::{MDDigest, Microdesc, MicrodescReader};
use tor_netdoc::doc::netstatus::{MDConsensus, UnvalidatedMDConsensus};
use tor_netdoc::AllowAnnotations;

use anyhow::{anyhow, Result};
use async_rwlock::RwLock;

use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::SystemTime;

pub use authority::Authority;
pub use config::{NetDirConfig, NetDirConfigBuilder};
pub use err::Error;

/// A directory manager to download, fetch, and cache a Tor directory
pub struct DirMgr {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: NetDirConfig,
    /// Handle to our sqlite cache.
    store: RwLock<SqliteStore>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: RwLock<Option<Arc<NetDir>>>,
}

impl DirMgr {
    /// Construct a DirMgr from a NetDirConfig.
    pub fn from_config(config: NetDirConfig) -> Result<Self> {
        let store = RwLock::new(config.open_sqlite_store()?);
        let netdir = RwLock::new(None);
        Ok(DirMgr {
            config,
            store,
            netdir,
        })
    }

    /// Run a complete bootstrapping process, using information from our
    /// cache when it is up-to-date enough.  When complete, update our
    /// NetDir with the one we've fetched.
    ///
    // TODO: We'll likely need to refactor this before too long.
    pub async fn bootstrap_directory<TR>(&self, circmgr: Arc<CircMgr<TR>>) -> Result<()>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let store = &self.store;

        let current_netdir = self.netdir().await;
        let dirinfo = match current_netdir {
            Some(ref nd) => nd.as_ref().into(),
            None => self.config.fallbacks().into(),
        };

        let noinfo = NoInformation::new();

        // TODO: need to make consensus non-pending eventually.
        let mut unval = match noinfo.load(true, &self.config, store).await? {
            NextState::SameState(noinfo) => {
                noinfo
                    .fetch_consensus(&self.config, store, dirinfo, Arc::clone(&circmgr))
                    .await?
            }
            NextState::NewState(unval) => unval,
        };

        unval.load(&self.config, store).await?;
        unval
            .fetch_certs(&self.config, store, dirinfo, Arc::clone(&circmgr))
            .await?;
        let mut partial = match unval.advance(&self.config)? {
            // TODO: retry.
            NextState::SameState(_) => return Err(anyhow!("Couldn't get certs")),
            NextState::NewState(p) => p,
        };

        partial.load(store).await?;
        partial
            .fetch_mds(store, dirinfo, Arc::clone(&circmgr))
            .await?;

        let nd = match partial.advance() {
            // XXXX Retry.
            NextState::NewState(nd) => nd,
            NextState::SameState(_) => return Err(anyhow!("Didn't get enough mds")),
        };

        {
            let mut w = self.netdir.write().await;
            *w = Some(Arc::new(nd));
        }

        Ok(())
    }

    /// Return an Arc handle to our latest sufficiently up-to-date directory.
    ///
    // TODO: make sure it's still up to date?
    pub async fn netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.read().await.as_ref().map(Arc::clone)
    }
}

/// Abstraction to handle the idea of a possible state transition
/// after fetching or loading directory information.
#[derive(Clone, Debug)]
enum NextState<A, B>
where
    A: Clone + Debug,
    B: Clone + Debug,
{
    /// We either got no new info, or we didn't get enough info to update
    /// to a new state.
    SameState(A),
    /// We found enough information to transition to a new state.
    NewState(B),
}

/// Initial directory state when no information is known.
#[derive(Debug, Clone, Default)]
struct NoInformation {}

#[derive(Debug, Clone)]
struct UnvalidatedDir {
    from_cache: bool,
    consensus: UnvalidatedMDConsensus,
    certs: Vec<AuthCert>,
}

#[derive(Debug, Clone)]
struct PartialDir {
    from_cache: bool,
    dir: PartialNetDir,
}

impl NoInformation {
    fn new() -> Self {
        NoInformation {}
    }

    async fn load(
        self,
        pending: bool,
        config: &NetDirConfig,
        store: &RwLock<SqliteStore>,
    ) -> Result<NextState<Self, UnvalidatedDir>> {
        let consensus_text = {
            let store = store.read().await;
            match store.latest_consensus(pending)? {
                Some(c) => c,
                None => return Ok(NextState::SameState(self)),
            }
        };
        let unvalidated = {
            let string = consensus_text.as_str()?;
            let (_signedval, parsed) = MDConsensus::parse(string)?;
            if let Ok(timely) = parsed.check_valid_now() {
                timely
            } else {
                return Ok(NextState::SameState(self));
            }
        };
        let n_authorities = config.authorities().len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);
        Ok(NextState::NewState(UnvalidatedDir {
            from_cache: true,
            consensus: unvalidated,
            certs: Vec::new(),
        }))
    }

    async fn fetch_consensus<TR>(
        &self,
        config: &NetDirConfig,
        store: &RwLock<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr<TR>>,
    ) -> Result<UnvalidatedDir>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let mut resource = tor_dirclient::request::ConsensusRequest::new();

        {
            let r = store.read().await;
            if let Some(valid_after) = r.latest_consensus_time()? {
                resource.set_last_consensus_date(valid_after.into());
            }
        }
        let text = tor_dirclient::get_resource(resource, info, circmgr).await?;

        let (signedval, parsed) = MDConsensus::parse(&text)?;
        let unvalidated = parsed.check_valid_now()?;
        let meta = ConsensusMeta::from_unvalidated(signedval, &unvalidated);

        {
            let mut w = store.write().await;
            w.store_consensus(&meta, true, &text)?;
        }
        let n_authorities = config.authorities().len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);
        Ok(UnvalidatedDir {
            from_cache: false,
            consensus: unvalidated,
            certs: Vec::new(),
        })
    }
}

impl UnvalidatedDir {
    fn prune_certs(&mut self, config: &NetDirConfig) {
        // Quadratic, but should be fine.
        let authorities = &config.authorities();
        self.certs
            .retain(|cert| authorities.iter().any(|a| a.matches_cert(cert)));
    }

    fn missing_certs(&mut self, config: &NetDirConfig) -> Vec<AuthCertKeyIds> {
        self.prune_certs(config);
        let authorities = config.authorities();

        match self.consensus.key_is_correct(&self.certs[..]) {
            Ok(()) => Vec::new(),
            Err(mut missing) => {
                missing.retain(|m| authorities.iter().any(|a| a.matches_keyid(m)));
                missing
            }
        }
    }

    async fn load(&mut self, config: &NetDirConfig, store: &RwLock<SqliteStore>) -> Result<()> {
        let missing = self.missing_certs(config);

        let newcerts = {
            let r = store.read().await;
            r.authcerts(&missing[..])?
        };

        for c in newcerts.values() {
            let cert = AuthCert::parse(c)?.check_signature()?;
            if let Ok(cert) = cert.check_valid_now() {
                // TODO: Complain if we find a cert we didn't want. That's a bug.
                self.certs.push(cert);
            }
        }

        self.prune_certs(config);

        Ok(())
    }

    async fn fetch_certs<TR>(
        &mut self,
        config: &NetDirConfig,
        store: &RwLock<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr<TR>>,
    ) -> Result<()>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let missing = self.missing_certs(config);
        if missing.is_empty() {
            return Ok(());
        }

        let mut resource = tor_dirclient::request::AuthCertRequest::new();
        for m in missing.iter() {
            resource.push(m.clone());
        }

        let text = tor_dirclient::get_resource(resource, info, circmgr).await?;

        let mut newcerts = Vec::new();
        for cert in AuthCert::parse_multiple(&text) {
            if let Ok(parsed) = cert {
                if let Ok(wellsigned) = parsed.check_signature() {
                    if let Ok(timely) = wellsigned.check_valid_now() {
                        let s = timely.within(&text).unwrap();
                        newcerts.push((timely, s));
                    }
                }
            }
            // XXXX warn on error.
        }

        // Throw away any that we didn't ask for.
        self.certs
            .retain(|cert| missing.iter().any(|m| m == cert.key_ids()));
        // XXXX warn on discard.

        {
            let mut w = store.write().await;
            w.store_authcerts(&newcerts[..])?;
        }

        for (cert, _) in newcerts {
            self.certs.push(cert);
        }

        // This should be redundant.
        self.prune_certs(config);

        Ok(())
    }

    fn advance(mut self, config: &NetDirConfig) -> Result<NextState<Self, PartialDir>> {
        let missing = self.missing_certs(config);

        if missing.is_empty() {
            // Either we can validate, or we never will.
            let validated = self.consensus.check_signature(&self.certs[..])?;
            Ok(NextState::NewState(PartialDir {
                from_cache: self.from_cache,
                dir: PartialNetDir::new(validated),
            }))
        } else {
            Ok(NextState::SameState(self))
        }
    }
}

impl PartialDir {
    async fn load(&mut self, store: &RwLock<SqliteStore>) -> Result<()> {
        let mark_listed = Some(SystemTime::now()); // XXXX use validafter, conditionally.

        load_mds(&mut self.dir, mark_listed, store).await
    }

    async fn fetch_mds<TR>(
        &mut self,
        store: &RwLock<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr<TR>>,
    ) -> Result<()>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let mark_listed = SystemTime::now(); // XXXX use validafter
        let missing: Vec<MDDigest> = self.dir.missing_microdescs().map(Clone::clone).collect();
        let mds = download_mds(missing, mark_listed, store, info, circmgr).await?;
        for md in mds {
            self.dir.add_microdesc(md);
        }
        Ok(())
    }

    fn advance(self) -> NextState<Self, NetDir> {
        match self.dir.unwrap_if_sufficient() {
            Ok(netdir) => NextState::NewState(netdir),
            Err(partial) => NextState::SameState(PartialDir {
                from_cache: self.from_cache,
                dir: partial,
            }),
        }
    }
}

async fn load_mds<M: MDReceiver>(
    doc: &mut M,
    mark_listed: Option<SystemTime>,
    store: &RwLock<SqliteStore>,
) -> Result<()> {
    let microdescs = {
        let r = store.read().await;
        r.microdescs(doc.missing_microdescs())?
    };

    let mut loaded = Vec::new();
    for (digest, text) in microdescs.iter() {
        let md = Microdesc::parse(text)?; // XXX recover from this
        if md.digest() != digest {
            // whoa! XXXX Log something about this.
            continue;
        }
        if doc.add_microdesc(md) {
            loaded.push(digest)
        }
    }

    if let Some(when) = mark_listed {
        let mut w = store.write().await;
        w.update_microdescs_listed(loaded, when)?;
    }

    Ok(())
}

async fn download_mds<TR>(
    mut missing: Vec<MDDigest>,
    mark_listed: SystemTime,
    store: &RwLock<SqliteStore>,
    info: DirInfo<'_>,
    circmgr: Arc<CircMgr<TR>>,
) -> Result<Vec<Microdesc>>
where
    TR: tor_chanmgr::transport::Transport,
{
    missing.sort_unstable();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let chunksize: usize = std::cmp::min(500, (missing.len() + 2) / 3);

    let mut new_mds: Vec<_> = Vec::new();
    for chunk in missing[..].chunks(chunksize) {
        // TODO: Do these in parallel.
        let mut resource = tor_dirclient::request::MicrodescRequest::new();
        for md in chunk.iter() {
            resource.push(*md);
        }
        let want: HashSet<_> = chunk.iter().collect();
        let cm = Arc::clone(&circmgr);

        let res = tor_dirclient::get_resource(resource, info, cm).await;

        // XXXX log error.
        if let Ok(text) = res {
            for annot in MicrodescReader::new(&text, AllowAnnotations::AnnotationsNotAllowed) {
                if let Ok(anno) = annot {
                    let txt = anno.within(&text).unwrap().to_string(); //XXXX ugly copy
                    let md = anno.into_microdesc();
                    if want.contains(md.digest()) {
                        new_mds.push((txt, md))
                    } // XXX warn if we didn't want this.
                }
                // XXXX log error
            }
        }
    }

    // Now save it to the database
    {
        let mut w = store.write().await;
        w.store_microdescs(new_mds.iter().map(|(txt, md)| (&txt[..], md)), mark_listed)?;
    }

    Ok(new_mds.into_iter().map(|(_, md)| md).collect())
}
