#![allow(unused_variables)]
#![allow(unused)]

pub mod authority;
// TODO: make this private.
mod config;
mod docmeta;
mod err;
pub mod storage;

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
use std::convert::TryInto;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

pub use authority::Authority;
pub use config::{NetDirConfig, NetDirConfigBuilder};
pub use err::Error;

/*
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DirState {
    NoInformation,
    Unvalidated(UnvalidatedMDConsensus),
    Insufficient(PartialNetDir),
    Sufficient(NetDir),
}
 */

pub struct DirMgr {
    config: NetDirConfig,
    store: RwLock<SqliteStore>,
}

impl DirMgr {
    pub fn from_config(config: NetDirConfig) -> Result<Self> {
        let store = RwLock::new(config.open_sqlite_store()?);
        Ok(DirMgr { config, store })
    }

    pub async fn bootstrap_directory<TR>(
        &self,
        netdir: Option<&NetDir>,
        circmgr: Arc<CircMgr<TR>>,
    ) -> Result<NetDir>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let authorities = self.config.authorities().to_vec();
        let store = &self.store;
        let dirinfo = match netdir {
            Some(nd) => nd.into(),
            None => self.config.fallbacks().into(),
        };

        let noinfo = NoInformation::new(authorities);

        // TODO: need to make consensus non-pending eventually.
        let mut unval = match noinfo.load(true, store).await? {
            NextState::NoChange(noinfo) => {
                noinfo
                    .fetch_consensus(store, dirinfo, Arc::clone(&circmgr))
                    .await?
            }
            NextState::NewState(unval) => unval,
        };

        unval.load(store).await?;
        unval
            .fetch_certs(store, dirinfo, Arc::clone(&circmgr))
            .await?;
        let mut partial = match unval.advance()? {
            // TODO: retry.
            NextState::NoChange(_) => return Err(anyhow!("Couldn't get certs")),
            NextState::NewState(p) => p,
        };

        partial.load(store).await?;
        partial
            .fetch_mds(store, dirinfo, Arc::clone(&circmgr))
            .await?;

        match partial.advance() {
            NextState::NewState(nd) => Ok(nd),
            NextState::NoChange(_) => Err(anyhow!("Didn't get enough mds")),
        }
    }
}

#[derive(Clone, Debug)]
pub enum NextState<A, B>
where
    A: Clone + Debug,
    B: Clone + Debug,
{
    NoChange(A),
    NewState(B),
}

#[derive(Debug, Clone, Default)]
pub struct NoInformation {
    authorities: Vec<Authority>,
}

#[derive(Debug, Clone)]
pub struct UnvalidatedDir {
    from_cache: bool,
    authorities: Vec<Authority>,
    consensus: UnvalidatedMDConsensus,
    certs: Vec<AuthCert>,
}

#[derive(Debug, Clone)]
pub struct PartialDir {
    from_cache: bool,
    dir: PartialNetDir,
}

impl NoInformation {
    fn new(authorities: Vec<Authority>) -> Self {
        assert!(authorities.len() <= std::u16::MAX as usize);
        NoInformation { authorities }
    }

    async fn load(
        self,
        pending: bool,
        store: &RwLock<SqliteStore>,
    ) -> Result<NextState<Self, UnvalidatedDir>> {
        let consensus_text = {
            let store = store.read().await;
            match store.latest_consensus(pending)? {
                Some(c) => c,
                None => return Ok(NextState::NoChange(self)),
            }
        };
        let unvalidated = {
            let string = consensus_text.as_str()?;
            let (signedval, parsed) = MDConsensus::parse(string)?;
            if let Ok(timely) = parsed.check_valid_now() {
                timely
            } else {
                return Ok(NextState::NoChange(self));
            }
        };
        let n_authorities = self.authorities.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);
        Ok(NextState::NewState(UnvalidatedDir {
            from_cache: true,
            authorities: self.authorities,
            consensus: unvalidated,
            certs: Vec::new(),
        }))
    }

    async fn fetch_consensus<TR>(
        &self,
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
        let n_authorities = self.authorities.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);
        let authorities = self.authorities.clone(); // TODO: I dislike this clone.
        Ok(UnvalidatedDir {
            from_cache: false,
            authorities,
            consensus: unvalidated,
            certs: Vec::new(),
        })
    }
}

impl UnvalidatedDir {
    fn prune_certs(&mut self) {
        // Quadratic, but should be fine.
        let authorities = &self.authorities;
        self.certs
            .retain(|cert| authorities.iter().any(|a| a.matches_cert(cert)));
    }

    fn missing_certs(&mut self) -> Vec<AuthCertKeyIds> {
        self.prune_certs();

        match self.consensus.key_is_correct(&self.certs[..]) {
            Ok(()) => Vec::new(),
            Err(mut missing) => {
                missing.retain(|m| self.authorities.iter().any(|a| a.matches_keyid(m)));
                missing
            }
        }
    }

    async fn load(&mut self, store: &RwLock<SqliteStore>) -> Result<()> {
        let missing = self.missing_certs();

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

        self.prune_certs();

        Ok(())
    }

    async fn fetch_certs<TR>(
        &mut self,
        store: &RwLock<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr<TR>>,
    ) -> Result<()>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        let missing = self.missing_certs();
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
        self.prune_certs();

        Ok(())
    }

    fn advance(mut self) -> Result<NextState<Self, PartialDir>> {
        let missing = self.missing_certs();

        if missing.is_empty() {
            // Either we can validate, or we never will.
            let validated = self.consensus.check_signature(&self.certs[..])?;
            Ok(NextState::NewState(PartialDir {
                from_cache: self.from_cache,
                dir: PartialNetDir::new(validated),
            }))
        } else {
            Ok(NextState::NoChange(self))
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
            Err(partial) => NextState::NoChange(PartialDir {
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
        w.update_microdescs_listed(loaded, when);
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

    Ok(new_mds.into_iter().map(|(txt, md)| md).collect())
}
