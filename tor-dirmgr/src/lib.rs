//! Code to fetch, store, and update directory information.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod authority;
mod config;
mod docid;
mod docmeta;
mod err;
mod retry;
mod shared_ref;
mod storage;
mod updater;

use crate::docid::{ClientRequest, DocQuery};
use crate::docmeta::{AuthCertMeta, ConsensusMeta};
use crate::retry::RetryDelay;
use crate::shared_ref::SharedMutArc;
use crate::storage::sqlite::SqliteStore;
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_circmgr::{CircMgr, DirInfo};
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::microdesc::{MdDigest, Microdesc, MicrodescReader};
use tor_netdoc::doc::netstatus::{ConsensusFlavor, MdConsensus, UnvalidatedMdConsensus};
use tor_netdoc::AllowAnnotations;
use tor_retry::RetryError;

use anyhow::{anyhow, Context, Result};
use futures::lock::Mutex;
use futures::stream::StreamExt;
use log::{debug, info, warn};

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::SystemTime;

pub use authority::Authority;
pub use config::{DownloadScheduleConfig, NetDirConfig, NetDirConfigBuilder, NetworkConfig};
pub use docid::DocId;
pub use err::Error;
pub use storage::DocumentText;
pub use updater::DirectoryUpdater;

/// A directory manager to download, fetch, and cache a Tor directory.
///
/// A DirMgr can operate in three modes:
///   * In **offline** mode, it only reads from the cache, and can
///     only read once.
///   * In **read-only** mode, it reads from the cache, but checks
///     whether it can acquire an associated lock file.  If it can, then
///     it enters read-write mode.  If not, it checks the cache
///     periodically for new information.
///   * In **read-write** mode, it knows that no other process will be
///     writing to the cache, and it takes responsibility for fetching
///     data from the network and updating the directory with new
///     directory information.
///
/// # Limitations
///
/// Because of portability issues in [`fslock::LockFile`], you might
/// get weird results if you run two of these in the same process with
/// the same underlying cache.
pub struct DirMgr {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: NetDirConfig,
    /// Handle to our sqlite cache.
    // XXXX I'd like to use an rwlock, but that's not feasible, since
    // rusqlite::Connection isn't Sync.
    // TODO: Does this have to be a futures::Mutex?  I would rather have
    // a rule that we never hold the guard for this mutex across an async
    // suspend point.  But that will be hard to enforce until the
    // `must_not_suspend` lint is in stable.
    store: Mutex<SqliteStore>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: SharedMutArc<NetDir>,

    /// A circuit manager, if this DirMgr supports downloading.
    circmgr: Option<Arc<CircMgr>>,
}

impl DirMgr {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async.
    pub async fn load_once(config: NetDirConfig) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::from_config(config, None)?;

        // TODO: add some way to return a directory that isn't up-to-date
        let _success = dirmgr.load_directory().await?;

        dirmgr
            .opt_netdir()
            .ok_or_else(|| Error::DirectoryNotPresent.into())
    }

    /// Return a current netdir, either loading it or bootstrapping it
    /// as needed.
    ///
    /// Like load_once, but will try to bootstrap (or wait for another
    /// process ot bootstrap) if we don't have an up-to-date
    /// bootstrapped directory.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    pub async fn load_or_bootstrap_once(
        config: NetDirConfig,
        circmgr: Arc<CircMgr>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, circmgr).await?;
        Ok(dirmgr.netdir())
    }

    /// Return a new directory manager from a given configuration,
    /// bootstrapping from the network as necessary.
    ///
    /// This function will to return until the directory is
    /// bootstrapped enough to build circuits.  It will also launch a
    /// background task that fetches any missing information, and that
    /// replaces the directory when a new one is available.
    pub async fn bootstrap_from_config(
        config: NetDirConfig,
        circmgr: Arc<CircMgr>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Arc::new(DirMgr::from_config(config, Some(circmgr))?);

        // Try to load from the cache.
        if dirmgr
            .load_directory()
            .await
            .context("Error loading cached directory")?
        {
            info!("Loaded a good directory from cache.")
        } else {
            // Okay, we didn't get a directory from the cache.  We need to
            // try fetching it if we can, or maybe loading it.
            Arc::clone(&dirmgr).initial_bootstrap_or_delay().await?;
            info!("Bootstrapped successfully.");
        }

        // Launch a task to run in the background and keep this dirmgr
        // up-to-date.
        Arc::clone(&dirmgr).launch_updater();

        Ok(dirmgr)
    }

    /// Try to bootstrap the directory from the network, or wait for
    /// another process to do so.
    async fn initial_bootstrap_or_delay(self: Arc<Self>) -> Result<()> {
        let mut logged = false;
        loop {
            if self.try_upgrade_to_readwrite().await? {
                // We now own the lock!  (Maybe we owned it before; the
                // upgrade_to_readwrite() function is idempotent.)  We can
                // do our own bootstrapping.
                return self.initial_bootstrap().await;
            }

            if !logged {
                logged = true;
                info!("Another process is bootstrapping. Waiting till it finishes or exits.");
            }

            // We don't own the lock.  Somebody else owns the cache.  They
            // should be updating it.  Wait a second, then try again.
            let one_sec = std::time::Duration::new(1, 0);
            tor_rtcompat::task::sleep(one_sec).await;
            // TODO: instead of loading the whole thing we should have a
            // database entry that says when the last update was.

            if self.load_directory().await? {
                // Successfully loaded.
                return Ok(());
            }
        }
    }

    /// Used when we are starting and don't have a directory yet: tries a few
    /// times to bootstrap it from the network.
    async fn initial_bootstrap(self: Arc<Self>) -> Result<()> {
        info!("Didn't find a usable directory in the cache, and we have write access. Trying to booststrap.");

        let retry_config = self.config.timing().retry_bootstrap();

        let mut retry: RetryDelay = retry_config.schedule();
        // XXXX actually we need to return an error if all the attmpts fail!
        for _ in retry_config.attempts() {
            match self.bootstrap_directory().await {
                Ok(()) => break,
                Err(e) => {
                    warn!("Can't bootstrap: {}. Will wait and try again.", e);
                }
            }

            let delay = retry.next_delay(&mut rand::thread_rng());
            tor_rtcompat::task::sleep(delay).await;
        }
        Ok(())
    }

    /// Get a reference to the circuit manager, if we have one.
    fn circmgr(&self) -> Result<Arc<CircMgr>> {
        self.circmgr
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| Error::NoDownloadSupport.into())
    }

    /// Try to make this a directory manager with read-write access to its
    /// storage.
    ///
    /// Return true if we got the lock, or if we already had it.
    ///
    /// Return false if another process has the lock
    async fn try_upgrade_to_readwrite(&self) -> Result<bool> {
        self.store.lock().await.upgrade_to_readwrite()
    }

    /// Construct a DirMgr from a NetDirConfig.
    fn from_config(config: NetDirConfig, circmgr: Option<Arc<CircMgr>>) -> Result<Self> {
        let readonly = circmgr.is_none();
        let store = Mutex::new(config.open_sqlite_store(readonly)?);
        let netdir = SharedMutArc::new();
        Ok(DirMgr {
            config,
            store,
            netdir,
            circmgr,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(&self) -> Result<bool> {
        let store = &self.store;

        let noinfo = NoInformation::new();

        // Load the consensus.
        let mut unval = match noinfo.load(false, &self.config, store).await? {
            NextState::SameState(_) => return Ok(false),
            NextState::NewState(unval) => unval,
        };

        let cached_vu = unval.consensus.peek_lifetime().valid_until();
        {
            if self.current_netdir_lasts_past(cached_vu).await {
                return Ok(false);
            }
        }

        // Load certificates, see if it's well-signed.
        unval.load(&self.config, store).await?;
        let mut partial = match unval.advance(&self.config)? {
            NextState::SameState(_) => {
                return Err(Error::CacheCorruption(
                    "Couldn't get certs for supposedly complete consensus",
                )
                .into());
            }
            NextState::NewState(p) => p,
        };

        // Load microdescs, make sure there are enough.
        partial.load(store, self.opt_netdir()).await?;
        let nd = match partial.advance() {
            NextState::NewState(nd) => nd,
            NextState::SameState(_) => {
                return Err(Error::CacheCorruption(
                    "Couldn't get microdescs for supposedly complete consensus",
                )
                .into());
            }
        };

        // This is now a good directory.  Put it in self.netdir.
        self.netdir.replace(nd);

        Ok(true)
    }

    /// Run a complete bootstrapping process, using information from our
    /// cache when it is up-to-date enough.
    async fn bootstrap_directory(&self) -> Result<()> {
        self.fetch_directory(true).await
    }

    /// Get a new directory, starting with a fresh consensus download.
    ///
    async fn fetch_new_directory(&self) -> Result<()> {
        self.fetch_directory(false).await
    }

    /// Try to fetch and add a new set of microdescriptors to the
    /// current NetDir.  On success, return the number of
    /// microdescriptors that are still missing.
    async fn fetch_additional_microdescs(&self) -> Result<usize> {
        let circmgr = self.circmgr()?;
        let new_microdescs = {
            // We introduce a scope here so that we'll drop our reference
            // to the old netdir when we're done downloading.
            let netdir = match self.opt_netdir() {
                Some(nd) => nd,
                None => return Ok(0),
            };

            let mark_listed = netdir.lifetime().valid_after();

            let missing: Vec<_> = netdir.missing_microdescs().map(Clone::clone).collect();
            let n_missing = missing.len();
            if n_missing == 0 {
                return Ok(0);
            }

            debug!(
                "{} missing microdescsriptors. Attempting to download...",
                n_missing
            );
            let mds = download_mds(
                missing,
                mark_listed,
                &self.config,
                &self.store,
                netdir.as_ref().into(),
                circmgr,
            )
            .await?;
            if mds.is_empty() {
                return Ok(n_missing);
            }
            mds
        };

        // Now we update the netdir.
        let n_missing = self.netdir.mutate(|nd| {
            for md in new_microdescs {
                nd.add_microdesc(md);
            }
            Ok(nd.missing_microdescs().count())
        })?;

        Ok(n_missing)
    }

    /// Launch an updater task that periodically re-fetches or re-loads the
    /// directory to keep it up-to-date.
    fn launch_updater(self: Arc<Self>) {
        let updater = updater::DirectoryUpdater::new(self);
        tor_rtcompat::task::spawn(async move {
            let _ = updater.run().await;
        });
    }

    /// Run a complete bootstrapping process, using information from our
    /// cache when it is up-to-date enough.  When complete, update our
    /// NetDir with the one we've fetched.
    ///
    /// If use_cached_consensus is true, we start with a cached
    /// consensus if it is live; otherwise, we start with a consensus
    /// download.
    // TODO: We'll likely need to refactor this before too long.
    // TODO: This needs to exit with a failure if the consensus expires
    // partway through the process.
    async fn fetch_directory(&self, use_cached_consensus: bool) -> Result<()> {
        let circmgr = self.circmgr()?;
        let store = &self.store;

        // Start out by using our previous netdir (if any): We'll need it
        // to decide where we ar downloading things from.
        let current_netdir = self.opt_netdir();
        let dirinfo = match current_netdir {
            Some(ref nd) => nd.as_ref().into(),
            None => self.config.fallbacks().into(),
        };

        // Get a cached consensus, or start from scratch, depending on
        // whether `use_cached_consensus` is true.
        let noinfo = NoInformation::new();
        let nextstate = if use_cached_consensus {
            noinfo.load(true, &self.config, store).await?
        } else {
            NextState::SameState(noinfo)
        };

        let mut unval = match nextstate {
            NextState::SameState(noinfo) => {
                // Couldn't load a pending consensus. Have to fetch one.
                info!("Fetching a consensus directory.");
                noinfo
                    .fetch_consensus(&self.config, store, dirinfo, Arc::clone(&circmgr))
                    .await?
            }
            NextState::NewState(unval) => unval,
        };

        // At this point we have a pending consensus.  We need to get certs
        // for it.  See what we can get from disk...
        unval.load(&self.config, store).await?;
        // Then fetch whatever we're missing.
        info!("Fetching certificate(s)."); // XXXX only log this when we have some to fetch.
        unval
            .fetch_certs(&self.config, store, dirinfo, Arc::clone(&circmgr))
            .await?;
        let mut partial = match unval.advance(&self.config)? {
            NextState::SameState(_) => return Err(anyhow!("Couldn't get certs")),
            NextState::NewState(p) => p,
        };

        // Finally, get microdescs from the cache...
        partial.load(store, self.opt_netdir()).await?;
        // .. and fetch whatever we're missing.
        partial
            .fetch_mds(&self.config, store, dirinfo, Arc::clone(&circmgr))
            .await?;

        let nd = match partial.advance() {
            NextState::NewState(nd) => nd,
            NextState::SameState(_) => return Err(anyhow!("Didn't get enough mds")),
        };

        self.netdir.replace(nd);

        Ok(())
    }

    /// Return true if we have a netdir, and it will be valid at least
    /// till 'when'.
    async fn current_netdir_lasts_past(&self, when: SystemTime) -> bool {
        let r = self.netdir.get();
        if let Some(current_netdir) = r.as_ref() {
            let current_vu = current_netdir.lifetime().valid_until();
            current_vu >= when
        } else {
            false
        }
    }

    /// Return an Arc handle to our latest directory, if we have one.
    ///
    /// This is a private method, since by the time anybody else has a
    /// handle to a DirMgr, the NetDir should definitely be
    /// bootstrapped.
    fn opt_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.get()
    }

    /// Return an Arc handle to our latest directory, if we have one.
    // TODO: Add variants of this that make sure that it's up-to-date?
    pub fn netdir(&self) -> Arc<NetDir> {
        self.opt_netdir().expect("DirMgr was not bootstrapped!")
    }

    /// Try to load the text of a signle document described by `doc` from
    /// storage.
    pub async fn text(&self, doc: &DocId) -> Result<Option<DocumentText>> {
        let mut result = HashMap::new();
        let query = doc.clone().into();
        self.load_documents_into(&query, &mut result).await?;
        if let Some((docid, doctext)) = result.into_iter().next() {
            assert_eq!(&docid, doc);
            Ok(Some(doctext))
        } else {
            Ok(None)
        }
    }

    /// Load the text for a collection of documents.
    ///
    /// If many of the documents have the same type, this can be more
    /// efficient than calling [`text`].
    pub async fn texts<T>(&self, docs: T) -> Result<HashMap<DocId, DocumentText>>
    where
        T: IntoIterator<Item = DocId>,
    {
        let partitioned = docid::partition_by_type(docs);
        let mut result = HashMap::new();
        for (_, query) in partitioned.into_iter() {
            self.load_documents_into(&query, &mut result).await?
        }
        Ok(result)
    }

    /// Load all the documents for a single DocumentQuery from the store.
    async fn load_documents_into(
        &self,
        query: &DocQuery,
        result: &mut HashMap<DocId, DocumentText>,
    ) -> Result<()> {
        use DocQuery::*;
        let store = self.store.lock().await;
        match query {
            LatestConsensus { flavor, pending } => {
                if let Some(c) = store.latest_consensus(*flavor, *pending)? {
                    let id = DocId::LatestConsensus {
                        flavor: *flavor,
                        pending: *pending,
                    };
                    result.insert(id, c.into());
                }
            }
            AuthCert(ids) => result.extend(
                store
                    .authcerts(&ids)?
                    .into_iter()
                    .map(|(id, c)| (DocId::AuthCert(id), DocumentText::from_string(c))),
            ),
            Microdesc(digests) => {
                result.extend(
                    store
                        .microdescs(digests)?
                        .into_iter()
                        .map(|(id, md)| (DocId::Microdesc(id), DocumentText::from_string(md))),
                );
            }
            Routerdesc(digests) => result.extend(
                store
                    .routerdescs(digests)?
                    .into_iter()
                    .map(|(id, rd)| (DocId::Routerdesc(id), DocumentText::from_string(rd))),
            ),
        }
        Ok(())
    }

    /// Convert a DocQuery into a set of ClientRequests, suitable for sending
    /// to a directory cache.
    ///
    /// This conversion has to be a function of the dirmgr, since it may
    /// require knowledge about our current state.
    async fn query_into_requests(self, q: DocQuery) -> Result<Vec<ClientRequest>> {
        let mut res = Vec::new();
        for q in q.split_for_download() {
            match q {
                DocQuery::LatestConsensus { flavor, .. } => {
                    res.push(self.make_consensus_request(flavor).await?);
                }
                DocQuery::AuthCert(ids) => {
                    res.push(ClientRequest::AuthCert(ids.into_iter().collect()));
                }
                DocQuery::Microdesc(ids) => {
                    res.push(ClientRequest::Microdescs(ids.into_iter().collect()));
                }
                DocQuery::Routerdesc(ids) => {
                    res.push(ClientRequest::Routerdescs(ids.into_iter().collect()));
                }
            }
        }
        Ok(res)
    }

    /// Construct an appropriate ClientRequest to download a consensus
    /// of the given flavor.
    async fn make_consensus_request(&self, flavor: ConsensusFlavor) -> Result<ClientRequest> {
        let mut request = tor_dirclient::request::ConsensusRequest::new(flavor);

        let r = self.store.lock().await;
        match r.latest_consensus_meta(flavor) {
            Ok(Some(meta)) => {
                request.set_last_consensus_date(meta.lifetime().valid_after());
                request.push_old_consensus_digest(*meta.sha3_256_of_signed());
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Error loading directory metadata: {}", e);
            }
        }

        Ok(ClientRequest::Consensus(request))
    }

    /// Given a request we sent and the response we got from a
    /// directory server, see whether we should expand that response
    /// into "something larger".
    ///
    /// Currently, this handles expanding consensus diffs, and nothing
    /// else.  We do it at this stage of our downloading operation
    /// because it requires access to the store.
    async fn expand_response_text(&self, req: &ClientRequest, text: String) -> Result<String> {
        if let ClientRequest::Consensus(req) = req {
            if tor_consdiff::looks_like_diff(&text) {
                if let Some(old_d) = req.old_consensus_digests().next() {
                    let db_val = {
                        let s = self.store.lock().await;
                        s.consensus_by_sha3_digest(old_d)?
                    };
                    if let Some((old_consensus, meta)) = db_val {
                        info!("Applying a consensus diff");
                        let new_consensus = tor_consdiff::apply_diff(
                            old_consensus.as_str()?,
                            &text,
                            Some(*meta.sha3_256_of_signed()),
                        )?;
                        new_consensus.check_digest()?;
                        return Ok(new_consensus.to_string());
                    }
                }
                return Err(Error::Unwanted("Received an unaskedfor diff").into());
            }
        }
        return Ok(text);
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
///
/// We can advance from this state by loading or fetching a consensus
/// document.
#[derive(Debug, Clone, Default)]
struct NoInformation {}

/// Second directory state: We know a consensus directory document,
/// but not the certs to validate it.
///
/// We can advance from this state by loading or fetching certificates.
#[derive(Debug, Clone)]
struct UnvalidatedDir {
    /// True if we loaded this consensus from our local cache.
    from_cache: bool,
    /// The consensus we've received
    consensus: UnvalidatedMdConsensus,
    /// Information about digests and lifetimes of that consensus,
    consensus_meta: ConsensusMeta,
    /// The certificates that we've received for this consensus.
    ///
    /// We ensure that certificates are only included in this list if
    /// they are for authorities we believe in.
    certs: Vec<AuthCert>,
}

/// Third directory state: we've validated the consensus, but don't have
/// enough microdescs for it yet.
///
/// We advance from this state by loading or detching microdescriptors.
#[derive(Debug, Clone)]
struct PartialDir {
    /// True if we loaded the consensus from our local cache.
    from_cache: bool,
    /// Information about digests and lifetimes of the consensus.
    consensus_meta: ConsensusMeta,
    /// The consensus directory, partially filled in with microdescriptors.
    dir: PartialNetDir,
}

impl NoInformation {
    /// Construct a new `NoInformation` into which directory information
    /// can loaded or fetched.
    fn new() -> Self {
        NoInformation {}
    }

    /// Try to fetch a currently timely consensus directory document
    /// from the local cache in `store`.  If `pending_ok`, then we'll
    /// happily return a pending document; otherwise, we'll only
    /// return a document that has been marked as having been completely
    /// bootstrapped.
    async fn load(
        self,
        pending_ok: bool,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
    ) -> Result<NextState<Self, UnvalidatedDir>> {
        let want_pending_status = if pending_ok { None } else { Some(false) };
        let consensus_text = {
            let store = store.lock().await;
            match store.latest_consensus(ConsensusFlavor::Microdesc, want_pending_status)? {
                Some(c) => c,
                None => return Ok(NextState::SameState(self)),
            }
        };

        let (consensus_meta, unvalidated) = {
            let string = consensus_text.as_str()?;
            let (signedval, remainder, parsed) = MdConsensus::parse(string)?;
            if let Ok(timely) = parsed.check_valid_now() {
                let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);

                (meta, timely)
            } else {
                return Ok(NextState::SameState(self));
            }
        };

        // Make sure that we could in principle validate this
        // consensus. If we couldn't, pretend it isn't cached at all.
        let authority_ids: Vec<_> = config
            .authorities()
            .iter()
            .map(|auth| auth.v3ident())
            .collect();
        if !unvalidated.authorities_are_correct(&authority_ids[..]) {
            // This is not for us.  Treat it as if we had no cached consensus.
            warn!("Found cached directory not signed by the right authorities. Are you using a mismatched cache?");
            store.lock().await.delete_consensus(&consensus_meta)?;
            return Ok(NextState::SameState(self));
        }

        let n_authorities = config.authorities().len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);
        Ok(NextState::NewState(UnvalidatedDir {
            from_cache: true,
            consensus_meta,
            consensus: unvalidated,
            certs: Vec::new(),
        }))
    }

    /// Try to fetch a currently timely consensus directory document
    /// from a randomly chosen directory cache server on the network.
    ///
    /// On failure, retry.
    async fn fetch_consensus(
        &self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<UnvalidatedDir> {
        let retry = config.timing().retry_consensus();
        let mut retry_delay = retry.schedule();

        let mut errors = RetryError::while_doing("download a consensus");
        for _ in retry.attempts() {
            let cm = Arc::clone(&circmgr);
            match self.fetch_consensus_once(config, store, info, cm).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    errors.push(e);
                    let delay = retry_delay.next_delay(&mut rand::thread_rng());
                    tor_rtcompat::task::sleep(delay).await;
                }
            }
        }

        Err(errors.into())
    }

    /// Try to fetch a currently timely consensus directory document
    /// from a randomly chosen directory cache server on the network.
    async fn fetch_consensus_once(
        &self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<UnvalidatedDir> {
        let mut resource =
            tor_dirclient::request::ConsensusRequest::new(ConsensusFlavor::Microdesc);
        // XXXX-A1 In some of the below error cases we should retire the circuit
        // to the cache that gave us this stuff.

        let meta = {
            let r = store.lock().await;
            match r.latest_consensus_meta(ConsensusFlavor::Microdesc) {
                Ok(Some(meta)) => {
                    resource.set_last_consensus_date(meta.lifetime().valid_after());
                    resource.push_old_consensus_digest(*meta.sha3_256_of_signed());
                    Some(meta)
                }
                Ok(None) => None,
                Err(e) => {
                    warn!("Error loading directory metadata: {}", e);
                    None
                }
            }
        };
        let response = tor_dirclient::get_resource(&resource, info, circmgr).await?;
        let text = response.output();

        let expanded_diff = if meta.is_some() && tor_consdiff::looks_like_diff(&text) {
            let meta = meta.unwrap();
            // This is a diff, not the consensus.
            let r = store.lock().await;
            let cons = r.consensus_by_meta(&meta)?;
            info!("Applying a consensus diff");
            let new_consensus =
                tor_consdiff::apply_diff(cons.as_str()?, &text, Some(*meta.sha3_256_of_signed()))?;

            new_consensus.check_digest()?;

            Some(new_consensus.to_string())
        } else {
            None
        };
        let text = match expanded_diff {
            Some(ref s) => s,
            None => text,
        };

        let (signedval, remainder, parsed) = MdConsensus::parse(&text)?;
        debug!("Successfully parsed the consensus");
        let unvalidated = parsed.check_valid_now()?;
        let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &unvalidated);

        // Make sure that we could in principle validate this, and it doesn't
        // have a totally different set of authorities than the ones
        // we asked for.
        let authority_ids: Vec<_> = config
            .authorities()
            .iter()
            .map(|auth| auth.v3ident())
            .collect();
        if !unvalidated.authorities_are_correct(&authority_ids[..]) {
            return Err(Error::Unwanted("Consensus not signed by correct authorities").into());
        }

        {
            let mut w = store.lock().await;
            w.store_consensus(&meta, ConsensusFlavor::Microdesc, true, &text)?;
        }
        let n_authorities = config.authorities().len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        Ok(UnvalidatedDir {
            from_cache: false,
            consensus: unvalidated,
            consensus_meta: meta,
            certs: Vec::new(),
        })
    }
}

impl UnvalidatedDir {
    /// Helper: Remove every member of self.certs that does not match
    /// some authority listed in `config`.
    fn prune_certs(&mut self, config: &NetDirConfig) {
        // Quadratic, but should be fine.
        let authorities = &config.authorities();
        self.certs
            .retain(|cert| authorities.iter().any(|a| a.matches_cert(cert)));
    }

    /// Helper: Return a list of certificate key identities for the
    /// certificates we should download in order to check this
    /// consensus.
    ///
    /// This function will return an empty list when we have enough
    /// certificates, whether or not it is a _complete_ list.
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

    /// Load authority certificates from our local cache.
    async fn load(&mut self, config: &NetDirConfig, store: &Mutex<SqliteStore>) -> Result<()> {
        let missing = self.missing_certs(config);

        let newcerts = {
            let r = store.lock().await;
            r.authcerts(&missing[..])?
        };

        for c in newcerts.values() {
            let cert = AuthCert::parse(c)?.check_signature()?;
            if let Ok(cert) = cert.check_valid_now() {
                self.certs.push(cert);
            }
        }

        self.prune_certs(config);

        Ok(())
    }

    /// Try to fetch authority certificates from the network.
    ///
    /// Retry if we couldn't get enough certs to validate the consensus.
    async fn fetch_certs(
        &mut self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<()> {
        let retry = config.timing().retry_certs();
        let mut retry_delay = retry.schedule();

        let mut errors = RetryError::while_doing("downloading authority certificates");
        for _ in retry.attempts() {
            let cm = Arc::clone(&circmgr);
            if let Err(e) = self.fetch_certs_once(config, store, info, cm).await {
                errors.push(e);
            }

            if self.missing_certs(config).is_empty() {
                // We have enough certificates to validate the consensus.
                return Ok(());
            }
            let delay = retry_delay.next_delay(&mut rand::thread_rng());
            tor_rtcompat::task::sleep(delay).await;
        }

        Err(errors.into())
    }

    /// Try to fetch authority certificates from the network.
    async fn fetch_certs_once(
        &mut self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<()> {
        let missing = self.missing_certs(config);
        if missing.is_empty() {
            return Ok(());
        }

        let mut resource = tor_dirclient::request::AuthCertRequest::new();
        for m in missing.iter() {
            resource.push(*m);
        }

        let response = tor_dirclient::get_resource(&resource, info, circmgr).await?;
        let text = response.output();
        // XXXX-A1 In some of the below error cases we should retire the circuit
        // to the cache that gave us this stuff.

        let mut newcerts = Vec::new();
        for cert in AuthCert::parse_multiple(&text) {
            if let Ok(parsed) = cert {
                let s = parsed
                    .within(&text)
                    .expect("Certificate was not in input as expected");
                if let Ok(wellsigned) = parsed.check_signature() {
                    if let Ok(timely) = wellsigned.check_valid_now() {
                        newcerts.push((timely, s));
                        continue;
                    }
                }
            }

            warn!(
                "Received an unusable certificate from {:?}.",
                response.source()
            );
        }

        // Throw away any that we didn't ask for.
        {
            let n_orig = self.certs.len();
            self.certs
                .retain(|cert| missing.iter().any(|m| m == cert.key_ids()));
            if self.certs.len() != n_orig {
                warn!(
                    "Received cert(s) from {:?} that we didn't request.",
                    response.source()
                );
            }
        }

        {
            let v: Vec<_> = newcerts[..]
                .iter()
                .map(|(cert, s)| (AuthCertMeta::from_authcert(cert), *s))
                .collect();
            let mut w = store.lock().await;
            w.store_authcerts(&v[..])?;
        }

        for (cert, _) in newcerts {
            self.certs.push(cert);
        }

        // This should be redundant.
        self.prune_certs(config);

        Ok(())
    }

    /// If we have enough certificates, check this document and return
    /// a PartialDir.  Otherwise remain in the same state.
    fn advance(mut self, config: &NetDirConfig) -> Result<NextState<Self, PartialDir>> {
        let missing = self.missing_certs(config);

        if missing.is_empty() {
            // Either we can validate, or we never will.
            let validated = self.consensus.check_signature(&self.certs[..])?;
            Ok(NextState::NewState(PartialDir {
                from_cache: self.from_cache,
                consensus_meta: self.consensus_meta,
                dir: PartialNetDir::new(validated, Some(config.override_net_params())),
            }))
        } else {
            Ok(NextState::SameState(self))
        }
    }
}

impl PartialDir {
    /// Try to load microdescriptors from our local cache.
    async fn load(&mut self, store: &Mutex<SqliteStore>, prev: Option<Arc<NetDir>>) -> Result<()> {
        let mark_listed = Some(self.dir.lifetime().valid_after());

        load_mds(&mut self.dir, prev, mark_listed, store).await
    }

    /// Try to fetch microdescriptors from the network.
    ///
    /// Retry if we didn't get enough to build circuits.
    async fn fetch_mds(
        &mut self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<()> {
        let retry = config.timing().retry_microdescs();
        let mut retry_delay = retry.schedule();

        let mut errors = RetryError::while_doing("download microdescriptors");
        for _ in retry.attempts() {
            let cm = Arc::clone(&circmgr);
            if let Err(e) = self.fetch_mds_once(config, store, info, cm).await {
                errors.push(e);
            }

            if self.dir.have_enough_paths() {
                // We can build circuits; return!
                return Ok(());
            }
            let delay = retry_delay.next_delay(&mut rand::thread_rng());
            tor_rtcompat::task::sleep(delay).await;
        }

        Err(errors.into())
    }
    /// Try to fetch microdescriptors from the network.
    async fn fetch_mds_once(
        &mut self,
        config: &NetDirConfig,
        store: &Mutex<SqliteStore>,
        info: DirInfo<'_>,
        circmgr: Arc<CircMgr>,
    ) -> Result<()> {
        let mark_listed = self.dir.lifetime().valid_after();

        let missing: Vec<MdDigest> = self.dir.missing_microdescs().map(Clone::clone).collect();
        let mds = download_mds(missing, mark_listed, config, store, info, circmgr).await?;
        for md in mds {
            self.dir.add_microdesc(md);
        }
        if self.dir.have_enough_paths() {
            // XXXX no need to do this if it was already non-pending.
            // XXXX this calculation is redundant with the one in advance().
            let mut w = store.lock().await;
            w.mark_consensus_usable(&self.consensus_meta)?;
            // Expire on getting a valid directory.
            w.expire_all()?;
        }
        Ok(())
    }

    /// If we have enough microdescriptors to build circuits, return a NetDir.
    /// Otherwise, return this same document.
    fn advance(self) -> NextState<Self, NetDir> {
        match self.dir.unwrap_if_sufficient() {
            Ok(netdir) => NextState::NewState(netdir),
            Err(partial) => NextState::SameState(PartialDir {
                from_cache: self.from_cache,
                consensus_meta: self.consensus_meta,
                dir: partial,
            }),
        }
    }
}

/// Helper to load microdescriptors from the cache and store them into
/// a PartialNetDir.
async fn load_mds(
    doc: &mut PartialNetDir,
    prev: Option<Arc<NetDir>>,
    mark_listed: Option<SystemTime>,
    store: &Mutex<SqliteStore>,
) -> Result<()> {
    let mut loaded = if let Some(ref prev_netdir) = prev {
        doc.fill_from_previous_netdir(prev_netdir.as_ref())
    } else {
        Vec::new()
    };

    let microdescs = {
        let r = store.lock().await;
        r.microdescs(doc.missing_microdescs())?
    };

    for (digest, text) in microdescs.iter() {
        if let Ok(md) = Microdesc::parse(text) {
            if md.digest() == digest && doc.add_microdesc(md) {
                loaded.push(digest);
                continue;
            }
        }
        warn!(
            "Found unusable microdescriptor {} in cache?",
            hex::encode(digest)
        )
    }

    if let Some(when) = mark_listed {
        let mut w = store.lock().await;
        if !w.is_readonly() {
            w.update_microdescs_listed(loaded, when)?;
        }
    }

    Ok(())
}

/// Helper to fetch microdescriptors from the network and store them either
/// into a PartialNetDir or a NetDir.
async fn download_mds(
    mut missing: Vec<MdDigest>,
    mark_listed: SystemTime,
    config: &NetDirConfig,
    store: &Mutex<SqliteStore>,
    info: DirInfo<'_>,
    circmgr: Arc<CircMgr>,
) -> Result<Vec<Microdesc>> {
    missing.sort_unstable();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let chunksize: usize = std::cmp::min(500, (missing.len() + 2) / 3);

    let n_parallel_requests = config.timing().microdesc_parallelism();

    // Now we're going to fetch the descriptors up to 500 at a time,
    // in up to n_parallel_requests requests.

    // TODO: we should maybe exit early if we wind up with a working
    // list.
    // TODO: we should maybe try to keep concurrent requests on
    // separate circuits?

    // Break 'missing' into the chunks we're going to fetch.
    // XXXX: I hate having to do all these copies, but otherwise I
    // wind up with lifetime issues.
    let missing: Vec<Vec<_>> = missing[..].chunks(chunksize).map(|s| s.to_vec()).collect();

    let new_mds: Vec<_> = futures::stream::iter(missing.into_iter())
        .map(|chunk| {
            let cm = Arc::clone(&circmgr);
            async move {
                info!("Fetching {} microdescriptors...", chunksize);
                let mut resource = tor_dirclient::request::MicrodescRequest::new();
                for md in chunk.iter() {
                    resource.push(*md);
                }
                let want: HashSet<_> = chunk.iter().collect();

                let res = tor_dirclient::get_resource(&resource, info, cm).await;

                // Handle fetch errors here
                if let Err(err) = &res {
                    info!("Problem fetching mds: {:?}", err);
                }

                let mut my_new_mds = Vec::new();
                if let Ok(response) = res {
                    let text = response.output();
                    // XXXX-A1 In some of the below error cases we should
                    // retire the circuit to the cache that gave us
                    // this stuff.

                    for annot in
                        MicrodescReader::new(&text, AllowAnnotations::AnnotationsNotAllowed)
                    {
                        match annot {
                            Ok(anno) => {
                                let txt = anno
                                    .within(&text)
                                    .expect("annotation not from within text as expected")
                                    .to_string(); //XXXX ugly copy
                                let md = anno.into_microdesc();
                                if want.contains(md.digest()) {
                                    my_new_mds.push((txt, md))
                                } else {
                                    warn!("Received md we did not ask for: {:?}", md.digest())
                                }
                            }
                            Err(err) => {
                                warn!("Problem with annotated md: {:?}", err)
                            }
                        }
                    }
                }

                info!("Received {} microdescriptors.", my_new_mds.len());
                my_new_mds
            }
        })
        .buffer_unordered(n_parallel_requests)
        .collect()
        .await;

    // Now save it to the database
    {
        let mut w = store.lock().await;
        w.store_microdescs(
            new_mds
                .iter()
                .flatten()
                .map(|(txt, md)| (&txt[..], md.digest())),
            mark_listed,
        )?;
    }

    Ok(new_mds.into_iter().flatten().map(|(_, md)| md).collect())
}
