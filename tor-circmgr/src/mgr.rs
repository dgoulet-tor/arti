//! Abstract code to manage a set of circuits.
//!
//! This module implements the real logic for deciding when and how to
//! launch circuits, and for which circuits to hand out in response to
//! which requests.
//!
//! For testing and abstraction purposes, this module _does not_
//! actually know anything about circuits _per se_.  Instead,
//! everything is handled using a set of traits that are internal to this
//! crate:
//!
//!  * [`AbstractCirc`] is a view of a circuit.
//!  * [`AbstractSpec`] represents a circuit's possible usages.
//!  * [`AbstractCircBuilder`] knows how to build an `AbstractCirc`.
//!
//! Using these traits, the [`AbstractCircMgr`] object manages a set of
//! circuits, launching them as necessary, and keeping track of the
//! restrictions on their use.

// TODO:
// - Testing
//    o Successful straight-line cases.
//    - Cases with side-circuit alerts.
//    - Cases where isolation forces a new circuit
//    - Ensuring that a circuit exists.

use crate::{DirInfo, Error, Result};

use tor_rtcompat::{Runtime, SleepProviderExt};

use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::future::{FutureExt, Shared};
use futures::stream::{FuturesUnordered, StreamExt};
use futures::task::SpawnExt;
use log::{info, log};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::{self, Arc, Weak};
use std::time::{Duration, Instant};
use weak_table::PtrWeakHashSet;

mod streams;

/// Represents restrictions on circuit usage.
///
/// An `AbstractSpec` describes what a circuit can be used for.  Each
/// `AbstractSpec` type has an associated `Usage` type that
/// describes a _single_ operation that the circuit might support or
/// not.
///
/// (For example, an `AbstractSpec` can describe a set of ports
/// supported by the exit relay on a circuit.  In that case, its
/// `Usage` type could be a single port that a client wants to
/// connect to.)
///
/// If an `AbstractSpec` A allows every operation described in a
/// `Usage` B, we say that A "supports" B.
///
/// If one `AbstractSpec` A supports every opertion suppored by
/// another `AbstractSpec` B, we say that A "contains" B.
///
/// Some circuits can be used for either of two operations, but not both.
/// For example, a circuit that is used as a rendezvous point can't
/// be used as an introduction point.  To represent these transitions,
/// we use a `restrict` operation.  Every time a circuit is used for something
/// new, that new use "restricts" the circuit's spec, and narrows
/// what the circuit can be used for.
pub(crate) trait AbstractSpec: Clone + Debug {
    /// A type to represent the kind of usages that this circuit permits.
    type Usage: Clone + Debug + Send + Sync;

    /// Return true if this spec permits the usage described by `other`.
    ///
    /// If this function returns `true`, then it is okay to use a circuit
    /// with this spec for the target usage desribed by `other`.
    fn supports(&self, other: &Self::Usage) -> bool;

    /// Change the value of this spec based on the circuit having
    /// been used for `usage`.
    ///
    /// # Requirements
    ///
    /// Must return an error and make no changes to `self` if `usage`
    /// was not supported by this spec.
    ///
    /// If this function returns Ok, the resulting spec must be
    /// contained by the original spec, and must support `usage`.
    fn restrict_mut(&mut self, usage: &Self::Usage) -> Result<()>;
}

/// Minimal abstract view of a circuit.
///
/// From this module's point of view, circuits are simply objects
/// with unique identities, and a possible closed-state.
pub(crate) trait AbstractCirc: Debug {
    /// Type for a unique identifier for circuits.
    type Id: Clone + Debug + Hash + Eq + Send + Sync;
    /// Return the unique identifier for this circuit.
    ///
    /// # Requirements
    ///
    /// The values returned by this function are unique for distinct
    /// circuits.
    fn id(&self) -> Self::Id;

    /// Return true if this circuit is usable for some purpose.
    ///
    /// Reasons a circuit might be unusable include being closed.
    fn usable(&self) -> bool;
}

/// An object that knows how to build circuits.
///
/// AbstractCircBuilder creates circuits in two phases.  First, a plan is
/// made for how to build the circuit.  This planning phase should be
/// relatively fast, and must not suspend or block.  Its purpose is to
/// get an early estimate of which operations the circuit will be able
/// to support when it's done.
///
/// Second, the circuit is actually built, using the plan as input.
#[async_trait]
pub(crate) trait AbstractCircBuilder: Send + Sync {
    /// The specification type describing what operations circuits can
    /// be used for.
    type Spec: AbstractSpec + Send + Sync;
    /// The circuit type that this builder knows how to build.
    type Circ: AbstractCirc + Send + Sync;
    /// An opaque type describing how a given circuit will be built.
    /// It may represent some or all of a path-or it may not.
    // TODO: It would be nice to have this parameterized on a lifetime,
    // and have that lifetime depend on the lifetime of the directory.
    // But I don't think that rust can do that.
    type Plan: Send;

    // TODO: I'd like to have a Dir type here to represent
    // create::DirInfo, but that would need to be parameterized too,
    // and would make everything complicated.

    /// Form a plan for how to build a new circuit that supports `usage`.
    ///
    /// Return an opaque Plan object, and a new spec describing what
    /// the circuit will actually support when it's built.  (For
    /// example, if the input spec requests a circuit that connect to
    /// port 80, then "planning" the circuit might involve picking an
    /// exit that supports port 80, and the resulting spec might be
    /// the exit's complete list of supported ports.)
    ///
    /// # Requirements
    ///
    /// The resulting Spec must support `usage`.
    fn plan_circuit(
        &self,
        usage: &<Self::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<(Self::Plan, Self::Spec)>;

    /// Construct a circuit according to a given plan.
    ///
    /// On success, return a spec describing what the circuit can be used for,
    /// and the circuit that was just constructed.
    ///
    /// This function should implement some kind of a timeout for
    /// circuits that are taking too long.
    ///
    /// # Requirements
    ///
    /// The spec that this function returns _must_ support the usage
    /// that was originally passed to `plan_circuit`.  It _must_ also
    /// contain the spec that was originally returned by
    /// `plan_circuit`.
    async fn build_circuit(&self, plan: Self::Plan) -> Result<(Self::Spec, Arc<Self::Circ>)>;

    /// Return a "parallelism factor" with which circuits should be
    /// constructed for a given purpose.
    ///
    /// If this function returns N, then whenever we launch circuits
    /// for this purpose, then we launch N in parallel.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    fn launch_parallelism(&self, usage: &<Self::Spec as AbstractSpec>::Usage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return a "parallelism factor" for which circuits should be
    /// used for a given purpose.
    ///
    /// If this function returns N, then whenever we select among
    /// open circuits for this purpose, we choose at random from the
    /// best N.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    // TODO: Possibly this doesn't belong in this trait.
    fn select_parallelism(&self, usage: &<Self::Spec as AbstractSpec>::Usage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }
}

/// An entry for an open circuit held by an `AbstractCircMgr`.
struct OpenEntry<B: AbstractCircBuilder> {
    /// Current AbstractCircSpec for this circuit's permitted usages.
    spec: B::Spec,
    /// The circuit under management.
    circ: Arc<B::Circ>,
    /// The time at which this circuit's spec was first restricted.
    dirty_since: Option<Instant>,
}

impl<B: AbstractCircBuilder> OpenEntry<B> {
    /// Make a new OpenEntry for a given circuit and spec.
    fn new(spec: B::Spec, circ: Arc<B::Circ>) -> Self {
        OpenEntry {
            spec,
            circ,
            dirty_since: None,
        }
    }

    /// Return true if this circuit can be used for `usage`.
    fn supports(&self, usage: &<B::Spec as AbstractSpec>::Usage) -> bool {
        self.circ.usable() && self.spec.supports(usage)
    }

    /// Change this circuit's permissible usage, based on its having
    /// been used for `usage` at time `now`.
    ///
    /// Return an error if this circuit may not be used for `usage`.
    fn restrict_mut(
        &mut self,
        usage: &<B::Spec as AbstractSpec>::Usage,
        now: Instant,
    ) -> Result<()> {
        self.spec.restrict_mut(usage)?;
        self.dirty_since.get_or_insert(now);
        Ok(())
    }

    /// Find the "best" entry from a vector of OpenEntry for supporting
    /// a given `usage`.
    ///
    /// If `parallelism` is some N greater than 1, we pick randomly
    /// from the best `N` circuits.
    ///
    /// # Requirements
    ///
    /// Requires that `ents` is nonempty, and that every element of `ents`
    /// supports `spec`.
    fn find_best<'a>(
        ents: &'a mut Vec<&'a mut Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        parallelism: usize,
    ) -> &'a mut Self {
        let _ = usage; // not yet used.
        use rand::seq::SliceRandom;
        let parallelism = parallelism.clamp(1, ents.len());
        // TODO: Actually look over the whole list to see which is better.
        let slice = &mut ents[0..parallelism];
        let mut rng = rand::thread_rng();
        slice.choose_mut(&mut rng).expect("Input list was empty")
    }

    /// Return true if this circuit has been marked as dirty before `cutoff`.
    fn marked_dirty_before(&self, when: Instant) -> bool {
        match self.dirty_since {
            Some(dirty) => dirty < when,
            None => false,
        }
    }
}

/// A result type whose "Ok" value is the Id for a circuit from B.
type PendResult<B> = Result<<<B as AbstractCircBuilder>::Circ as AbstractCirc>::Id>;

/// An in-progress circuit request tracked by an `AbstractCircMgr`.
///
/// (In addition to tracking circuits, `AbstractCircMgr` tracks
/// _requests_ for circuits.  The manager uses these entries if it
/// finds that some circuit created _after_ a request first launched
/// might meet the request's requirements.)
struct PendingRequest<B: AbstractCircBuilder> {
    /// Usage for the operation requested by this request
    usage: <B::Spec as AbstractSpec>::Usage,
    /// A channel to use for telling this request about circuits that it
    /// might like.
    notify: mpsc::Sender<PendResult<B>>,
}

impl<B: AbstractCircBuilder> PendingRequest<B> {
    /// Return true if this request would be supported by `spec`.
    fn supported_by(&self, spec: &B::Spec) -> bool {
        spec.supports(&self.usage)
    }
}

/// An entry for an under-construction in-progress circuit tracked by
/// an `AbstractCircMgr`.
struct PendingEntry<B: AbstractCircBuilder> {
    /// Specification for the usages that this circuit will support
    /// immediately after it is constructed, before it is used for any
    /// operation.
    #[allow(dead_code)]
    // TODO: Nothing actually uses this.  Should we remove it?  Or is
    // it good for something?
    circ_spec: B::Spec,
    /// Specification that this circuit will support, if every pending
    /// request that is waiting for it is attached to it.
    ///
    /// This spec becomes more and more restricted as more pending
    /// requests are waiting for this circuit.
    ///
    /// This spec is contained by circ_spec, and must support the usage
    /// of every pending request that's waiting for this circuit.
    tentative_assignment: sync::Mutex<B::Spec>,
    /// A shared future for requests to use when waiting for
    /// notification of this circuit's success.
    receiver: Shared<oneshot::Receiver<PendResult<B>>>,
}

impl<B: AbstractCircBuilder> PendingEntry<B> {
    /// Make a new PendingEntry that starts out supporting a given
    /// spec.  Return that PendingEntry, along with a Sender to use to
    /// report the result of building this circuit.
    fn new(circ_spec: B::Spec) -> (Self, oneshot::Sender<PendResult<B>>) {
        let tentative_assignment = sync::Mutex::new(circ_spec.clone());
        let (sender, receiver) = oneshot::channel();
        let receiver = receiver.shared();
        let entry = PendingEntry {
            circ_spec,
            tentative_assignment,
            receiver,
        };
        (entry, sender)
    }

    /// Return true if this circuit's current tentative assignment
    /// supports `usage`.
    fn supports(&self, usage: &<B::Spec as AbstractSpec>::Usage) -> bool {
        let assignment = self.tentative_assignment.lock().expect("poisoned lock");
        assignment.supports(usage)
    }

    /// Try to change the tentative assignment of this circuit by
    /// restricting it for use with `useage`.
    ///
    /// Return an error if the current tentative assignment didn't
    /// support `usage` in the first place.
    fn tentative_restrict_mut(&self, usage: &<B::Spec as AbstractSpec>::Usage) -> Result<()> {
        if let Ok(mut assignment) = self.tentative_assignment.lock() {
            assignment.restrict_mut(usage)?;
        }
        Ok(())
    }

    /// Find the best PendingEntry values from a slice for use with
    /// `usage`.
    ///
    /// # Requirements
    ///
    /// The `ents` slice must not be empty.  Every element of `ents`
    /// must support the given spec.
    fn find_best(ents: &[Arc<Self>], usage: &<B::Spec as AbstractSpec>::Usage) -> Vec<Arc<Self>> {
        // TODO: Actually look over the whole list to see which is better.
        let _ = usage; // currently unused
        vec![Arc::clone(&ents[0])]
    }
}

/// Wrapper type to represent the state between planning to build a
/// circuit and constructing it.
struct CircBuildPlan<B: AbstractCircBuilder> {
    /// The Plan object returned by [`AbstractCircBuilder::plan_circuit`].
    plan: B::Plan,
    /// A sender to notify any pending requests when this circuit is done.
    sender: oneshot::Sender<PendResult<B>>,
    /// A strong entry to the PendingEntry for this circuit build attempt.
    pending: Arc<PendingEntry<B>>,
}

/// The inner state of an [`AbstractCircMgr`].
struct CircList<B: AbstractCircBuilder> {
    /// A map from circuit ID to [`OpenEntry`] values for all managed
    /// open circuits.
    open_circs: HashMap<<B::Circ as AbstractCirc>::Id, OpenEntry<B>>,
    /// Weak-set of PendingEntry for circuits that are being built.
    ///
    /// Because this set only holds weak references, and the only
    /// strong reference to the PendingEntry is held by the task
    /// building the circuit, this set's members are lazily removed
    /// after the circuit is either built or fails to build.
    pending_circs: PtrWeakHashSet<Weak<PendingEntry<B>>>,
    /// Weak-set of PendingRequest for requests that are waiting for a
    /// circuit to be built.
    ///
    /// Because this set only holds weak references, and the only
    /// strong reference to the PendingRequest is held by the task
    /// waiting for the circuit to be built, this set's members are
    /// lazily removed after the request succeeds or fails.
    pending_requests: PtrWeakHashSet<Weak<PendingRequest<B>>>,
}

impl<B: AbstractCircBuilder> CircList<B> {
    /// Make a new empty `CircList`
    fn new() -> Self {
        CircList {
            open_circs: HashMap::new(),
            pending_circs: PtrWeakHashSet::new(),
            pending_requests: PtrWeakHashSet::new(),
        }
    }

    /// Add `e` to the list of open circuits.
    fn add_open(&mut self, e: OpenEntry<B>) {
        let id = e.circ.id();
        self.open_circs.insert(id, e);
    }

    /// Find all the usable open circuits that support `usage`.
    ///
    /// Return None if there are no such circuits.
    fn find_open(
        &mut self,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Option<Vec<&mut OpenEntry<B>>> {
        let v: Vec<_> = self
            .open_circs
            .values_mut()
            .filter(|oc| oc.supports(usage))
            .collect();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    /// Find an open circuit by ID.
    ///
    /// Return None if no such circuit exists in this list.
    fn get_open_mut(&mut self, id: &<B::Circ as AbstractCirc>::Id) -> Option<&mut OpenEntry<B>> {
        self.open_circs.get_mut(id)
    }

    /// Extract an open circuit by ID, removing it from this list.
    ///
    /// Return None if no such circuit exists in this list.
    fn take_open(&mut self, id: &<B::Circ as AbstractCirc>::Id) -> Option<OpenEntry<B>> {
        self.open_circs.remove(id)
    }

    /// Remove every open circuit marked as dirty before `cutoff`.
    fn expire_dirty_before(&mut self, cutoff: Instant) {
        self.open_circs
            .retain(|_k, v| !v.marked_dirty_before(cutoff))
    }

    /// Add `pending` to the set of in-progress circuits.
    fn add_pending_circ(&mut self, pending: Arc<PendingEntry<B>>) {
        self.pending_circs.insert(pending);
    }

    /// Find all pending circuits that support `usage`.
    ///
    /// If no such circuits are currently being built, return None.
    fn find_pending_circs(
        &self,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Option<Vec<Arc<PendingEntry<B>>>> {
        let result: Vec<_> = self
            .pending_circs
            .iter()
            .filter(|p| p.supports(usage))
            .collect();

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Construct and add a new entry to the set of request waiting
    /// for a circuit.
    ///
    /// Return the request, and a new receiver stream that it should
    /// use for notification of possible circuits to use.
    fn add_pending_request(&mut self, pending: &Arc<PendingRequest<B>>) {
        self.pending_requests.insert(Arc::clone(pending));
    }

    /// Return all pending requests that would be satisfied by a circuit
    /// that supports `circ_spec`.
    fn find_pending_requests(&self, circ_spec: &B::Spec) -> Vec<Arc<PendingRequest<B>>> {
        self.pending_requests
            .iter()
            .filter(|pend| pend.supported_by(circ_spec))
            .collect()
    }
}

/// Abstract implementation for circuit management.
///
/// The algorithm provided here is fairly simple. In its simplest form:
///
/// When somebody asks for a circuit for a given operation: if we find
/// one open already, we return it.  If we find in-progress circuits
/// that would meet our needs, we wait for one to finish (or for all
/// to fail).  And otherwise, we launch one or more circuits to meet the
/// request's needs.
///
/// If this process fails, then we retry it, up to a timeout or a
/// numerical limit.
///
/// If a circuit not previously considered for a given request
/// finishes before the request is satisfied, and if the circuit would
/// satisfy the request, we try to give that circuit as an answer to
/// that request even if it was not one of the circuits that request
/// was waiting for.
pub(crate) struct AbstractCircMgr<B: AbstractCircBuilder, R: Runtime> {
    /// Builder used to construct circuits.
    builder: B,
    /// An asynchronous runtime to use for launching tasks and
    /// checking timeouts.
    runtime: R,
    /// A CircList to manage our list of circuits, requests, and
    /// pending circuits.
    circs: sync::Mutex<CircList<B>>,
}

/// An action to take in order to satisfy a request for a circuit.
enum Action<B: AbstractCircBuilder> {
    /// We found an open circuit: return immediately.
    Open(Arc<B::Circ>),
    /// We found one or more pending circuits: wait until one succeeds,
    /// or all fail.
    Wait(FuturesUnordered<Shared<oneshot::Receiver<PendResult<B>>>>),
    /// We should launch circuits: here are the instructions for how
    /// to do so.
    Build(Vec<CircBuildPlan<B>>),
}

impl<B: AbstractCircBuilder + 'static, R: Runtime> AbstractCircMgr<B, R> {
    /// Construct a new AbstractCircMgr.
    pub(crate) fn new(builder: B, runtime: R) -> Self {
        AbstractCircMgr {
            builder,
            runtime,
            circs: sync::Mutex::new(CircList::new()),
        }
    }

    /// Return a circuit suitable for use with a given `usage`,
    /// creating that circuit if necessary, and restricting it
    /// under the assumption that it will be used for that spec.
    ///
    /// This is the primary entry point for AbstractCircMgr.
    pub(crate) async fn get_or_launch(
        self: &Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<Arc<B::Circ>> {
        // TODO: Timeouts and retries should be configurable, and possibly
        // even an argument to this function?
        let wait_for_circ = Duration::from_secs(60);
        let timeout_at = self.runtime.now() + wait_for_circ;
        let max_tries: usize = 32;

        for n in 0..max_tries {
            // How much time is remaining?
            let remaining = match timeout_at.checked_duration_since(self.runtime.now()) {
                None => return Err(Error::RequestTimeout),
                Some(t) => t,
            };

            let err = match self.pick_action(usage, dir, true) {
                Ok(action) => {
                    // We successfully found an action: Take that action.
                    let outcome = self
                        .runtime
                        .timeout(remaining, Arc::clone(&self).take_action(action, usage))
                        .await;

                    match outcome {
                        Ok(Ok(circ)) => return Ok(circ),
                        Ok(Err(e)) => e,
                        Err(_) => return Err(Error::RequestTimeout),
                    }
                }
                Err(e) => {
                    // We couldn't take the action! This is unusual; wait
                    // a little while before we try again.
                    let wait_for_action = Duration::from_millis(50);
                    self.runtime
                        .sleep(std::cmp::min(remaining, wait_for_action))
                        .await;
                    e
                }
            };

            info!("Build attempt {} failed: {:?}", n + 1, err);
        }

        // TODO: remember the errors using tor_retry or similar.
        Err(crate::Error::PendingFailed)
    }

    /// Make sure a circuit exists, without actually asking for it.
    ///
    /// Make sure that there is a circuit (built or in-progress) that could be
    /// used for `usage`, and launch one or more circuits in a background task
    /// if there is not.
    // TODO: This should probably take some kind of parallelism parameter.
    #[allow(dead_code)]
    pub(crate) async fn ensure_circuit(
        self: &Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<()> {
        let action = self.pick_action(usage, dir, false)?;
        if let Action::Build(plans) = action {
            for plan in plans {
                let self_clone = Arc::clone(self);
                let _ignore_receiver = self_clone.launch(usage, plan);
            }
        }

        Ok(())
    }

    /// Choose which action we should take in order to provide a circuit
    /// for a given `usage`.
    ///
    /// If `restrict_circ` is true, we restrict the spec of any
    /// circ we decide to use to mark that it _is_ being used for
    /// `usage`.
    fn pick_action(
        &self,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
        restrict_circ: bool,
    ) -> Result<Action<B>> {
        let mut list = self.circs.lock().expect("poisoned lock");

        if let Some(mut open) = list.find_open(usage) {
            // We have open circuits that meet the spec: return the best one.
            let parallelism = self.builder.select_parallelism(usage);
            let best = OpenEntry::find_best(&mut open, usage, parallelism);
            if restrict_circ {
                let now = self.runtime.now();
                best.restrict_mut(usage, now)?;
            }
            // TODO: If we have fewer circuits here than our select
            // parallelism, perhaps we should launch more?

            return Ok(Action::Open(Arc::clone(&best.circ)));
        }

        if let Some(pending) = list.find_pending_circs(usage) {
            // There are pending circuits that could meet the spec.
            // Restrict them under the assumption that they could all
            // be used for this, and then wait until one is ready (or
            // all have failed)
            let best = PendingEntry::find_best(&pending, usage);
            if restrict_circ {
                for item in best.iter() {
                    // TODO: Do we want to tentatively restrict _all_ of these?
                    // not clear to me.
                    item.tentative_restrict_mut(usage)?;
                }
            }
            let stream = best.iter().map(|item| item.receiver.clone()).collect();
            // TODO: if we have fewer circuits here than our launch
            // parallelism, we might want to launch more.

            return Ok(Action::Wait(stream));
        }

        // Okay, we need to launch circuits here.
        let parallelism = std::cmp::max(1, self.builder.launch_parallelism(usage));
        let mut plans = Vec::new();
        for _ in 0..parallelism {
            let (plan, bspec) = self.builder.plan_circuit(usage, dir)?;
            let (pending, sender) = PendingEntry::new(bspec);
            let pending = Arc::new(pending);
            list.add_pending_circ(Arc::clone(&pending));
            let plan = CircBuildPlan {
                plan,
                sender,
                pending,
            };
            plans.push(plan);
        }
        Ok(Action::Build(plans))
    }

    /// Execute an action returned by pick-action, and return the
    /// resulting circuit or error.
    async fn take_action(
        self: Arc<Self>,
        act: Action<B>,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Result<Arc<B::Circ>> {
        // Get or make a stream of futures to wait on.
        let wait_on_stream = match act {
            Action::Open(c) => return Ok(c),
            Action::Wait(f) => f,
            Action::Build(plans) => {
                let futures = FuturesUnordered::new();
                for plan in plans {
                    let self_clone = Arc::clone(&self);
                    // (This is where we actually launch circuits.)
                    futures.push(self_clone.launch(usage, plan));
                }
                futures
            }
        };

        // Insert ourself into the list of pending requests, and make a
        // stream for us to listn on for notification from pending circuits
        // other than those we are pending on.
        let (pending_request, additional_stream) = {
            let (send, recv) = mpsc::channel(8);
            let pending = Arc::new(PendingRequest {
                usage: usage.clone(),
                notify: send,
            });

            let mut list = self.circs.lock().expect("poisoned lock");
            list.add_pending_request(&pending);

            (pending, recv)
        };

        // We use our "select_biased" stream combiner here to ensure
        // that:
        //   1) Circuits from wait_on_stream (the ones we're pending
        //      on) are preferred.
        //   2) We exit this function when those circuits are exhausted.
        //   3) We still get notified about other circuits that might
        //      meet our interests.
        let mut incoming = streams::select_biased(wait_on_stream, additional_stream.map(Ok));

        while let Some((src, id)) = incoming.next().await {
            if let Ok(Ok(ref id)) = id {
                // Great, we have a circuit.  See if we can use it!
                let mut list = self.circs.lock().expect("poisoned lock");
                if let Some(ent) = list.get_open_mut(&id) {
                    let now = self.runtime.now();
                    match ent.restrict_mut(usage, now) {
                        Ok(()) => {
                            // Great, this will work.  We drop the
                            // pending request now explicitly to remove
                            // it from the list.
                            drop(pending_request);
                            return Ok(Arc::clone(&ent.circ));
                        }
                        Err(e) => {
                            // TODO: as below, improve this log message.
                            let level = match src {
                                streams::Source::Left => log::Level::Info,
                                _ => log::Level::Debug,
                            };
                            log!(
                                level,
                                "{:?} suggested we use {:?}, but restrictions failed: {:?}",
                                src,
                                id,
                                e
                            );
                            continue;
                        }
                    }
                }
            }

            // TODO: Improve this log message; using :? here will make it
            // hard to understand.
            info!("While waiting on circuit: {:?} from {:?}", id, src);
        }

        // Nothing worked.  We drop the pending request now explicitly
        // to remove it from the list.  (We could just let it get dropped
        // implicitly, but that's a bit confusing.)
        drop(pending_request);

        // TODO: Maybe use a tor_retry to collect all of these errors
        Err(crate::Error::PendingFailed)
    }

    /// Actually launch a circuit in a background task.
    ///
    /// The `usage` argument is the usage from the original request that made
    /// us build this circuit.
    fn launch(
        self: Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        plan: CircBuildPlan<B>,
    ) -> Shared<oneshot::Receiver<PendResult<B>>> {
        let _ = usage; // Currently unused.
        let CircBuildPlan {
            plan,
            sender,
            pending,
        } = plan;

        let wait_on_future = pending.receiver.clone();
        let runtime = self.runtime.clone();
        let runtime_copy = self.runtime.clone();

        runtime
            .spawn(async move {
                let outcome = self.builder.build_circuit(plan).await;
                let (new_spec, reply) = match outcome {
                    Err(e) => (None, Err(e)),
                    Ok((new_spec, circ)) => {
                        let id = circ.id();
                        // I used to call restrict_mut here, but now I'm not so
                        // sure. Doing restrict_mut makes sure that this
                        // circuit will be suitable for the request that asked
                        // for us in the first place, but that should be
                        // ensured anyway by our tracking its tentative
                        // assignment.
                        //
                        // new_spec.restrict_mut(&usage_copy).unwrap();
                        let open_ent = OpenEntry::new(new_spec.clone(), circ);
                        {
                            let mut list = self.circs.lock().expect("poisoned lock");
                            list.add_open(open_ent);
                            // We drop our refrence to 'pending' here:
                            // this should make all the weak references to
                            // the `PendingEntry` become dangling.
                            drop(pending);
                        }

                        (Some(new_spec), Ok(id))
                    }
                };
                // Tell anybody who was listening about it that this
                // circuit is now usable or failed.
                //
                // (We ignore any errors from `send`: That just means that nobody
                // was waiting for this circuit.)
                let _ = sender.send(reply.clone());

                if let Some(new_spec) = new_spec {
                    // Wait briefly before we notify opportunistically.  This
                    // delay will give the circuits that were originally
                    // specifically intended for a request a little more time
                    // to finish, before we offer it this circuit instead.
                    // TODO: make this configurable.
                    let briefly = Duration::from_millis(50);
                    runtime_copy.sleep(briefly).await;

                    let pending = {
                        let list = self.circs.lock().expect("poisoned lock");
                        list.find_pending_requests(&new_spec)
                    };
                    for pending_request in pending {
                        let _ = pending_request.notify.clone().try_send(reply.clone());
                    }
                }
            })
            .expect("Couldn't spawn circuit-building task");

        wait_on_future
    }

    /// Remove the cicuit with a given `id` from this manager.
    ///
    /// After this fnuction is called, that cicuit will no longer be handed
    /// out to any future requests.
    ///
    /// Return None if we have no circuit with the given ID.
    pub(crate) fn take_circ(&self, id: &<B::Circ as AbstractCirc>::Id) -> Option<Arc<B::Circ>> {
        let mut list = self.circs.lock().expect("poisoned lock");
        list.take_open(id).map(|e| e.circ)
    }

    /// Expire every circuit that was marked as dirty at a time before
    /// `cutoff`.
    ///
    /// Expired circuits will not be automatically closed, but they will
    /// no longer be given out for new circuits.
    pub(crate) fn expire_dirty_before(&self, cutoff: Instant) {
        let mut list = self.circs.lock().expect("poisoned lock");
        list.expire_dirty_before(cutoff)
    }

    /// Get a reference to this manager's runtime.
    pub(crate) fn peek_runtime(&self) -> &R {
        &self.runtime
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;
    use std::collections::HashSet;
    use std::sync::atomic::{self, AtomicUsize};
    use tor_rtmock::MockSleepRuntime;

    #[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
    struct FakeId {
        id: usize,
    }

    static NEXT_FAKE_ID: AtomicUsize = AtomicUsize::new(0);
    impl FakeId {
        fn next() -> Self {
            let id = NEXT_FAKE_ID.fetch_add(1, atomic::Ordering::SeqCst);
            FakeId { id }
        }
    }

    #[derive(Debug)]
    struct FakeCirc {
        id: FakeId,
    }

    impl AbstractCirc for FakeCirc {
        type Id = FakeId;
        fn id(&self) -> FakeId {
            self.id
        }
        fn usable(&self) -> bool {
            true
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakeSpec {
        ports: HashSet<u16>,
        isolation_group: Option<u8>,
    }

    impl AbstractSpec for FakeSpec {
        type Usage = FakeSpec;
        fn supports(&self, other: &FakeSpec) -> bool {
            let ports_ok = self.ports.is_superset(&other.ports);
            let iso_ok = match (self.isolation_group, other.isolation_group) {
                (None, _) => true,
                (_, None) => true,
                (Some(a), Some(b)) => a == b,
            };
            ports_ok && iso_ok
        }
        fn restrict_mut(&mut self, other: &FakeSpec) -> Result<()> {
            if !self.ports.is_superset(&other.ports) {
                return Err(Error::UsageNotSupported("Missing ports".into()));
            }
            let new_iso = match (self.isolation_group, other.isolation_group) {
                (None, x) => x,
                (x, None) => x,
                (Some(a), Some(b)) if a == b => Some(a),
                (_, _) => return Err(Error::UsageNotSupported("Bad isolation".into())),
            };

            self.isolation_group = new_iso;
            Ok(())
        }
    }

    impl FakeSpec {
        fn new<T>(ports: T) -> Self
        where
            T: IntoIterator,
            T::Item: Into<u16>,
        {
            let ports = ports.into_iter().map(Into::into).collect();
            FakeSpec {
                ports,
                isolation_group: None,
            }
        }
        fn isolated(self, group: u8) -> Self {
            FakeSpec {
                ports: self.ports.clone(),
                isolation_group: Some(group),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakePlan {
        spec: FakeSpec,
    }

    #[derive(Debug)]
    struct FakeBuilder<RT: Runtime> {
        runtime: RT,
        script: sync::Mutex<Vec<FakeOp>>,
    }

    #[derive(Debug, Clone)]
    enum FakeOp {
        Succeed,
        Fail,
        Timeout,
    }

    const FAKE_CIRC_DELAY: Duration = Duration::from_millis(30);

    static DI_EMPTY: [tor_netdir::fallback::FallbackDir; 0] = [];

    fn di() -> DirInfo<'static> {
        DI_EMPTY[..].into()
    }

    #[async_trait]
    impl<RT: Runtime> AbstractCircBuilder for FakeBuilder<RT> {
        type Spec = FakeSpec;
        type Circ = FakeCirc;
        type Plan = FakePlan;

        fn plan_circuit(&self, spec: &FakeSpec, _dir: DirInfo<'_>) -> Result<(FakePlan, FakeSpec)> {
            let plan = FakePlan { spec: spec.clone() };
            Ok((plan, spec.clone()))
        }

        async fn build_circuit(&self, plan: FakePlan) -> Result<(FakeSpec, Arc<FakeCirc>)> {
            let op = {
                let mut s = self.script.lock().unwrap();
                s.pop().unwrap_or(FakeOp::Succeed)
            };
            self.runtime.sleep(FAKE_CIRC_DELAY).await;
            match op {
                FakeOp::Succeed => Ok((plan.spec, Arc::new(FakeCirc { id: FakeId::next() }))),
                FakeOp::Fail => Err(Error::PendingFailed),
                FakeOp::Timeout => {
                    let () = futures::future::pending().await;
                    unreachable!()
                }
            }
        }
    }

    impl<RT: Runtime> FakeBuilder<RT> {
        fn new<I>(rt: &RT, v: I) -> Self
        where
            I: IntoIterator<Item = FakeOp>,
        {
            let mut ops: Vec<_> = v.into_iter().collect();
            ops.reverse();
            FakeBuilder {
                runtime: rt.clone(),
                script: sync::Mutex::new(ops),
            }
        }
    }

    // TODO: If this is generally useful maybe it should be a method on
    // MockSleepRuntime.
    async fn wait_for<RT: Runtime, F: futures::Future>(
        rt: &MockSleepRuntime<RT>,
        fut: F,
    ) -> F::Output {
        let (send, mut recv) = oneshot::channel();
        let increment = Duration::from_millis(5);

        let (output, _) = futures::join!(
            async {
                let o = fut.await;
                send.send(()).unwrap();
                o
            },
            async {
                loop {
                    rt.advance(increment).await;
                    match recv.try_recv() {
                        Err(_) => break,
                        Ok(Some(())) => break,
                        _ => {}
                    }
                }
            }
        );

        output
    }

    #[test]
    fn basic_tests() {
        tor_rtcompat::test_with_runtime(|rt| async {
            let rt = MockSleepRuntime::new(rt);

            let builder = FakeBuilder::new(&rt, vec![]);

            let mgr = Arc::new(AbstractCircMgr::new(builder, rt.clone()));

            let webports = FakeSpec::new(vec![80_u16, 443]);

            // Launch a circuit; make sure we get it.
            let c1 = wait_for(&rt, mgr.get_or_launch(&webports, di())).await;
            let c1 = c1.unwrap();

            // Make sure we get the one we already made if we ask for it.
            let port80 = FakeSpec::new(vec![80_u16]);
            let c2 = mgr.get_or_launch(&port80, di()).await;

            let c2 = c2.unwrap();
            assert!(Arc::ptr_eq(&c1, &c2));

            // Now try launching two circuits "at once" to make sure that our
            // pending-circuit code works.

            let dnsport = FakeSpec::new(vec![53_u16]);
            let dnsport_restrict = dnsport.clone().isolated(7);

            let (c3, c4) = wait_for(
                &rt,
                futures::future::join(
                    mgr.get_or_launch(&dnsport, di()),
                    mgr.get_or_launch(&dnsport_restrict, di()),
                ),
            )
            .await;

            let c3 = c3.unwrap();
            let c4 = c4.unwrap();
            assert!(!Arc::ptr_eq(&c1, &c3));
            assert!(Arc::ptr_eq(&c3, &c4));
        });
    }

    #[test]
    fn request_timeout() {
        tor_rtcompat::test_with_runtime(|rt| async {
            let rt = MockSleepRuntime::new(rt);

            // This will fail once, and then completely time out.  The
            // result will be a failure.
            let builder = FakeBuilder::new(&rt, vec![FakeOp::Fail, FakeOp::Timeout]);

            let mgr = Arc::new(AbstractCircMgr::new(builder, rt.clone()));
            let ports = FakeSpec::new(vec![80_u16, 443]);
            let c1 = wait_for(&rt, mgr.get_or_launch(&ports, di())).await;

            assert!(matches!(c1, Err(Error::RequestTimeout)));
        });
    }

    #[test]
    fn request_fails_too_much() {
        tor_rtcompat::test_with_runtime(|rt| async {
            let rt = MockSleepRuntime::new(rt);

            // This will fail 1000 times, which is above the retry limit.
            let builder = FakeBuilder::new(&rt, vec![FakeOp::Fail; 1000]);

            let mgr = Arc::new(AbstractCircMgr::new(builder, rt.clone()));
            let ports = FakeSpec::new(vec![80_u16, 443]);
            let c1 = wait_for(&rt, mgr.get_or_launch(&ports, di())).await;

            assert!(matches!(c1, Err(Error::PendingFailed)));
        });
    }

    #[test]
    fn request_retried() {
        tor_rtcompat::test_with_runtime(|rt| async {
            let rt = MockSleepRuntime::new(rt);

            // This will fail twice, and then succeed. The result will be
            // a success.
            let builder = FakeBuilder::new(&rt, vec![FakeOp::Fail, FakeOp::Fail]);

            let mgr = Arc::new(AbstractCircMgr::new(builder, rt.clone()));
            let ports = FakeSpec::new(vec![80_u16, 443]);
            let (c1, c2) = wait_for(
                &rt,
                futures::future::join(
                    mgr.get_or_launch(&ports, di()),
                    mgr.get_or_launch(&ports, di()),
                ),
            )
            .await;

            let c1 = c1.unwrap();
            let c2 = c2.unwrap();

            assert!(Arc::ptr_eq(&c1, &c2));
        });
    }
}
