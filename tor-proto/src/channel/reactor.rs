//! Code to handle incoming cells on a channel.
//!
//! The role of this code is to run in a separate asynchronous task,
//! and routes cells to the right circuits.
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.

use super::circmap::{CircEnt, CircMap};
use super::LogId;
use crate::{Error, Result};
use tor_cell::chancell::msg::{Destroy, DestroyReason};
use tor_cell::chancell::{msg::ChanMsg, ChanCell, CircID};

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::{self, Stream, StreamExt};

use std::convert::TryInto;
use std::sync::{Arc, Weak};

use log::{debug, trace};

/// A message telling the channel reactor to do something.
#[derive(Debug)]
pub(super) enum CtrlMsg {
    /// Shut down the reactor.
    Shutdown,
    /// Register a new one-shot receiver that can send a CtrlMsg to the
    /// reactor.
    Register(oneshot::Receiver<CtrlMsg>),
    /// Tell the reactor that a given circuit has gone away.
    CloseCircuit(CircID),
}

/// Type returned by a oneshot channel for a CtrlMsg.
///
/// TODO: copy documentation from circuit::reactor if we don't unify
/// these types somehow.
pub(super) type CtrlResult = std::result::Result<CtrlMsg, oneshot::Canceled>;

/// A stream to multiplex over a bunch of oneshot CtrlMsg replies.
///
/// TODO: copy documentation from circuit::reactor if we don't unify
/// these types somehow.
type OneshotStream = stream::SelectAll<stream::Once<oneshot::Receiver<CtrlMsg>>>;

/// Error return value from run_once: indicates an error or a shutdown.
#[derive(Debug)]
enum ReactorError {
    /// The reactor should shut down with an abnormal exit condition.
    Err(Error),
    /// The reactor should shut down without an error, since all is well.
    Shutdown,
}
impl From<Error> for ReactorError {
    fn from(e: Error) -> ReactorError {
        ReactorError::Err(e)
    }
}
#[cfg(test)]
impl ReactorError {
    /// Tests only: assert that this is an Error, and return it.
    fn unwrap_err(self) -> Error {
        match self {
            ReactorError::Shutdown => panic!(),
            ReactorError::Err(e) => e,
        }
    }
}

/// Object to handle incoming cells on a channel.
///
/// This type is returned when you finish a channel; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the channel won't work."]
pub struct Reactor<T>
where
    T: Stream<Item = std::result::Result<ChanCell, tor_cell::Error>> + Unpin + Send + 'static,
{
    /// A stream of oneshot receivers that this reactor can use to get
    /// control messages.
    ///
    /// TODO: copy documentation from circuit::reactor if we don't unify
    /// these types somehow.
    control: stream::Fuse<stream::Select<mpsc::Receiver<CtrlResult>, OneshotStream>>,
    /// A Stream from which we can read ChanCells.  This should be backed
    /// by a TLS connection.
    input: stream::Fuse<T>,
    // TODO: This lock is used pretty asymmetrically.  The reactor
    // task needs to use the circmap all the time, whereas other tasks
    // only need the circmap when dealing with circuit creation.
    // Maybe it would be better to use some kind of channel to tell
    // the reactor about new circuits?
    /// A map from circuit ID to Sinks on which we can deliver cells.
    circs: Arc<Mutex<CircMap>>,

    /// Channel pointer -- used to send DESTROY cells.
    channel: Weak<Mutex<super::ChannelImpl>>,

    /// Logging identifier for this channel
    logid: LogId,
}

impl<T> Reactor<T>
where
    T: Stream<Item = std::result::Result<ChanCell, tor_cell::Error>> + Unpin + Send + 'static,
{
    /// Construct a new Reactor.
    ///
    /// Cells should be taken from input and routed according to circmap.
    ///
    /// When closeflag fires, the reactor should shut down.
    pub(super) fn new(
        channel: Arc<Mutex<super::ChannelImpl>>,
        circmap: Arc<Mutex<CircMap>>,
        control: mpsc::Receiver<CtrlResult>,
        closeflag: oneshot::Receiver<CtrlMsg>,
        input: T,
        logid: LogId,
    ) -> Self {
        let mut oneshots = stream::SelectAll::new();
        oneshots.push(stream::once(closeflag));
        let control = stream::select(control, oneshots);
        Reactor {
            control: control.fuse(),
            input: input.fuse(),
            channel: Arc::downgrade(&channel),
            circs: circmap,
            logid,
        }
    }

    /// Launch the reactor, and run until the channel closes or we
    /// encounter an error.
    pub async fn run(mut self) -> Result<()> {
        if let Some(chan) = self.channel.upgrade() {
            let chan = chan.lock().await;
            if chan.closed {
                return Err(Error::ChannelClosed);
            }
        } else {
            return Err(Error::ChannelClosed);
        }
        debug!("{}: Running reactor", self.logid);
        let result: Result<()> = loop {
            dbg!("Loop");
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        dbg!("Out");
        debug!("{}: Reactor stopped: {:?}", self.logid, result);
        if let Some(chan) = self.channel.upgrade() {
            let mut chan = chan.lock().await;
            chan.closed = true;
        }
        dbg!("None.");
        dbg!(&result);
        result
    }

    /// Helper for run(): handles only one action, and doesn't mark
    /// the channel closed on finish.
    async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        // Let's see what's next: maybe we got a cell, maybe the TLS
        // connection got closed, or maybe we've been told to shut
        // down.
        select_biased! {
            // we got a control message!
            ctrl = self.control.next() => {
                match ctrl {
                    Some(Ok(CtrlMsg::Shutdown)) =>
                        return Err(ReactorError::Shutdown),
                    Some(Ok(msg)) => self.handle_control(msg).await?,
                    Some(Err(_)) => (), // sender cancelled; ignore.
                    None => panic!() // should be impossible.
                }
            }
            // we got a cell or a close.
            item = self.input.next() => {
                let item = match item {
                    None => return Err(ReactorError::Shutdown), // the TLS connection closed.
                    Some(r) => r.map_err(|e| Error::CellErr(e))?, // it's a cell.
                };
                self.handle_cell(item).await?;

            }
        };

        Ok(()) // Run again.
    }

    /// Handle a CtrlMsg other than Shutdown.
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        trace!("{}: reactor received {:?}", self.logid, msg);
        match msg {
            CtrlMsg::Shutdown => panic!(), // was handled in reactor loop.
            CtrlMsg::Register(ch) => self.register(ch),
            CtrlMsg::CloseCircuit(id) => self.outbound_destroy_circ(id).await?,
        }
        Ok(())
    }

    /// Ensure that we get a message on self.control when `ch` fires.
    fn register(&mut self, ch: oneshot::Receiver<CtrlMsg>) {
        let (_, select_all) = self.control.get_mut().get_mut();
        select_all.push(stream::once(ch));
    }

    /// Helper: process a cell on a channel.  Most cell types get ignored
    /// or rejected; a few get delivered to circuits.
    async fn handle_cell(&mut self, cell: ChanCell) -> Result<()> {
        let (circid, msg) = cell.into_circid_and_msg();
        use ChanMsg::*;

        match msg {
            Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
            _ => trace!("{}: received {} for {}", self.logid, msg.cmd(), circid),
        }

        match msg {
            // These aren't allowed on clients.
            Create(_) | CreateFast(_) | Create2(_) | RelayEarly(_) | PaddingNegotiate(_) => Err(
                Error::ChanProto(format!("{} cell on client channel", msg.cmd())),
            ),

            // In theory this is allowed in clients, but we should never get
            // one, since we don't use TAP.
            Created(_) => Err(Error::ChanProto(format!("{} cell received", msg.cmd()))),

            // These aren't allowed after handshaking is done.
            Versions(_) | Certs(_) | Authorize(_) | Authenticate(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "{} cell after handshake is done",
                msg.cmd()
            ))),

            // These are allowed, and need to be handled.
            Relay(_) => self.deliver_relay(circid, msg).await,

            Destroy(_) => self.deliver_destroy(circid, msg).await,

            CreatedFast(_) | Created2(_) => self.deliver_created(circid, msg).await,

            // These are always ignored.
            Padding(_) | VPadding(_) => Ok(()),

            // Unrecognized cell types should be safe to allow _on channels_,
            // since they can't propagate.
            Unrecognized(_) => Ok(()),

            // tor_cells knows about this type, but we don't.
            _ => Ok(()),
        }
    }

    /// Give the RELAY cell `msg` to the appropriate circuid.
    async fn deliver_relay(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        let mut map = self.circs.lock().await;

        match map.get_mut(circid) {
            Some(CircEnt::Open(s)) => {
                // There's an open circuit; we can give it the RELAY cell.
                // XXXXM3 handle errors better.
                // XXXXM3 should we really be holding the mutex for this?
                // XXXXM3 I think that this one actually means the other side
                // is closed
                s.send(msg.try_into()?).await.map_err(|_| {
                    Error::InternalError(
                        "Circuit queue rejected message. Is it closing? XXX".into(),
                    )
                })
            }
            Some(CircEnt::Opening(_, _)) => Err(Error::ChanProto(
                "Relay cell on pending circuit before CREATED received".into(),
            )),
            // Some(DestroySent(s)) => ...  XXXXM3 need to implement this
            None => Err(Error::ChanProto("Relay cell on nonexistent circuit".into())),
        }
    }

    /// Handle a CREATED{,_FAST,2} cell by passing it on to the appropriate
    /// circuit, if that circuit is waiting for one.
    async fn deliver_created(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        let mut map = self.circs.lock().await;
        if let Some(target) = map.advance_from_opening(circid) {
            let created = msg.try_into()?;
            // XXXX handle errors better.
            // XXXX should we really be holding the mutex for this?
            // XXXX I think that this one actually means the other side
            // is closed
            target.send(created).map_err(|_| {
                Error::InternalError(
                    "Circuit queue rejected created message. Is it closing? XXX".into(),
                )
            })
        } else {
            Err(Error::ChanProto(format!("Unexpected {} cell", msg.cmd())))
        }
    }

    /// Handle a DESTROY cell by removing the corresponding circuit
    /// from the map, and pasing the destroy cell onward to the circuit.
    async fn deliver_destroy(&mut self, circid: CircID, msg: ChanMsg) -> Result<()> {
        // XXXXM3 TODO: do we need to put a dummy entry in the map until
        // the other side of the circuit object is gone?

        let mut map = self.circs.lock().await;
        // Remove the circuit from the map: nothing more can be done with it.
        let entry = map.remove(circid);
        match entry {
            // If the circuit is waiting for CREATED, tell it that it
            // won't get one.
            Some(CircEnt::Opening(oneshot, _)) => {
                trace!(
                    "{}: Passing destroy to pending circuit {}",
                    self.logid,
                    circid
                );
                oneshot
                    .send(msg.try_into()?)
                    // XXXX I think that this one actually means the other side
                    // is closed
                    .map_err(|_| {
                        Error::InternalError(
                            "pending circuit wasn't interested in Destroy cell?".into(),
                        )
                    })
            }
            // It's an open circuit: tell it that it got a DESTROY cell.
            Some(CircEnt::Open(mut sink)) => {
                trace!("{}: Passing destroy to open circuit {}", self.logid, circid);
                sink.send(msg.try_into()?)
                    .await
                    // XXXX I think that this one actually means the other side
                    // is closed
                    .map_err(|_| {
                        Error::InternalError("circuit wan't interested in destroy cell?".into())
                    })
            }
            // Some(DestroySent) => ... XXXXM3 implement this
            // Got a DESTROY cell for a circuit we don't have.
            None => {
                trace!("{}: Destroy for nonexistent circuit {}", self.logid, circid);
                Err(Error::ChanProto("Destroy for nonexistent circuit".into()))
            }
        }
    }

    /// Called when a circuit goes away: sends a DESTROY cell and removes
    /// the circuit.
    async fn outbound_destroy_circ(&mut self, id: CircID) -> Result<()> {
        trace!("{}: Circuit {} is gone; sending DESTROY", self.logid, id);
        {
            let mut map = self.circs.lock().await;
            // Remove the circuit's entry from the map: nothing more
            // can be done with it.
            let _old_entry = map.remove(id);

            // TODO: should we remember that there was a circuit with this ID,
            // so we can recognize junk cells? XXXXM3
        }
        {
            let destroy = Destroy::new(DestroyReason::NONE).into();
            let cell = ChanCell::new(id, destroy);
            if let Some(chan) = self.channel.upgrade() {
                let mut chan = chan.lock().await;
                chan.send_cell(cell).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::executor::LocalPool;
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures_await_test::async_test;

    type CodecResult = std::result::Result<ChanCell, tor_cell::Error>;

    fn new_reactor() -> (
        crate::channel::Channel,
        Reactor<mpsc::Receiver<CodecResult>>,
        mpsc::Receiver<ChanCell>,
        mpsc::Sender<CodecResult>,
    ) {
        let link_protocol = 4;
        let (send1, recv1) = mpsc::channel(32);
        let (send2, recv2) = mpsc::channel(32);
        let logid = LogId::new();
        let ed_id = [0x1; 32].into();
        let rsa_id = [0x2; 20].into();
        let send1 = send1.sink_map_err(|_| tor_cell::Error::ChanProto("dummy message".into()));
        let (chan, reactor) = crate::channel::Channel::new(
            link_protocol,
            Box::new(send1),
            recv2,
            logid,
            ed_id,
            rsa_id,
        );
        (chan, reactor, recv1, send2)
    }

    // Try shutdown from inside run_once..
    #[async_test]
    async fn shutdown() {
        let (chan, mut reactor, _output, _input) = new_reactor();

        chan.terminate().await;
        let r = reactor.run_once().await;
        assert!(matches!(r, Err(ReactorError::Shutdown)));

        // This "run" won't even start.
        let r = reactor.run().await;
        assert!(matches!(r, Err(Error::ChannelClosed)));
    }

    // Try shutdown while reactor is running.
    #[test]
    fn shutdown2() {
        // TODO: Ask a rust person if this is how to do this.
        use futures::future::FutureExt;
        use futures::task::LocalSpawnExt;

        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let (chan, reactor, _output, _input) = new_reactor();
        // Let's get the reactor running...
        let run_reactor = reactor.run().map(|x| x.is_ok()).shared();
        let run_handle = spawner
            .spawn_local_with_handle(run_reactor.clone())
            .unwrap();
        run_handle.forget();
        pool.run_until_stalled();

        // Now let's see. The reactor should _still_ be running.
        assert!(run_reactor.peek().is_none());

        // Now let's try shutting down.
        spawner.spawn_local(chan.terminate()).unwrap();
        pool.run_until_stalled();

        // Now let's see. The reactor should not _still_ be running.
        assert_eq!(run_reactor.peek(), Some(&true));
    }

    #[async_test]
    async fn new_circ_closed() {
        let mut rng = rand::thread_rng();
        let (chan, mut reactor, _output, _input) = new_reactor();

        let (pending, _circr) = chan.new_circ(&mut rng).await.unwrap();

        reactor.run_once().await.unwrap();

        let id = pending.peek_circid().await;

        {
            let mut circs = reactor.circs.lock().await;
            let ent = circs.get_mut(id);
            assert!(matches!(ent, Some(CircEnt::Opening(_, _))));
        }
        // Now drop the circuit; this should tell the reactor to remove
        // the circuit from the map.
        drop(pending);

        reactor.run_once().await.unwrap();
        {
            let mut circs = reactor.circs.lock().await;
            let ent = circs.get_mut(id);
            assert!(matches!(ent, None));
        }
    }

    // Test proper delivery of a created cell that doesn't make a channel
    #[async_test]
    async fn new_circ_create_failure() {
        use tor_cell::chancell::msg;
        let mut rng = rand::thread_rng();
        let (chan, mut reactor, mut output, mut input) = new_reactor();

        let (pending, _circr) = chan.new_circ(&mut rng).await.unwrap();

        reactor.run_once().await.unwrap();

        let id = pending.peek_circid().await;

        {
            let mut circs = reactor.circs.lock().await;
            let ent = circs.get_mut(id);
            assert!(matches!(ent, Some(CircEnt::Opening(_, _))));
        }
        // We'll get a bad handshake result from this createdfast cell.
        let created_cell = ChanCell::new(id, msg::CreatedFast::new(*b"x").into());
        input.send(Ok(created_cell)).await.unwrap();

        let (circ, reac) =
            futures::join!(pending.create_firsthop_fast(&mut rng), reactor.run_once());
        // Make sure statuses are as expected.
        assert!(matches!(circ.err().unwrap(), Error::BadHandshake));
        assert!(reac.is_ok());

        // Make sure that the createfast cell got sent
        let cell_sent = output.next().await.unwrap();
        assert!(matches!(cell_sent.msg(), msg::ChanMsg::CreateFast(_)));

        // The circid now counts as open, since as far as the reactor knows,
        // it was accepted.  (TODO: is this a bug?)
        {
            let mut circs = reactor.circs.lock().await;
            let ent = circs.get_mut(id);
            assert!(matches!(ent, Some(CircEnt::Open(_))));
        }

        // But the next run if the reactor will make the circuit get closed.
        reactor.run_once().await.unwrap();
        {
            let mut circs = reactor.circs.lock().await;
            let ent = circs.get_mut(id);
            assert!(matches!(ent, None));
        }
    }

    // Try incoming cells that shouldn't arrive on channels.
    #[async_test]
    async fn bad_cells() {
        use tor_cell::chancell::msg;
        let (_chan, mut reactor, _output, mut input) = new_reactor();

        // We shouldn't get create cells, ever.
        let create_cell = msg::Create2::new(4, *b"hihi").into();
        input
            .send(Ok(ChanCell::new(9.into(), create_cell)))
            .await
            .unwrap();

        // shouldn't get created2 cells for nonexistent circuits
        let created2_cell = msg::Created2::new(*b"hihi").into();
        input
            .send(Ok(ChanCell::new(7.into(), created2_cell)))
            .await
            .unwrap();

        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: CREATE2 cell on client channel"
        );

        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Unexpected CREATED2 cell"
        );

        // Can't get a relay cell on a circuit we've never heard of.
        let relay_cell = msg::Relay::new(b"abc").into();
        input
            .send(Ok(ChanCell::new(4.into(), relay_cell)))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Relay cell on nonexistent circuit"
        );

        // Can't get handshaking cells while channel is open.
        let versions_cell = msg::Versions::new([3]).into();
        input
            .send(Ok(ChanCell::new(0.into(), versions_cell)))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: VERSIONS cell after handshake is done"
        );
    }
}
