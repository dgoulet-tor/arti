//! Code to handle incoming cells on a circuit
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.
//!
//! TODO: perhaps this should share code with channel::reactor; perhaps
//! it should just not exist.

use super::streammap::StreamEnt;
use crate::chancell::{msg::ChanMsg, msg::Relay};
use crate::circuit::ClientCirc;
use crate::crypto::cell::HopNum;
use crate::relaycell::msg::{End, RelayCell, RelayMsg, Sendme};
use crate::relaycell::StreamID;
use crate::{Error, Result};

use futures::channel::{mpsc, oneshot};
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::{self, StreamExt};

/// A message telling the reactor to do something.
pub(super) enum CtrlMsg {
    /// Shut down the reactor.
    Shutdown,
    /// Register a new one-shot receiver that can send a CtrlMsg to the
    /// reactor.
    ///
    /// IMPORTANT: we can't just let everybody use the mpsc control stream,
    /// since we need to be able to send messages to the reactor from drop().
    /// One-shot senders can be activated synchronously, but mpsc senders
    /// require the sender to .await.
    Register(oneshot::Receiver<CtrlMsg>),
    /// Tell the reactor that a given stream has gone away.
    CloseStream(HopNum, StreamID),
}

/// Type returned by a oneshot channel for a ctonrolmsg.  For convenience,
/// we also use this as the type for the control mpsc channel, so we can
/// join them.
pub(super) type CtrlResult = std::result::Result<CtrlMsg, oneshot::Canceled>;

type OneshotStream = stream::SelectAll<stream::Once<oneshot::Receiver<CtrlMsg>>>;

/// Object to handle incoming cells on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// A stream of oneshot receivers that tell this reactor about things it
    /// needs to handle, like closed streams.
    //
    // The actual type here is quite ugly! Is there a better way?
    //
    // See documentation of CtrlMsg and CtrlResult for info about why
    // we're using this ugly type.
    control: stream::Fuse<stream::Select<mpsc::Receiver<CtrlResult>, OneshotStream>>,

    /// Input Stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: stream::Fuse<mpsc::Receiver<ChanMsg>>,
    /// The main implementation of the reactor.
    core: ReactorCore,
}

/// This is a separate; we use it when handling cells.
struct ReactorCore {
    /// Reference to the circuit.
    circuit: ClientCirc,
}

impl Reactor {
    /// Construct a new Reactor.
    pub(super) fn new(
        circuit: ClientCirc,
        control: mpsc::Receiver<CtrlResult>,
        closeflag: oneshot::Receiver<CtrlMsg>,
        input: mpsc::Receiver<ChanMsg>,
    ) -> Self {
        let core = ReactorCore { circuit };

        let mut oneshots = stream::SelectAll::new();
        oneshots.push(stream::once(closeflag));
        let control = stream::select(control, oneshots);
        Reactor {
            input: input.fuse(),
            control: control.fuse(),
            core,
        }
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    pub async fn run(mut self) -> Result<()> {
        loop {
            // What's next to do?
            let item = select_biased! {
                // Got a control message!
                ctrl = self.control.next() => {
                    match ctrl {
                        Some(Ok(CtrlMsg::Shutdown)) => return Ok(()),
                        Some(Ok(msg)) => self.handle_control(msg).await?,
                        Some(Err(_)) => (), // sender was cancelled; ignore.
                        None => panic!(), // impossible, right? XXXX
                    }
                    continue;
                }
                // we got a message on our channel, or it closed.
                item = self.input.next() => item,
            };
            let item = match item {
                // the channel closed; we're done.
                None => return Ok(()),
                // we got a ChanMsg!
                Some(r) => r,
            };

            let exit = self.core.handle_cell(item).await?;
            if exit {
                // XXXX does this really shutdown?
                return Ok(());
            }
        }
    }

    /// Handle a CtrlMsg other than Shutdown.
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        match msg {
            CtrlMsg::Shutdown => panic!(), // was handled in reactor loop.
            CtrlMsg::CloseStream(hop, id) => self.close_stream(hop, id).await?,
            CtrlMsg::Register(ch) => self.register(ch),
        }
        Ok(())
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    async fn close_stream(&mut self, hopnum: HopNum, id: StreamID) -> Result<()> {
        // Mark the stream as closing.
        let mut circ = self.core.circuit.c.lock().await;
        let hop = &mut circ.hops[Into::<usize>::into(hopnum)];
        let should_send_end = hop.map.remove(id);
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if should_send_end {
            let end_cell = RelayCell::new(id, End::new_misc().into());
            circ.send_relay_cell(hopnum, false, end_cell).await?;
        }
        Ok(())
    }

    /// Ensure that we get a message on self.control when `ch` fires.
    fn register(&mut self, ch: oneshot::Receiver<CtrlMsg>) {
        let (_, select_all) = self.control.get_mut().get_mut();
        select_all.push(stream::once(ch));
    }
}

impl ReactorCore {
    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return true if we should exit.
    async fn handle_cell(&mut self, cell: ChanMsg) -> Result<bool> {
        use ChanMsg::*;
        match cell {
            Relay(r) | RelayEarly(r) => {
                self.handle_relay_cell(r).await?;
                Ok(false)
            }
            Destroy(_) => {
                self.handle_destroy_cell()?;
                Ok(true)
            }
            // TODO: It would be better for this channel to instead
            // carry only good cell types.
            _ => Err(Error::InternalError(
                "Unsupported cell type on circuit.".into(),
            )),
        }
    }

    /// React to a Relay or RelayEarly cell.
    async fn handle_relay_cell(&mut self, cell: Relay) -> Result<()> {
        let mut body = cell.into_relay_body();
        // XXX I don't like locking the whole circuit
        let mut circ = self.circuit.c.lock().await;

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = circ.crypto.decrypt(&mut body)?;
        // Make a copy of the authentication tag. TODO: I'd rather not
        // copy it, but I don't see a way around it right now.
        let tag = {
            let mut tag_copy = [0u8; 20];
            // XXXX could crash if length changes.
            (&mut tag_copy).copy_from_slice(tag);
            tag_copy
        };
        // Decode the cell.
        let msg = RelayCell::decode(body)?;

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if msg.counts_towards_circuit_windows() {
            // XXXX unwrap is yucky.
            match circ.get_hop_mut(hopnum).unwrap().recvwindow.take() {
                Some(true) => true,
                Some(false) => false,
                None => {
                    return Err(Error::CircProto(
                        "received a cell when circuit sendme window was empty.".into(),
                    ))
                }
            }
        } else {
            false
        };
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            let sendme = Sendme::new_tag(tag);
            let cell = RelayCell::new(0.into(), sendme.into());
            circ.send_relay_cell(hopnum, false, cell).await?;
            circ.get_hop_mut(hopnum).unwrap().recvwindow.put();
        }

        // Break the message apart into its streamID and message.
        let (streamid, msg) = msg.into_streamid_and_msg();

        // If this cell wants/refuses to have a Stream ID, does it
        // have/not have one?
        if !msg.get_cmd().accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                streamid,
                msg.get_cmd()
            )));
        }

        // If this has a reasonable streamID value of 0, it's a meta cell,
        // not meant for a particualr stream.
        if streamid.is_zero() {
            return circ.handle_meta_cell(hopnum, msg).await;
        }

        //XXXX this is still an unwrap, and still risky.
        let hop = circ.get_hop_mut(hopnum).unwrap();
        if let Some(StreamEnt::Open(s, w)) = hop.map.get_mut(streamid) {
            // The stream for this message exists, and is open.

            if let RelayMsg::Sendme(_) = msg {
                // We need to handle sendmes here, not in the stream's
                // recv() method, or else we'd never notice them if the
                // stream isn't reading.
                w.put(Some(())).await;
                return Ok(());
            }

            // Remember whether this was an end cell: if so we should
            // close the stream.
            let end_cell = matches!(msg, RelayMsg::End(_));

            // XXXX handle errors better. Does this one mean that the
            // the stream is closed?

            // XXXX reject cells that should never go to a client,
            // XXXX like BEGIN.

            // XXXXXXXXXXXXXXXXXXXXX
            // XXXXX If possible we should try to stop holding the mutex
            // XXXXX for this:
            // XXXXX This send() operation can deadlock if the queue
            // XXXXX is full and the other side is trying to send a sendme.
            // XXXXX That's why I've chosen a really high queue length.
            // XXXXX I should fix that.
            let result = s
                .send(msg)
                .await
                // XXXX I think this shouldn't be possible?
                .map_err(|_| Error::InternalError("Can't queue cell for open stream?".into()));
            if end_cell {
                hop.map.mark_closing(streamid);
            }
            result
        } else {
            // No stream wants this message.

            // XXXX what do we do with unrecognized cells?
            Ok(())
        }
    }

    /// Helper: process a destroy cell.
    fn handle_destroy_cell(&mut self) -> Result<()> {
        // XXXX anything more to do here?
        Ok(())
    }
}
