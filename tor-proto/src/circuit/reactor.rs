//! Code to handle incoming cells on a circuit
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.
//!
//! TODO: perhaps this should share code with channel::reactor; perhaps
//! it should just not exist.

use super::streammap::StreamEnt;
use crate::circuit::{sendme, streammap};
use crate::crypto::cell::{HopNum, InboundClientCrypt, InboundClientLayer};
use crate::{Error, Result};
use tor_cell::chancell::{msg::ChanMsg, msg::Relay};
use tor_cell::relaycell::msg::{End, RelayMsg, Sendme};
use tor_cell::relaycell::{RelayCell, StreamID};

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::{self, StreamExt};

use std::sync::{Arc, Weak};

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
    CloseStream(HopNum, StreamID, sendme::StreamRecvWindow),
    /// Ask the reactor for a new stream ID, and allocate a circuit for it.
    AddStream(
        HopNum,
        mpsc::Sender<RelayMsg>,
        sendme::StreamSendWindow,
        oneshot::Sender<Result<StreamID>>,
    ),
    /// Tell the reactor to add a new hop to its view of the circuit, and
    /// then tell us when it has done so.
    AddHop(
        InboundHop,
        Box<dyn InboundClientLayer + Send>,
        oneshot::Sender<()>,
    ),
}

/// Type returned by a oneshot channel for a controlmsg.  For convenience,
/// we also use this as the type for the control mpsc channel, so we can
/// join them.
pub(super) type CtrlResult = std::result::Result<CtrlMsg, oneshot::Canceled>;

/// A stream to multiplex over a bunch of oneshot CtrlMsg replies.
///
/// We use oneshot channels to handle stream shutdowns, since oneshot
/// senders can be sent from within a non-async function.  We wrap
/// them in stream::Once so we can treat them as streams, and wrap
/// _those_ in a SelectAll so we can learn about them as they fire.
type OneshotStream = stream::SelectAll<stream::Once<oneshot::Receiver<CtrlMsg>>>;

/// Represents the reactor's view of a single hop.
pub(super) struct InboundHop {
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    map: streammap::StreamMap,
    /// Window used to say how many cells we can receive.
    recvwindow: sendme::CircRecvWindow,
}

impl InboundHop {
    /// Create a new hop.
    pub(super) fn new() -> Self {
        InboundHop {
            map: streammap::StreamMap::new(),
            recvwindow: sendme::CircRecvWindow::new(1000),
        }
    }
}

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
///
/// Why is this type separate, exactly?
struct ReactorCore {
    /// Reference to the circuit.
    circuit: Weak<Mutex<super::ClientCircImpl>>,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    ///
    /// We keep this separately from the state for outbound cells, since
    /// it is convenient for the reactor to be able to use this without
    /// locking the circuit.
    crypto_in: InboundClientCrypt,
    /// List of hops state objects used by the reactor
    hops: Vec<InboundHop>,
}

impl Reactor {
    /// Construct a new Reactor.
    pub(super) fn new(
        circuit: Arc<Mutex<super::ClientCircImpl>>,
        control: mpsc::Receiver<CtrlResult>,
        closeflag: oneshot::Receiver<CtrlMsg>,
        input: mpsc::Receiver<ChanMsg>,
    ) -> Self {
        let core = ReactorCore {
            circuit: Arc::downgrade(&circuit),
            crypto_in: InboundClientCrypt::new(),
            hops: Vec::new(),
        };

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
        if let Some(circ) = self.core.circuit.upgrade() {
            let circ = circ.lock().await;
            if circ.closed {
                return Err(Error::CircuitClosed);
            }
        } else {
            return Err(Error::CircuitClosed);
        }
        let result = self.run_impl().await;
        if let Some(circ) = self.core.circuit.upgrade() {
            let mut circ = circ.lock().await;
            circ.closed = true;
            if let Some(sender) = circ.sendmeta.take() {
                let _ignore_err = sender.send(Err(Error::CircuitClosed));
            }
        }
        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.
    async fn run_impl(&mut self) -> Result<()> {
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
            CtrlMsg::CloseStream(hop, id, recvwindow) => {
                self.close_stream(hop, id, recvwindow).await?
            }
            CtrlMsg::Register(ch) => self.register(ch),
            CtrlMsg::AddStream(hop, sink, window, sender) => {
                let hop = self.core.get_hop_mut(hop);
                if let Some(hop) = hop {
                    let r = hop.map.add_ent(sink, window);
                    // XXXX not sure if this is right to ignore
                    let _ignore = sender.send(r);
                }
                // If there was no hop with this index, dropping the sender
                // will cancel the attempt to add the stream.
            }
            CtrlMsg::AddHop(hop, layer, sender) => {
                self.core.hops.push(hop);
                self.core.crypto_in.add_layer(layer);
                // XXXX not sure if this is right to ignore
                let _ignore = sender.send(());
            }
        }
        Ok(())
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    async fn close_stream(
        &mut self,
        hopnum: HopNum,
        id: StreamID,
        window: sendme::StreamRecvWindow,
    ) -> Result<()> {
        // Mark the stream as closing.
        let hop = self.core.get_hop_mut(hopnum).ok_or_else(|| {
            Error::InternalError("Tried to close a stream on a hop that wasn't there?".into())
        })?;

        let should_send_end = hop.map.terminate(id, window)?;
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if should_send_end {
            let end_cell = RelayCell::new(id, End::new_misc().into());
            if let Some(circ) = self.core.circuit.upgrade() {
                let mut circ = circ.lock().await;
                circ.send_relay_cell(hopnum, false, end_cell).await?;
            } else {
                return Err(Error::CircuitClosed);
            }
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
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(&mut body)?;
        // Make a copy of the authentication tag. TODO: I'd rather not
        // copy it, but I don't see a way around it right now.
        let tag = {
            let mut tag_copy = [0u8; 20];
            // XXXX could crash if length changes.
            (&mut tag_copy).copy_from_slice(tag);
            tag_copy
        };
        // Decode the cell.
        let msg = RelayCell::decode(body.into())?;

        let c_t_w = sendme::cell_counts_towards_windows(&msg);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            // XXXX unwrap is yucky.
            match self.get_hop_mut(hopnum).unwrap().recvwindow.take() {
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
            if let Some(circ) = self.circuit.upgrade() {
                let mut circ = circ.lock().await;
                circ.send_relay_cell(hopnum, false, cell).await?;
            } else {
                return Err(Error::CircuitClosed);
            }
            self.get_hop_mut(hopnum).unwrap().recvwindow.put();
        }

        // Break the message apart into its streamID and message.
        let (streamid, msg) = msg.into_streamid_and_msg();

        // If this cell wants/refuses to have a Stream ID, does it
        // have/not have one?
        if !msg.cmd().accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                streamid,
                msg.cmd()
            )));
        }

        // If this has a reasonable streamID value of 0, it's a meta cell,
        // not meant for a particualr stream.
        if streamid.is_zero() {
            if let Some(circ) = self.circuit.upgrade() {
                let mut circ = circ.lock().await;
                return circ.handle_meta_cell(hopnum, msg).await;
            } else {
                return Err(Error::CircuitClosed);
            }
        }

        //XXXX this is still an unwrap, and still risky.
        let hop = self.get_hop_mut(hopnum).unwrap();
        match hop.map.get_mut(streamid) {
            Some(StreamEnt::Open(s, w, ref mut dropped)) => {
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
                let result = s.send(msg).await;
                if result.is_err() && c_t_w {
                    // the other side of the stream has gone away; remember
                    // that we received a cell that we couldn't queue for it.
                    *dropped += 1;
                }
                if end_cell {
                    hop.map.end_received(streamid)?;
                }
                Ok(())
            }
            Some(StreamEnt::EndSent(halfstream)) => {
                // We sent an end but maybe the other side hasn't heard.

                if matches!(msg, RelayMsg::End(_)) {
                    hop.map.end_received(streamid)
                } else {
                    halfstream.handle_msg(&msg).await
                }
            }
            _ => {
                // No stream wants this message.
                Err(Error::CircProto(
                    "Cell received on nonexistent stream!?".into(),
                ))
            }
        }
    }

    /// Helper: process a destroy cell.
    fn handle_destroy_cell(&mut self) -> Result<()> {
        // XXXX anything more to do here?
        Ok(())
    }

    /// Return the hop corresponding to `hopnum`, if there is one.
    fn get_hop_mut(&mut self, hopnum: HopNum) -> Option<&mut InboundHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }
}
