//! Manage a set of channels on the Tor network.
//!
//! In Tor, a Channel is a connection to a Tor relay.  It can be
//! direct via TLS, or indirect via TLS over a pluggable transport.
//! (For now, only direct channels are supported.)
//!
//! Since a channel can be used for more than one circuit, it's
//! important to reuse channels when possible.  This crate implements
//! a [ChanMgr] type that can be used to do that.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use tor_linkspec::ChanTarget;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_proto::channel::Channel;

use futures::lock::Mutex;
use futures::task::{Spawn, SpawnExt};
use std::collections::HashMap;
use std::sync::Arc;

mod err;
pub mod transport;

pub use err::Error;

/// A Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A Type that remembers a set of live channels, and launches new
/// ones on request.
///
/// Use the [ChanMgr::get_or_launch] function to craete a new channel, or
/// get one if it exists.
pub struct ChanMgr<TR> {
    /// Map from Ed25519 identity to channel state.
    ///
    /// Note that eventually we might want to have this be only
    /// _canonical_ connections (those whose address matches the
    /// relay's official address) and we might want this to be indexed
    /// by pluggable transport too. But since right now only
    /// client-initiated channels are supported, and pluggable
    /// transports are not supported, this structure is fine.
    ///
    /// Note that other Channels may exist that are not indexed here.
    channels: Mutex<HashMap<Ed25519Identity, ChannelState>>,

    /// Object used to launch channel reactors.
    spawn: Box<dyn Spawn>,

    /// Object used to create TLS connections to relays.
    transport: TR,
}

/// Possible states for a managed channel
enum ChannelState {
    /// The channel is open, autthenticated, and canonical: we can give
    /// it out as needed.
    Open(Channel),
    /// Some task is building the channel, and will notify all
    /// listeners on this event on success or failure.
    Building(Arc<event_listener::Event>),
}

impl<TR> ChanMgr<TR>
where
    TR: transport::Transport,
{
    /// Construct a new channel manager.  It will use `transport` to construct
    /// TLS streams, and `spawn` to launch reactor tasks.
    pub fn new<S: Spawn + 'static>(transport: TR, spawn: S) -> Self {
        ChanMgr {
            channels: Mutex::new(HashMap::new()),
            spawn: Box::new(spawn),
            transport,
        }
    }

    /// Helper: Return the channel if it matches the target; otherwise
    /// return an error.
    ///
    /// We need to do this check since it's theoretically possible for
    /// a channel to (for example) match the Ed25519 key of the
    /// target, but not the RSA key.
    async fn check_chan_match<T: ChanTarget>(&self, target: &T, ch: Channel) -> Result<Channel> {
        ch.check_match(target).await?;
        Ok(ch)
    }

    /// Try to get a suitable channel to the provided `target`,
    /// launching one if one does not exist.
    ///
    /// If there is already a channel launch attempt in progress, this
    /// function will wait until that launch is complete, and succeed
    /// or fail depending on its outcome.
    pub async fn get_or_launch<T: ChanTarget + Sync>(&self, target: &T) -> Result<Channel> {
        let ed_identity = target.ed_identity();
        use ChannelState::*;

        // Look up the current cache entry.
        let (should_launch, event) = {
            let mut channels = self.channels.lock().await;
            let state = channels.get(ed_identity);

            match state {
                Some(Open(ch)) => {
                    if ch.is_closing().await {
                        // duplicate with below. XXXXX
                        let e = Arc::new(event_listener::Event::new());
                        let state = Building(Arc::clone(&e));
                        channels.insert(*ed_identity, state);
                        (true, e)
                    } else {
                        return self.check_chan_match(target, ch.new_ref()).await;
                    }
                }
                Some(Building(e)) => (false, Arc::clone(e)),
                None => {
                    let e = Arc::new(event_listener::Event::new());
                    let state = Building(Arc::clone(&e));
                    channels.insert(*ed_identity, state);
                    (true, e)
                }
            }
        };

        if should_launch {
            // TODO: We might want to try again here if the pending channel
            // failed?
            let result = self.build_channel(target).await;
            {
                let mut channels = self.channels.lock().await;
                match &result {
                    Ok(ch) => {
                        channels.insert(*ed_identity, Open(ch.new_ref()));
                    }
                    Err(_) => {
                        channels.remove(ed_identity);
                    }
                }
            }
            event.notify(usize::MAX);
            result
        } else {
            // TODO: We might want to try again here if the pending channel
            // failed?
            event.listen().await;
            let chan = self
                .get_nowait_by_ed_id(ed_identity)
                .await
                .ok_or(Error::PendingFailed)?;
            self.check_chan_match(target, chan).await
        }
    }

    /// Helper: construct a new channel for a target
    async fn build_channel<T: ChanTarget + Sync>(&self, target: &T) -> Result<Channel> {
        use crate::transport::CertifiedConn;

        let (addr, tls) = self.transport.connect(target).await?;

        // XXXX wrong error
        let peer_cert = tls
            .peer_cert()?
            .ok_or_else(|| Error::UnusableTarget("No peer certificate!?".into()))?;
        let mut builder = tor_proto::channel::ChannelBuilder::new();
        builder.set_declared_addr(addr);
        let chan = builder.launch(tls).connect().await?;
        let chan = chan.check(target, &peer_cert)?;
        let (chan, reactor) = chan.finish().await?;

        self.spawn.spawn(async {
            let _ = reactor.run().await;
        })?;
        Ok(chan)
    }

    /// Helper: Get the Channel with the given Ed25519 identity, if there
    /// is one.
    async fn get_nowait_by_ed_id(&self, ed_id: &Ed25519Identity) -> Option<Channel> {
        use ChannelState::*;
        let channels = self.channels.lock().await;
        match channels.get(ed_id) {
            Some(Open(ch)) => Some(ch.new_ref()),
            _ => None,
        }
    }
}
