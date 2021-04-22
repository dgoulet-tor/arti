#![allow(unused)]
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::err::PendingChanError;
use crate::Result;
use crate::TargetInfo;

use async_trait::async_trait;
use futures::channel::oneshot;
use futures::future::{FutureExt, Shared};
use futures::task::Spawn;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_rtcompat::Runtime;

mod map;

pub(crate) trait AbstractChannel {
    type Ident: Hash + Eq + Clone;
    fn ident(&self) -> &Self::Ident;
    fn is_usable(&self) -> bool;
}

#[async_trait]
pub(crate) trait ChannelFactory {
    type Channel: AbstractChannel;
    type BuildSpec;

    async fn build_channel(
        &self,
        runtime: &(dyn Spawn + Sync),
        target: &Self::BuildSpec,
    ) -> Result<Arc<Self::Channel>>;
}

pub(crate) struct AbstractChannelMgr<RT: Runtime, CF: ChannelFactory> {
    /// Abstract runtime, used to launch tasks, create network
    /// connections via TCP and TLS, and run timeouts.
    runtime: RT,

    /// A 'connector' object that we use to create channels.
    connector: CF,

    /// A map from ed25519 identity to channel, or to pending channel status.
    channels: map::ChannelMap<CF::Channel>,
}

type PendResult<T> = std::result::Result<T, crate::err::PendingChanError>;

type Pending<C> = Shared<oneshot::Receiver<PendResult<Arc<C>>>>;
type Sending<C> = oneshot::Sender<PendResult<Arc<C>>>;

impl<RT: Runtime, CF: ChannelFactory> AbstractChannelMgr<RT, CF> {
    pub(crate) fn new(runtime: RT, connector: CF) -> Self {
        AbstractChannelMgr {
            runtime,
            connector,
            channels: map::ChannelMap::new(),
        }
    }

    pub fn remove_unusable_entries(&self) -> Result<()> {
        self.channels.remove_unusable()
    }

    fn setup_launch<C>(&self) -> (map::ChannelState<C>, Sending<C>) {
        let (snd, rcv) = oneshot::channel();
        let shared = rcv.shared();
        (map::ChannelState::Building(shared), snd)
    }

    pub async fn get_or_launch(
        &self,
        ident: <<CF as ChannelFactory>::Channel as AbstractChannel>::Ident,
        target: CF::BuildSpec,
    ) -> Result<Arc<CF::Channel>> {
        use map::ChannelState::*;
        enum Action<C> {
            Launch(Sending<C>),
            Wait(Pending<C>),
            Return(Arc<C>),
        }
        const N_ATTEMPTS: usize = 2;

        'retry: for _ in 0..N_ATTEMPTS {
            let action = self
                .channels
                .change_state(&ident, |oldstate| match oldstate {
                    Some(Open(ref ch)) => {
                        if ch.is_usable() {
                            let action = Action::Return(Arc::clone(ch));
                            (oldstate, action)
                        } else {
                            let (newstate, send) = self.setup_launch();
                            let action = Action::Launch(send);
                            (Some(newstate), action)
                        }
                    }
                    Some(Building(ref pending)) => {
                        let action = Action::Wait(pending.clone());
                        (oldstate, action)
                    }
                    Some(Poisoned(_)) => panic!(),
                    None => {
                        let (newstate, send) = self.setup_launch();
                        let action = Action::Launch(send);
                        (Some(newstate), action)
                    }
                })?;

            match action {
                Action::Return(v) => {
                    return Ok(v);
                }
                Action::Wait(pend) => match pend.await {
                    Ok(Ok(chan)) => return Ok(chan),
                    _ => continue 'retry,
                },
                Action::Launch(send) => {
                    match self.connector.build_channel(&self.runtime, &target).await {
                        Ok(chan) => {
                            self.channels
                                .replace(ident.clone(), Open(Arc::clone(&chan)))?;
                            send.send(Ok(Arc::clone(&chan)));
                            return Ok(chan);
                        }
                        Err(e) => {
                            self.channels.remove(&ident)?;
                            send.send(Err(e.into()));
                            continue 'retry;
                        }
                    }
                }
            }
        }

        Err(crate::Error::ChanTimeout) // not quite right. XXXX
    }
}
