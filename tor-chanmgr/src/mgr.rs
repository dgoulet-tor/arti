#![allow(dead_code)]
use crate::err::PendingChanError;
use crate::{Error, Result};

use async_trait::async_trait;
use futures::channel::oneshot;
use futures::future::{FutureExt, Shared};
use std::hash::Hash;
use std::sync::Arc;

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

    async fn build_channel(&self, target: &Self::BuildSpec) -> Result<Arc<Self::Channel>>;
}

pub(crate) struct AbstractChannelMgr<CF: ChannelFactory> {
    /// A 'connector' object that we use to create channels.
    connector: CF,

    /// A map from ed25519 identity to channel, or to pending channel status.
    channels: map::ChannelMap<CF::Channel>,
}

type PendResult<T> = std::result::Result<T, PendingChanError>;

type Pending<C> = Shared<oneshot::Receiver<PendResult<Arc<C>>>>;
type Sending<C> = oneshot::Sender<PendResult<Arc<C>>>;

impl<CF: ChannelFactory> AbstractChannelMgr<CF> {
    pub(crate) fn new(connector: CF) -> Self {
        AbstractChannelMgr {
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

        // XXXX It would be neat to use tor_retry instead, but it's
        // too tied to anyhow right now.
        let mut last_err = Err(Error::Internal("Error was never set!?"));

        for _ in 0..N_ATTEMPTS {
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
                    Ok(Err(e)) => {
                        last_err = Err(e.into());
                    }
                    Err(_) => {
                        last_err = Err(Error::Internal("channel build task disappeared"));
                    }
                },
                Action::Launch(send) => match self.connector.build_channel(&target).await {
                    Ok(chan) => {
                        self.channels
                            .replace(ident.clone(), Open(Arc::clone(&chan)))?;
                        // It's okay if all the receivers went away:
                        // that means that nobody was waiting for this channel.
                        let _ignore_err = send.send(Ok(Arc::clone(&chan)));
                        return Ok(chan);
                    }
                    Err(e) => {
                        self.channels.remove(&ident)?;
                        // (As above)
                        let _ignore_err = send.send(Err((&e).into()));
                        last_err = Err(e);
                    }
                },
            }
        }

        last_err
    }

    #[cfg(test)]
    pub fn get_nowait(
        &self,
        ident: &<<CF as ChannelFactory>::Channel as AbstractChannel>::Ident,
    ) -> Option<Arc<CF::Channel>> {
        use map::ChannelState::*;
        match self.channels.get(ident) {
            Ok(Some(Open(ref ch))) if ch.is_usable() => Some(Arc::clone(ch)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;

    use futures::join;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tor_rtcompat::{task::yield_now, test_with_runtime, Runtime};

    struct FakeChannelFactory<RT> {
        runtime: RT,
    }

    #[derive(Debug)]
    struct FakeChannel {
        ident: u32,
        mood: char,
        closing: AtomicBool,
    }

    impl AbstractChannel for FakeChannel {
        type Ident = u32;
        fn ident(&self) -> &u32 {
            &self.ident
        }
        fn is_usable(&self) -> bool {
            !self.closing.load(Ordering::SeqCst)
        }
    }

    impl FakeChannel {
        fn start_closing(&self) {
            self.closing.store(true, Ordering::SeqCst);
        }
    }

    impl<RT: Runtime> FakeChannelFactory<RT> {
        fn new(runtime: RT) -> Self {
            FakeChannelFactory { runtime }
        }
    }

    #[async_trait]
    impl<RT: Runtime> ChannelFactory for FakeChannelFactory<RT> {
        type Channel = FakeChannel;
        type BuildSpec = (u32, char);

        async fn build_channel(&self, target: &Self::BuildSpec) -> Result<Arc<FakeChannel>> {
            yield_now().await;
            let (ident, mood) = *target;
            match mood {
                // "X" means never connect.
                '❌' | '🔥' => return Err(Error::UnusableTarget("emoji".into())),
                // "zzz" means wait for 15 seconds then succeed.
                '💤' => {
                    self.runtime.sleep(Duration::new(15, 0)).await;
                }
                _ => {}
            }
            Ok(Arc::new(FakeChannel {
                ident,
                mood,
                closing: AtomicBool::new(false),
            }))
        }
    }

    #[test]
    fn connect_one_ok() {
        test_with_runtime(|runtime| async {
            let cf = FakeChannelFactory::new(runtime);
            let mgr = AbstractChannelMgr::new(cf);
            let target = (413, '!');
            let chan1 = mgr.get_or_launch(413, target.clone()).await.unwrap();
            let chan2 = mgr.get_or_launch(413, target.clone()).await.unwrap();

            assert!(Arc::ptr_eq(&chan1, &chan2));

            let chan3 = mgr.get_nowait(&413).unwrap();
            assert!(Arc::ptr_eq(&chan1, &chan3));
        });
    }

    #[test]
    fn connect_one_fail() {
        test_with_runtime(|runtime| async {
            let cf = FakeChannelFactory::new(runtime);
            let mgr = AbstractChannelMgr::new(cf);

            // This is set up to always fail.
            let target = (999, '❌');
            let res1 = mgr.get_or_launch(999, target).await;
            dbg!(&res1);
            assert!(matches!(res1, Err(Error::UnusableTarget(_))));

            let chan3 = mgr.get_nowait(&999);
            assert!(chan3.is_none());
        });
    }

    #[test]
    fn test_concurrent() {
        test_with_runtime(|runtime| async {
            let cf = FakeChannelFactory::new(runtime);
            let mgr = AbstractChannelMgr::new(cf);

            // TODO XXXX: figure out how to make these actually run
            // concurrently. Right now it seems that they don't actually
            // interact.
            let (ch3a, ch3b, ch44a, ch44b, ch86a, ch86b) = join!(
                mgr.get_or_launch(3, (3, 'a')),
                mgr.get_or_launch(3, (3, 'b')),
                mgr.get_or_launch(44, (44, 'a')),
                mgr.get_or_launch(44, (44, 'b')),
                mgr.get_or_launch(86, (86, '❌')),
                mgr.get_or_launch(86, (86, '🔥')),
            );
            let ch3a = ch3a.unwrap();
            let ch3b = ch3b.unwrap();
            let ch44a = ch44a.unwrap();
            let ch44b = ch44b.unwrap();
            let err_a = ch86a.unwrap_err();
            let err_b = ch86b.unwrap_err();

            assert!(Arc::ptr_eq(&ch3a, &ch3b));
            assert!(Arc::ptr_eq(&ch44a, &ch44b));
            assert!(!Arc::ptr_eq(&ch44a, &ch3a));

            assert!(matches!(
                err_a,
                Error::UnusableTarget(_) | Error::PendingChanFailed(_)
            ));
            assert!(matches!(
                err_b,
                Error::UnusableTarget(_) | Error::PendingChanFailed(_)
            ));
        });
    }

    #[test]
    fn unusable_entries() {
        test_with_runtime(|runtime| async {
            let cf = FakeChannelFactory::new(runtime);
            let mgr = AbstractChannelMgr::new(cf);

            let (ch3, ch4, ch5) = join!(
                mgr.get_or_launch(3, (3, 'a')),
                mgr.get_or_launch(4, (4, 'a')),
                mgr.get_or_launch(5, (5, 'a')),
            );

            let ch3 = ch3.unwrap();
            let _ch4 = ch4.unwrap();
            let ch5 = ch5.unwrap();

            ch3.start_closing();
            ch5.start_closing();

            let ch3_new = mgr.get_or_launch(3, (3, 'b')).await.unwrap();
            assert!(!Arc::ptr_eq(&ch3, &ch3_new));
            assert_eq!(ch3_new.mood, 'b');

            mgr.remove_unusable_entries().unwrap();

            assert!(mgr.get_nowait(&3).is_some());
            assert!(mgr.get_nowait(&4).is_some());
            assert!(mgr.get_nowait(&5).is_none());
        })
    }
}
