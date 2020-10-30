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

mod err;
#[cfg(test)]
mod testing;
pub mod transport;

use tor_linkspec::ChanTarget;
use tor_llcrypto::pk::ed25519::Ed25519Identity;

#[cfg(test)]
use testing::{FakeChannel as Channel, FakeChannelBuilder as ChannelBuilder};
#[cfg(not(test))]
use tor_proto::channel::{Channel, ChannelBuilder};

use futures::lock::Mutex;
use futures::task::{Spawn, SpawnExt};
use std::collections::HashMap;
use std::sync::Arc;

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
    /// The channel is open, authenticated, and canonical: we can give
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
        let mut builder = ChannelBuilder::new();
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

#[cfg(test)]
mod test {
    use super::*;

    use tor_llcrypto::pk::rsa::RSAIdentity;

    use async_trait::async_trait;
    use futures::executor::LocalPool;
    use futures::io::{AsyncRead, AsyncWrite};
    use futures::join;
    use futures::task::Context;
    use futures_await_test::async_test;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::Poll;

    struct FakeTransport;
    struct FakeConnection;

    #[async_trait]
    impl crate::transport::Transport for FakeTransport {
        type Connection = FakeConnection;
        async fn connect<T: ChanTarget + Sync>(
            &self,
            t: &T,
        ) -> Result<(std::net::SocketAddr, FakeConnection)> {
            let addr = t.addrs().get(0).unwrap();
            if addr.port() == 1337 {
                Err(Error::UnusableTarget("too leet!".into()))
            } else {
                Ok((*addr, FakeConnection))
            }
        }
    }

    impl crate::transport::CertifiedConn for FakeConnection {
        fn peer_cert(&self) -> Result<Option<Vec<u8>>> {
            Ok(Some(vec![]))
        }
    }
    impl AsyncRead for FakeConnection {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _buf: &mut [u8],
        ) -> Poll<std::result::Result<usize, std::io::Error>> {
            Poll::Ready(Ok(0))
        }
    }
    impl AsyncWrite for FakeConnection {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _buf: &[u8],
        ) -> Poll<std::result::Result<usize, std::io::Error>> {
            Poll::Ready(Ok(0))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Target {
        addr: [std::net::SocketAddr; 1],
        ed_id: Ed25519Identity,
        rsa_id: RSAIdentity,
    }
    impl ChanTarget for Target {
        fn addrs(&self) -> &[SocketAddr] {
            &self.addr[..]
        }
        fn ed_identity(&self) -> &Ed25519Identity {
            &self.ed_id
        }
        fn rsa_identity(&self) -> &RSAIdentity {
            &self.rsa_id
        }
    }

    #[async_test]
    async fn connect_one_ok() {
        let pool = LocalPool::new();
        let mgr = ChanMgr::new(FakeTransport, pool.spawner());
        let target = Target {
            addr: ["127.0.0.1:443".parse().unwrap()],
            ed_id: [3; 32].into(),
            rsa_id: [2; 20].into(),
        };
        let chan1 = mgr.get_or_launch(&target).await.unwrap();
        let chan2 = mgr.get_or_launch(&target).await.unwrap();

        assert!(chan1.same_channel(&chan2));

        {
            let channels = mgr.channels.lock().await;
            let entry = channels.get(&[3; 32].into());
            match entry {
                Some(ChannelState::Open(c)) => assert!(c.same_channel(&chan1)),
                _ => panic!(),
            }
        }

        let chan3 = mgr.get_nowait_by_ed_id(&[3; 32].into()).await;
        assert!(chan3.unwrap().same_channel(&chan1));
    }

    #[async_test]
    async fn connect_one_fail() {
        let pool = LocalPool::new();
        let mgr = ChanMgr::new(FakeTransport, pool.spawner());
        // port 1337 is set up to always fail in FakeTransport.
        let target = Target {
            addr: ["127.0.0.1:1337".parse().unwrap()],
            ed_id: [3; 32].into(),
            rsa_id: [2; 20].into(),
        };

        let res1 = mgr.get_or_launch(&target).await;
        assert!(matches!(res1, Err(Error::UnusableTarget(_))));

        // port 8686 is set up to always fail in FakeTransport.
        let target = Target {
            addr: ["127.0.0.1:8686".parse().unwrap()],
            ed_id: [4; 32].into(),
            rsa_id: [2; 20].into(),
        };

        let res1 = mgr.get_or_launch(&target).await;
        assert!(matches!(res1, Err(Error::ProtoError(_))));

        let chan3 = mgr.get_nowait_by_ed_id(&[4; 32].into()).await;
        assert!(chan3.is_none());
    }

    #[async_test]
    async fn test_concurrent() {
        let pool = LocalPool::new();
        let mgr = ChanMgr::new(FakeTransport, pool.spawner());
        let target3 = Target {
            addr: ["127.0.0.1:99".parse().unwrap()],
            ed_id: [3; 32].into(),
            rsa_id: [2; 20].into(),
        };
        let target44 = Target {
            addr: ["127.0.0.2:99".parse().unwrap()],
            ed_id: [44; 32].into(), // note different ed key.
            rsa_id: [2; 20].into(),
        };
        let target_bad = Target {
            addr: ["127.0.0.1:8686".parse().unwrap()],
            ed_id: [66; 32].into(),
            rsa_id: [2; 20].into(),
        };

        // TODO XXXX: figure out how to make these actually run
        // concurrently. Right now it seems that they don't actually
        // interact.
        let (ch3a, ch3b, ch44a, ch44b, ch86a, ch86b) = join!(
            mgr.get_or_launch(&target3),
            mgr.get_or_launch(&target3),
            mgr.get_or_launch(&target44),
            mgr.get_or_launch(&target44),
            mgr.get_or_launch(&target_bad),
            mgr.get_or_launch(&target_bad),
        );
        let ch3a = ch3a.unwrap();
        let ch3b = ch3b.unwrap();
        let ch44a = ch44a.unwrap();
        let ch44b = ch44b.unwrap();
        let err_a = ch86a.unwrap_err();
        let err_b = ch86b.unwrap_err();

        assert!(ch3a.same_channel(&ch3b));
        assert!(ch44a.same_channel(&ch44b));
        assert!(!ch3a.same_channel(&ch44b));

        assert!(matches!(err_a, Error::ProtoError(_)));
        assert!(matches!(err_b, Error::ProtoError(_)));
    }

    #[async_test]
    async fn test_stall() {
        use futures::FutureExt;

        let pool = LocalPool::new();
        let mgr = ChanMgr::new(FakeTransport, pool.spawner());
        let target = Target {
            addr: ["127.0.0.1:99".parse().unwrap()],
            ed_id: [12; 32].into(),
            rsa_id: [2; 20].into(),
        };

        {
            let mut channels = mgr.channels.lock().await;
            let e = Arc::new(event_listener::Event::new());
            let state = ChannelState::Building(Arc::clone(&e));
            channels.insert([12; 32].into(), state);
        }

        let h = mgr.get_or_launch(&target);

        assert!(h.now_or_never().is_none());
    }

    #[async_test]
    async fn connect_two_closing() {
        let pool = LocalPool::new();
        let mgr = ChanMgr::new(FakeTransport, pool.spawner());
        let target = Target {
            addr: ["127.0.0.1:443".parse().unwrap()],
            ed_id: [3; 32].into(),
            rsa_id: [2; 20].into(),
        };
        let chan1 = mgr.get_or_launch(&target).await.unwrap();
        chan1.mark_closing();
        let chan2 = mgr.get_or_launch(&target).await.unwrap();

        assert!(!chan1.same_channel(&chan2));
    }
}
