//! Declare MockSleepRuntime.

use crate::time::MockSleepProvider;
use tor_rtcompat::{Runtime, SleepProvider, SpawnBlocking, TcpProvider, TlsProvider};

use async_trait::async_trait;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

/// A wrapper Runtime that overrides the SleepProvider trait for the
/// underlying runtime.
#[derive(Clone)]
pub struct MockSleepRuntime<R: Runtime> {
    /// The underlying runtime. Most calls get delegated here.
    runtime: R,
    /// A MockSleepProvider.  Time-related calls get delegated here.
    sleep: MockSleepProvider,
}

impl<R: Runtime> MockSleepRuntime<R> {
    /// Create a new runtime that wraps `runtime`, but overrides
    /// its view of time with a [`MockSleepProvider`].
    pub fn new(runtime: R) -> Self {
        let sleep = MockSleepProvider::new(SystemTime::now());
        MockSleepRuntime { runtime, sleep }
    }

    /// Return a reference to the underlying runtime.
    pub fn inner(&self) -> &R {
        &self.runtime
    }

    /// Return a reference to the [`MockSleepProvider`]
    pub fn mock_sleep(&self) -> &MockSleepProvider {
        &self.sleep
    }

    /// See [`MockSleepProvider::advance()`]
    pub async fn advance(&self, dur: Duration) {
        self.sleep.advance(dur).await;
    }
    /// See [`MockSleepProvider::jump_to()`]
    pub fn jump_to(&self, new_wallclock: SystemTime) {
        self.sleep.jump_to(new_wallclock);
    }
    /// Advance time one millisecond at a time until the provided
    /// future is ready.
    pub async fn wait_for<F: futures::Future>(&self, fut: F) -> F::Output {
        let (send, mut recv) = futures::channel::oneshot::channel();
        let increment = Duration::from_millis(1);

        let (output, _) = futures::join!(
            async {
                let o = fut.await;
                send.send(()).unwrap();
                o
            },
            async {
                loop {
                    self.advance(increment).await;
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
}

impl<R: Runtime> Spawn for MockSleepRuntime<R> {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        self.runtime.spawn_obj(future)
    }
}

impl<R: Runtime> SpawnBlocking for MockSleepRuntime<R> {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

#[async_trait]
impl<R: Runtime> TcpProvider for MockSleepRuntime<R> {
    type TcpStream = R::TcpStream;
    type TcpListener = R::TcpListener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
        self.runtime.connect(addr).await
    }
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        self.runtime.listen(addr).await
    }
}

impl<R: Runtime> TlsProvider for MockSleepRuntime<R> {
    type Connector = R::Connector;
    type TlsStream = R::TlsStream;
    fn tls_connector(&self) -> Self::Connector {
        self.runtime.tls_connector()
    }
}

impl<R: Runtime> SleepProvider for MockSleepRuntime<R> {
    type SleepFuture = crate::time::Sleeping;
    fn sleep(&self, dur: Duration) -> Self::SleepFuture {
        self.sleep.sleep(dur)
    }
    fn now(&self) -> Instant {
        self.sleep.now()
    }
    fn wallclock(&self) -> SystemTime {
        self.sleep.wallclock()
    }
}
