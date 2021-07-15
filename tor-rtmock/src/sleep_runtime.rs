//! Declare MockSleepRuntime.

use crate::time::MockSleepProvider;
use tor_rtcompat::{Runtime, SleepProvider, SpawnBlocking, TcpProvider, TlsProvider};

use async_trait::async_trait;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::Future;
use pin_project::pin_project;
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
    pub fn wait_for<F: futures::Future>(&self, fut: F) -> WaitFor<F> {
        WaitFor {
            sleep: self.sleep.clone(),
            yielding: false,
            fut,
        }
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

/// A future that advances time until another future is ready to complete.
#[pin_project]
pub struct WaitFor<F: Future> {
    /// A reference to the sleep provider that's simulating time for us.
    sleep: MockSleepProvider,
    /// True if we just found that this inner future is pending, and we
    /// should yield to give other futures a chance to run.
    yielding: bool,
    /// The future that we're waiting for.
    #[pin]
    fut: F,
}

use std::pin::Pin;
use std::task::{Context, Poll};

impl<F: Future> Future for WaitFor<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        if *this.yielding {
            *this.yielding = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Poll::Ready(r) = this.fut.poll(cx) {
            return Poll::Ready(r);
        }

        // TODO: This increment is unpleasantly short, and slows down
        // the tests that run this future.  But if I increase it, this
        // future doesn't yield enough for other futures to run, and
        // some of the tests in tor-circmgr give bad results.
        //
        // We should resolve this issue; see ticket #149.
        this.sleep.advance_noyield(Duration::from_micros(10));
        *this.yielding = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
