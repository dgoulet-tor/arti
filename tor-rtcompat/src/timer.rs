//! Definitions for [`SleepProviderExt`] and related types.

use crate::traits::SleepProvider;
use futures::{Future, FutureExt};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

/// An error value given when a function times out.
///
/// This value is generated when the timeout from
/// [`SleepProviderExt::timeout`] expires before the provided future
/// is ready.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TimeoutError;
impl std::error::Error for TimeoutError {}
impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timeout expired")
    }
}

/// An extension trait on [`SleepProvider`] for timeouts and clock delays.
pub trait SleepProviderExt: SleepProvider {
    /// Wrap a [`Future`] with a timeout.
    ///
    /// The output of the new future will be the returned value of
    /// `future` if it completes within `duration`.  Otherwise, it
    /// will be `Err(TimeoutError)`.
    ///
    /// # Limitations
    ///
    /// This uses [`SleepProvider::sleep`] for its timer, and is
    /// subject to the same limitations.
    #[must_use = "timeout() returns a future, which does nothing unless used"]
    fn timeout<F: Future>(&self, duration: Duration, future: F) -> Timeout<F, Self::SleepFuture> {
        let sleep_future = self.sleep(duration);

        Timeout {
            future,
            sleep_future,
        }
    }

    /// Pause until the wall-clock is at `when` or later, trying to
    /// recover from clock jumps.
    ///
    /// Unlike [`SleepProvider::sleep()`], the future returned by this function will
    /// wake up periodically to check the current time, and see if
    /// it is at or past the target.
    ///
    /// # Limitations
    ///
    /// The ability of this function to detect clock jumps is limited
    /// to its granularity; it may finish a while after the declared
    /// wallclock time if the system clock jumps forward.
    ///
    /// This function does not detect backward clock jumps; arguably,
    /// we should have another function to do that.
    ///
    /// This uses [`SleepProvider::sleep`] for its timer, and is
    /// subject to the same limitations.
    #[must_use = "sleep_until_wallclock() returns a future, which does nothing unless used"]
    fn sleep_until_wallclock(&self, when: SystemTime) -> SleepUntilWallclock<'_, Self> {
        SleepUntilWallclock {
            provider: self,
            target: when,
            sleep_future: None,
        }
    }
}

impl<T: SleepProvider> SleepProviderExt for T {}

/// A timeout returned by [`SleepProviderExt::timeout`].
#[pin_project]
pub struct Timeout<T, S> {
    /// The future we want to execute.
    #[pin]
    future: T,
    /// The future implementing the timeout.
    #[pin]
    sleep_future: S,
}

impl<T, S> Future for Timeout<T, S>
where
    T: Future,
    S: Future<Output = ()>,
{
    type Output = Result<T::Output, TimeoutError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(x) = this.future.poll(cx) {
            return Poll::Ready(Ok(x));
        }

        match this.sleep_future.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(Err(TimeoutError)),
        }
    }
}

/// A future implementing [`SleepProviderExt::sleep_until_wallclock`].
pub struct SleepUntilWallclock<'a, SP: SleepProvider + ?Sized> {
    /// Reference to the provider that we use to make new SleepFutures.
    provider: &'a SP,
    /// The time that we are waiting for.
    target: SystemTime,
    /// The future representing our current delay.
    sleep_future: Option<Pin<Box<SP::SleepFuture>>>,
}

impl<'a, SP> Future for SleepUntilWallclock<'a, SP>
where
    SP: SleepProvider + ?Sized,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Strategy: we implement sleep_until_wallclock by
        // waiting in increments of up to MAX_SLEEP, checking the
        // wall clock before and after each increment.  This makes
        // us wake up a bit more frequently, but enables us to detect it
        // if the system clock jumps forward.
        let target = self.target;
        loop {
            let now = self.provider.wallclock();
            if now >= target {
                return Poll::Ready(());
            }

            let (last_delay, delay) = calc_next_delay(now, target);

            // Note that we store this future to keep it from being
            // cancelled, even though we don't ever poll it more than
            // once.
            //
            // TODO: I'm not sure that it's actually necessary to keep
            // this future around.
            self.sleep_future.take();

            let mut sleep_future = Box::pin(self.provider.sleep(delay));
            match sleep_future.poll_unpin(cx) {
                Poll::Pending => {
                    self.sleep_future = Some(sleep_future);
                    return Poll::Pending;
                }
                Poll::Ready(()) => {
                    if last_delay {
                        return Poll::Ready(());
                    }
                }
            }
        }
    }
}

/// We never sleep more than this much, in case our system clock jumps.
///
/// Note that there's a tradeoff here: Making this duration
/// shorter helps our accuracy, but makes us wake up more
/// frequently and consume more CPU.
const MAX_SLEEP: Duration = Duration::from_secs(600);

/// Return the amount of time we should wait next, when running
/// sleep_until_wallclock().  Also return a boolean indicating whether we
/// expect this to be the final delay.
///
/// (This is a separate function for testing.)
fn calc_next_delay(now: SystemTime, when: SystemTime) -> (bool, Duration) {
    let remainder = when
        .duration_since(now)
        .unwrap_or_else(|_| Duration::from_secs(0));
    if remainder > MAX_SLEEP {
        (false, MAX_SLEEP)
    } else {
        (true, remainder)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mock::time::MockSleepProvider;
    use crate::test_with_runtime;

    use futures::channel::oneshot;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn sleep_delay() {
        fn calc(now: SystemTime, when: SystemTime) -> Duration {
            calc_next_delay(now, when).1
        }
        let minute = Duration::from_secs(60);
        let second = Duration::from_secs(1);
        let start = SystemTime::now();

        let target = start + 30 * minute;

        assert_eq!(calc(start, target), minute * 10);
        assert_eq!(calc(target + minute, target), minute * 0);
        assert_eq!(calc(target, target), minute * 0);
        assert_eq!(calc(target - second, target), second);
        assert_eq!(calc(target - minute * 9, target), minute * 9);
        assert_eq!(calc(target - minute * 11, target), minute * 10);
    }

    #[test]
    fn timeouts() {
        fn setup() -> (
            MockSleepProvider,
            oneshot::Sender<()>,
            Timeout<oneshot::Receiver<()>, crate::mock::time::Sleeping>,
        ) {
            let start = SystemTime::now();
            let (send, recv) = oneshot::channel::<()>();
            let mock_sp = MockSleepProvider::new(start);
            let ten_min = Duration::new(10 * 60, 0);
            let timeout_future = mock_sp.timeout(ten_min, recv);
            (mock_sp, send, timeout_future)
        }

        // The timeout occurs.
        test_with_runtime(|_| async {
            let (mock_sp, _send, timeout_future) = setup();
            mock_sp.advance(Duration::new(3600, 0)).await;
            assert_eq!(timeout_future.await, Err(TimeoutError));
        });
        // The data is ready immediately.
        test_with_runtime(|_| async {
            let (_, send, timeout_future) = setup();
            send.send(()).unwrap();
            assert_eq!(timeout_future.await, Ok(Ok(())));
        });
        // The data is ready after a little while
        test_with_runtime(|_| async {
            let (mock_sp, send, timeout_future) = setup();
            mock_sp.advance(Duration::new(10, 0)).await;
            send.send(()).unwrap();
            assert_eq!(timeout_future.await, Ok(Ok(())));
        });
        // The data is ready _and_ the timout occurs.
        test_with_runtime(|_| async {
            let (mock_sp, send, timeout_future) = setup();
            send.send(()).unwrap();
            mock_sp.advance(Duration::new(3600, 0)).await;
            assert_eq!(timeout_future.await, Ok(Ok(())));
        });
        // Make sure that nothing happens too early.
        test_with_runtime(|_| async {
            let (mock_sp, _send, timeout_future) = setup();
            mock_sp.advance(Duration::new(300, 0)).await;
            assert_eq!(timeout_future.now_or_never(), None);
        });
    }

    fn start() -> SystemTime {
        // Yes this is a homestuck reference
        SystemTime::UNIX_EPOCH + Duration::from_secs(1239657180)
    }
    const ONE_DAY: Duration = Duration::from_secs(86400);

    #[test]
    fn wallclock_simple() {
        // Simple case: time goes by.
        test_with_runtime(|_| async {
            let mock_sp = MockSleepProvider::new(start());
            let b = AtomicBool::new(false);
            futures::join!(
                async {
                    mock_sp.sleep_until_wallclock(start() + ONE_DAY).await;
                    b.store(true, Ordering::SeqCst);
                },
                async {
                    while mock_sp.wallclock() < start() + ONE_DAY {
                        assert_eq!(false, b.load(Ordering::SeqCst));
                        mock_sp.advance(Duration::new(413, 0)).await;
                    }
                }
            );
            assert_eq!(true, b.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn wallclock_early() {
        // Simple case 2: time goes by, but not enough of it.
        test_with_runtime(|_| async {
            let mock_sp = MockSleepProvider::new(start());
            let b = AtomicBool::new(false);
            let (send, mut recv) = oneshot::channel();
            futures::join!(
                async {
                    let mut sleep = mock_sp.sleep_until_wallclock(start() + ONE_DAY).fuse();
                    futures::select! {
                        _ = sleep => b.store(true, Ordering::SeqCst),
                        _ = recv => (),
                    };
                },
                async {
                    while mock_sp.wallclock() < start() + (ONE_DAY / 2) {
                        assert_eq!(false, b.load(Ordering::SeqCst));
                        mock_sp.advance(Duration::new(413, 0)).await;
                    }
                    send.send(()).unwrap();
                }
            );
            assert_eq!(false, b.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn wallclock_jump_forward() {
        // Clock jumps forward, so event triggers.
        test_with_runtime(|_| async {
            let mock_sp = MockSleepProvider::new(start());
            let b = AtomicBool::new(false);
            let i1 = mock_sp.now();
            futures::join!(
                async {
                    mock_sp.sleep_until_wallclock(start() + ONE_DAY).await;
                    b.store(true, Ordering::SeqCst);
                },
                async {
                    mock_sp.jump_to(start() + ONE_DAY);
                    mock_sp.advance(MAX_SLEEP).await; // have to rest some.
                }
            );
            assert_eq!(true, b.load(Ordering::SeqCst));
            let i2 = mock_sp.now();
            assert!(i2 - i1 < ONE_DAY);
        });
    }

    #[test]
    fn wallclock_jump_backwards() {
        // Clock jumps backward, so event does not trigger early.
        test_with_runtime(|_| async {
            let mock_sp = MockSleepProvider::new(start());
            let b = AtomicBool::new(false);
            let (send, mut recv) = oneshot::channel();
            let i1 = mock_sp.now();
            futures::join!(
                async {
                    let mut sleep = mock_sp.sleep_until_wallclock(start() + ONE_DAY).fuse();
                    futures::select! {
                        _ = sleep => b.store(true, Ordering::SeqCst),
                        _ = recv => (),
                    };
                },
                async {
                    mock_sp.jump_to(start() - ONE_DAY);
                    let mut elapsed = Duration::new(0, 0);
                    while elapsed < (3 * ONE_DAY) / 2 {
                        assert_eq!(false, b.load(Ordering::SeqCst));
                        mock_sp.advance(Duration::new(413, 0)).await;
                        elapsed += Duration::new(413, 0);
                    }
                    send.send(()).unwrap();
                }
            );
            assert_eq!(false, b.load(Ordering::SeqCst));
            let i2 = mock_sp.now();
            assert!(i2 - i1 > ONE_DAY);
            assert!(mock_sp.wallclock() < start() + ONE_DAY);
        });
    }
}
