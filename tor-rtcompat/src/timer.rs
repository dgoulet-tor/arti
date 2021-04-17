use crate::traits::SleepProvider;
use async_trait::async_trait;
use futures::Future;
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

#[derive(Copy, Clone, Debug)]
pub struct TimeoutError;
impl std::error::Error for TimeoutError {}
impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timeout expired")
    }
}

#[async_trait]
pub trait SleepProviderExt: SleepProvider {
    fn timeout<F: Future>(&self, duration: Duration, future: F) -> Timeout<F, Self::SleepFuture> {
        let sleep_future = self.sleep(duration);

        Timeout {
            future,
            sleep_future,
        }
    }

    /// Pause until the wall-clock is at `when` or later, trying to
    /// recover from clock jumps.
    async fn sleep_until_wallclock(&self, when: SystemTime) {
        loop {
            let now = SystemTime::now();
            if now >= when {
                return;
            }
            let delay = calc_next_delay(now, when);
            self.sleep(delay).await;
        }
    }
}

impl<T: SleepProvider> SleepProviderExt for T {}

#[pin_project]
pub struct Timeout<T, S> {
    #[pin]
    future: T,
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

/// Return the amount of time we should wait next, when running
/// sleep_until_wallclock().
///
/// (This is a separate function for testing.)
fn calc_next_delay(now: SystemTime, when: SystemTime) -> Duration {
    /// We never sleep more than this much, in case our system clock jumps
    const MAX_SLEEP: Duration = Duration::from_secs(600);
    let remainder = when
        .duration_since(now)
        .unwrap_or_else(|_| Duration::from_secs(0));
    std::cmp::min(MAX_SLEEP, remainder)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn sleep_delay() {
        use calc_next_delay as calc;
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
}
