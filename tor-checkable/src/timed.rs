//! Convenience implementation of a TimeBound object.

use std::ops::{Bound, RangeBounds};
use std::time;

/// A TimeBound object that is valid for a specified range of time.
///
/// The range is given as an argument, as in `t1..t2`.
///
///
/// ```
/// use std::time::{SystemTime, Duration};
/// use tor_checkable::{Timebound, TimeValidityError, timed::TimerangeBound};
///
/// let now = SystemTime::now();
/// let one_hour = Duration::new(3600, 0);
///
/// // This seven is only valid for another hour!
/// let seven = TimerangeBound::new(7u32, ..now+one_hour);
///
/// assert_eq!(seven.check_valid_at(&now).unwrap(), 7);
///
/// // That consumed the previous seven. Try another one.
/// let seven = TimerangeBound::new(7u32, ..now+one_hour);
/// assert_eq!(seven.check_valid_at(&(now+2*one_hour)),
///            Err(TimeValidityError::Expired(one_hour)));
///
/// ```
pub struct TimerangeBound<T> {
    obj: T,
    start: Option<time::SystemTime>,
    end: Option<time::SystemTime>,
}

fn unwrap_bound(b: Bound<&'_ time::SystemTime>) -> Option<time::SystemTime> {
    match b {
        Bound::Included(x) => Some(*x),
        Bound::Excluded(x) => Some(*x),
        _ => None,
    }
}

impl<T> TimerangeBound<T> {
    /// Construct a new TimerangeBound object from a given object and range.
    ///
    /// Note that we do not distinguish between inclusive and
    /// exclusive bounds: `x..y` and `x..=y` are treated the same
    /// here.
    pub fn new<U>(obj: T, range: U) -> Self
    where
        U: RangeBounds<time::SystemTime>,
    {
        let start = unwrap_bound(range.start_bound());
        let end = unwrap_bound(range.end_bound());
        Self { obj, start, end }
    }

    /// Adjust this time-range bound to tolerate an expiration time farther
    /// in the future.
    pub fn extend_tolerance(self, d: time::Duration) -> Self {
        let end = self.end.map(|t| t + d);
        Self { end, ..self }
    }
    /// Adjust this time-range bound to tolerate an initial validity
    /// time farther in the past.
    pub fn extend_pre_tolerance(self, d: time::Duration) -> Self {
        let start = self.start.map(|t| t - d);
        Self { start, ..self }
    }
}

impl<T> crate::Timebound<T> for TimerangeBound<T> {
    type Error = crate::TimeValidityError;

    fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error> {
        use crate::TimeValidityError;
        if let Some(start) = self.start {
            if let Ok(d) = start.duration_since(*t) {
                return Err(TimeValidityError::NotYetValid(d));
            }
        }

        if let Some(end) = self.end {
            if let Ok(d) = t.duration_since(end) {
                return Err(TimeValidityError::Expired(d));
            }
        }

        Ok(())
    }

    fn dangerously_assume_timely(self) -> T {
        self.obj
    }
}
