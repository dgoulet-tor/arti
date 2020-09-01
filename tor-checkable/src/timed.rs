//! Convenience implementation of a TimeBound object.

use std::ops::RangeBounds;
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
pub struct TimerangeBound<T, U>
where
    U: RangeBounds<time::SystemTime>,
{
    obj: T,
    range: U,
}

impl<T, U> TimerangeBound<T, U>
where
    U: RangeBounds<time::SystemTime>,
{
    /// Construct a new TimerangeBound object from a given object and range.
    pub fn new(obj: T, range: U) -> Self {
        Self { obj, range }
    }
}

impl<T, U> crate::Timebound<T> for TimerangeBound<T, U>
where
    U: RangeBounds<time::SystemTime>,
{
    type Error = crate::TimeValidityError;

    fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error> {
        use crate::TimeValidityError;
        use std::ops::Bound::{self, *};

        fn unwrap_bound<'a, 'b>(
            b: &'a Bound<&'b time::SystemTime>,
        ) -> Option<&'b time::SystemTime> {
            match b {
                Included(x) => Some(x),
                Excluded(x) => Some(x),
                _ => None,
            }
        }

        if self.range.contains(t) {
            return Ok(());
        }

        if let Some(end) = unwrap_bound(&self.range.end_bound()) {
            if let Ok(d) = t.duration_since(*end) {
                return Err(TimeValidityError::Expired(d));
            }
        }
        if let Some(start) = unwrap_bound(&self.range.start_bound()) {
            if let Ok(d) = start.duration_since(*t) {
                return Err(TimeValidityError::NotYetValid(d));
            }
        }

        Err(TimeValidityError::Unspecified)
    }

    fn dangerously_assume_timely(self) -> T {
        self.obj
    }
}
