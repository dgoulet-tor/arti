/// Helper functions and types for use in parsing
use std::iter::Peekable;

/// An iterator adaptor that pauses when a given predicate is true.
///
/// Unlike std::iter::TakeWhile, it doesn't consume the first non-returned
/// element.
///
/// We guarantee that the predicate is called no more than once for
/// each item.
pub struct PauseAt<'a, I: Iterator, F: FnMut(&I::Item) -> bool> {
    peek: &'a mut Peekable<I>,
    pred: F,
    /// Memoized value of self.pred(self.peek()), so we never
    /// calculate it more than once.
    paused: Option<bool>,
}

impl<'a, I: Iterator, F: FnMut(&I::Item) -> bool> PauseAt<'a, I, F> {
    pub fn from_peekable(peek: &'a mut Peekable<I>, pred: F) -> Self
    where
        F: FnMut(&I::Item) -> bool,
    {
        PauseAt {
            peek,
            pred,
            paused: None,
        }
    }
    /// Replace the predicate on a PauseAt, returning a new PauseAt.
    pub fn new_pred<F2>(self, pred: F2) -> PauseAt<'a, I, F2>
    where
        F2: FnMut(&I::Item) -> bool,
    {
        PauseAt::from_peekable(self.peek, pred)
    }
    #[allow(unused)]
    pub fn remaining(self) -> &'a mut Peekable<I> {
        self.peek
    }
    /// Return the next item that will be yielded from this iterator, or
    /// None if this iterator is about to yield None.
    #[allow(unused)]
    pub fn peek(&mut self) -> Option<&I::Item> {
        // TODO: I wish it weren't necessary for this function to take
        // a mutable reference.
        if self.check_paused() {
            None
        } else {
            self.peek.peek()
        }
    }
    /// Helper: Return true if we will pause before the next element,
    /// and false otherwise.  Store the value in self.paused, so that
    /// we don't invoke self.pred more than once.
    fn check_paused(&mut self) -> bool {
        if let Some(p) = self.paused {
            return p;
        }
        if let Some(nextval) = self.peek.peek() {
            let p = (self.pred)(nextval);
            self.paused = Some(p);
            p
        } else {
            self.paused = Some(false);
            false
        }
    }
}

impl<'a, I: Iterator, F: FnMut(&I::Item) -> bool> Iterator for PauseAt<'a, I, F> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        if self.check_paused() {
            None
        } else {
            self.paused = None;
            self.peek.next()
        }
    }
}

/// Return the position of one string slice within another.
///
/// If `needle` is indeed part of `haystack`, returns some offset
/// `off`, such that `needle` is the same as
/// `&haystack[off..needle.len()]`.
///
/// Returns None if `needle` is not a part of `haystack`.
///
/// Remember, offsets are in bytes, not in characters.
///
/// # Example
/// ```ignore
/// use tor_netdoc::util::str_offset;
/// let quote = "A rose is a rose is a rose."; // -- Gertrude Stein
/// assert_eq!(&quote[2..6], "rose");
/// assert_eq!(str_offset(quote, &quote[2..6]).unwrap(), 2);
/// assert_eq!(&quote[12..16], "rose");
/// assert_eq!(str_offset(quote, &quote[12..16]).unwrap(), 12);
/// assert_eq!(&quote[22..26], "rose");
/// assert_eq!(str_offset(quote, &quote[22..26]).unwrap(), 22);
///
/// assert_eq!(str_offset(quote, "rose"), None);
///
/// assert_eq!(str_offset(&quote[1..], &quote[2..6]), Some(1));
/// assert_eq!(str_offset(&quote[1..5], &quote[2..6]), None);
/// ```
pub fn str_offset(haystack: &str, needle: &str) -> Option<usize> {
    let needle_start_u = needle.as_ptr() as usize;
    let needle_end_u = needle_start_u + needle.len();
    let haystack_start_u = haystack.as_ptr() as usize;
    let haystack_end_u = haystack_start_u + haystack.len();
    if haystack_start_u <= needle_start_u && needle_end_u <= haystack_end_u {
        Some(needle_start_u - haystack_start_u)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_pause_at() {
        use super::PauseAt;
        let mut iter = (1..10).into_iter().peekable();
        let mut iter = PauseAt::from_peekable(&mut iter, |x| *x == 3);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), None);

        let mut iter = iter.new_pred(|x| *x > 5);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);

        let iter = iter.remaining();
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.peek(), Some(&7));
        assert_eq!(iter.next(), Some(7));
        assert_eq!(iter.next(), Some(8));
        assert_eq!(iter.next(), Some(9));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_parse_at_mutable() {
        use super::PauseAt;
        let mut count = 0;
        let mut iter = (1..10).into_iter().peekable();
        // pause at the third item, using mutable state in the closure.
        let mut iter = PauseAt::from_peekable(&mut iter, |_| {
            count += 1;
            count == 4
        });
        assert_eq!(iter.peek(), Some(&1)); // we can do this multiple times,
        assert_eq!(iter.peek(), Some(&1)); // but count isn't advanced.
        assert_eq!(iter.next(), Some(1));

        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.peek(), Some(&3));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_str_offset() {
        use super::str_offset;
        let quote = "A rose is a rose is a rose."; // -- Gertrude Stein
        assert_eq!(&quote[2..6], "rose");
        assert_eq!(str_offset(quote, &quote[2..6]).unwrap(), 2);
        assert_eq!(&quote[12..16], "rose");
        assert_eq!(str_offset(quote, &quote[12..16]).unwrap(), 12);
        assert_eq!(&quote[22..26], "rose");
        assert_eq!(str_offset(quote, &quote[22..26]).unwrap(), 22);

        assert_eq!(str_offset(quote, "rose"), None);

        assert_eq!(str_offset(&quote[1..], &quote[2..6]), Some(1));
        assert_eq!(str_offset(&quote[1..5], &quote[2..6]), None);
    }
}
