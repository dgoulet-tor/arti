/// Helper functions and types for use in parsing
///
/// For now this module has a single type -- an iterator that pauses
/// when a certain predicate is true.  We use it for chunking
/// documents into sections.  If it turns out to be useful somewhere
/// else, we should move it.
use std::iter::Peekable;

/// An iterator adaptor that pauses when a given predicate is true.
///
/// Unlike std::iter::TakeWhile, it doesn't consume the first non-returned
/// element.
pub struct PauseAt<I: Iterator, F: FnMut(&I::Item) -> bool> {
    peek: Peekable<I>,
    pred: F,
}

/// Trait for iterators that support `pause_at()`.
pub trait Pausable: Iterator + Sized {
    /// Construct a new iterator based on 'self' that will pause when
    /// the function 'pred' would be true of the next item.
    fn pause_at<F>(self, pred: F) -> PauseAt<Self, F>
    where
        F: FnMut(&Self::Item) -> bool;
}

// Make all iterators support `pause_at()`.
impl<I> Pausable for I
where
    I: Iterator,
{
    /// Construct a new iterator based on 'self' that will pause when
    /// predicate would be true of the next item.
    fn pause_at<F>(self, pred: F) -> PauseAt<Self, F>
    where
        F: FnMut(&Self::Item) -> bool,
    {
        PauseAt::from_iter(self, pred)
    }
}

impl<I: Iterator, F: FnMut(&I::Item) -> bool> PauseAt<I, F> {
    fn from_peekable(peek: Peekable<I>, pred: F) -> Self
    where
        F: FnMut(&I::Item) -> bool,
    {
        PauseAt { peek, pred }
    }
    fn from_iter(iter: I, pred: F) -> Self {
        Self::from_peekable(iter.peekable(), pred)
    }
    /// Replace the predicate on a PauseAt, returning a new PauseAt.
    pub fn new_pred<F2>(self, pred: F2) -> PauseAt<I, F2>
    where
        F2: FnMut(&I::Item) -> bool,
    {
        PauseAt::from_peekable(self.peek, pred)
    }
    /// Return an iterator for all the remaining elements of this PauseAt.
    pub fn remaining(self) -> Peekable<I> {
        self.peek
    }
}

impl<I: Iterator, F: FnMut(&I::Item) -> bool> Iterator for PauseAt<I, F> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(nextval) = self.peek.peek() {
            if (self.pred)(nextval) {
                None
            } else {
                self.peek.next()
            }
        } else {
            None
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
        use super::Pausable;
        let mut iter = (1..10).into_iter().pause_at(|x| *x == 3);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), None);

        let mut iter = iter.new_pred(|x| *x > 5);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.next(), None);

        let mut iter = iter.remaining();
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.next(), Some(7));
        assert_eq!(iter.next(), Some(8));
        assert_eq!(iter.next(), Some(9));
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
