//! Helpers to implement retry-related functionality.
//!
//! Right now, this crate only has an error type that we use when we
//! retry something a few times, and they all fail.  Instead of
//! returning only a single error, it records _all of the errors
//! received, in case they are different.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! It's used by higher-level crates that retry
//! operations.
//!
//! ## Design notes
//!
//! XXXX We'll want to refactor this one.  It might be better in a
//! crate called retry-error or something, since it isn't
//! tor-specific.
//!
//! The [`RetryError`] type might be more generally useful in the
//! future, if it gets a stable interface, and if we can make it stop
//! depending on [`anyhow`].
//!
//! Maybe this error type should be parameterized on an input error type.
//!
//! # Example
//!
//! ```
//! # fn some_operation() -> Result<(),anyhow::Error> {Ok(())}
//! # fn demo() -> Result<(),tor_retry::RetryError> {
//! use tor_retry::RetryError;
//!
//! const N_ATTEMPTS: usize = 10;
//! let mut err = RetryError::while_doing("perform an example operation");
//! for _ in 0..N_ATTEMPTS {
//!     match some_operation() {
//!         Ok(val) => return Ok(val),
//!         Err(e) => err.push(e),
//!     }
//! }
//! // All attempts failed; return all the errors.
//! return Err(err)
//! # }
//! ```

#![deny(missing_docs)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

use std::error::Error;
use std::fmt::{Display, Error as FmtError, Formatter};

/// An error type for use when we're going to do something a few times,
/// and they might all fail.
///
/// To use this error type, initialize a new RetryError before you
/// start trying to do whatever it is.  Then, every time the operation
/// fails, use [`RetryError::push()`] to add a new error to the list
/// of errors.  If the operation fails too many times, you can use
/// RetryError as an [`Error`] itself.
#[derive(Debug, Default)]
pub struct RetryError {
    /// The operation we were trying to do.
    doing: &'static str,
    /// The errors that we encountered when doing the operation.
    // TODO: It might be nice to have this crate not depend on anyhow.
    // When I first tried to do that, though, I ran into a big pile of
    // type errors and gave up.
    errors: Vec<anyhow::Error>,
}

// TODO: Should we declare that some error is the 'source' of this one?
impl Error for RetryError {}

impl RetryError {
    /// Crate a new RetryError, with no failed attempts,
    ///
    /// The provided `doing` argument is a short string that describes
    /// what we were trying to do when we failed too many times.  It
    /// will be used to format the final error message; it should be a
    /// phrase that can go after "while trying to".
    ///
    /// This RetryError should not be used as-is, since when no
    /// [`Error`]s have been pushed into it, it doesn't represent an
    /// actual failure.
    pub fn while_doing(doing: &'static str) -> Self {
        RetryError {
            doing,
            errors: Vec::new(),
        }
    }
    /// Add an error to this RetryError.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    pub fn push<E>(&mut self, err: E)
    where
        E: Into<anyhow::Error>,
    {
        let e: anyhow::Error = err.into();
        self.errors.push(e);
    }
    /// Return an iterator over all of the reasons that the attempt
    /// behind this RetryError has failed.
    pub fn sources(&self) -> impl Iterator<Item = &anyhow::Error> {
        self.errors.iter()
    }
}

impl Display for RetryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self.errors.len() {
            0 => write!(
                f,
                "Programming error: somebody made a RetryError without any errors!"
            ),
            1 => self.errors[0].fmt(f),
            n => {
                writeln!(
                    f,
                    "Tried to {} {} times, but all attempts failed.",
                    self.doing, n
                )?;

                for (idx, e) in self.sources().enumerate() {
                    write!(f, "Attempt {}:\n{}\n", idx + 1, e)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bad_parse1() {
        let mut err = RetryError::while_doing("convert some things");
        if let Err(e) = "maybe".parse::<bool>() {
            err.push(e);
        }
        if let Err(e) = "a few".parse::<u32>() {
            err.push(e);
        }
        if let Err(e) = "teh_g1b50n".parse::<std::net::IpAddr>() {
            err.push(e);
        }
        let disp = format!("{}", err);
        assert_eq!(
            disp,
            "\
Tried to convert some things 3 times, but all attempts failed.
Attempt 1:
provided string was not `true` or `false`
Attempt 2:
invalid digit found in string
Attempt 3:
invalid IP address syntax
"
        );
    }

    #[test]
    fn no_problems() {
        let empty = RetryError::while_doing("immanentize the eschaton");
        let disp = format!("{}", empty);
        assert_eq!(
            disp,
            "Programming error: somebody made a RetryError without any errors!"
        );
    }

    #[test]
    fn one_problem() {
        let mut err = RetryError::while_doing("connect to torproject.org");
        if let Err(e) = "teh_g1b50n".parse::<std::net::IpAddr>() {
            err.push(e);
        }
        let disp = format!("{}", err);
        assert_eq!(disp, "invalid IP address syntax");
    }
}
