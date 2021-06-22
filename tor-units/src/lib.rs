//! `tor-units` -- Safe wrappers for primitive numeric types.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! It provides safe wrappers for primitive numeric wrappers used in
//! other parts of Arti.
//! In particular, it provides:
//!   * a bounded i32 with both checked and clamping constructors,
//!   * an integer milliseconds wrapper with conversion to [`Duration`]
//!   * a percentage wrapper, to prevent accidental failure
//!     to divide by 100.
//!   * a SendMeVersion which can be compared only.

#![deny(missing_docs)]
#![warn(noop_method_call)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

use derive_more::{Add, Display, Div, From, FromStr, Mul};

use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use thiserror::Error;

/// Conversion errors from converting a value into a [`BoundedInt32`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A passed value was below the lower bound for the type.
    #[error("Value {0} was below the lower bound {1} for this type.")]
    BelowLowerBound(i32, i32),
    /// A passed value was above the upper bound for the type.
    #[error("Value {0} was above the lower bound {1} for this type.")]
    AboveUpperBound(i32, i32),
    /// Tried to parse a value that was not representable as the
    /// underlying type.
    #[error("Value could not be represented as an i32")]
    Unrepresentable,
    /// Tried to instantiate an uninhabited type.
    #[error("No value is valid for this type")]
    Uninhabited,
}

/// A 32-bit signed integer with a restricted range.
///
/// This type holds an i32 value such that `LOWER` <= value <= `UPPER`
///
/// # Limitations
///
/// If you try to instantiate this type with LOWER > UPPER, you will
/// get an uninhabitable type.  It would be better if we could check that at
/// compile time, and prevent such types from being named.
//
// [TODO: If you need a Bounded* for some type other than i32, ask nickm:
// he has an implementation kicking around.]
#[derive(Debug, Clone, Copy)]
pub struct BoundedInt32<const LOWER: i32, const UPPER: i32> {
    /// Interior Value
    value: i32,
}

impl<const LOWER: i32, const UPPER: i32> BoundedInt32<LOWER, UPPER> {
    /// Lower bound
    pub const LOWER: i32 = LOWER;
    /// Upper bound
    pub const UPPER: i32 = UPPER;

    /// Private constructor function for this type.
    fn unchecked_new(value: i32) -> Self {
        assert!(LOWER <= UPPER); //The compiler optimises this out, no run-time cost.

        BoundedInt32 { value }
    }

    /// Return the underlying i32 value.
    ///
    /// This value will always be between [`Self::LOWER`] and [`Self::UPPER`],
    /// inclusive.
    pub fn get(&self) -> i32 {
        self.value
    }

    /// If `val` is within range, return a new `BoundedInt32` wrapping
    /// it; othwerwise, clamp it to the upper or lower bound as
    /// appropriate.
    pub fn saturating_new(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }

    /// If `val` is an acceptable value inside the range for this type,
    /// return a new [`BoundedInt32`].  Otherwise return an error.
    pub fn checked_new(val: i32) -> Result<Self, Error> {
        if val > UPPER {
            Err(Error::AboveUpperBound(val, UPPER))
        } else if val < LOWER {
            Err(Error::BelowLowerBound(val, LOWER))
        } else {
            Ok(BoundedInt32::unchecked_new(val))
        }
    }

    /// This private function clamps an input to the acceptable range.
    fn clamp(val: i32) -> i32 {
        Ord::clamp(val, LOWER, UPPER)
    }

    /// Convert from the underlying type, clamping to the upper or
    /// lower bound if needed.
    ///
    /// # Panics
    ///
    /// This function will panic if UPPER < LOWER.
    pub fn saturating_from(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }

    /// Convert from a string, clamping to the upper or lower bound if needed.
    ///
    /// # Limitations
    ///
    /// If the input is a number that cannot be represented as an i32,
    /// then we return an error instead of clamping it.
    pub fn saturating_from_str(s: &str) -> Result<Self, Error> {
        if UPPER < LOWER {
            // The compiler should optimize this block out at compile time.
            return Err(Error::Uninhabited);
        }
        let val: i32 = s.parse().map_err(|_| Error::Unrepresentable)?;
        Ok(Self::saturating_from(val))
    }
}

impl<const L: i32, const U: i32> std::fmt::Display for BoundedInt32<L, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<const L: i32, const U: i32> From<BoundedInt32<L, U>> for i32 {
    fn from(val: BoundedInt32<L, U>) -> i32 {
        val.value
    }
}

impl<const L: i32, const U: i32> From<BoundedInt32<L, U>> for f64 {
    fn from(val: BoundedInt32<L, U>) -> f64 {
        val.value.into()
    }
}

impl<const L: i32, const H: i32> TryFrom<i32> for BoundedInt32<L, H> {
    type Error = Error;
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        Self::checked_new(val)
    }
}

impl<const L: i32, const H: i32> std::str::FromStr for BoundedInt32<L, H> {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::checked_new(s.parse().map_err(|_| Error::Unrepresentable)?)
    }
}

impl From<BoundedInt32<0, 1>> for bool {
    fn from(val: BoundedInt32<0, 1>) -> bool {
        val.value == 1
    }
}

impl From<BoundedInt32<0, 255>> for u8 {
    fn from(val: BoundedInt32<0, 255>) -> u8 {
        val.value as u8
    }
}

impl From<BoundedInt32<1, { i32::MAX }>> for u64 {
    fn from(val: BoundedInt32<1, { i32::MAX }>) -> u64 {
        val.value as u64
    }
}

/// A percentage value represented as a number.
///
/// This type wraps an underlying numeric type, and ensures that callers
/// are clear whether they want a _fraction_, or a _percentage_.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Percentage<T: Copy + Into<f64>> {
    /// The underlying percentage value.
    value: T,
}

impl<T: Copy + Into<f64>> Percentage<T> {
    /// Create a new `IntPercentage` from the underlying percentage.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Return this value as a (possibly improper) fraction.
    ///
    /// ```
    /// use tor_units::Percentage;
    /// let pct_200 = Percentage::<u8>::new(200);
    /// let pct_100 = Percentage::<u8>::new(100);
    /// let pct_50 = Percentage::<u8>::new(50);
    ///
    /// assert_eq!(pct_200.as_fraction(), 2.0);
    /// assert_eq!(pct_100.as_fraction(), 1.0);
    /// assert_eq!(pct_50.as_fraction(), 0.5);
    /// // Note: don't actually compare f64 with ==.
    /// ```
    pub fn as_fraction(self) -> f64 {
        self.value.into() / 100.0
    }

    /// Return this value as a percentage.
    ///
    /// ```
    /// use tor_units::Percentage;
    /// let pct_200 = Percentage::<u8>::new(200);
    /// let pct_100 = Percentage::<u8>::new(100);
    /// let pct_50 = Percentage::<u8>::new(50);
    ///
    /// assert_eq!(pct_200.as_percent(), 200);
    /// assert_eq!(pct_100.as_percent(), 100);
    /// assert_eq!(pct_50.as_percent(), 50);
    /// ```
    pub fn as_percent(self) -> T {
        self.value
    }
}

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
/// This type represents an integer number of milliseconds.
///
/// The underlying type should implement TryInto<u64>.
pub struct IntegerMilliseconds<T> {
    /// Interior Value. Should Implement TryInto<u64> to be useful.
    value: T,
}

impl<T: TryInto<u64>> IntegerMilliseconds<T> {
    /// Public Constructor
    pub fn new(value: T) -> Self {
        IntegerMilliseconds { value }
    }
}

impl<T: TryInto<u64>> TryFrom<IntegerMilliseconds<T>> for Duration {
    type Error = <T as TryInto<u64>>::Error;
    fn try_from(val: IntegerMilliseconds<T>) -> Result<Self, <T as TryInto<u64>>::Error> {
        Ok(Self::from_millis(val.value.try_into()?))
    }
}

/// A SendMe Version
///
/// DOCDOC: Explain why this needs to have its own type, or remove it.
#[derive(Clone, Copy, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SendMeVersion(u8);

impl SendMeVersion {
    /// Public Constructor
    pub fn new(value: u8) -> Self {
        SendMeVersion(value)
    }

    /// Helper
    pub fn get(&self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::BoundedInt32;
    use crate::Error;

    type TestFoo = BoundedInt32<1, 5>;
    type TestBar = BoundedInt32<-45, 17>;

    //make_parameter_type! {TestFoo(3,)}
    #[test]
    fn entire_range_parsed() {
        let x: TestFoo = "1".parse().unwrap();
        assert!(x.get() == 1);
        let x: TestFoo = "2".parse().unwrap();
        assert!(x.get() == 2);
        let x: TestFoo = "3".parse().unwrap();
        assert!(x.get() == 3);
        let x: TestFoo = "4".parse().unwrap();
        assert!(x.get() == 4);
        let x: TestFoo = "5".parse().unwrap();
        assert!(x.get() == 5);
    }

    #[test]
    fn saturating() {
        let x: TestFoo = TestFoo::saturating_new(1000);
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = TestFoo::saturating_new(0);
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::LOWER);
    }
    #[test]
    fn saturating_string() {
        let x: TestFoo = TestFoo::saturating_from_str("1000").unwrap();
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = TestFoo::saturating_from_str("0").unwrap();
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::LOWER);
    }

    #[test]
    fn errors_correct() {
        let x: Result<TestBar, Error> = "1000".parse();
        assert!(x.unwrap_err() == Error::AboveUpperBound(1000, TestBar::UPPER));
        let x: Result<TestBar, Error> = "-1000".parse();
        assert!(x.unwrap_err() == Error::BelowLowerBound(-1000, TestBar::LOWER));
        let x: Result<TestBar, Error> = "xyz".parse();
        assert!(x.unwrap_err() == Error::Unrepresentable);
    }

    #[test]
    fn display() {
        let v = BoundedInt32::<99, 1000>::checked_new(345).unwrap();
        assert_eq!(v.to_string(), "345".to_string());
    }

    #[test]
    #[should_panic]
    fn checked_too_high() {
        let _: TestBar = "1000".parse().unwrap();
    }

    #[test]
    #[should_panic]
    fn checked_too_low() {
        let _: TestBar = "-46".parse().unwrap();
    }
}
