//! This crate provides safe wrappers for primitive types. In particular it provides
//! a bounded i32 with both checked and clamping constructors, an integer milliseconds
//! wrapper which must be converted to a std::duration and SendMeVersion which can be compared.
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

extern crate derive_more;
use derive_more::{Add, Display, Div, From, FromStr, Mul};

use std::convert::{TryFrom, TryInto};

/// Errors returned by bounded types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A passed value was below the lower bound for the type.
    BelowLowerBound(i32, i32),
    /// A passed value was above the upper bound for the type.
    AboveUpperBound(i32, i32),
    /// A passed value was could not be represented as an i32.
    Unrepresentable(),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::BelowLowerBound(x, y) => {
                write!(f, "Value {} was below the lower bound {}", x, y)
            }
            Error::AboveUpperBound(x, y) => {
                write!(
                    f,
                    "Value {} was above the upper bound {} for this type",
                    x, y
                )
            }
            Error::Unrepresentable() => {
                write!(f, "Value could not be represented as an i32")
            }
        }
    }
}

impl std::error::Error for Error {}

/// This type holds an i32 value such that LOWER <= value <= UPPER
#[derive(Debug, Clone, Copy)]
pub struct BoundedInt32<const LOWER: i32, const UPPER: i32> {
    /// Interior Value
    value: i32,
}

#[allow(dead_code)]
impl<const LOWER: i32, const UPPER: i32> BoundedInt32<LOWER, UPPER> {
    /// Lower bound
    const LOWER: i32 = LOWER;
    /// Upper bound
    const UPPER: i32 = UPPER;

    /// Private constructor function for this type.
    fn unchecked_new(value: i32) -> Self {
        assert!(LOWER <= UPPER); //The compiler optimises this out, no run-time cost.
        BoundedInt32 { value }
    }

    /// Public getter for the underlying type.
    pub fn get(&self) -> i32 {
        self.value
    }
    /// This constructor returns a new value with type equal to the input value.
    /// If the value lies outside the maximum range of the type, it is clamped to the
    /// upper or lower bound as appropriate.
    pub fn saturating_new(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }
    /// This constructor returns a result containing the new value or else
    /// an error if the input lies outside the acceptable range.
    pub fn checked_new(val: i32) -> std::result::Result<Self, Error> {
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
        val.clamp(LOWER, UPPER)
    }
    /// Convert from the underlying type, clamping to the upper or lower bound if needed.
    pub fn saturating_from(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }
    /// Convert from a string, clamping to the upper or lower bound if needed.
    pub fn saturating_from_str(s: &str) -> std::result::Result<Self, Error> {
        let val: i32 = s.parse().map_err(|_| Error::Unrepresentable())?;
        Ok(Self::saturating_from(val))
    }
}
impl<const L: i32, const U: i32> std::fmt::Display for BoundedInt32<L, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}
impl<const L: i32, const U: i32> std::convert::From<BoundedInt32<L, U>> for i32 {
    fn from(val: BoundedInt32<L, U>) -> i32 {
        val.value
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
        Self::checked_new(s.parse().map_err(|_| Error::Unrepresentable())?)
    }
}

impl std::convert::From<BoundedInt32<0, 1>> for bool {
    fn from(val: BoundedInt32<0, 1>) -> bool {
        val.value == 1
    }
}

impl std::convert::From<BoundedInt32<0, 255>> for u8 {
    fn from(val: BoundedInt32<0, 255>) -> u8 {
        val.value as u8
    }
}

impl std::convert::From<BoundedInt32<1, { i32::MAX }>> for u64 {
    fn from(val: BoundedInt32<1, { i32::MAX }>) -> u64 {
        val.value as u64
    }
}

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
/// This type represents an integer number of milliseconds.
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

impl<T: TryInto<u64>> TryFrom<IntegerMilliseconds<T>> for std::time::Duration {
    type Error = <T as TryInto<u64>>::Error;
    fn try_from(val: IntegerMilliseconds<T>) -> Result<Self, <T as TryInto<u64>>::Error> {
        Ok(Self::from_millis(val.value.try_into()?))
    }
}

/// A SendMe Version
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
        assert!(x.unwrap_err() == Error::Unrepresentable());
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
