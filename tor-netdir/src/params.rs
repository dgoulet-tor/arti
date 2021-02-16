//! Implements a usable view of Tor network parameters.
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  They are used to tune the behavior of
//! numerous aspects of the network.

use caret::caret_enum;
use tor_netdoc::doc::netstatus;

use std::collections::HashMap;
use std::ops::{Bound, RangeBounds, RangeInclusive};

/// A set of Tor network parameters.
///
/// The Tor consensus document contains a number of 'network
/// parameters', which are integer-valued items voted on by the
/// directory authorities.  These parameters are used to tune the
/// behavior of numerous aspects of the network.
///
/// This type differs from [`netstatus::NetParams`] in that it only
/// exposes a set of parameters recognized by arti.  In return for
/// this restriction, it makes sure that the values it gives are in
/// range, and provides default values for any parameters that are
/// missing.
#[derive(Clone, Debug)]
pub struct NetParameters {
    /// A map from parameters to their values.  If a parameter is not
    /// present in this map, its value is the default.
    ///
    /// All values in this map are clamped to be within the range for their
    /// associated parameters.
    params: HashMap<Param, i32>,
}

impl Default for NetParameters {
    fn default() -> NetParameters {
        NetParameters::new()
    }
}

impl NetParameters {
    /// Construct a new NetParameters containing the default value for
    /// each recognized parameter.
    pub fn new() -> Self {
        NetParameters {
            params: HashMap::new(),
        }
    }

    /// Return the value for the parameter `key`.
    pub fn get(&self, key: Param) -> i32 {
        match self.params.get(&key) {
            Some(v) => *v,
            None => key.default_val(),
        }
    }

    /// Returns the value for the parameter `key` as a u16.
    ///
    /// Panics if any allowable value for `key` can't be represented as a u16.
    pub fn get_u16(&self, key: Param) -> u16 {
        let range = key.range();
        assert!(range.min >= 0);
        assert!(range.max <= 65535);
        self.get(key) as u16
    }

    /// Returns the value for the parameter `key` as a u16.
    ///
    /// Panics if any allowable value for `key` can't be represented a
    pub fn get_bool(&self, key: Param) -> bool {
        let range = key.range();
        assert!(range.min >= 0);
        assert!(range.max <= 1);

        self.get(key) != 0
    }

    /// Change the value for the parameter `key` to be `value`.
    ///
    /// If `value` is not in range, clamp it to the minimum or maximum
    /// for `key`, depending on whether it is too low or too high.
    pub fn set_clamped(&mut self, key: Param, value: i32) {
        let value = key.clamp(value);
        self.params.insert(key, value);
    }

    /// Replace any values in this NetParameters that are overridden in `new`.
    ///
    /// Return a vector of unrecognized keys.
    pub fn update<'a>(&mut self, new: &'a netstatus::NetParams<i32>) -> Vec<&'a str> {
        let mut unrecognized = Vec::new();
        for (name, value) in new.iter() {
            if let Ok(param) = name.parse() {
                self.set_clamped(param, *value);
            } else {
                unrecognized.push(name.as_ref());
            }
        }
        unrecognized
    }
}

caret_enum! {
    #[non_exhaustive]
    #[derive(Hash,Debug)]
    /// A recognized Tor consensus directory parameter.
    ///
    /// Each parameter has a corresponding string representation for use
    /// in directory documents.
    ///
    /// This list does not (yet) include every parameter in Tor's
    /// param-spec.txt.
    pub enum Param as u16 {
        /// A value that bandwidth-weights are divided by.
        ///
        /// This is mostly used by directory authorities, but clients
        /// need it when computing how to weight directory-flagged
        /// relays.
        BwWeightScale ("bwweightscale"),
        /// Default starting value for circuit SENDME windows.
        CircWindow ("circwindow"),
        /// Halflife for weighting circuits and deciding which should send
        /// the next cell.
        ///
        /// XXXX Not yet implemented
        CircuitPriorityHalflifeMsec ("CircuitPriorityHalflifeMsec"),
        /// Whether clients should include Ed25519 identities for
        /// relays when generating EXTEND2 cells.
        ExtendByEd25519Id ("ExtendByEd25519ID"),
        /// A percentage threshold that determines whether clients
        /// believe they have enough directory information to build
        /// circuits.
        MinPathsForCircsPct ("min_paths_for_circs_pct"),
        /// Minimum SENDME version to accept from others.
        ///
        /// XXXX not yet implemented
        SendmeAcceptMinVersion ("sendme_accept_min_version"),
        /// Minimum SENDME version to send.
        ///
        /// XXXX not yet implemented
        SendmeEmitMinVersion ("sendme_emit_min_version"),
    }
}

impl Param {
    /// Return `val`, clamped to be within an appropriate range for
    /// this parameter.
    fn clamp(self, val: i32) -> i32 {
        let ParamRange { min, max, .. } = self.range();
        if val < min {
            min
        } else if val > max {
            max
        } else {
            val
        }
    }
    /// Return the default value for this perameter.
    fn default_val(self) -> i32 {
        self.range().default
    }

    /// Return a ParamRange representing the default value and
    /// allowable range for this parameter.
    fn range(self) -> ParamRange {
        use Param::*;
        use ParamRange as P;

        /// Range for a value that can be 0 or 1.
        const BOOLEAN: RangeInclusive<i32> = 0..=1;

        match self {
            BwWeightScale => P::new(10_000, 1..),
            CircWindow => P::new(1_000, 100..=1000),
            ExtendByEd25519Id => P::new(0, BOOLEAN),
            CircuitPriorityHalflifeMsec => P::new(30_000, 1..),
            MinPathsForCircsPct => P::new(60, 25..=95),
            SendmeAcceptMinVersion => P::new(0, 0..=255),
            SendmeEmitMinVersion => P::new(0, 0..=255),
        }
    }
}

/// Internal type: represents the default value and allowable range
/// for this parameter.
#[derive(Clone, Debug)]
struct ParamRange {
    /// Default value to assume when none is listed in the consensus.
    default: i32,
    /// Lowest allowable value
    min: i32,
    /// Highest allowable value
    max: i32,
}

impl ParamRange {
    /// Construct a new ParamRange from a default value and a RangeBounds.
    fn new<B>(default: i32, range: B) -> Self
    where
        B: RangeBounds<i32>,
    {
        assert!(range.contains(&default));
        let min = match range.start_bound() {
            Bound::Included(n) => *n,
            Bound::Excluded(n) => *n + 1,
            Bound::Unbounded => std::i32::MIN,
        };
        let max = match range.end_bound() {
            Bound::Included(n) => *n,
            Bound::Excluded(n) => *n - 1,
            Bound::Unbounded => std::i32::MAX,
        };
        assert!(min <= default);
        assert!(default <= max);

        ParamRange { default, min, max }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn param_range() {
        let p = ParamRange::new(7, 1..1000);
        assert_eq!(p.default, 7);
        assert_eq!(p.min, 1);
        assert_eq!(p.max, 999);

        let p = ParamRange::new(1000, 1..=1000);
        assert_eq!(p.default, 1000);
        assert_eq!(p.min, 1);
        assert_eq!(p.max, 1000);

        let p = ParamRange::new(-10, ..);
        assert_eq!(p.default, -10);
        assert_eq!(p.min, std::i32::MIN);
        assert_eq!(p.max, std::i32::MAX);
    }

    #[test]
    #[should_panic]
    fn param_range_oob() {
        ParamRange::new(-7, 1..1000);
    }

    #[test]
    fn defaults() {
        let p = NetParameters::new();

        assert_eq!(p.get(Param::BwWeightScale), 10_000);
        assert_eq!(p.get(Param::CircWindow), 1_000);
    }

    #[test]
    fn set_clamped() {
        let mut p = NetParameters::new();
        p.set_clamped(Param::BwWeightScale, 6);
        p.set_clamped(Param::CircWindow, 6);
        p.set_clamped(Param::MinPathsForCircsPct, 1000);

        assert_eq!(p.get(Param::BwWeightScale), 6);
        assert_eq!(p.get(Param::CircWindow), 100);
        assert_eq!(p.get(Param::MinPathsForCircsPct), 95);
    }

    #[test]
    fn from_consensus() {
        let mut p = NetParameters::new();
        let np =
            "bwweightscale=70 min_paths_for_circs_pct=45 im_a_little_teapot=1 circwindow=99999"
                .parse()
                .unwrap();
        let unrec = p.update(&np);

        assert_eq!(p.get(Param::BwWeightScale), 70);
        assert_eq!(p.get(Param::CircWindow), 1000);
        assert_eq!(p.get(Param::MinPathsForCircsPct), 45);
        assert_eq!(p.get(Param::CircuitPriorityHalflifeMsec), 30_000);

        assert_eq!(unrec.len(), 1);
        assert_eq!(unrec[0], "im_a_little_teapot");
    }

    #[test]
    fn get_casting_ok() {
        let mut p = NetParameters::new();
        assert_eq!(p.get_bool(Param::ExtendByEd25519Id), false);
        assert_eq!(p.get_u16(Param::ExtendByEd25519Id), 0);

        p.set_clamped(Param::MinPathsForCircsPct, 99);
        assert_eq!(p.get_u16(Param::MinPathsForCircsPct), 95);
    }

    #[test]
    #[should_panic]
    fn get_bool_panics() {
        NetParameters::new().get_bool(Param::MinPathsForCircsPct);
    }

    #[test]
    #[should_panic]
    fn get_u16_panics() {
        NetParameters::new().get_u16(Param::BwWeightScale);
    }
}
