//! Implements a usable view of Tor network parameters.
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  They are used to tune the behavior of
//! numerous aspects of the network.
//! A set of Tor network parameters
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  These parameters are used to tune the
//! behavior of numerous aspects of the network.
//!
//! This type differs from
//! [`NetParams`](tor_netdoc::doc::netstatus::NetParams) in that it
//! only exposes a set of parameters recognized by arti.  In return
//! for this restriction, it makes sure that the values it gives are
//! in range, and provides default values for any parameters that are
//! missing.

/// The error type for this module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<'a> {
    /// A string key wasn't recognised
    KeyNotRecognized(&'a str),
    /// Key recognised but invalid value provided
    InvalidValue(&'a str, &'a str, tor_units::Error),
}

impl std::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyNotRecognized(unknown_key) => {
                write!(f, "A Key for NetParams was not recognised: {}", unknown_key)
            }
            Error::InvalidValue(x, y, z) => {
                write!(f, "The key {} had an invalid value {} because {}", x, y, z)
            }
        }
    }
}

impl std::error::Error for Error<'_> {}

use tor_units::{BoundedInt32, IntegerMilliseconds, SendMeVersion};

/// This structure holds recognised configuration parameters. All values are type-safe,
/// and where applicable clamped to be within range.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NetParameters {
    /// A weighting factor for bandwidth calculations
    pub bw_weight_scale: BoundedInt32<0, { i32::MAX }>,
    /// The maximum cell window size?
    pub circuit_window: BoundedInt32<100, 1000>,
    /// The decay parameter for circuit priority
    pub circuit_priority_half_life: IntegerMilliseconds<BoundedInt32<1, { i32::MAX }>>,
    /// Whether to perform circuit extenstions by Ed25519 ID
    pub extend_by_ed25519_id: BoundedInt32<0, 1>,
    /// The minimum threshold for circuit patch construction
    pub min_circuit_path_threshold: BoundedInt32<25, 95>,
    /// The minimum sendme version to accept.
    pub send_me_accept_min_version: SendMeVersion,
    /// The minimum sendme version to transmit.
    pub send_me_emit_min_version: SendMeVersion,
}

impl Default for NetParameters {
    fn default() -> Self {
        NetParameters {
            bw_weight_scale: BoundedInt32::checked_new(10000).unwrap(),
            circuit_window: BoundedInt32::checked_new(1000).unwrap(),
            circuit_priority_half_life: IntegerMilliseconds::new(
                BoundedInt32::checked_new(30000).unwrap(),
            ),
            extend_by_ed25519_id: BoundedInt32::checked_new(0).unwrap(),
            min_circuit_path_threshold: BoundedInt32::checked_new(60).unwrap(),
            send_me_accept_min_version: SendMeVersion::new(0),
            send_me_emit_min_version: SendMeVersion::new(0),
        }
    }
}

impl NetParameters {
    /// Replace the parameter whose name is `name` with the `value`,
    /// clamping the value to be within allowable bounds.
    ///
    /// Return true if the parameter was recognized; false otherwise.
    fn saturating_update_override<'a>(&mut self, name: &'a str, value: i32) -> bool {
        match name {
            "bwweightscale" => {
                self.bw_weight_scale = BoundedInt32::saturating_from(value);
            }
            "circwindow" => {
                self.circuit_window = BoundedInt32::saturating_from(value);
            }
            "CircuitPriorityHalflifeMsec" => {
                self.circuit_priority_half_life =
                    IntegerMilliseconds::new(BoundedInt32::saturating_from(value))
            }
            "ExtendByEd25519ID" => {
                self.extend_by_ed25519_id = BoundedInt32::saturating_from(value);
            }
            "min_paths_for_circs_pct" => {
                self.min_circuit_path_threshold = BoundedInt32::saturating_from(value);
                // XXXXX This should be a percentage.
            }
            "sendme_accept_min_version" => {
                self.send_me_accept_min_version =
                    SendMeVersion::new(BoundedInt32::<0, 255>::saturating_from(value).into());
            }
            "sendme_emit_min_version" => {
                self.send_me_emit_min_version =
                    SendMeVersion::new(BoundedInt32::<0, 255>::saturating_from(value).into());
            }
            _ => {
                return false;
            } // unrecognized parameters are ignored.
        }
        true
    }

    /// Replace a list of parameters, using the logic of
    /// `saturating_update_override`.
    ///
    /// Return a vector of the parameter names we didn't recognize.
    pub(crate) fn saturating_update<'a>(
        &mut self,
        iter: impl Iterator<Item = (&'a String, &'a i32)>,
    ) -> Vec<&'a String> {
        let mut unrecognized = Vec::new();
        for (k, v) in iter {
            if !self.saturating_update_override(k, *v) {
                unrecognized.push(k);
            }
        }
        unrecognized
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)]
mod test {
    use super::*;
    use std::string::String;

    #[test]
    fn empty_list() {
        let mut x = NetParameters::default();
        let y = Vec::<(&String, &i32)>::new();
        let u = x.saturating_update(y.into_iter());
        assert!(u.is_empty());
    }

    #[test]
    fn unknown_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("This_is_not_a_real_key");
        let v = &456;
        y.push((k, v));
        let u = x.saturating_update(y.into_iter());
        assert_eq!(u, vec![&String::from("This_is_not_a_real_key")])
    }

    // #[test]
    // fn duplicate_parameter() {}

    #[test]
    fn single_good_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &54;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.min_circuit_path_threshold.get(), 54);
    }

    #[test]
    fn multiple_good_parameters() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &54;
        y.push((k, v));
        let k = &String::from("circwindow");
        let v = &900;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.min_circuit_path_threshold.get(), 54);
        assert_eq!(x.circuit_window.get(), 900);
    }

    #[test]
    fn good_out_of_range() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &255;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.send_me_accept_min_version.get(), 30);
        assert_eq!(x.min_circuit_path_threshold.get(), 95);
    }

    #[test]
    fn good_invalid_rep() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &9000;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.send_me_accept_min_version.get(), 30);
        assert_eq!(x.min_circuit_path_threshold.get(), 95);
    }

    // #[test]
    // fn good_duplicate() {}
    #[test]
    fn good_unknown() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("not_a_real_parameter");
        let v = &9000;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert_eq!(z, vec![&String::from("not_a_real_parameter")]);
        assert_eq!(x.send_me_accept_min_version.get(), 30);
    }

    #[test]
    fn from_consensus() {
        let mut p = NetParameters::default();
        let mut mp: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        mp.insert("bwweightscale".to_string(), 70);
        mp.insert("min_paths_for_circs_pct".to_string(), 45);
        mp.insert("im_a_little_teapot".to_string(), 1);
        mp.insert("circwindow".to_string(), 99999);
        mp.insert("ExtendByEd25519ID".to_string(), 1);

        let z = p.saturating_update(mp.iter());
        assert_eq!(z, vec![&String::from("im_a_little_teapot")]);

        assert_eq!(p.bw_weight_scale.get(), 70);
        assert_eq!(p.min_circuit_path_threshold.get(), 45);
        let b_val: bool = p.extend_by_ed25519_id.into();
        assert_eq!(b_val, true);
    }
}
