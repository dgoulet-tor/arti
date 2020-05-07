//! Implementation of Tor's "subprotocol versioning" feature.
//!
//! Different aspects of the Tor protocol are given versions
//! independently, and Tor implementations use these versions to tell
//! which relays support which features.  They are also used to
//! determine which versions of the protocol are required to connect
//! to the network (or just recommended).
//!
//! This implementation assumes that the "xxx-limit-protovers.md"
//! proposal has been accepted, limiting versions to the range 0
//! through 63.

use caret::caret_enum;
use thiserror::Error;

caret_enum! {
/// Recognized protocol identities.  These names are kept in sync with
/// the names used in consensus documents; the values are kept in sync
/// with the values in the cbor document format in the walking onions
/// proposal.
#[non_exhaustive]
pub enum ProtoKind as u16 {
    Link = 0,
    LinkAuth = 1,
    Relay = 2,
    DirCache = 3,
    HSDir = 4,
    HSIntro = 5,
    HSRend = 6,
    Desc = 7,
    MicroDesc = 8,
    Cons = 9,
    Padding = 10,
    FlowCtrl = 11,
}
}

/// How many recognized protocols are there?
const N_RECOGNIZED: usize = 12;

/// Representation for a known or unknown protocol.
#[derive(Eq, PartialEq)]
enum Protocol {
    Proto(ProtoKind),
    Unrecognized(String),
}

impl Protocol {
    /// Return true iff `s` is the name of a protocol we do not recognize.
    fn is_unrecognized(&self, s: &str) -> bool {
        match self {
            Protocol::Unrecognized(s2) => s2 == s,
            _ => false,
        }
    }
    /// Return a string representation of this protocol.
    fn to_str(&self) -> &str {
        match self {
            Protocol::Proto(k) => k.to_str(),
            Protocol::Unrecognized(s) => &s,
        }
    }
}

/// Representation of a set of versions supported by a protocol.
///
/// For now, we only use this type for unrecognized protocols.
struct SubprotocolEntry {
    proto: Protocol,
    /// A bit-vector defining which versions are supported.  If bit
    /// `(1<<i)` is set, then protocol version `i` is supported.
    supported: u64,
}

/// A set of supported or required protocol versions.
pub struct Protocols {
    /// A mapping from protocols' integer encodings to bit-vectors.
    recognized: [u64; N_RECOGNIZED],
    /// A vector of unrecognized protocol vesions.
    unrecognized: Vec<SubprotocolEntry>,
}

impl Protocols {
    /// Return a new empty set of protocol versions.
    pub fn new() -> Self {
        Protocols {
            recognized: [0u64; N_RECOGNIZED],
            unrecognized: Vec::new(),
        }
    }
    /// Helper: return true iff this protocol set contains the
    /// version `ver` of the protocol represented by the integer `proto`.
    fn supports_recognized_ver(&self, proto: usize, ver: u8) -> bool {
        if ver > 63 {
            return false;
        }
        if proto >= self.recognized.len() {
            return false;
        }
        (self.recognized[proto] & (1 << ver)) != 0
    }
    /// Helper: return true iff this protocol set contains version
    /// `ver` of the unrecognized protocol represented by the string
    /// `proto`.
    ///
    /// Requires that `proto` is not the name of a recognized protocol.
    fn supports_unrecognized_ver(&self, proto: &str, ver: u8) -> bool {
        if ver > 63 {
            return false;
        }
        let ent = self
            .unrecognized
            .iter()
            .find(|ent| ent.proto.is_unrecognized(proto));
        match ent {
            Some(e) => (e.supported & (1 << ver)) != 0,
            None => false,
        }
    }
    /// Return true iff this protocol set contains version `ver`
    /// of the protocol `proto`.
    pub fn supports_subver(&self, proto: ProtoKind, ver: u8) -> bool {
        self.supports_recognized_ver(proto as usize, ver)
    }
    /// Return true iff this protocol set contains version `ver`
    /// of the protocol represented by the string `proto`.
    pub fn supports_raw_subver(&self, proto: &str, ver: u8) -> bool {
        match ProtoKind::from_string(proto) {
            Some(p) => self.supports_recognized_ver(p as usize, ver),
            None => self.supports_unrecognized_ver(proto, ver),
        }
    }

    /// Parsing helper: Try to add a new entry `ent` to this set of protocols.
    ///
    /// Uses `foundmask`, a bit mask saying which recognized protocols
    /// we've already found entries for.  Returns an error if `ent` is
    /// for a protocol we've already added.
    fn add(&mut self, foundmask: &mut u64, ent: SubprotocolEntry) -> Result<(), ParseError> {
        match ent.proto {
            Protocol::Proto(k) => {
                let idx = k as usize;
                let bit = 1 << (k as u64);
                if (*foundmask & bit) != 0 {
                    return Err(ParseError::Duplicate);
                }
                *foundmask |= bit;
                self.recognized[idx] = ent.supported;
            }
            Protocol::Unrecognized(ref s) => {
                if self
                    .unrecognized
                    .iter()
                    .any(|ent| ent.proto.is_unrecognized(&s))
                {
                    return Err(ParseError::Duplicate);
                }
                self.unrecognized.push(ent);
            }
        }
        Ok(())
    }
}

impl Default for Protocols {
    fn default() -> Self {
        Protocols::new()
    }
}

/// An error representing a failure to parse a set of protocol versions.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("protocol version out of range")]
    OutOfRange,
    #[error("duplicate protocol entry")]
    Duplicate,
    #[error("malformed protocol entry")]
    Malformed,
}

/// Helper: return a new u64 in which bits `lo` through `hi` inclusive
/// are set to 1, and all the other bits are set to 0.
///
/// In other words, `bitrange(a,b)` is how we represent the range of
/// versions `a-b` in a protocol version bitmask.
fn bitrange(lo: u64, hi: u64) -> u64 {
    assert!(lo <= hi && lo <= 63 && hi <= 63);
    let mut mask = !0;
    mask <<= 63 - hi;
    mask >>= 63 - hi + lo;
    mask <<= lo;
    mask
}

/// A single SubprotocolEntry is parsed from a string of the format
/// Name=Versions, where Versions is a comma-separated list of
/// integers or ranges of integers.
impl std::str::FromStr for SubprotocolEntry {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        // split the string on the =.
        let (name, versions) = {
            let eq_idx = s.find('=').ok_or(ParseError::Malformed)?;
            (&s[..eq_idx], &s[eq_idx + 1..])
        };
        // Look up the protocol by name.
        let proto = match ProtoKind::from_string(name) {
            Some(p) => Protocol::Proto(p),
            None => Protocol::Unrecognized(name.to_string()),
        };
        // Construct a bitmask based on the comma-separated versions.
        let mut supported = 0u64;
        for ent in versions.split(',') {
            // Find and parse lo and hi for a single range of versions.
            // (If this is not a range, but rather a single version v,
            // treat it as if it were a range v-v.)
            let (lo_s, hi_s) = {
                match ent.find('-') {
                    Some(pos) => (&ent[..pos], &ent[pos + 1..]),
                    None => (ent, ent),
                }
            };
            let lo: u64 = lo_s.parse().map_err(|_| ParseError::Malformed)?;
            let hi: u64 = hi_s.parse().map_err(|_| ParseError::Malformed)?;
            // Make sure that lo and hi are in-bounds and consistent.
            if lo > 63 || hi > 63 {
                return Err(ParseError::OutOfRange);
            }
            if lo > hi {
                return Err(ParseError::Malformed);
            }
            let mask = bitrange(lo, hi);
            // Make sure that no version is included twice.
            if (supported & mask) != 0 {
                return Err(ParseError::Duplicate);
            }
            // Add the appropriate bits to the mask.
            supported |= mask;
        }
        Ok(SubprotocolEntry { proto, supported })
    }
}

/// A Protocols set can be parsed from a string according to the
/// format used in Tor consensus documents.
///
/// A protocols set is represented by a space-separated list of
/// entries.  Each entry is of the form `Name=Versions`, where `Name`
/// is the name of a protocol, and `Versions` is a comma-separated
/// list of version numbers and version ranges.  Each version range is
/// a pair of integers separated by `-`.
///
/// No protocol name may be listed twice.  No version may be listed
/// twice for a single protocol.  All versions must be in range 0
/// through 63 inclusive.
impl std::str::FromStr for Protocols {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let mut result = Protocols::new();
        let mut foundmask = 0u64;
        for ent in s.split(' ') {
            if ent.is_empty() {
                continue;
            }

            let s: SubprotocolEntry = ent.parse()?;
            result.add(&mut foundmask, s)?;
        }
        Ok(result)
    }
}

/// Given a bitmask, return a list of the bits set in the mask, as a
/// String in the format expectd by Tor consensus documents.
///
/// This implementation constructs ranges greedily.  For example, the
/// bitmask `0b0111011` will be represented as `0-1,3-5`, and not
/// `0,1,3,4,5` or `0,1,3-5`.
fn dumpmask(mut mask: u64) -> String {
    // We'll be building up our result here, then joining it with
    // commas.
    let mut result = Vec::new();
    // Helper: push a range (which may be a singleton) onto `v`.
    fn append(v: &mut Vec<String>, lo: u32, hi: u32) {
        if lo == hi {
            v.push(lo.to_string());
        } else {
            v.push(format!("{}-{}", lo, hi));
        }
    }
    // This implementation is a little tricky, but it should be more
    // efficient than a raw search.  Basically, we're using the
    // function u64::trailing_zeros to count how large each range of
    // 1s or 0s is, and then shifting by that amount.

    // How many bits have we already shifted `mask`?
    let mut shift = 0;
    while mask != 0 {
        let zeros = mask.trailing_zeros();
        mask >>= zeros;
        shift += zeros;
        // We'd like to do it this way, but trailing_ones() is not yet
        // in stable Rust. (TODO)
        //    let ones = mask.trailing_ones();
        let ones = (!mask).trailing_zeros();
        append(&mut result, shift, shift + ones - 1);
        shift += ones;
        if ones == 64 {
            // We have to do this check to avoid overflow when formatting
            // the range 0-63.  XXXX (It's a bit ugly, isn't it?)
            break;
        }
        mask >>= ones;
    }
    result.join(",")
}

/// The Display trait formats a protocol set in the format expected by Tor
/// consensus documents.
impl std::fmt::Display for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entries = Vec::new();
        for (idx, mask) in self.recognized.iter().enumerate() {
            if *mask != 0 {
                let pk = ProtoKind::from_int(idx as u16).unwrap();
                entries.push(format!("{}={}", pk.to_str(), dumpmask(*mask)))
            }
        }
        for ent in self.unrecognized.iter() {
            if ent.supported != 0 {
                entries.push(format!(
                    "{}={}",
                    ent.proto.to_str(),
                    dumpmask(ent.supported)
                ))
            }
        }
        // This sort is required.
        entries.sort();
        write!(f, "{}", entries.join(" "))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bitrange() {
        assert_eq!(0b1, bitrange(0, 0));
        assert_eq!(0b10, bitrange(1, 1));
        assert_eq!(0b11, bitrange(0, 1));
        assert_eq!(0b1111110000000, bitrange(7, 12));
        assert_eq!(!0, bitrange(0, 63));
    }

    #[test]
    fn test_dumpmask() {
        assert_eq!("", dumpmask(0));
        assert_eq!("0-5", dumpmask(0b111111));
        assert_eq!("4-5", dumpmask(0b110000));
        assert_eq!("1,4-5", dumpmask(0b110010));
        assert_eq!("0-63", dumpmask(!0));
    }
}
