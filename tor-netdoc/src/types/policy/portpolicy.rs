//! Implement port-based policies
//!
//! These are also known as "short policies" or "policy summaries".

use std::fmt::Display;
use std::str::FromStr;

use super::{PolicyError, PortRange};

/// A policy to match zero or more TCP/UDP ports.
///
/// These are used in Tor to summarize all policies in
/// microdescriptors, and Ipv6 policies in router descriptors.
///
/// # Examples
/// ```
/// use tor_netdoc::types::policy::PortPolicy;
/// let policy: PortPolicy = "accept 1-1023,8000-8999,60000-65535".parse().unwrap();
///
/// assert!(policy.allows_port(22));
/// assert!(policy.allows_port(8000));
/// assert!(! policy.allows_port(1024));
/// assert!(! policy.allows_port(9000));
/// ```
#[derive(Clone)]
pub struct PortPolicy {
    /// A list of port ranges that this policy allows.
    ///
    /// These ranges are sorted and disjoint.
    allowed: Vec<PortRange>,
}

impl Display for PortPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.allowed.is_empty() {
            write!(f, "reject 1-65535")?;
        } else {
            write!(f, "accept ")?;
            let mut comma = "";
            for range in self.allowed.iter() {
                write!(f, "{}{}", comma, range)?;
                comma = ",";
            }
        }
        Ok(())
    }
}

impl PortPolicy {
    /// Return a new PortPolicy that rejects all ports.
    pub fn new_reject_all() -> Self {
        PortPolicy {
            allowed: Vec::new(),
        }
    }
    /// Helper: replace this policy with its inverse.
    fn invert(&mut self) {
        let mut prev_hi = 0;
        let mut new_allowed = Vec::new();
        for entry in self.allowed.iter() {
            // ports prev_hi+1 through entry.lo-1 were rejected.  We should
            // make them allowed.
            if entry.lo > prev_hi + 1 {
                new_allowed.push(PortRange::new_unchecked(prev_hi + 1, entry.lo - 1));
            }
            prev_hi = entry.hi;
        }
        if prev_hi < 65535 {
            new_allowed.push(PortRange::new_unchecked(prev_hi + 1, 65535));
        }
        self.allowed = new_allowed;
    }
    /// Return true iff `port` is allowed by this policy.
    pub fn allows_port(&self, port: u16) -> bool {
        self.allowed
            .binary_search_by(|range| range.compare_to_port(port))
            .is_ok()
    }
}

impl FromStr for PortPolicy {
    type Err = PolicyError;
    fn from_str(mut s: &str) -> Result<Self, PolicyError> {
        let invert = if s.starts_with("accept ") {
            false
        } else if s.starts_with("reject ") {
            true
        } else {
            return Err(PolicyError::InvalidPolicy);
        };
        let mut result = PortPolicy {
            allowed: Vec::new(),
        };
        s = &s[7..];
        for item in s.split(',') {
            let r: PortRange = item.parse()?;
            if let Some(prev) = result.allowed.last() {
                if r.lo <= prev.hi {
                    // Or should this be "<"? TODO XXXX
                    return Err(PolicyError::InvalidPolicy);
                }
            }
            result.allowed.push(r);
        }
        if invert {
            result.invert();
        }
        Ok(result)
    }
}
