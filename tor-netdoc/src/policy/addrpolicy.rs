/// Implements address policies, based on a series of accept/reject
/// rules.
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::{PolicyError, PortRange};

/// A sequence of rules that are applied to an address:port until one
/// matches.
pub struct AddrPolicy {
    rules: Vec<AddrPolicyRule>,
}

impl AddrPolicy {
    /// Apply this policy to an address:port combination
    ///
    /// We do this by applying each rule in sequence, until one
    /// matches.  If that rule is accept, we return Some(true).  If
    /// that rule is reject, we return Some(false).
    ///
    /// Returns None if no rule matches.
    pub fn allows(&self, addr: &IpAddr, port: u16) -> Option<bool> {
        match self
            .rules
            .iter()
            .find(|rule| rule.pattern.matches(addr, port))
        {
            Some(AddrPolicyRule { accept, .. }) => Some(*accept),
            None => None,
        }
    }

    /// Create a new AddrPolicy that matches nothing.
    pub fn new() -> Self {
        AddrPolicy { rules: Vec::new() }
    }

    /// Add a new rule to this policy.
    ///
    /// The newly added rule is applied _after_ all previous rules.
    /// It matches all addresses and ports coverd by AddrPortPattern.
    ///
    /// If accept is true, the rule is to accept addresses that match;
    /// if accept is false, the rule rejects such addresses.
    pub fn push(&mut self, accept: bool, pattern: AddrPortPattern) {
        self.rules.push(AddrPolicyRule { accept, pattern })
    }
}

impl Default for AddrPolicy {
    fn default() -> Self {
        AddrPolicy::new()
    }
}

/// A single rule in an address policy.
///
/// Contains a pattern and what to do with things that match it.
struct AddrPolicyRule {
    /// What do we do with items that match the pattern?
    accept: bool,
    /// What pattern are we trying to match?
    pattern: AddrPortPattern,
}

impl Display for AddrPolicyRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmd = if self.accept { "accept" } else { "reject" };
        write!(f, "{} {}", cmd, self.pattern)
    }
}

/// A pattern that may or may not match an address and port.
///
/// Each AddrPortPattern has an IP pattern, which matches a set of
/// addresses by prefix, and a port pattern, which matches a range of
/// ports.
///
/// # Example
///
/// ```
/// use tor_netdoc::policy::AddrPortPattern;
/// use std::net::{IpAddr,Ipv4Addr};
/// let localhost = IpAddr::V4(Ipv4Addr::new(127,3,4,5));
/// let not_localhost = IpAddr::V4(Ipv4Addr::new(192,0,2,16));
/// let pat: AddrPortPattern = "127.0.0.0/8:*".parse().unwrap();
///
/// assert!(pat.matches(&localhost, 22));
/// assert!(! pat.matches(&not_localhost, 22));
/// ```
pub struct AddrPortPattern {
    pattern: IpPattern,
    ports: PortRange,
}

impl AddrPortPattern {
    pub fn matches(&self, addr: &IpAddr, port: u16) -> bool {
        self.pattern.matches(addr) && self.ports.contains(port)
    }
}

impl Display for AddrPortPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ports.is_all() {
            write!(f, "{}:*", self.pattern)
        } else {
            write!(f, "{}:{}", self.pattern, self.ports)
        }
    }
}

impl FromStr for AddrPortPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let last_colon = s.rfind(':').ok_or(PolicyError::InvalidPolicy)?;
        let pattern: IpPattern = s[..last_colon].parse()?;
        let ports_s = &s[last_colon + 1..];
        let ports: PortRange = if ports_s == "*" {
            PortRange::new_all()
        } else {
            ports_s.parse()?
        };

        Ok(AddrPortPattern { pattern, ports })
    }
}

/// A pattern that matches one or more IP addresses.
enum IpPattern {
    /// Match all addresses.
    Star,
    /// Match all IPv4 addresses.
    V4Star,
    /// Match all IPv6 addresses.
    V6Star,
    /// Match all IPv4 addresses beginning with a given prefix.
    V4(Ipv4Addr, u8),
    /// Match all IPv6 addresses beginning with a given prefix.
    V6(Ipv6Addr, u8),
}

impl IpPattern {
    /// Construct an IpPattern that matches the first `mask` bits of `addr`.
    fn from_addr_and_mask(addr: IpAddr, mask: u8) -> Result<Self, PolicyError> {
        match (addr, mask) {
            (IpAddr::V4(_), 0) => Ok(IpPattern::V4Star),
            (IpAddr::V6(_), 0) => Ok(IpPattern::V6Star),
            (IpAddr::V4(a), m) if m <= 32 => Ok(IpPattern::V4(a, m)),
            (IpAddr::V6(a), m) if m <= 128 => Ok(IpPattern::V6(a, m)),
            (_, _) => Err(PolicyError::InvalidMask),
        }
    }
    /// Return true iff `addr` is matched by this pattern.
    fn matches(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (IpPattern::Star, _) => true,
            (IpPattern::V4Star, IpAddr::V4(_)) => true,
            (IpPattern::V6Star, IpAddr::V6(_)) => true,
            (IpPattern::V4(pat, mask), IpAddr::V4(addr)) => {
                let p1 = u32::from_be_bytes(pat.octets());
                let p2 = u32::from_be_bytes(addr.octets());
                let shift = 32 - mask;
                (p1 >> shift) == (p2 >> shift)
            }
            (IpPattern::V6(pat, mask), IpAddr::V6(addr)) => {
                let p1 = u128::from_be_bytes(pat.octets());
                let p2 = u128::from_be_bytes(addr.octets());
                let shift = 128 - mask;
                (p1 >> shift) == (p2 >> shift)
            }
            (_, _) => false,
        }
    }
}

impl Display for IpPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IpPattern::*;
        match self {
            Star | V4Star | V6Star => write!(f, "*"),
            V4(a, 32) => write!(f, "{}", a),
            V4(a, m) => write!(f, "{}/{}", a, m),
            V6(a, 128) => write!(f, "[{}]", a),
            V6(a, m) => write!(f, "[{}]/{}", a, m),
        }
    }
}

impl FromStr for IpPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let (ip_s, mask_s) = match s.find('/') {
            Some(slash_idx) => (&s[..slash_idx], Some(&s[slash_idx + 1..])),
            None => (s, None),
        };
        match (ip_s, mask_s) {
            ("*", Some(_)) => Err(PolicyError::MaskWithStar),
            ("*", None) => Ok(IpPattern::Star),
            (s, Some(m)) => {
                let a: IpAddr = s.parse().map_err(|_| PolicyError::InvalidAddress)?;
                let m: u8 = m.parse().map_err(|_| PolicyError::InvalidMask)?;
                IpPattern::from_addr_and_mask(a, m)
            }
            (s, None) => {
                let a: IpAddr = s.parse().map_err(|_| PolicyError::InvalidAddress)?;
                let m = if a.is_ipv4() { 32 } else { 128 };
                IpPattern::from_addr_and_mask(a, m)
            }
        }
    }
}
