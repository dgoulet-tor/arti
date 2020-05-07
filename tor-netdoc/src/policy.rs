mod full;
mod short;

use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;

pub use full::{AddrPolicy, AddrPortPattern};
pub use short::PortPolicy;

#[derive(Debug, Error, Clone)]
pub enum PolicyError {
    #[error("Invalid port")]
    InvalidPort,
    #[error("Invalid port range")]
    InvalidRange,
    #[error("Invalid policy")]
    InvalidPolicy,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("mask with star")]
    MaskWithStar,
    #[error("invalid mask")]
    InvalidMask,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    lo: u16,
    hi: u16,
}
impl PortRange {
    fn new_unchecked(lo: u16, hi: u16) -> Self {
        assert!(lo != 0);
        assert!(lo <= hi);
        PortRange { lo, hi }
    }
    fn new_all() -> Self {
        PortRange::new_unchecked(1, 65535)
    }
    fn new(lo: u16, hi: u16) -> Option<Self> {
        if lo != 0 && lo <= hi {
            Some(PortRange { lo, hi })
        } else {
            None
        }
    }
    fn contains(&self, port: u16) -> bool {
        self.lo <= port && port <= self.hi
    }
    pub fn is_all(&self) -> bool {
        self.lo == 1 && self.hi == 65535
    }
}
impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl FromStr for PortRange {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let idx = s.find('-');
        let (lo, hi) = if let Some(pos) = idx {
            (
                s[..pos]
                    .parse::<u16>()
                    .map_err(|_| PolicyError::InvalidPort)?,
                s[pos + 1..]
                    .parse::<u16>()
                    .map_err(|_| PolicyError::InvalidPort)?,
            )
        } else {
            let v = s.parse::<u16>().map_err(|_| PolicyError::InvalidPort)?;
            (v, v)
        };
        PortRange::new(lo, hi).ok_or(PolicyError::InvalidRange)
    }
}
