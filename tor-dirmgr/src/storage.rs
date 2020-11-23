//! Methods for storing and loading directory information from disk.
//!
//! We have code implemented for two methods: the legacy format used by
//! the C Tor implementation, and a more flexible format based on sqlite.

pub(crate) mod legacy;
pub(crate) mod sqlite;

use crate::{Error, Result};
use std::path::Path;

/// An abstraction over a possible string that we've loaded or mapped from
/// a cache.
#[derive(Debug)]
pub enum InputString {
    /// A string that's been validated as UTF-8
    Utf8(String),
    /// A set of unvalidated bytes.
    UncheckedBytes(Vec<u8>),
    /// A set of memory-mapped bytes (not yet validated as UTF-8).
    MappedBytes(memmap::Mmap),
}

impl InputString {
    /// Return a view of this InputString as a &str, if it is valid UTF-8.
    pub fn as_str(&self) -> Result<&str> {
        match self {
            InputString::Utf8(s) => Ok(&s[..]),
            InputString::UncheckedBytes(v) => std::str::from_utf8(&v[..]),
            InputString::MappedBytes(m) => std::str::from_utf8(&m[..]),
        }
        .map_err(|_| Error::CacheCorruption("Invalid UTF-8").into())
    }

    /// Construct a new InputString from a file on disk, trying to
    /// memory-map the file if possible.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = std::fs::File::open(path)?;
        let mapping = unsafe {
            // I'd rather have a safe option, but the crate that provides
            // a safe API here is unix-only.
            memmap::Mmap::map(&f)
        };
        if let Ok(m) = mapping {
            return Ok(InputString::MappedBytes(m));
        }

        use std::io::{BufReader, Read};
        let mut f = BufReader::new(f);
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        Ok(InputString::Utf8(result))
    }
}

impl From<String> for InputString {
    fn from(s: String) -> InputString {
        InputString::Utf8(s)
    }
}

impl From<Vec<u8>> for InputString {
    fn from(v: Vec<u8>) -> InputString {
        InputString::UncheckedBytes(v)
    }
}
