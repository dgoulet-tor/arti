#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(unused)]

pub(crate) mod legacy;

use crate::{Error, Result};
use std::path::{Path, PathBuf};
// use tor_netdoc::doc::microdesc::MDDigest;
// use std::collections::HashMap;

#[derive(Debug)]
pub(crate) enum InputString {
    Utf8(String),
    UncheckedBytes(Vec<u8>),
    MappedBytes(memmap::Mmap),
}

impl InputString {
    pub fn as_str(&self) -> Result<&str> {
        match self {
            InputString::Utf8(s) => Ok(&s[..]),
            InputString::UncheckedBytes(v) => std::str::from_utf8(&v[..]),
            InputString::MappedBytes(m) => std::str::from_utf8(&m[..]),
        }
        .map_err(|_| Error::CacheCorruption("Invalid UTF-8"))
    }

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

pub(crate) trait ReadableStore {
    type MDStrIter: Iterator<Item = Result<InputString>>;
    type CertStrIter: Iterator<Item = Result<InputString>>;
    fn latest_consensus(&self) -> Result<InputString>;
    fn microdescs(&self) -> Self::MDStrIter;
    fn authcerts(&self) -> Self::CertStrIter;
}

/*
pub(crate) trait WritableStore {
    fn store_consensus(&mut self, text: &str);
    fn store_authority_cert(&mut self, text: &str);
    fn store_microdescs(&mut self, text: HashMap<MDDigest, &str>); // XXXX need annotations!
}
*/
