use super::InputString;
use crate::{Error, Result};

use std::path::{Path, PathBuf};

pub(crate) struct LegacyStore {
    dir: PathBuf,
}

impl LegacyStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        LegacyStore {
            dir: path.as_ref().into(),
        }
    }

    fn relative_path<P: AsRef<Path>>(&self, relpath: P) -> PathBuf {
        let mut pb = self.dir.to_path_buf();
        pb.push(relpath);
        pb
    }

    pub fn latest_consensus(&self) -> Result<InputString> {
        let p = self.relative_path("cached-microdesc-consensus");
        Ok(InputString::load(p)?)
    }

    pub fn microdescs(&self) -> impl Iterator<Item = Result<InputString>> {
        // impl Iterator<Item=Result<InputString,Self::Error>> {
        let paths = vec![
            self.relative_path("cached-microdescs"),
            self.relative_path("cached-microdescs.new"),
        ];
        Box::new(paths.into_iter().map(InputString::load))
    }

    pub fn authcerts(&self) -> impl Iterator<Item = Result<InputString>> {
        // impl Iterator<Item=Result<InputString,Self::Error>> {
        let paths = vec![self.relative_path("cached-certs")];
        Box::new(paths.into_iter().map(InputString::load))
    }
}
