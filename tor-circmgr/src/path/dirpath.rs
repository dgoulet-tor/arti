use super::*;
use crate::Error;

pub struct DirPathBuilder {}
impl DirPathBuilder {
    pub fn new() -> Self {
        DirPathBuilder {}
    }
}
impl Default for DirPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl PathBuilder for DirPathBuilder {
    fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>> {
        // TODO: this will need to learn about directory guards.
        // TODO: this needs to work with fallback directories.

        // XXXX Weight correctly.
        let relay = netdir.pick_relay(rng, |r, w| if r.is_dir_cache() { w } else { 0 });
        if let Some(r) = relay {
            Ok(TorPath::OneHop(r))
        } else {
            Err(Error::NoRelays(
                "No relays found for use as directory cache".into(),
            ))
        }
    }
}
