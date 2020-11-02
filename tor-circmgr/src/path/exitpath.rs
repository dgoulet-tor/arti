use super::*;
use crate::Error;

pub struct ExitPathBuilder {
    wantports: Vec<u16>,
}

impl ExitPathBuilder {
    pub fn new<P: Into<Vec<u16>>>(ports: P) -> Self {
        let wantports = ports.into();
        ExitPathBuilder { wantports }
    }

    fn ports_supported_by(&self, r: &Relay<'_>) -> bool {
        self.wantports.iter().all(|p| r.supports_exit_port(*p))
    }
}

impl PathBuilder for ExitPathBuilder {
    fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>> {
        // XXXX weight correctly for each position.
        // TODO: implement families
        // TODO: implement guards
        let exit = netdir
            .pick_relay(rng, |r, weight| {
                if self.ports_supported_by(r) {
                    weight
                } else {
                    0
                }
            })
            .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?;

        let middle = netdir
            .pick_relay(
                rng,
                |r, weight| if r.same_relay(&exit) { 0 } else { weight },
            )
            .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?;

        let entry = netdir
            .pick_relay(rng, |r, weight| {
                if r.same_relay(&exit) || r.same_relay(&middle) {
                    0
                } else {
                    weight
                }
            })
            .ok_or_else(|| Error::NoRelays("No entry relay found".into()))?;

        Ok(TorPath::Path(vec![entry, middle, exit]))
    }
}
