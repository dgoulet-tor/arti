use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::{Error, Position};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum TorVerStatus {
    Other,
    Alpha,
    Beta,
    Rc,
    Stable,
}

impl TorVerStatus {
    fn suffix(self) -> &'static str {
        use TorVerStatus::*;
        match self {
            Stable => "",
            Rc => "-rc",
            Beta => "-beta",
            Alpha => "-alpha",
            Other => "-???",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TorVersion {
    maj: u8,
    min: u8,
    micro: u8,
    patch: u8,
    status: TorVerStatus,
    dev: bool,
}

impl Display for TorVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let devsuffix = if self.dev { "-dev" } else { "" };
        write!(
            f,
            "{}.{}.{}.{}{}{}",
            self.maj,
            self.min,
            self.micro,
            self.patch,
            self.status.suffix(),
            devsuffix
        )
    }
}

impl FromStr for TorVersion {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        let mut parts = s.split('-').fuse();
        let ver_part = parts.next();
        let status_part = parts.next();
        let dev_part = parts.next();
        if parts.next().is_some() {
            return Err(Error::BadVersion(Position::None));
        }

        let vers: Result<Vec<_>, _> = ver_part
            .ok_or(Error::BadVersion(Position::None))?
            .splitn(4, '.')
            .map(|v| v.parse::<u8>())
            .collect();
        let vers = vers.map_err(|_| Error::BadVersion(Position::None))?;
        if vers.len() < 3 {
            return Err(Error::BadVersion(Position::None));
        }
        let maj = vers[0];
        let min = vers[1];
        let micro = vers[2];
        let patch = if vers.len() == 4 { vers[3] } else { 0 };

        let status = match status_part {
            Some("alpha") => TorVerStatus::Alpha,
            Some("beta") => TorVerStatus::Beta,
            Some("rc") => TorVerStatus::Rc,
            None | Some("dev") => TorVerStatus::Stable,
            _ => TorVerStatus::Other,
        };
        let dev = match (status_part, dev_part) {
            (_, Some("dev")) => true,
            (_, Some(_)) => {
                return Err(Error::BadVersion(Position::None));
            }
            (Some("dev"), None) => true,
            (_, _) => false,
        };

        Ok(TorVersion {
            maj,
            min,
            micro,
            patch,
            status,
            dev,
        })
    }
}
impl TorVersion {
    fn as_tuple(&self) -> (u8, u8, u8, u8, TorVerStatus, bool) {
        (
            self.maj,
            self.min,
            self.micro,
            self.patch,
            self.status,
            self.dev,
        )
    }
}
impl PartialOrd for TorVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TorVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_tuple().cmp(&other.as_tuple())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_good() {
        let mut lastver = None;
        for (s1, s2) in &[
            ("0.1.2", "0.1.2.0"),
            ("0.1.2.0-dev", "0.1.2.0-dev"),
            ("0.4.3.1-bloop", "0.4.3.1-???"),
            ("0.4.3.1-alpha", "0.4.3.1-alpha"),
            ("0.4.3.1-alpha-dev", "0.4.3.1-alpha-dev"),
            ("0.4.3.1-beta", "0.4.3.1-beta"),
            ("0.4.3.1-rc", "0.4.3.1-rc"),
            ("0.4.3.1", "0.4.3.1"),
        ] {
            let t: TorVersion = s1.parse().unwrap();
            assert_eq!(&t.to_string(), s2);

            if let Some(v) = lastver {
                assert!(v < t);
            }
            lastver = Some(t);
        }
    }
}
