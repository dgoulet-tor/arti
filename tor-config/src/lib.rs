//! Tools for configuration management.
//!
//! Arti's configuration is handled using `serde` and `config` crates,
//! plus extra features defined here for convenience.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod cmdline;
pub use cmdline::CmdLine;

use std::path::{Path, PathBuf};

/// Load a Config object based on a set of files and/or command-line
/// arguments.
///
/// The files should be toml; the command-line arguments have the extended
/// syntax of [`CmdLine`].
///
/// If `default_path` is present, and there is no list of files, then use a
/// default file if it exists.
//
// XXXX Add an error type for this crate.
pub fn load<'a, P1, C1, P2, C2>(
    cfg: &mut config::Config,
    default_path: Option<P1>,
    files: C1,
    opts: C2,
) -> Result<(), config::ConfigError>
where
    P1: AsRef<Path> + 'a,
    C1: IntoIterator<Item = &'a P2>,
    P2: AsRef<Path> + 'a,
    C2: IntoIterator,
    C2::Item: AsRef<str>,
{
    let mut search_path = Vec::new();
    for f in files {
        search_path.push(f.as_ref());
    }
    let mut missing_ok = false;
    if search_path.is_empty() {
        if let Some(f) = &default_path {
            // XXXX shouldn't be println, but no logs exist yet.
            println!("looking for default configuration in {:?}", f.as_ref());
            search_path.push(f.as_ref());
            missing_ok = true;
        }
    }

    for p in search_path {
        // Not going to use File::with_name here, since it doesn't
        // quite do what we want.
        let f: config::File<_> = p.into();
        cfg.merge(f.format(config::FileFormat::Toml).required(!missing_ok))?;
    }

    let mut cmdline = CmdLine::new();
    for opt in opts {
        cmdline.push_toml_line(opt.as_ref().to_string());
    }
    cfg.merge(cmdline)?;

    Ok(())
}

/// Return a filename for the default user configuration file.
pub fn default_config_file() -> Option<PathBuf> {
    let pd = directories::ProjectDirs::from("org", "torproject", "Arti")?;

    Some(pd.config_dir().join("arti.toml"))
}
