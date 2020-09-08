use log::LevelFilter;
use std::path::Path;
use tor_netdir::*;

fn main() -> Result<()> {
    simple_logging::log_to_stderr(LevelFilter::Info);
    let mut cfg = NetDirConfig::new();

    let argv: Vec<_> = std::env::args().skip(1).collect();
    let chutney_dir = if argv.len() == 2 && argv[0] == "chutney" {
        Some(argv[1].clone())
    } else {
        None
    };

    match chutney_dir {
        Some(d) => {
            cfg.add_authorities_from_chutney(Path::new(&d))?;
            cfg.set_cache_path(Path::new(&d));
        }
        None => cfg.add_default_authorities(),
    };
    let dir = cfg.load()?;

    for r in dir.relays() {
        println!("{}", r.get_rsa_id())
    }

    Ok(())
}
