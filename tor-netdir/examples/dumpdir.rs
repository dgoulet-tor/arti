use log::LevelFilter;
use tor_netdir::*;

fn main() -> Result<()> {
    simple_logging::log_to_stderr(LevelFilter::Info);
    let mut cfg = NetDirConfig::new();
    cfg.add_default_authorities();
    let dir = cfg.load()?;

    for r in dir.relays() {
        println!("{:?}", r.get_id().unwrap())
    }

    Ok(())
}
