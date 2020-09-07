use log::LevelFilter;
use tor_netdir::*;

fn main() {
    simple_logging::log_to_stderr(LevelFilter::Info);
    let mut cfg = NetDirConfig::new();
    cfg.add_default_authorities();
    let outcome = cfg.load();
    match outcome {
        Ok(_) => println!("ok"),
        Err(e) => println!("Error: {}", e),
    }
}
