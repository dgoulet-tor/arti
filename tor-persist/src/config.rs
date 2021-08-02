
/// configuration object for a circuit manager.
#[derive(Debug,Clone)]
pub struct StateConfig {
    /// A directory where we store our state.
    // TODO: move this to a better place once we have state figured out.
    state_path: PathBuf,
}


