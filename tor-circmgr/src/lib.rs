mod err;
pub mod path;

pub use err::Error;
pub type Result<T> = std::result::Result<T, Error>;
