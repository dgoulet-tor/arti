mod err;
mod handshake;
mod msg;

pub use err::Error;
pub use handshake::{Action, SocksHandshake};
pub use msg::{SocksAddr, SocksAuth, SocksCmd, SocksRequest, SocksStatus};

pub type Result<T> = std::result::Result<T, Error>;
