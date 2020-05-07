#![allow(dead_code)]

mod crypto;
pub mod proto;
mod util;
pub use util::err::Error;

use zeroize::Zeroizing;

pub type SecretBytes = Zeroizing<Vec<u8>>;

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
