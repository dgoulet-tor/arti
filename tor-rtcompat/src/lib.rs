// foo

pub(crate) mod impls;

#[cfg(all(feature = "async-std"))]
pub use impls::async_std::*;
