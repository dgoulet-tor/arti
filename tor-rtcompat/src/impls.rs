//! Different implementations of a common async API for use in arti
//!
//! Currently only async_std is provided.

#[cfg(all(feature = "async-std"))]
pub(crate) mod async_std;
