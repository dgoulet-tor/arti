/// Compatibility between different async runtimes for Arti
///
/// We try to isolate these dependencies in a single place so that
/// we depend only on a minimal set of required features that our
/// runtime needs to give us.
///
/// Right now, this crate exposes a small subset of the async_std
/// runtime, and the async_io rutime that it's built on, for use by
/// the rest of Arti.  Later we should add tokio support.  When we do
/// so, we may change which APIs this crate exposes, depending on
/// which interface is easier to build based on the other.
pub(crate) mod impls;

#[cfg(all(feature = "async-std"))]
pub use impls::async_std::*;
