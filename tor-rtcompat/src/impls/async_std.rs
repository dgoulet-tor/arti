//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

/// Types used for networking (async_std implementation)
pub mod net {
    pub use async_std_crate::net::{TcpListener, TcpStream};
}

/// Functions for launching and managing tasks (async_std implementation)
pub mod task {
    pub use async_std_crate::task::{block_on, sleep, spawn};
}

/// Functions and types for manipulating timers (async_std implementation)
pub mod timer {
    pub use async_io::Timer;
    pub use async_std_crate::future::timeout;
}
