//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

/// Types used for networking (async_std implementation)
pub mod net {
    pub use async_std_crate::net::{TcpListener, TcpStream};

    /// Split a read/write stream into its read and write halves.
    pub fn split_io<T>(stream: T) -> (futures::io::ReadHalf<T>, futures::io::WriteHalf<T>)
    where
        T: futures::io::AsyncRead + futures::io::AsyncWrite,
    {
        use futures::io::AsyncReadExt;
        stream.split()
    }

    /// Return a stream that yields incoming sockets from `lis`
    pub fn listener_to_stream<'a>(
        lis: &'a TcpListener,
    ) -> impl futures::stream::Stream<Item = Result<TcpStream, std::io::Error>> + 'a {
        lis.incoming()
    }
}

/// Functions for launching and managing tasks (async_std implementation)
pub mod task {
    pub use async_std_crate::task::{block_on, sleep, spawn};
}

/// Functions and types for manipulating timers (async_std implementation)
pub mod timer {
    use std::time::Duration;

    /// Return a future that will be ready after `duration` has passed.
    pub fn sleep(duration: Duration) -> async_io::Timer {
        async_io::Timer::after(duration)
    }

    pub use async_std_crate::future::{timeout, TimeoutError};
}

/// Traits specific to async_std
pub mod traits {}
