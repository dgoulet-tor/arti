//! Re-exports of the tokio runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Types used for networking (tokio implementation)
pub mod net {
    pub use tokio_crate::io::split as split_io;
    pub use tokio_crate::net::{TcpListener, TcpStream};

    /// Return a stream that yields incoming sockets from `lis`
    pub fn listener_to_stream(
        lis: TcpListener,
    ) -> impl futures::stream::Stream<Item = Result<TcpStream, std::io::Error>> {
        tokio_stream::wrappers::TcpListenerStream::new(lis)
    }
}

/// Functions for launching and managing tasks (tokio implementation)
pub mod task {
    use std::future::Future;
    use tokio_crate::runtime::Runtime;

    /// Create a runtime and run `future` to completion
    pub fn block_on<F: Future>(future: F) -> F::Output {
        let rt = Runtime::new().unwrap(); // XXXX Not good: This could panic.
        rt.block_on(future)
    }

    pub use tokio_crate::spawn;
    pub use tokio_crate::time::sleep;
}

/// Functions and types for manipulating timers (tokio implementation)
pub mod timer {
    pub use tokio_crate::time::{error::Elapsed as TimeoutError, sleep, timeout};
}

/// Traits specific to the runtime.
pub mod traits {
    pub use tokio_crate::io::{
        AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt,
        AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt,
    };
}
