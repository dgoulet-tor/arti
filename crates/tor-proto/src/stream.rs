//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use [crate::circuit::ClientCirc::begin_stream].
//!
//! # Limitations
//!
//! TODO: This should eventually expose a bytes-oriented type rather than a
//! cell-oriented type.
//!
//! XXXX TODO: There is no fairness, rate-limiting, or flow control.

mod data;
mod raw;
mod resolve;

pub use data::DataStream;
pub use raw::RawCellStream;
pub use resolve::ResolveStream;
