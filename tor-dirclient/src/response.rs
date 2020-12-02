//! Define a response type for directory requests.

use tor_proto::circuit::UniqId;

/// A successful (or at any rate, well-formed) response to a directory
/// request.
#[derive(Debug, Clone)]
pub struct DirResponse {
    /// An HTTP status code.
    status: u16,
    /// The decompressed output that we got from the directory cache.
    output: String,
    /// Information about the directory cache we used.
    source: SourceInfo,
}

/// Information about the source of a directory response.
///
/// We use this to remember when a request has failed, so we can
/// abandon the circuit.
///
/// (In the future, we will probably want to use this structure to
/// remember that the cache isn't working.)
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Unique identifier for the circuit we're using
    circuit: UniqId,
}

impl DirResponse {
    /// Construct a new DirResponse from its parts
    pub(crate) fn new(status: u16, output: String, source: SourceInfo) -> Self {
        DirResponse {
            status,
            output,
            source,
        }
    }

    /// Return the HTTP status code for this response.
    pub fn status_code(&self) -> u16 {
        self.status
    }

    /// Return the output from this response.
    pub fn output(&self) -> &str {
        &self.output
    }

    /// Consume this DirResponse and return the output in it.
    pub fn into_output(self) -> String {
        self.output
    }

    /// Return the source information about this response.
    pub fn source(&self) -> &SourceInfo {
        &self.source
    }
}

impl SourceInfo {
    /// Construct a new SourceInfo
    pub(crate) fn new(circuit: UniqId) -> Self {
        SourceInfo { circuit }
    }
    /// Return the unique circuit identifier for the circuit on which
    /// we received this info.
    pub fn unique_circ_id(&self) -> &UniqId {
        &self.circuit
    }
}
