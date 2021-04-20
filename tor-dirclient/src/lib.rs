//! Implements a directory client for Tor.
//!
//! Tor makes directory requests as HTTP/1.0 requests tunneled over Tor circuits.
//! For most objects, Tor uses a one-hop tunnel.
//!
//! # Limitations
//!
//! Multi-hop tunnels are not supported.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod err;
pub mod request;
mod response;
mod util;

use tor_circmgr::{CircMgr, DirInfo};
use tor_rtcompat::{Runtime, SleepProvider, SleepProviderExt};

use async_compression::futures::bufread::{XzDecoder, ZlibDecoder, ZstdDecoder};
use futures::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use futures::FutureExt;
use log::info;
use memchr::memchr;
use std::sync::Arc;
use std::time::Duration;

pub use err::Error;
pub use response::{DirResponse, SourceInfo};

/// Type for results returned in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Fetch the resource described by `req` over the Tor network.
///
/// Circuits are built or found using `circ_mgr`, using paths
/// constructed using `dirinfo`.
///
/// For more fine-grained control over the circuit and stream used,
/// construct them yourself, and then call [`download`] instead.
///
/// # TODO
///
/// This is the only function in this crate that knows about CircMgr and
/// DirInfo.  Perhaps this function should move up a level into DirMgr?
pub async fn get_resource<CR, R, SP>(
    req: &CR,
    dirinfo: DirInfo<'_>,
    runtime: &SP,
    circ_mgr: Arc<CircMgr<R>>,
) -> anyhow::Result<DirResponse>
where
    CR: request::Requestable + ?Sized,
    R: Runtime,
    SP: SleepProvider,
{
    let circuit = circ_mgr.get_or_launch_dir(dirinfo).await?;

    // XXXX should be an option, and is too long.
    let begin_timeout = Duration::from_secs(5);
    let source = SourceInfo::new(circuit.unique_id());

    // Launch the stream.
    let mut stream = runtime
        .timeout(begin_timeout, circuit.begin_dir_stream())
        .await??; // XXXX handle fatalities here too

    // TODO: Perhaps we want separate timeouts for each phase of this.
    // For now, we just use higher-level timeouts in `dirmgr`.
    let r = download(runtime, req, &mut stream, Some(source.clone())).await;

    let retire = match &r {
        Err(e) => e.should_retire_circ(),
        Ok(dr) => dr.error().map(Error::should_retire_circ) == Some(true),
    };

    if retire {
        retire_circ(circ_mgr, &source, "Partial response").await;
    }

    Ok(r?)
}

/// Fetch a Tor directory object from a provided stream.
///
/// To do this, we send a simple HTTP/1.0 request for the described
/// object in `req` over `stream`, and then wait for a response.  In
/// log messatges, we describe the origin of the data as coming from
/// `source`.
///
/// # Notes
///
/// It's kind of bogus to have a 'source' field here at all; we may
/// eventually want to remove it.
pub async fn download<R, S, SP>(
    runtime: &SP,
    req: &R,
    stream: &mut S,
    source: Option<SourceInfo>,
) -> Result<DirResponse>
where
    R: request::Requestable + ?Sized,
    S: AsyncRead + AsyncWrite + Send + Unpin,
    SP: SleepProvider,
{
    let partial_ok = req.partial_docs_ok();
    let maxlen = req.max_response_len();
    let req = req.make_request()?;
    let encoded = util::encode_request(req);

    // Write the request.
    stream.write_all(encoded.as_bytes()).await?;
    stream.flush().await?;

    let mut buffered = BufReader::new(stream);

    // Handle the response
    let header = read_headers(&mut buffered).await?;
    if header.status != Some(200) {
        return Err(Error::HttpStatus(header.status));
    }

    let mut decoder = get_decoder(buffered, header.encoding)?;

    let mut result = Vec::new();
    let ok = read_and_decompress(runtime, &mut decoder, maxlen, &mut result).await;

    let ok = match (partial_ok, ok, result.len()) {
        (true, Err(e), n) if n > 0 => {
            // Note that we _don't_ return here: we want the partial response.
            Err(e)
        }
        (_, Err(e), _) => {
            return Err(e);
        }
        (_, Ok(()), _) => Ok(()),
    };

    let output = String::from_utf8(result)?;

    Ok(DirResponse::new(200, ok.err(), output, source))
}

/// Read and parse HTTP/1 headers from `stream`.
async fn read_headers<S>(stream: &mut S) -> Result<HeaderStatus>
where
    S: AsyncBufRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);

    loop {
        // TODO: it's inefficient to do this a line at a time; it would
        // probably be better to read until the CRLF CRLF ending of the
        // response.  But this should be fast enough.
        let n = read_until_limited(stream, b'\n', 2048, &mut buf).await?;

        // XXXX Better maximum and/or let this expand.
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);

        match response.parse(&buf[..])? {
            httparse::Status::Partial => {
                // We didn't get a whole response; we may need to try again.

                if n == 0 {
                    // We hit an EOF; no more progress can be made.
                    return Err(Error::TruncatedHeaders);
                }

                // XXXX Pick a better maximum
                if buf.len() >= 16384 {
                    return Err(httparse::Error::TooManyHeaders.into());
                }
            }
            httparse::Status::Complete(n_parsed) => {
                if response.code != Some(200) {
                    return Ok(HeaderStatus {
                        status: response.code,
                        encoding: None,
                    });
                }
                let encoding = if let Some(enc) = response
                    .headers
                    .iter()
                    .find(|h| h.name == "Content-Encoding")
                {
                    Some(String::from_utf8(enc.value.to_vec())?)
                } else {
                    None
                };
                /*
                if let Some(clen) = response.headers.iter().find(|h| h.name == "Content-Length") {
                    let clen = std::str::from_utf8(clen.value)?;
                    length = Some(clen.parse()?);
                }
                 */
                assert!(n_parsed == buf.len());
                return Ok(HeaderStatus {
                    status: Some(200),
                    encoding,
                });
            }
        }
        if n == 0 {
            return Err(Error::TruncatedHeaders);
        }
    }
}

/// Return value from read_headers
struct HeaderStatus {
    /// HTTP status code.
    status: Option<u16>,
    /// The Content-Encoding header, if any.
    encoding: Option<String>,
}

/// Helper: download directory information from `stream` and
/// decompress it into a result buffer.  Assumes we've started with
/// n_in_buf bytes of partially downloaded data in `buf`.
///
/// If we get more than maxlen bytes after decompression, give an error.
///
/// Returns the status of our download attempt, stores any data that
/// we were able to download into `result`.  Existing contents of
/// `result` are overwritten.
async fn read_and_decompress<S, SP>(
    runtime: &SP,
    mut stream: S,
    maxlen: usize,
    result: &mut Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
    SP: SleepProvider,
{
    let mut buf = [0_u8; 1024];
    let mut written_total: usize = 0;

    // XXXX should be an option and is maybe too long.  Though for some
    // users this may be too short?
    let read_timeout = Duration::from_secs(10);
    let timer = runtime.sleep(read_timeout).fuse();
    futures::pin_mut!(timer);

    loop {
        let status = futures::select! {
            status = stream.read(&mut buf[..]).fuse() => status,
            _ = timer => {
                return Err(Error::DirTimeout);
            }
        };
        let n = match status {
            Ok(n) => n,
            Err(other) => {
                return Err(other.into());
            }
        };
        if n == 0 {
            return Ok(());
        }
        result.extend(&buf[..n]);
        written_total += n;

        // TODO: It would be good to detect compression bombs, but
        // that would require access to the internal stream, which
        // would in turn require some tricky programming.  For now, we
        // use the maximum length here to prevent an attacker from
        // filling our RAM.
        if written_total > maxlen {
            result.resize(maxlen, 0);
            return Err(Error::ResponseTooLong(written_total));
        }
    }
}

/// Retire a directory circuit because of an error we've encountered on it.
async fn retire_circ<R, E>(circ_mgr: Arc<CircMgr<R>>, source_info: &SourceInfo, error: &E)
where
    R: Runtime,
    E: std::fmt::Display + ?Sized,
{
    let id = source_info.unique_circ_id();
    info!(
        "{}: Retiring circuit because of directory failure: {}",
        &id, &error
    );
    circ_mgr.retire_circ(&id).await;
}

/// As AsyncBufReadExt::read_until, but stops after reading `max` bytes.
///
/// Note that this function might not actually read any byte of value
/// `byte`, since EOF might occur, or we might fill the buffer.
///
/// A return value of 0 indicates an end-of-file.
async fn read_until_limited<S>(
    stream: &mut S,
    byte: u8,
    max: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize>
where
    S: AsyncBufRead + Unpin,
{
    let mut n_added = 0;
    loop {
        let data = stream.fill_buf().await?;
        if data.is_empty() {
            // End-of-file has been reached.
            return Ok(n_added);
        }
        debug_assert!(n_added < max);
        let remaining_space = max - n_added;
        let (available, found_byte) = match memchr(byte, data) {
            Some(idx) => (idx + 1, true),
            None => (data.len(), false),
        };
        debug_assert!(available >= 1);
        let n_to_copy = std::cmp::min(remaining_space, available);
        buf.extend(&data[..n_to_copy]);
        stream.consume_unpin(n_to_copy);
        n_added += n_to_copy;
        if found_byte || n_added == max {
            return Ok(n_added);
        }
    }
}

macro_rules! decoder {
    ($dec:ident, $s:expr) => {{
        let mut decoder = $dec::new($s);
        decoder.multiple_members(true);
        Ok(Box::new(decoder))
    }};
}

/// Wrap `stream` in an appropriate type to undo the content encoding
/// as described in `encoding`.
fn get_decoder<'a, S: AsyncBufRead + Unpin + Send + 'a>(
    stream: S,
    encoding: Option<String>,
) -> Result<Box<dyn AsyncRead + Unpin + Send + 'a>> {
    match encoding.as_deref() {
        None | Some("identity") => Ok(Box::new(stream)),
        Some("deflate") => decoder!(ZlibDecoder, stream),
        Some("x-tor-lzma") => decoder!(XzDecoder, stream),
        Some("x-zstd") => decoder!(ZstdDecoder, stream),
        Some(other) => Err(Error::ContentEncoding(other.into())),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use futures_await_test::async_test;

    #[async_test]
    async fn test_read_until_limited() -> Result<()> {
        let mut out = Vec::new();
        let bytes = b"This line eventually ends\nthen comes another\n";

        // Case 1: find a whole line.
        let mut s = &bytes[..];
        let res = read_until_limited(&mut s, b'\n', 100, &mut out).await;
        assert_eq!(res?, 26);
        assert_eq!(&out[..], b"This line eventually ends\n");

        // Case 2: reach the limit.
        let mut s = &bytes[..];
        out.clear();
        let res = read_until_limited(&mut s, b'\n', 10, &mut out).await;
        assert_eq!(res?, 10);
        assert_eq!(&out[..], b"This line ");

        // Case 3: reach EOF.
        let mut s = &bytes[..];
        out.clear();
        let res = read_until_limited(&mut s, b'Z', 100, &mut out).await;
        assert_eq!(res?, 45);
        assert_eq!(&out[..], &bytes[..]);

        Ok(())
    }
}
