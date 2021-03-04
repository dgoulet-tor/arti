//! Implements a directory client for Tor.
//!
//! Tor makes directory requests as HTTP/1.0 requests tunneled over Tor circuits.
//! For most objects, Tor uses a one-hop tunnel.
//!
//! # Limitations
//!
//! Multi-hop tunnels are not supported.
//!
//! Only zlib, zstd and lzma compression is supported.

// XXXX THIS CODE IS HORRIBLE AND NEEDS REFACTORING.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod err;
pub mod request;
mod response;
mod util;

use tor_circmgr::{CircMgr, DirInfo};
use tor_decompress::{identity, Decompressor, StatusKind};

use anyhow::{Context, Result};
use futures::FutureExt;
use log::info;
use std::sync::Arc;
use std::time::Duration;

pub use err::Error;
pub use response::{DirResponse, SourceInfo};

/// Fetch the resource described by `req` over the Tor network.
///
/// Circuits are built or found using `circ_mgr`, using paths
/// constructed using `dirinfo`.
pub async fn get_resource<CR>(
    req: CR,
    dirinfo: DirInfo<'_>,
    circ_mgr: Arc<CircMgr>,
) -> Result<DirResponse>
where
    CR: request::ClientRequest,
{
    use tor_rtcompat::timer::timeout;

    let partial_ok = req.partial_docs_ok();
    let maxlen = req.max_response_len();
    let req = req.into_request()?;
    let encoded = util::encode_request(req);

    let circuit = circ_mgr.get_or_launch_dir(dirinfo).await?;
    let source = SourceInfo::new(circuit.unique_id());

    let (header, stream) = {
        // XXXX should be an option, and is too long.
        let begin_timeout = Duration::from_secs(5);
        let r = timeout(begin_timeout, async {
            // Send the HTTP request
            let mut stream = circuit
                .begin_dir_stream()
                .await
                .with_context(|| format!("Failed to open a directory stream to {:?}", source))?;
            stream
                .write_bytes(encoded.as_bytes())
                .await
                .with_context(|| format!("Failed to send HTTP request to {:?}", source))?;

            // Handle the response
            let hdr = read_headers(&mut stream)
                .await
                .with_context(|| format!("Failed to handle the HTTP response from {:?}", source))?;
            Result::<_, anyhow::Error>::Ok((hdr, stream))
        })
        .await;

        match r {
            Err(e) => {
                retire_circ(circ_mgr, &source, &e).await;
                return Err(e.into());
            }
            Ok(Err(e)) => {
                retire_circ(circ_mgr, &source, &e).await;
                return Err(e);
            }
            Ok(Ok((hdr, stream))) => {
                if hdr.status != Some(200) {
                    // XXXX-A1 we should retire the circuit in some of
                    // these cases, and return a response in others.
                    return Err(Error::HttpStatus(hdr.status).into());
                }
                (hdr, stream)
            }
        }
    };
    let encoding = header.encoding;
    let buf = header.pending;
    let n_in_buf = header.n_pending;

    let decompressor = match get_decompressor(encoding.as_deref()) {
        Err(e) => {
            retire_circ(circ_mgr, &source, &e).await;
            return Err(e);
        }
        Ok(x) => x,
    };

    let mut result = vec![0_u8; 2048];

    let ok = read_and_decompress(stream, maxlen, decompressor, buf, n_in_buf, &mut result).await;
    match (partial_ok, ok, result.len()) {
        (true, Err(e), n) if n > 0 => {
            retire_circ(Arc::clone(&circ_mgr), &source, &e).await;
            // Note that we _don't_ return here: we want the partial response.
        }
        (_, Err(e), _) => {
            retire_circ(circ_mgr, &source, &e).await;
            return Err(e);
        }
        (_, _, _) => (),
    }

    match String::from_utf8(result) {
        Err(e) => {
            retire_circ(circ_mgr, &source, &e).await;
            Err(e.into())
        }
        Ok(output) => Ok(DirResponse::new(200, output, source)),
    }
}

/// Read and parse HTTP/1 headers from `stream`.
async fn read_headers(stream: &mut tor_proto::stream::DataStream) -> Result<HeaderStatus> {
    let mut buf = vec![0; 1024];
    let mut n_in_buf = 0;

    loop {
        let n = stream.read_bytes(&mut buf[n_in_buf..]).await?;
        n_in_buf += n;

        // XXXX Better maximum and/or let this expand.
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        let res = response.parse(&buf[..n_in_buf])?;

        if res.is_partial() {
            // We didn't get a whole response; we may need to try again.

            // XXXX Pick a better maximum
            if n_in_buf >= buf.len() - 500 {
                // We should resize the buffer; it's nearly empty.
                if buf.len() >= 16384 {
                    return Err(httparse::Error::TooManyHeaders.into());
                }
                buf.resize(buf.len() * 2, 0u8);
            }
        } else {
            if response.code != Some(200) {
                return Ok(HeaderStatus {
                    status: response.code,
                    encoding: None,
                    pending: Vec::new(),
                    n_pending: 0,
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
            let n_parsed = res.unwrap();
            n_in_buf -= n_parsed;
            buf.copy_within(n_parsed.., 0);
            return Ok(HeaderStatus {
                status: Some(200),
                encoding,
                pending: buf,
                n_pending: n_in_buf,
            });
        }
        if n == 0 {
            return Err(Error::TruncatedHeaders.into());
        }
    }
}

/// Return value from read_headers
struct HeaderStatus {
    /// HTTP status code.
    status: Option<u16>,
    /// The Content-Encoding header, if any.
    encoding: Option<String>,
    /// A buffer containing leftover data beyond what was in the header.
    pending: Vec<u8>,
    /// The number of usable bytes in `pending`.
    n_pending: usize,
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
async fn read_and_decompress(
    mut stream: tor_proto::stream::DataStream,
    maxlen: usize,
    mut decompressor: Box<dyn Decompressor + Send>,
    mut buf: Vec<u8>,
    mut n_in_buf: usize,
    result: &mut Vec<u8>,
) -> Result<()> {
    let mut read_total = n_in_buf;
    let mut written_total = 0;

    let mut done_reading = false;

    // XXX should be an option and is too long.
    let read_timeout = Duration::from_secs(10);
    let timer = tor_rtcompat::timer::sleep(read_timeout).fuse();
    futures::pin_mut!(timer);

    loop {
        let status = futures::select! {
            status = stream.read_bytes(&mut buf[n_in_buf..]).fuse() => status,
            _ = timer => {
                result.resize(written_total, 0);
                return Err(Error::DirTimeout.into());
            }
        };
        let n = match status {
            Ok(n) => n,
            Err(tor_proto::Error::StreamClosed(_)) => 0,
            Err(other) => {
                result.resize(written_total, 0);
                return Err(other.into());
            }
        };
        if n == 0 {
            done_reading = true;
        }
        read_total += n;
        n_in_buf += n;

        if result.len() == written_total {
            result.resize(result.len() * 2, 0);
        }

        let st = decompressor.process(&buf[..n_in_buf], &mut result[written_total..], done_reading);
        let st = match st {
            Ok(st) => st,
            Err(e) => {
                result.resize(written_total, 0);
                return Err(e);
            }
        };
        n_in_buf -= st.consumed;
        buf.copy_within(st.consumed.., 0);
        written_total += st.written;

        if written_total > 2048 && written_total > read_total * 20 {
            result.resize(written_total, 0);
            return Err(Error::CompressionBomb.into());
        }
        if written_total > maxlen {
            result.resize(maxlen, 0);
            return Err(Error::ResponseTooLong(written_total).into());
        }

        match st.status {
            StatusKind::Done => break,
            StatusKind::Written => (),
            StatusKind::OutOfSpace => result.resize(result.len() * 2, 0),
        }
    }
    result.resize(written_total, 0);

    Ok(())
}

/// Return a decompressor object corresponding to a given Content-Encoding.
fn get_decompressor(encoding: Option<&str>) -> Result<Box<dyn Decompressor + Send>> {
    match encoding {
        None | Some("identity") => Ok(Box::new(identity::Identity)),
        Some("deflate") => Ok(miniz_oxide::inflate::stream::InflateState::new_boxed(
            miniz_oxide::DataFormat::Zlib,
        )),
        Some("x-tor-lzma") => Ok(Box::new(
            xz2::stream::Stream::new_lzma_decoder(16 * 1024 * 1024).unwrap(),
        )),
        Some("x-zstd") => Ok(Box::new(zstd::stream::raw::Decoder::new().unwrap())),
        Some(other) => Err(Error::BadEncoding(other.into()).into()),
    }
}

/// Retire a directory circuit because of an error we've encountered on it.
async fn retire_circ<E>(circ_mgr: Arc<CircMgr>, source_info: &SourceInfo, error: &E)
where
    E: std::fmt::Display,
{
    let id = source_info.unique_circ_id();
    info!(
        "{}: Retiring circuit because of directory failure: {}",
        &id, &error
    );
    circ_mgr.retire_circ(&id).await;
}

#[cfg(test)]
mod test {

    use super::*;
    use anyhow::anyhow;

    fn check_decomp(name: Option<&str>, inp: &[u8]) -> Vec<u8> {
        let mut d = get_decompressor(name).unwrap();
        let mut buf = vec![0; 2048];
        let s = d.process(inp, &mut buf[..], true).unwrap();
        // TODO: what if d requires multiple steps to work?
        assert_eq!(s.status, StatusKind::Done);
        assert_eq!(s.consumed, inp.len());
        buf.truncate(s.written);
        buf
    }

    #[test]
    fn test_get_decompressor_ident() {
        assert_eq!(
            &check_decomp(None, &b"Hello world"[..])[..],
            &b"Hello world"[..]
        );

        assert_eq!(
            &check_decomp(Some("identity"), &b"Hello world"[..])[..],
            &b"Hello world"[..]
        );
    }

    #[test]
    fn test_get_decompressor_err() {
        let name = "quantum-entanglement";
        let r = get_decompressor(Some(name));
        assert!(r.is_err());

        let e = r.err();
        let msg = format!("unsupported HTTP encoding \"{}\"", name);
        let err_msg = format!("{}", anyhow!(e.unwrap()));
        assert_eq!(msg, err_msg);
    }
}
