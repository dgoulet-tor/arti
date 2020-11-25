//! Implements a directory client for Tor.
//!
//! Tor makes directory requests as HTTP/1.0 requests tunneled over Tor circuits.
//! For most objects, Tor uses a one-hop tunnel.
//!
//! # Limitations
//!
//! Multi-hop tunnels are not supported.
//!
//! Only zlib compression is supported.

// XXXX THIS CODE IS HORRIBLE AND NEEDS REFACTORING.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod decompress;
mod err;
pub mod request;
mod util;

use crate::decompress::Decompressor;

use tor_circmgr::{CircMgr, DirInfo};

use anyhow::Result;
use log::info;
use std::sync::Arc;

pub use err::Error;

/// Fetch the resource described by `req` over the Tor network.
///
/// Circuits are built or found using `circ_mgr`, using paths
/// constructed using `dirinfo`.
pub async fn get_resource<CR, TR>(
    req: CR,
    dirinfo: DirInfo<'_>,
    circ_mgr: Arc<CircMgr<TR>>,
) -> Result<String>
where
    CR: request::ClientRequest,
    TR: tor_chanmgr::transport::Transport,
{
    let partial_ok = req.partial_docs_ok();
    let maxlen = req.max_response_len();
    let req = req.into_request()?;
    let encoded = util::encode_request(req);

    let circuit = circ_mgr.get_or_launch_dir(dirinfo).await?;
    let mut stream = circuit.begin_dir_stream().await?;

    stream.write_bytes(encoded.as_bytes()).await?;

    let (encoding, buf, n_in_buf) = read_headers(&mut stream).await?;

    let decompressor = get_decompressor(encoding.as_deref())?;
    let mut result = vec![0_u8; 2048];
    let ok = read_and_decompress(stream, maxlen, decompressor, buf, n_in_buf, &mut result).await;
    match (partial_ok, ok, result.len()) {
        (true, Err(e), n) if n > 0 => info!("Error while downloading: {}", e),
        (_, Err(e), _) => return Err(e),
        (_, _, _) => (),
    }
    Ok(String::from_utf8(result)?)
}

/// Read and parse HTTP/1 headers from `stream`.
///
/// On success, return the Content-Encoding header, a buffer containing
/// leftover data beyond what was in the header, and the number of usable
/// bytes in that buffer.
///
/// TODO: fix up this complicated return type!
async fn read_headers(
    stream: &mut tor_proto::stream::DataStream,
) -> Result<(Option<String>, Vec<u8>, usize)> {
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
                return Err(Error::HttpStatus(response.code).into());
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
            return Ok((encoding, buf, n_in_buf));
        }
        if n == 0 {
            return Err(Error::TruncatedHeaders.into());
        }
    }
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
    mut decompressor: Box<dyn Decompressor>,
    mut buf: Vec<u8>,
    mut n_in_buf: usize,
    result: &mut Vec<u8>,
) -> Result<()> {
    let mut read_total = n_in_buf;
    let mut written_total = 0;

    let mut done_reading = false;
    use decompress::StatusKind;

    loop {
        let status = stream.read_bytes(&mut buf[n_in_buf..]).await;
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
fn get_decompressor(encoding: Option<&str>) -> Result<Box<dyn Decompressor>> {
    match encoding {
        None | Some("identity") => Ok(Box::new(decompress::identity::Identity)),
        Some("deflate") => Ok(miniz_oxide::inflate::stream::InflateState::new_boxed(
            miniz_oxide::DataFormat::Zlib,
        )),
        Some(other) => Err(Error::BadEncoding(other.into()).into()),
    }
}
