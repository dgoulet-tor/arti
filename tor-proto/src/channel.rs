//! Talking directly (over a TLS connection) to a Tor node

#![allow(missing_docs)]

use arrayref::array_ref;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::sink::SinkExt;
use futures::stream::StreamExt;

use crate::chancell::{codec, msg, ChanCell, ChanCmd};
use crate::{Error, Result};

use std::net;
use tor_bytes::Reader;
use tor_linkspec::ChanTarget;

// We only support version 4 for now, since we don't do padding right
static LINK_PROTOCOLS: &[u16] = &[4];

type CellFrame<T> = futures_codec::Framed<T, codec::ChannelCodec>;

pub struct OutboundClientHandshake<T: AsyncRead + AsyncWrite + Unpin> {
    tls: T,
}

pub struct UnverifiedChannel<T: AsyncRead + AsyncWrite + Unpin> {
    link_protocol: u16,
    tls: CellFrame<T>,
    certs_cell: msg::Certs,
    netinfo_cell: msg::Netinfo,
}

pub struct VerifiedChannel<T: AsyncRead + AsyncWrite + Unpin> {
    link_protocol: u16,
    tls: CellFrame<T>,
}

pub struct Channel<T: AsyncRead + AsyncWrite + Unpin> {
    link_protocol: u16,
    tls: CellFrame<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> OutboundClientHandshake<T> {
    pub fn new(tls: T) -> Self {
        Self { tls }
    }

    pub async fn connect(mut self) -> Result<UnverifiedChannel<T>> {
        // Send versions cell
        {
            let my_versions = msg::Versions::new(LINK_PROTOCOLS);
            self.tls.write(&my_versions.encode_for_handshake()).await?;
            self.tls.flush().await?;
        }

        // Get versions cell.
        let their_versions: msg::Versions = {
            let mut hdr = [0u8; 5];
            self.tls.read(&mut hdr).await?;
            if hdr[0..3] != [0, 0, ChanCmd::VERSIONS.into()] {
                return Err(Error::ChanProto("Doesn't seem to be a tor relay".into()));
            }
            let msglen = u16::from_be_bytes(*array_ref![hdr, 3, 2]);
            let mut msg = vec![0; msglen as usize];
            self.tls.read_exact(&mut msg).await?;
            let mut reader = Reader::from_slice(&msg);
            reader.extract()?
        };

        // Determine shared versions.
        let link_protocol = their_versions
            .best_shared_link_protocol(LINK_PROTOCOLS)
            .ok_or_else(|| Error::ChanProto("No shared link protocols".into()))?;

        // Now we can switch to using a "Framed".
        let mut tls = futures_codec::Framed::new(self.tls, codec::ChannelCodec::new(link_protocol));

        let mut certs: Option<msg::Certs> = None;
        let mut netinfo: Option<msg::Netinfo> = None;
        let mut seen_authchallenge = false;

        while let Some(m) = tls.next().await {
            use msg::ChanMsg::*;
            let (_, m) = m?.into_circid_and_msg();
            // trace!("READ: {:?}", m);
            match m {
                // Are these technically allowed?
                Padding(_) | VPadding(_) => (),
                // Unrecognized cells get ignored.
                Unrecognized(_) => (),
                // Clients don't care about AuthChallenge
                AuthChallenge(_) => {
                    if seen_authchallenge {
                        return Err(Error::ChanProto("Duplicate Authchallenge cell".into()));
                    }
                    seen_authchallenge = true;
                }
                Certs(c) => {
                    if certs.is_some() {
                        return Err(Error::ChanProto("Duplicate certs cell".into()));
                    }
                    certs = Some(c);
                }
                Netinfo(n) => {
                    if netinfo.is_some() {
                        return Err(Error::ChanProto("Duplicate certs cell".into()));
                    }
                    netinfo = Some(n);
                    break;
                }
                // No other cell types are allowed.
                m => {
                    return Err(Error::ChanProto(format!(
                        "Unexpected cell type {}",
                        m.get_cmd()
                    )))
                }
            }
        }

        match (certs, netinfo) {
            (Some(_), None) => Err(Error::ChanProto("Missing netinfo or closed stream".into())),
            (None, _) => Err(Error::ChanProto("Missing certs cell".into())),
            (Some(certs_cell), Some(netinfo_cell)) => Ok(UnverifiedChannel {
                link_protocol,
                tls,
                certs_cell,
                netinfo_cell,
            }),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> UnverifiedChannel<T> {
    pub fn check<U: ChanTarget>(self, _peer: &U) -> Result<VerifiedChannel<T>> {
        // XXXX need to verify certificates
        Ok(VerifiedChannel {
            link_protocol: self.link_protocol,
            tls: self.tls,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> VerifiedChannel<T> {
    pub async fn finish(mut self, peer_addr: &net::IpAddr) -> Result<Channel<T>> {
        use msg::Body;
        let netinfo = msg::Netinfo::for_client(*peer_addr);
        let cell = ChanCell::new(0.into(), netinfo.as_message());
        self.tls.send(cell).await?;

        Ok(Channel {
            link_protocol: self.link_protocol,
            tls: self.tls,
        })
    }
}
