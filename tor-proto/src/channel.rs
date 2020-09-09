//! Talking directly (over a TLS connection) to a Tor node

#![allow(missing_docs)]

use arrayref::array_ref;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::sink::SinkExt;
use futures::stream::StreamExt;

use crate::chancell::{codec, msg, ChanCmd};
use crate::{Error, Result};

use std::net;
use tor_bytes::Reader;
use tor_linkspec::ChanTarget;
use tor_llcrypto as ll;

use digest::Digest;

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
    pub fn check<U: ChanTarget>(self, peer: &U, peer_cert: &[u8]) -> Result<VerifiedChannel<T>> {
        use tor_cert::CertType;
        use tor_checkable::*;
        let c = &self.certs_cell;
        let id_sk = c.parse_ed_cert(CertType::IDENTITY_V_SIGNING)?;
        let sk_tls = c.parse_ed_cert(CertType::SIGNING_V_TLS_CERT)?;
        // XXXX need to verify RSA crosscert.

        let id_sk = id_sk
            .check_key(&None)?
            .check_signature()
            .map_err(|_| Error::ChanProto("Bad certificate signature".into()))?
            .check_valid_now()
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        let identity_key = id_sk.get_signing_key().ok_or_else(|| {
            Error::ChanProto("Missing identity key in identity->signing cert".into())
        })?;

        let signing_key = id_sk
            .get_subject_key()
            .as_ed25519()
            .ok_or_else(|| Error::ChanProto("Bad key type in identity->signing cert".into()))?;

        let sk_tls = sk_tls
            .check_key(&Some(*signing_key))? // this is a bad interface XXXX
            .check_signature()
            .map_err(|_| Error::ChanProto("Bad certificate signature".into()))?
            .check_valid_now()
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        let cert_sha256 = ll::d::Sha256::digest(peer_cert);
        if &cert_sha256[..] != sk_tls.get_subject_key().as_bytes() {
            return Err(Error::ChanProto(
                "Peer cert did not authenticate TLS cert".into(),
            ));
        }

        if identity_key != peer.get_ed_identity() {
            return Err(Error::ChanProto("Peer ed25519 id not as expected".into()));
        }

        Ok(VerifiedChannel {
            link_protocol: self.link_protocol,
            tls: self.tls,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> VerifiedChannel<T> {
    pub async fn finish(mut self, peer_addr: &net::IpAddr) -> Result<Channel<T>> {
        let netinfo = msg::Netinfo::for_client(*peer_addr);
        self.tls.send(netinfo.into()).await?;

        Ok(Channel {
            link_protocol: self.link_protocol,
            tls: self.tls,
        })
    }
}
