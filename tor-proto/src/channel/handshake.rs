//! Implementations for the channel handshake

use arrayref::array_ref;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::sink::SinkExt;
use futures::stream::StreamExt;

use crate::channel::codec::ChannelCodec;
use crate::{Error, Result};
use tor_cell::chancell::{msg, ChanCmd};

use std::net;
use tor_bytes::Reader;
use tor_linkspec::ChanTarget;
use tor_llcrypto as ll;

use digest::Digest;

use super::CellFrame;

/// A list of the link protocols that we support.
// We only support version 4 for now, since we don't do padding right.
static LINK_PROTOCOLS: &[u16] = &[4];

/// A raw client channel on which nothing has been done.
pub struct OutboundClientHandshake<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    tls: T,
}

/// A client channel on which versions have been negotiated and the
/// server's handshake has been read, but where the certs have not
/// been checked.
pub struct UnverifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// The negotiated link protocol.  Must be a member of LINK_PROTOCOLS
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
    /// The certs cell that we got from the relay.
    certs_cell: msg::Certs,
    /// The netinfo cell that we got from the relay.
    #[allow(dead_code)] // Relays will need this.
    netinfo_cell: msg::Netinfo,
}

/// A client channel on which versions have been negotiated,
/// server's handshake has been read, but the client has not yet
/// finished the handshake.
///
/// This type is separate from UnverifiedChannel, since finishing the
/// handshake requires a bunch of CPU, and you might want to do it as
/// a separate task or after a yield.
pub struct VerifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// The negotiated link protocol.
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> OutboundClientHandshake<T> {
    /// Construct a new OutboundClientHandshake.
    pub(crate) fn new(tls: T) -> Self {
        Self { tls }
    }

    /// Negotiate a link protocol version with the relay, and read
    /// the relay's handshake information.
    pub async fn connect(mut self) -> Result<UnverifiedChannel<T>> {
        // Send versions cell
        {
            let my_versions = msg::Versions::new(LINK_PROTOCOLS);
            self.tls.write(&my_versions.encode_for_handshake()).await?;
            self.tls.flush().await?;
        }

        // Get versions cell.
        let their_versions: msg::Versions = {
            // TODO: this could be turned into another function, I suppose.
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

        // Determine which link protocol we negotiated.
        let link_protocol = their_versions
            .best_shared_link_protocol(LINK_PROTOCOLS)
            .ok_or_else(|| Error::ChanProto("No shared link protocols".into()))?;

        // Now we can switch to using a "Framed". We can ignore the
        // AsyncRead/AsyncWrite aspects of the tls, and just treat it
        // as a stream and a sink for cells.
        let codec = ChannelCodec::new(link_protocol);
        let mut tls = futures_codec::Framed::new(self.tls, codec);

        // Read until we have the netinfo cells.
        let mut certs: Option<msg::Certs> = None;
        let mut netinfo: Option<msg::Netinfo> = None;
        let mut seen_authchallenge = false;

        // Loop: reject duplicate and unexpected cells
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
                        m.cmd()
                    )))
                }
            }
        }

        // If we have certs and netinfo, we can finish authenticating.
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

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> UnverifiedChannel<T> {
    /// Validate the certificates and keys in the relay's handshake.
    ///
    /// 'peer' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_cert' is the x.509 certificate that the peer presented during
    /// its handshake.
    ///
    /// This is a separate function because it's likely to be somewhat
    /// CPU-intensive.
    pub fn check<U: ChanTarget>(self, peer: &U, peer_cert: &[u8]) -> Result<VerifiedChannel<T>> {
        // TODO: Enable batch verification.
        use tor_cert::CertType;
        use tor_checkable::*;
        // We need to check the following lines of authentication:
        //
        // First, to bind the ed identity to the channel.
        //    peer.ed_identity() matches the key in...
        //    IDENTITY_V_SIGNING cert, which signs...
        //    SIGNING_V_TLS_CERT cert, which signs peer_cert.
        //
        // Second, to bind the rsa identity to the ed identity:
        //    peer.rsa_identity() matches the key in...
        //    the x.509 RSA identity certificate (type 2), which signs...
        //    the RSA->Ed25519 crosscert (type 7), which signs...
        //    peer.ed_identity().

        let c = &self.certs_cell;
        let id_sk = c.parse_ed_cert(CertType::IDENTITY_V_SIGNING)?;
        let sk_tls = c.parse_ed_cert(CertType::SIGNING_V_TLS_CERT)?;

        // Part 1: validate ed25519 stuff.

        // Check the identity->signing cert
        let id_sk = id_sk
            .check_key(&None)?
            .check_signature()
            .map_err(|_| Error::ChanProto("Bad certificate signature".into()))?
            .check_valid_now()
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        // Take the identity key from the identity->signing cert
        let identity_key = id_sk.signing_key().ok_or_else(|| {
            Error::ChanProto("Missing identity key in identity->signing cert".into())
        })?;

        // Take the signing key from the identity->signing cert
        let signing_key = id_sk
            .subject_key()
            .as_ed25519()
            .ok_or_else(|| Error::ChanProto("Bad key type in identity->signing cert".into()))?;

        // Now look at the signing->TLS cert and check it against the
        // peer certificate.
        let sk_tls = sk_tls
            .check_key(&Some(*signing_key))? // this is a bad interface XXXX
            .check_signature()
            .map_err(|_| Error::ChanProto("Bad certificate signature".into()))?
            .check_valid_now()
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        let cert_sha256 = ll::d::Sha256::digest(peer_cert);
        if &cert_sha256[..] != sk_tls.subject_key().as_bytes() {
            return Err(Error::ChanProto(
                "Peer cert did not authenticate TLS cert".into(),
            ));
        }

        // Part 2: validate rsa stuff.

        // What is the RSA identity key, according to the X.509 certificate
        // in which it is self-signed?
        //
        // (We don't actually check this self-signed certificate, and we use
        // a kludge to extract the RSA key)
        let pkrsa = c
            .cert_body(2.into()) // XXX use a constant.
            .map(ll::util::x509_extract_rsa_subject_kludge)
            .flatten()
            .ok_or_else(|| Error::ChanProto("Couldn't find RSA identity key".into()))?;

        // Now verify the RSA identity -> Ed Identity crosscert.
        //
        // This proves that the RSA key vouches for the Ed key.  Note that
        // the Ed key does not vouch for the RSA key: The RSA key is too
        // weak.
        let rsa_cert = c
            .cert_body(7.into()) // XXXX use a constant
            .ok_or_else(|| Error::ChanProto("No RSA->Ed crosscert".into()))?;
        let rsa_cert = tor_cert::rsa::RSACrosscert::decode(rsa_cert)?
            .check_signature(&pkrsa)
            .map_err(|_| Error::ChanProto("Bad RSA->Ed crosscert signature".into()))?
            .check_valid_now()
            .map_err(|_| Error::ChanProto("RSA->Ed crosscert expired or invalid".into()))?;

        if !rsa_cert.subject_key_matches(identity_key) {
            return Err(Error::ChanProto(
                "RSA->Ed crosscert certifies incorrect key".into(),
            ));
        }

        // Now that we've done all the verification steps on the
        // certificates, we know who we are talking to.  It's time to
        // make sure that the peer we are talking to is the peer we
        // actually wanted.
        //
        // We do this _last_, since "this is the wrong peer" is
        // usually a different situation than "this peer couldn't even
        // identify itself right."
        if identity_key != peer.ed_identity() {
            return Err(Error::ChanProto("Peer ed25519 id not as expected".into()));
        }

        if &pkrsa.to_rsa_identity() != peer.rsa_identity() {
            return Err(Error::ChanProto("Peer RSA id not as expected".into()));
        }

        Ok(VerifiedChannel {
            link_protocol: self.link_protocol,
            tls: self.tls,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> VerifiedChannel<T> {
    /// Send a 'Netinfo' message to the relay to finish the handshake,
    /// and create an open channel and reactor.
    ///
    /// The channel is used to send cells, and to create outgoing circuits.
    /// The reactor is used to route incoming messages to their appropriate
    /// circuit.
    pub async fn finish(
        mut self,
        peer_addr: &net::IpAddr,
    ) -> Result<(super::Channel, super::reactor::Reactor<T>)> {
        let netinfo = msg::Netinfo::for_client(*peer_addr);
        self.tls.send(netinfo.into()).await?;

        Ok(super::Channel::new(self.link_protocol, self.tls))
    }
}
