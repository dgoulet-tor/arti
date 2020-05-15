//! Parsing implementation for Tor router descriptors.
//!
//! A "router descriptor" is a signed statment that a relay makes
//! about itself, explaining its keys, its capabilities, its location,
//! and its status.
//!
//! Relays upload their router descriptors to authorities, which use
//! them to build consensus documents.  Old clients and relays used to
//! fetch and use router descriptors for all the relays, but nowadays they use
//! microdescriptors instead.
//!
//! Clients still use router descriptors when communicating with
//! bridges: since bridges are not passed through an authority,
//! clients accept their descriptors directly.
//!
//! For full information about the router descriptor format, see
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! # Limitations
//!
//! TODO: This needs to get tested much more!
//!
//! TODO: This implementation can be memory-inefficient.  In practice,
//! it gets really expensive storing policy entries, family
//! descriptions, parsed keys, and things like that.  We will probably want to
//! de-duplicate those.
//!
//! TODO: There should be accessor functions for some or all of the
//! fields in RouterDesc.  I'm deferring those until I know what they
//! should be.
use crate::argtype::*;
use crate::parse::{Section, SectionRules};
use crate::policy::*;
use crate::rules::Keyword;
use crate::version::TorVersion;
use crate::{Error, Result};

use lazy_static::lazy_static;
use std::{net, time};
use tor_llcrypto as ll;
use tor_llcrypto::pk::rsa::RSAIdentity;

use digest::Digest;

/// Information about a relay, parsed from a router descriptor.
///
/// This type does not hold all the information in the router descriptor
///
/// # Limitations
///
/// See module documentation.
///
/// Additionally, some fields that from router descriptors are not yet
/// parsed: see the comments in ROUTER_BODY_RULES for information about those.
///
/// Before using this type to connect to a relay, you MUST check that
/// it is valid, using is_expired_at().
#[allow(dead_code)] // don't warn about fields not getting read.
pub struct RouterDesc {
    nickname: String,
    ipv4addr: Option<net::Ipv4Addr>,
    orport: u16,
    ipv6addr: Option<(net::Ipv6Addr, u16)>, // we don't use a socketaddrv6 because we don't care about the flow and scope fields.
    dirport: u16,
    uptime: Option<u64>,
    published: time::SystemTime,
    identity_cert: tor_cert::Ed25519Cert,
    rsa_identity: ll::pk::rsa::PublicKey,
    ntor_onion_key: ll::pk::curve25519::PublicKey,
    tap_onion_key: ll::pk::rsa::PublicKey,
    expiry: std::time::SystemTime,
    proto: tor_protover::Protocols,
    is_dircache: bool,
    is_hsdir: bool,
    is_extrainfo_cache: bool,
    // TODO: these families can get bulky. Perhaps we should de-duplicate
    // them in a cache, like Tor does.
    family: Option<RelayFamily>,
    platform: Option<RelayPlatform>,
    // TODO: these polices can get bulky too. Perhaps we should
    // de-duplicate them too.
    ipv4_policy: AddrPolicy,
    ipv6_policy: PortPolicy,
}

/// Information about a relay family.
///
/// Tor relays may declare that they belong to the same family, to
/// indicate that they are controlled by the same party or parties,
/// and as such should not be used in the same circuit. Two relays
/// belong to the same family if and only if each one lists the other
/// as belonging to its family.
///
/// TODO: This type probably belongs in a different crate.
pub struct RelayFamily(Vec<RSAIdentity>);

impl std::str::FromStr for RelayFamily {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v: Result<Vec<RSAIdentity>> = s
            .split(crate::tokenize::is_sp)
            .map(|e| e.parse::<LongIdent>().map(|v| v.into()))
            .collect();
        Ok(RelayFamily(v?))
    }
}

/// Description of the software a relay is running.
pub enum RelayPlatform {
    /// Software advertised to be some version of Tor, on some platform.
    Tor(TorVersion, String),
    /// Software not advertised to be Tor.
    Other(String),
}

impl std::str::FromStr for RelayPlatform {
    type Err = Error;
    fn from_str(args: &str) -> Result<Self> {
        if args.starts_with("Tor ") {
            let v: Vec<_> = args.splitn(4, ' ').collect();
            match &v[..] {
                ["Tor", ver, "on", p] => Ok(RelayPlatform::Tor(ver.parse()?, (*p).to_string())),
                ["Tor", ver, ..] => Ok(RelayPlatform::Tor(ver.parse()?, "".to_string())),
                _ => unreachable!(),
            }
        } else {
            Ok(RelayPlatform::Other(args.to_string()))
        }
    }
}

decl_keyword! {
    /// RouterKW is an instance of Keyword, used to denote the different
    /// Items that are recognized as appearing in a router descriptor.
    RouterKW {
        "accept" | "reject" => POLICY,
        "bandwidth" => BANDWIDTH,
        "bridge-distribution-request" => BRIDGE_DISTRIBUTION_REQUEST,
        "caches-extra-info" => CACHES_EXTRA_INFO,
        "contact" => CONTACT,
        "extra-info-digest" => EXTRA_INFO_DIGEST,
        "family" => FAMILY,
        "fingerprint" => FINGERPRINT,
        "hibernating" => HIBERNATING,
        "hidden-service-dir" => HIDDEN_SERVICE_DIR,
        "identity-ed25519" => IDENTITY_ED25519,
        "ipv6-policy" => IPV6_POLICY,
        "master-key-ed25519" => MASTER_KEY_ED25519,
        "ntor-onion-key" => NTOR_ONION_KEY,
        "ntor-onion-key-crosscert" => NTOR_ONION_KEY_CROSSCERT,
        "onion-key" => ONION_KEY,
        "onion-key-crosscert" => ONION_KEY_CROSSCERT,
        "or-address" => OR_ADDRESS,
        "platform" => PLATFORM,
        "proto" => PROTO,
        "published" => PUBLISHED,
        "router" => ROUTER,
        "router-sig-ed25519" => ROUTER_SIG_ED25519,
        "router-signature" => ROUTER_SIGNATURE,
        "signing-key" => SIGNING_KEY,
        "tunnelled_dir_server" => TUNNELLED_DIR_SERVER,
        "uptime" => UPTIME,
        // "protocols" once existed, but is obsolete
        // "eventdns" once existed, but is obsolete
        // "allow-single-hop-exits" is also obsolete.
    }
}

lazy_static! {
    /// Rules for tokens that are allowed in the first part of a
    /// router descriptor.
    static ref ROUTER_HEADER_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        rules.add(ROUTER.rule().required().args(5..));
        // IDENTITY_ED25519 is not yet required as of this writing;
        // I'm assuming that proposal 315 will get accepted.
        rules.add(IDENTITY_ED25519.rule().required().no_args().obj_required());
        rules
    };
    /// Rules for  tokens that are allowed in the first part of a
    /// router descriptor.
    static ref ROUTER_BODY_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        rules.add(MASTER_KEY_ED25519.rule().args(1..));
        rules.add(PLATFORM.rule());
        rules.add(PUBLISHED.rule().required());
        rules.add(FINGERPRINT.rule());
        rules.add(UPTIME.rule().args(1..));
        rules.add(ONION_KEY.rule().no_args().required().obj_required());
        rules.add(ONION_KEY_CROSSCERT.rule().no_args().obj_required());
        rules.add(NTOR_ONION_KEY.rule().args(1..));
        rules.add(NTOR_ONION_KEY_CROSSCERT.rule().args(1..=1).obj_required());
        rules.add(SIGNING_KEY.rule().no_args().required().obj_required());
        rules.add(POLICY.rule().may_repeat().args(1..));
        rules.add(IPV6_POLICY.rule().args(2..));
        rules.add(FAMILY.rule().args(1..));
        rules.add(CACHES_EXTRA_INFO.rule().no_args());
        rules.add(HIDDEN_SERVICE_DIR.rule());
        rules.add(OR_ADDRESS.rule().may_repeat().args(1..));
        rules.add(TUNNELLED_DIR_SERVER.rule());
        rules.add(PROTO.rule().args(1..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        // TODO: these aren't parsed yet.  Only authorities use them.
        {
            rules.add(BANDWIDTH.rule().required().args(3..));
            rules.add(BRIDGE_DISTRIBUTION_REQUEST.rule().args(1..));
            rules.add(HIBERNATING.rule().args(1..));
            rules.add(CONTACT.rule());
        }
        // TODO: this is ignored for now.
        {
            rules.add(EXTRA_INFO_DIGEST.rule().args(1..));
        }
        rules
    };

    /// Rules for items that appear at the end of a router descriptor.
    static ref ROUTER_SIG_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        rules.add(ROUTER_SIG_ED25519.rule().args(1..));
        rules.add(ROUTER_SIGNATURE.rule().no_args().obj_required());
        rules
    };
}

impl RouterDesc {
    /// Return true iff this router descriptor is expired.
    ///
    /// The check is performed under the assumption that the current
    /// time is `when`.
    pub fn is_expired_at(&self, when: time::SystemTime) -> bool {
        self.expiry <= when
    }

    /// Helper: tokenize `s`, and divide it into three validated sections.
    fn parse_sections<'a>(
        s: &'a str,
    ) -> Result<(
        Section<'a, RouterKW>,
        Section<'a, RouterKW>,
        Section<'a, RouterKW>,
    )> {
        use crate::util::*;

        let reader = crate::tokenize::NetDocReader::new(s);

        // Parse everything up through the header.
        let mut reader = reader.pause_at(|item| {
            item.is_ok()
                && item.as_ref().unwrap().get_kwd() != "router"
                && item.as_ref().unwrap().get_kwd() != "identity-ed25519"
        });
        let header = ROUTER_HEADER_RULES.parse(&mut reader)?;

        // Parse everything up to but not including the signature.
        let mut reader = reader.new_pred(|item| {
            item.is_ok() && (item.as_ref().unwrap().get_kwd() == "router-signature")
                || (item.as_ref().unwrap().get_kwd() == "router-sig-ed25519")
        });
        let body = ROUTER_BODY_RULES.parse(&mut reader)?;

        // Parse the signature.
        let mut reader = reader.remaining();
        let sig = ROUTER_SIG_RULES.parse(&mut reader)?;

        Ok((header, body, sig))
    }

    /// Try to parse `s` as a router descriptor.
    ///
    /// # Limitations
    ///
    /// This function does too much and too little.  It validates all
    /// the signatures in the descriptor, which is too much for a
    /// parsing function, but it doesn't check the expiration time,
    /// because it doesn't know it.
    ///
    /// I would prefer that this function would instead return some
    /// kind of object that could only be used as a router descriptor
    /// after the signatures and expiration were checked.  But that's
    /// future work for now, partially because of limitations in the
    /// ed25519 API.
    pub fn parse(s: &str) -> Result<RouterDesc> {
        Self::parse_internal(s).map_err(|e| e.within(s))
    }

    /// Helper: parse a router descriptor from `s`.
    ///
    /// This function does the same as parse(), but returns errors based on
    /// byte-wise positions.  The parse() function converts such errors
    /// into line-and-byte positions.
    fn parse_internal(s: &str) -> Result<RouterDesc> {
        // TODO: This function is too long!  The little "paragraphs" here
        // that parse one item at a time should be made into sub-functions.
        use RouterKW::*;

        let (header, body, sig) = RouterDesc::parse_sections(s)?;

        let start_offset = header.get_required(ROUTER)?.offset_in(s).unwrap();

        // ed25519 identity and signing key.
        let (identity_cert, ed25519_signing_key) = {
            let cert_tok = header.get_required(IDENTITY_ED25519)?;
            if cert_tok.offset_in(s).unwrap() < start_offset {
                return Err(Error::MisplacedToken("identity-ed25519", cert_tok.pos()));
            }
            let cert: tor_cert::Ed25519Cert = cert_tok
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .validate(None)?
                .check_cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)?
                .into();
            let sk = cert.get_subject_key().as_ed25519().ok_or_else(|| {
                Error::BadObjectVal(cert_tok.pos(), "no ed25519 signing key".to_string())
            })?;
            let sk = *sk;
            (cert, sk)
        };

        // start computing expiry time.
        let mut expiry = identity_cert.get_expiry();

        // Legacy RSA identity
        let rsa_identity: ll::pk::rsa::PublicKey = body
            .get_required(SIGNING_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len_eq(1024)?
            .check_exponent(65537)?
            .into();

        let ed_sig = sig.get_required(ROUTER_SIG_ED25519)?;
        let rsa_sig = sig.get_required(ROUTER_SIGNATURE)?;
        let ed_sig_pos = ed_sig.offset_in(s).unwrap();
        let rsa_sig_pos = rsa_sig.offset_in(s).unwrap();

        if ed_sig_pos > rsa_sig_pos {
            return Err(Error::UnexpectedToken(
                ROUTER_SIG_ED25519.to_str(),
                ed_sig.pos(),
            ));
        }

        //  Check ed25519 signature.
        {
            let mut d = ll::d::Sha256::new();
            // XXXX spec is ambiguous whether this prefix goes on
            // before or after taking the hash.
            d.input(&b"Tor router descriptor signature v1"[..]);
            let signed_end = ed_sig_pos + b"router-sig-ed25519 ".len();
            d.input(&s[start_offset..signed_end]);
            let d = d.result();
            let sig: B64 = ed_sig.parse_arg(0)?;
            let sig = ll::pk::ed25519::Signature::from_bytes(sig.as_bytes())
                .map_err(|_| Error::BadSignature(ed_sig.pos()))?;

            let verified = ed25519_signing_key.verify(&d, &sig);
            assert!(verified.is_ok());
            if verified.is_err() {
                return Err(Error::BadSignature(ed_sig.pos()));
            }
        }

        // Check legacy RSA signature.
        {
            let mut d = ll::d::Sha1::new();
            let signed_end = rsa_sig_pos + b"router-signature\n".len();
            d.input(&s[start_offset..signed_end]);
            let d = d.result();
            let sig = rsa_sig.get_obj("SIGNATURE")?;
            let verified = rsa_identity.verify(&d, &sig);
            if verified.is_err() {
                return Err(Error::BadSignature(rsa_sig.pos()));
            }
        }

        //
        // Okay, if we reach this point we've checked the signatures on the
        // document.  Let's move forward and parse the rest.
        //

        // router nickname ipv4addr orport socksport dirport
        let (nickname, ipv4addr, orport, dirport) = {
            let rtrline = header.get_required(ROUTER)?;
            (
                rtrline.get_arg(0).unwrap().to_string(),
                Some(rtrline.parse_arg::<net::Ipv4Addr>(1)?),
                rtrline.parse_arg(2)?,
                // Skipping socksport.
                rtrline.parse_arg(4)?,
            )
        };

        // uptime
        let uptime = body.maybe(UPTIME).parse_arg(0)?;

        // published time.
        let published = body
            .get_required(PUBLISHED)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();

        // ntor key
        // XXXX technically this isn't "required"
        let ntor_onion_key: Curve25519Public = body.get_required(NTOR_ONION_KEY)?.parse_arg(0)?;
        let ntor_onion_key: ll::pk::curve25519::PublicKey = ntor_onion_key.into();
        // ntor crosscert
        {
            // Technically required? XXXX
            let cc = body.get_required(NTOR_ONION_KEY_CROSSCERT)?;
            let sign: u8 = cc.parse_arg(0)?;
            if sign != 0 && sign != 1 {
                return Err(Error::BadArgument(cc.arg_pos(0), "not 0 or 1".to_string()));
            }
            let ntor_as_ed =
                ll::pk::keymanip::convert_curve25519_to_ed25519_public(&ntor_onion_key, sign)
                    .ok_or_else(|| Error::Internal(cc.pos()))?; // XXX not really 'internal'
            let crosscert: tor_cert::Ed25519Cert = cc
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .validate(Some(&ntor_as_ed))?
                .check_cert_type(tor_cert::CertType::NTOR_CC_IDENTITY)?
                .check_subject_key_is(identity_cert.get_signing_key())?
                .into();
            expiry = std::cmp::min(expiry, crosscert.get_expiry());
        }

        // TAP key
        let tap_onion_key: ll::pk::rsa::PublicKey = body
            .get_required(ONION_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len_eq(1024)?
            .check_exponent(65537)?
            .into();

        // TAP crosscert
        {
            // not offically required yet xxxx
            let cc_tok = body.get_required(ONION_KEY_CROSSCERT)?;
            let cc_val = cc_tok.get_obj("CROSSCERT")?;
            let mut signed = Vec::new();
            signed.extend(rsa_identity.to_rsa_identity().as_bytes());
            signed.extend(identity_cert.get_signing_key().as_bytes());
            let verified = tap_onion_key.verify(&signed[..], &cc_val[..]);
            if verified.is_err() {
                return Err(Error::BadSignature(cc_tok.pos()));
            }
        }

        // Protocols: treat these as required. (XXXX)
        let proto = {
            let proto_tok = body.get_required(PROTO)?;
            proto_tok
                .args_as_str()
                .parse::<tor_protover::Protocols>()
                .map_err(|e| Error::BadArgument(proto_tok.pos(), e.to_string()))?
        };

        // tunneled-dir-server
        let is_dircache = (dirport != 0) || body.get(TUNNELLED_DIR_SERVER).is_some();

        // hidden-service-dir
        let is_hsdir = body.get(HIDDEN_SERVICE_DIR).is_some();

        // caches-extra-info
        let is_extrainfo_cache = body.get(CACHES_EXTRA_INFO).is_some();

        // fingerprint: check for consistency with RSA identity.
        if let Some(fp_tok) = body.get(FINGERPRINT) {
            let fp: RSAIdentity = fp_tok.args_as_str().parse::<SpFingerprint>()?.into();
            if fp != rsa_identity.to_rsa_identity() {
                return Err(Error::BadArgument(
                    fp_tok.pos(),
                    "fingerprint does not match RSA identity".into(),
                ));
            }
        }

        // Family
        let family = body.maybe(FAMILY).parse_args_as_str::<RelayFamily>()?;

        // or-address
        // Extract at most one ipv6 address from the list.  It's not great,
        // but it's what Tor does.
        let mut ipv6addr = None;
        for tok in body.get_slice(OR_ADDRESS) {
            if let Ok(net::SocketAddr::V6(a)) = tok.parse_arg::<net::SocketAddr>(0) {
                ipv6addr = Some((*a.ip(), a.port()));
                break;
            }
            // We skip over unparseable addresses. Is that right?
        }

        // platform
        let platform = body.maybe(PLATFORM).parse_args_as_str::<RelayPlatform>()?;

        // ipv4_policy
        let ipv4_policy = {
            let mut pol = AddrPolicy::new();
            for ruletok in body.get_slice(POLICY).iter() {
                let accept = ruletok.get_kwd() == "accept";
                let pat: AddrPortPattern = ruletok
                    .args_as_str()
                    .parse()
                    .map_err(|e| Error::BadPolicy(ruletok.pos(), e))?;
                pol.push(accept, pat);
            }
            pol
        };

        // ipv6 policy
        let ipv6_policy = match body.get(IPV6_POLICY) {
            Some(p) => p
                .args_as_str()
                .parse()
                .map_err(|e| Error::BadPolicy(p.pos(), e))?,
            None => "reject 1-65535".parse::<PortPolicy>().unwrap(),
        };

        Ok(RouterDesc {
            nickname,
            ipv4addr,
            orport,
            ipv6addr,
            dirport,
            uptime,
            published,
            identity_cert,
            rsa_identity,
            ntor_onion_key,
            tap_onion_key,
            expiry,
            proto,
            is_dircache,
            is_hsdir,
            is_extrainfo_cache,
            family,
            platform,
            ipv4_policy,
            ipv6_policy,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const TESTDATA: &str = include_str!("../testdata/routerdesc1.txt");

    #[test]
    fn parse_arbitrary() {
        let rd = RouterDesc::parse(TESTDATA).unwrap();

        assert_eq!(rd.nickname, "idun2");
        assert_eq!(rd.orport, 9001);
        assert_eq!(rd.dirport, 0);

        assert_eq!(rd.uptime, Some(1828391));
        //assert_eq!(rd.platform.unwrap(), "Tor 0.4.2.6 on Linux");
    }
}
