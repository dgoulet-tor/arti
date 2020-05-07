//use crate::rules::*;

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

use ll::traits::Digest;

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
    // TODO: these families can get bulky. Perhaps we should memoize,
    // like Tor does.
    family: RelayFamily,
    platform: Option<RelayPlatform>,
    // TODO: cache these.
    ipv4_policy: AddrPolicy,
    ipv6_policy: PortPolicy,
}

pub struct RelayFamily(Vec<RSAIdentity>);

fn parse_family_ent(mut s: &str) -> Option<RSAIdentity> {
    if s.starts_with('$') {
        s = &s[1..];
    }
    if let Some(idx) = s.find(|ch| ch == '=' || ch == '~') {
        s = &s[..idx];
    }
    let bytes = hex::decode(s).ok()?;
    RSAIdentity::from_bytes(&bytes)
}

pub enum RelayPlatform {
    Tor(TorVersion, String),
    Other(String),
}

decl_keyword! {
    RouterKW {
        "router" => ROUTER,
        "identity-ed25519" => IDENTITY_ED25519,
        "master-key-ed25519" => MASTER_KEY_ED25519,
        "bandwidth" => BANDWIDTH,
        "platform" => PLATFORM,
        "published" => PUBLISHED,
        "fingerprint" => FINGERPRINT,
        "hibernating" => HIBERNATING,
        "uptime" => UPTIME,
        "onion-key" => ONION_KEY,
        "onion-key-crosscert" => ONION_KEY_CROSSCERT,
        "ntor-onion-key" => NTOR_ONION_KEY,
        "ntor-onion-key-crosscert" => NTOR_ONION_KEY_CROSSCERT,
        "signing-key" => SIGNING_KEY,
        "accept" | "reject" => POLICY,
        "ipv6-policy" => IPV6_POLICY,
        "contact" => CONTACT,
        "bridge-distribution-request" => BRIDGE_DISTRIBUTION_REQUEST,
        "family" => FAMILY,
        "caches-extra-info" => CACHES_EXTRA_INFO,
        "extra-info-digest" => EXTRA_INFO_DIGEST,
        "hidden-service-dir" => HIDDEN_SERVICE_DIR,
        // "protocols" obsolete
        // "eventdns" obsolete
        // "allow-single-hop-exits" obsolete
        "or-address" => OR_ADDRESS,
        "tunnelled_dir_server" => TUNNELLED_DIR_SERVER,
        "proto" => PROTO,
        "router-sig-ed25519" => ROUTER_SIG_ED25519,
        "router-signature" => ROUTER_SIGNATURE,
    }
}

impl RouterKW {
    fn is_signature(self) -> bool {
        use RouterKW::*;
        match self {
            ROUTER_SIG_ED25519 | ROUTER_SIGNATURE => true,
            _ => false,
        }
    }
}

lazy_static! {
    static ref ROUTER_HEADER_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        rules.add(ROUTER.rule().required().args(5..));
        rules
    };
    static ref ROUTER_BODY_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        // This is not yet required as of this writing; I'm assuming
        // that proposal 315 will get accepted.
        rules.add(IDENTITY_ED25519.rule().required().no_args().obj_required());
        rules.add(MASTER_KEY_ED25519.rule().args(1..));
        rules.add(BANDWIDTH.rule().required().args(3..)); // todo -- auth only
        rules.add(PLATFORM.rule());
        rules.add(PUBLISHED.rule().required());
        rules.add(FINGERPRINT.rule());
        rules.add(HIBERNATING.rule().args(1..)); //todo -- auth only
        rules.add(UPTIME.rule().args(1..));
        rules.add(ONION_KEY.rule().no_args().required().obj_required());
        rules.add(ONION_KEY_CROSSCERT.rule().no_args().obj_required());
        rules.add(NTOR_ONION_KEY.rule().args(1..));
        rules.add(NTOR_ONION_KEY_CROSSCERT.rule().args(1..=1).obj_required());
        rules.add(SIGNING_KEY.rule().no_args().required().obj_required());
        rules.add(POLICY.rule().may_repeat().args(1..));
        rules.add(IPV6_POLICY.rule().args(2..));
        rules.add(CONTACT.rule()); // todo; ignored for now.
        rules.add(BRIDGE_DISTRIBUTION_REQUEST.rule().args(1..)); // todo; ignored for now. (auth only)
        rules.add(FAMILY.rule().args(1..));
        // "protocols" obsolete
        // "eventdns" obsolete
        // "allow-single-hop-exits" obsolete
        rules.add(CACHES_EXTRA_INFO.rule().no_args());
        rules.add(EXTRA_INFO_DIGEST.rule().args(1..)); // todo; ignored for now
        rules.add(HIDDEN_SERVICE_DIR.rule());
        rules.add(OR_ADDRESS.rule().may_repeat().args(1..));
        rules.add(TUNNELLED_DIR_SERVER.rule());
        rules.add(PROTO.rule().args(1..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };

    static ref ROUTER_SIG_RULES : SectionRules<RouterKW> = {
        use RouterKW::*;

        let mut rules = SectionRules::new();
        rules.add(ROUTER_SIG_ED25519.rule().args(1..));
        rules.add(ROUTER_SIGNATURE.rule().no_args().obj_required());
        rules
    };
}

impl RouterDesc {
    pub fn is_expired_at(&self, when: time::SystemTime) -> bool {
        self.expiry <= when
    }

    fn parse_sections<'a>(
        s: &'a str,
    ) -> Result<(
        Section<'a, RouterKW>,
        Section<'a, RouterKW>,
        Section<'a, RouterKW>,
    )> {
        use crate::util::*;

        let reader = crate::tokenize::NetDocReader::new(s);
        let mut reader =
            reader.pause_at(|item| item.is_ok() && item.as_ref().unwrap().get_kwd() != "router");
        let header = ROUTER_HEADER_RULES.parse(&mut reader)?;

        let mut reader = reader.new_pred(|item| {
            item.is_ok() && (item.as_ref().unwrap().get_kwd() == "router-signature")
                || (item.as_ref().unwrap().get_kwd() == "router-sig-ed25519")
        });
        let body = ROUTER_BODY_RULES.parse(&mut reader)?;

        let mut reader = reader.remaining();
        let sig = ROUTER_SIG_RULES.parse(&mut reader)?;

        Ok((header, body, sig))
    }

    pub fn parse(s: &str) -> Result<RouterDesc> {
        Self::parse_internal(s).map_err(|e| e.within(s))
    }

    fn parse_internal(s: &str) -> Result<RouterDesc> {
        use RouterKW::*;

        let (header, body, sig) = RouterDesc::parse_sections(s)?;

        let start_offset = header.get_required(ROUTER)?.off;

        // ed25519 identity and signing key.
        let (identity_cert, ed25519_signing_key) = {
            let cert_tok = body.get_required(IDENTITY_ED25519)?;
            let cert = cert_tok.get_obj("ED25519 CERT")?;
            let cert = tor_cert::Ed25519Cert::decode_and_check(&cert[..], None)
                .map_err(|_| Error::BadSignature(cert_tok.pos()))?;
            if cert.get_cert_type() != tor_cert::certtype::IDENTITY_V_SIGNING {
                return Err(Error::BadObjectVal(
                    cert_tok.pos(),
                    "wrong certificate type".to_string(),
                ));
            }
            let sk = cert.get_subject_key().as_ed25519().ok_or_else(|| {
                Error::BadObjectVal(cert_tok.pos(), "no ed25519 signing key".to_string())
            })?;
            let sk = *sk;
            (cert, sk)
        };

        // start computing expiry time.
        let mut expiry = identity_cert.get_expiry();

        // Legacy RSA identity
        let rsa_identity = {
            let ident_tok = body.get_required(SIGNING_KEY)?;
            let ident_val = ident_tok.get_obj("RSA PUBLIC KEY")?;
            let k = ll::pk::rsa::PublicKey::from_der(&ident_val).ok_or_else(|| {
                Error::BadObjectVal(ident_tok.pos(), "invalid RSA key".to_string())
            })?;
            if k.bits() != 1024 || !k.exponent_is(65537) {
                return Err(Error::BadObjectVal(
                    ident_tok.pos(),
                    "invalid RSA parameters".to_string(),
                ));
            }
            k
        };

        let ed_sig = sig.get_required(ROUTER_SIG_ED25519)?;
        let rsa_sig = sig.get_required(ROUTER_SIGNATURE)?;

        if ed_sig.off > rsa_sig.off {
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
            let signed_end = ed_sig.off + b"router-sig-ed25519 ".len();
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
            let signed_end = rsa_sig.off + b"router-signature\n".len();
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
        let published = {
            let p_item = body.get_required(PUBLISHED)?;
            let p: ISO8601TimeSp = p_item
                .args_as_str()
                .parse()
                .map_err(|e: ArgError| Error::BadArgument(1, p_item.pos(), e.to_string()))?;
            p.into()
        };

        // ntor key
        // XXXX technically this isn't "required"
        let ntor_onion_key: Curve25519Public = body.get_required(NTOR_ONION_KEY)?.parse_arg(0)?;
        let ntor_onion_key: ll::pk::curve25519::PublicKey = ntor_onion_key.into();
        // ntor crosscert
        {
            // Technically required? XXXX
            let cc = body.get_required(NTOR_ONION_KEY_CROSSCERT)?;
            let sign: u8 = cc.parse_arg(0)?;
            let cert = cc.get_obj("ED25519 CERT")?;
            if sign != 0 && sign != 1 {
                return Err(Error::BadArgument(1, cc.pos(), "not 0 or 1".to_string()));
            }
            let ntor_as_ed =
                ll::pk::keymanip::convert_curve25519_to_ed25519_public(&ntor_onion_key, sign)
                    .ok_or_else(|| Error::Internal(cc.pos()))?; // XXX not really 'internal'
            let crosscert = tor_cert::Ed25519Cert::decode_and_check(&cert[..], Some(&ntor_as_ed))
                .map_err(|_| Error::BadSignature(cc.pos()))?;
            if crosscert.get_cert_type() != tor_cert::certtype::NTOR_CC_IDENTITY {
                return Err(Error::BadObjectVal(
                    cc.pos(),
                    "wrong certificate type".into(),
                ));
            }
            if crosscert.get_subject_key().as_ed25519() != Some(identity_cert.get_signing_key()) {
                return Err(Error::BadSignature(cc.pos()));
            }
            expiry = std::cmp::min(expiry, crosscert.get_expiry());
        }

        // TAP key
        let tap_onion_key = {
            let k_tok = body.get_required(ONION_KEY)?;
            let k_val = k_tok.get_obj("RSA PUBLIC KEY")?;
            let k = ll::pk::rsa::PublicKey::from_der(&k_val)
                .ok_or_else(|| Error::BadObjectVal(k_tok.pos(), "invalid RSA key".to_string()))?;
            if k.bits() != 1024 || !k.exponent_is(65537) {
                return Err(Error::BadObjectVal(
                    k_tok.pos(),
                    "invalid RSA parameters".to_string(),
                ));
            }

            k
        };

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
                .map_err(|e| Error::BadArgument(1, proto_tok.pos(), e.to_string()))?
        };

        // tunneled-dir-server
        let is_dircache = (dirport != 0) || body.get(TUNNELLED_DIR_SERVER).is_some();

        // hidden-service-dir
        let is_hsdir = body.get(HIDDEN_SERVICE_DIR).is_some();

        // caches-extra-info
        let is_extrainfo_cache = body.get(CACHES_EXTRA_INFO).is_some();

        // fingerprint: check for consistency with RSA identity.
        if let Some(fp_tok) = body.get(FINGERPRINT) {
            let fp_val = fp_tok.args_as_str().replace(' ', "");
            let bytes = hex::decode(&fp_val)
                .map_err(|e| Error::BadArgument(1, fp_tok.pos(), e.to_string()))?;
            if bytes != rsa_identity.to_rsa_identity().as_bytes() {
                return Err(Error::BadArgument(
                    1,
                    fp_tok.pos(),
                    "fingerprint does not match RSA identity".into(),
                ));
            }
        }

        // Family
        let family = {
            let mut family = RelayFamily(Vec::new());
            if let Some(fam_tok) = body.get(FAMILY) {
                for (idx, ent) in fam_tok.args().enumerate() {
                    match parse_family_ent(ent) {
                        Some(id) => family.0.push(id),
                        None => {
                            // XXXX are we supposed to ignore this?
                            return Err(Error::BadArgument(
                                idx + 1,
                                fam_tok.pos(),
                                "invalid family member".into(),
                            ));
                        }
                    }
                }
            }
            family
        };

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
        let platform = if let Some(p_tok) = body.get(PLATFORM) {
            let args = p_tok.args_as_str();
            if args.starts_with("Tor ") {
                let v: Vec<_> = args.splitn(4, ' ').collect();
                match &v[..] {
                    ["Tor", ver, "on", p] => {
                        Some(RelayPlatform::Tor(ver.parse()?, (*p).to_string()))
                    }
                    ["Tor", ver, ..] => Some(RelayPlatform::Tor(ver.parse()?, "".to_string())),
                    _ => None,
                }
            } else {
                Some(RelayPlatform::Other(args.to_string()))
            }
        } else {
            None
        };

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
