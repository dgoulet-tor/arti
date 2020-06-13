//! Parsing implementation for Tor authority certificates
//!
//! An "authority certificate" is a short signed document that binds a
//! directory authority's permanent "identity key" to its medium-term
//! "signing key".  Using separate keys here enables the authorities
//! to keep their identity keys securely offline, while using the
//! signing keys to sign votes and consensuses.

use crate::argtype::{ISO8601TimeSp, RSAPublic};
use crate::err::Pos;
use crate::keyword::Keyword;
use crate::parse::SectionRules;
use crate::tokenize::{ItemResult, NetDocReader};
use crate::{Error, Result};

use tor_llcrypto::d;
use tor_llcrypto::pk::rsa;

use lazy_static::lazy_static;

use std::{net, time};

use digest::Digest;

decl_keyword! {
    AuthCertKW {
        "dir-key-certificate-version" => DIR_KEY_CERTIFICATE_VERSION,
        "dir-address" => DIR_ADDRESS,
        "fingerprint" => FINGERPRINT,
        "dir-identity-key" => DIR_IDENTITY_KEY,
        "dir-key-published" => DIR_KEY_PUBLISHED,
        "dir-key-expires" => DIR_KEY_EXPIRES,
        "dir-signing-key" => DIR_SIGNING_KEY,
        "dir-key-crosscert" => DIR_KEY_CROSSCERT,
        "dir-key-certification" => DIR_KEY_CERTIFICATION,
    }
}

lazy_static! {
    static ref AUTHCERT_RULES: SectionRules<AuthCertKW> = {
        use AuthCertKW::*;

        let mut rules = SectionRules::new();
        rules.add(DIR_KEY_CERTIFICATE_VERSION.rule().required().args(1..));
        rules.add(DIR_ADDRESS.rule().args(1..));
        rules.add(FINGERPRINT.rule().required().args(1..));
        rules.add(DIR_IDENTITY_KEY.rule().required().no_args().obj_required());
        rules.add(DIR_SIGNING_KEY.rule().required().no_args().obj_required());
        rules.add(DIR_KEY_PUBLISHED.rule().required());
        rules.add(DIR_KEY_EXPIRES.rule().required());
        rules.add(DIR_KEY_CROSSCERT.rule().required().no_args().obj_required());
        rules.add(
            DIR_KEY_CERTIFICATION
                .rule()
                .required()
                .no_args()
                .obj_required(),
        );
        rules
    };
}

/// A single authority certificate
#[allow(dead_code)]
pub struct AuthCert {
    address: Option<net::SocketAddrV4>,
    identity_key: rsa::PublicKey,
    signing_key: rsa::PublicKey,
    published: time::SystemTime,
    expires: time::SystemTime,
}

impl AuthCert {
    /// Parse an authority certificate from a string.
    ///
    /// This function verifies the certificate's signatures, but doesn't
    /// check its expiration dates.
    pub fn parse(s: &str) -> Result<AuthCert> {
        let mut reader = NetDocReader::new(s);
        let result = AuthCert::take_from_reader(&mut reader).map_err(|e| e.within(s));
        reader.should_be_exhausted()?;
        result
    }

    /// Return true if this certificate is expired at a given time, or
    /// not yet valid at that time.
    pub fn is_expired_at(&self, when: time::SystemTime) -> bool {
        when < self.published || when > self.expires
    }

    /// Parse an authority certificate from a reader.
    fn take_from_reader(reader: &mut NetDocReader<'_, AuthCertKW>) -> Result<AuthCert> {
        use AuthCertKW::*;

        let mut start_found = false;
        let mut iter = reader.pause_at(|item| {
            let is_start = item.is_ok_with_kwd(DIR_KEY_CERTIFICATE_VERSION);
            let pause = is_start && start_found;
            if is_start {
                start_found = true;
            }
            pause
        });
        let body = AUTHCERT_RULES.parse(&mut iter)?;

        // Make sure first and last element are correct types.  We can
        // safely call unwrap() on first and last, since there are required
        // tokens in the rules, so we know that at least one token will have
        // been parsed.
        if body.first_item().unwrap().get_kwd() != DIR_KEY_CERTIFICATE_VERSION {
            // TODO: this is not the best possible error.
            return Err(Error::MissingToken("onion-key"));
        }
        if body.last_item().unwrap().get_kwd() != DIR_KEY_CERTIFICATION {
            // TODO: this is not the best possible error.
            return Err(Error::MissingToken("dir-key-certification"));
        }

        let version = body
            .get_required(DIR_KEY_CERTIFICATE_VERSION)?
            .get_arg(0)
            .unwrap();
        if version != "3" {
            // TODO Better error needed
            return Err(Error::Internal(Pos::None));
        }

        let signing_key: rsa::PublicKey = body
            .get_required(DIR_SIGNING_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let identity_key: rsa::PublicKey = body
            .get_required(DIR_IDENTITY_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let published = body
            .get_required(DIR_KEY_PUBLISHED)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();

        let expires = body
            .get_required(DIR_KEY_EXPIRES)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();

        // TODO: Check fingerprint.

        let address = body
            .maybe(DIR_ADDRESS)
            .parse_args_as_str::<net::SocketAddrV4>()?;

        // check crosscert
        {
            let crosscert = body.get_required(DIR_KEY_CROSSCERT)?;
            let mut tag = crosscert.get_obj_tag().unwrap();
            // we are required to support both.
            if tag != "ID SIGNATURE" && tag != "SIGNATURE" {
                tag = "ID SIGNATURE";
            }
            let sig = crosscert.get_obj(tag)?;

            let signed = identity_key.to_rsa_identity();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.
            let verified = signing_key.verify(signed.as_bytes(), &sig);
            if verified.is_err() {
                return Err(Error::BadSignature(crosscert.pos()));
            }
        }

        // check the signature
        {
            let signature = body.get_required(DIR_KEY_CERTIFICATION)?;
            let sig = signature.get_obj("SIGNATURE")?;

            let mut sha1 = d::Sha1::new();
            let s = reader.str();
            let start_offset = body.first_item().unwrap().offset_in(s).unwrap();
            let end_offset = body.last_item().unwrap().offset_in(s).unwrap();
            let end_offset = end_offset + "dir-key-certification\n".len();
            sha1.update(&s[start_offset..end_offset]);
            let sha1 = sha1.finalize();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.
            let verified = identity_key.verify(&sha1, &sig);
            if verified.is_err() {
                return Err(Error::BadSignature(signature.pos()));
            }
        }

        Ok(AuthCert {
            address,
            identity_key,
            signing_key,
            published,
            expires,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const TESTDATA: &str = include_str!("../testdata/authcert1.txt");

    #[test]
    fn parse_one() -> Result<()> {
        let _rd = AuthCert::parse(TESTDATA)?;

        Ok(())
    }
}
