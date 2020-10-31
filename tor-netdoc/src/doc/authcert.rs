//! Parsing implementation for Tor authority certificates
//!
//! An "authority certificate" is a short signed document that binds a
//! directory authority's permanent "identity key" to its medium-term
//! "signing key".  Using separate keys here enables the authorities
//! to keep their identity keys securely offline, while using the
//! signing keys to sign votes and consensuses.

use crate::parse::keyword::Keyword;
use crate::parse::parser::SectionRules;
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::types::misc::{Fingerprint, ISO8601TimeSp, RSAPublic};
use crate::util::str::Extent;
use crate::{Error, Result};

use tor_checkable::{signed, timed};
use tor_llcrypto::pk::rsa;
use tor_llcrypto::{d, pk, pk::rsa::RSAIdentity};

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

/// A single authority certificate.
///
/// Authority certificates bind a long-term RSA identity key from a
/// directory authority to a medium-term signing key.  The signing
/// keys are the ones used to sign votes and consensuses; the identity
/// keys can be kept offline.
#[allow(dead_code)]
#[derive(Clone)]
pub struct AuthCert {
    /// Where we found this AuthCert within the string containing it.
    ///
    /// (Perhaps this field should be within some other wrapper type?)
    location: Option<Extent>,

    /// An IPv4 address for this authority.
    address: Option<net::SocketAddrV4>,
    /// The long-term RSA identity key for this authority
    identity_key: rsa::PublicKey,
    /// The medium-term RSA signing key for this authority
    signing_key: rsa::PublicKey,
    /// Declared time when this certificate was published
    published: time::SystemTime,
    /// Declared time when this certificate expires.
    expires: time::SystemTime,

    /// Derived field: fingerprint of identity key
    id_fingerprint: rsa::RSAIdentity,
    /// Derived field: fingerprint of signing key
    sk_fingerprint: rsa::RSAIdentity,
}

/// An authority certificate whose signature and validity time we
/// haven't checked.
pub type UncheckedAuthCert = signed::SignatureGated<timed::TimerangeBound<AuthCert>>;

impl AuthCert {
    /// Parse an authority certificate from a string.
    ///
    /// This function verifies the certificate's signatures, but doesn't
    /// check its expiration dates.
    pub fn parse(s: &str) -> Result<UncheckedAuthCert> {
        let mut reader = NetDocReader::new(s);
        let result = AuthCert::take_from_reader(&mut reader).map_err(|e| e.within(s));
        reader.should_be_exhausted()?;
        result
    }

    /// Return an iterator yielding authority certificates from a string.
    pub fn parse_multiple(s: &str) -> impl Iterator<Item = Result<UncheckedAuthCert>> + '_ {
        AuthCertIterator(NetDocReader::new(s))
    }
    /*
        /// Return true if this certificate is expired at a given time, or
        /// not yet valid at that time.
        pub fn is_expired_at(&self, when: time::SystemTime) -> bool {
            when < self.published || when > self.expires
        }
    */
    /// Return the signing key certified by this certificate.
    pub fn signing_key(&self) -> &rsa::PublicKey {
        &self.signing_key
    }

    /// Return an RSAIdentity for this certificate's identity key.
    pub fn id_fingerprint(&self) -> &rsa::RSAIdentity {
        &self.id_fingerprint
    }

    /// Return an RSAIdentity for this certificate's signing key.
    pub fn sk_fingerprint(&self) -> &rsa::RSAIdentity {
        &self.sk_fingerprint
    }

    /// If this AuthCert was originally parsed from `haystack`, return its
    /// text.
    ///
    /// TODO: This is a pretty bogus interface; there should be a
    /// better way to remember where to look for this thing if we want
    /// it without keeping the input alive forever.  We should
    /// refactor.
    pub fn within<'a>(&self, haystack: &'a str) -> Option<&'a str> {
        self.location
            .as_ref()
            .map(|ext| ext.reconstruct(haystack))
            .flatten()
    }

    /// Parse an authority certificate from a reader.
    fn take_from_reader(reader: &mut NetDocReader<'_, AuthCertKW>) -> Result<UncheckedAuthCert> {
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
        let start_pos = {
            let first_item = body.first_item().unwrap();
            if first_item.kwd() != DIR_KEY_CERTIFICATE_VERSION {
                return Err(Error::WrongStartingToken(
                    first_item.kwd_str().into(),
                    first_item.pos(),
                ));
            }
            first_item.pos()
        };
        let end_pos = {
            let last_item = body.last_item().unwrap();
            if last_item.kwd() != DIR_KEY_CERTIFICATION {
                return Err(Error::WrongEndingToken(
                    last_item.kwd_str().into(),
                    last_item.pos(),
                ));
            }
            last_item.end_pos()
        };

        let version = body
            .required(DIR_KEY_CERTIFICATE_VERSION)?
            .parse_arg::<u32>(0)?;
        if version != 3 {
            return Err(Error::BadDocumentVersion(version));
        }

        let signing_key: rsa::PublicKey = body
            .required(DIR_SIGNING_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let identity_key: rsa::PublicKey = body
            .required(DIR_IDENTITY_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let published = body
            .required(DIR_KEY_PUBLISHED)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();

        let expires = body
            .required(DIR_KEY_EXPIRES)?
            .args_as_str()
            .parse::<ISO8601TimeSp>()?
            .into();

        {
            // Check fingerprint for consistency with key.
            let fp_tok = body.required(FINGERPRINT)?;
            let fingerprint: RSAIdentity = fp_tok.args_as_str().parse::<Fingerprint>()?.into();
            if fingerprint != identity_key.to_rsa_identity() {
                return Err(Error::BadArgument(
                    fp_tok.pos(),
                    "fingerprint does not match RSA identity".into(),
                ));
            }
        }

        let address = body
            .maybe(DIR_ADDRESS)
            .parse_args_as_str::<net::SocketAddrV4>()?;

        // check crosscert
        let v_crosscert = {
            let crosscert = body.required(DIR_KEY_CROSSCERT)?;
            let mut tag = crosscert.obj_tag().unwrap();
            // we are required to support both.
            if tag != "ID SIGNATURE" && tag != "SIGNATURE" {
                tag = "ID SIGNATURE";
            }
            let sig = crosscert.obj(tag)?;

            let signed = identity_key.to_rsa_identity();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            rsa::ValidatableRSASignature::new(&signing_key, &sig, signed.as_bytes())
        };

        // check the signature
        let v_sig = {
            let signature = body.required(DIR_KEY_CERTIFICATION)?;
            let sig = signature.obj("SIGNATURE")?;

            let mut sha1 = d::Sha1::new();
            let s = reader.str();
            let start_offset = body.first_item().unwrap().offset_in(s).unwrap();
            let end_offset = body.last_item().unwrap().offset_in(s).unwrap();
            let end_offset = end_offset + "dir-key-certification\n".len();
            sha1.update(&s[start_offset..end_offset]);
            let sha1 = sha1.finalize();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            rsa::ValidatableRSASignature::new(&identity_key, &sig, &sha1)
        };

        let id_fingerprint = identity_key.to_rsa_identity();
        let sk_fingerprint = signing_key.to_rsa_identity();

        let location = {
            let s = reader.str();
            let start_idx = start_pos.offset_within(s);
            let end_idx = end_pos.offset_within(s);
            match (start_idx, end_idx) {
                (Some(a), Some(b)) => Extent::new(s, &s[a..b + 1]),
                _ => None,
            }
        };

        let authcert = AuthCert {
            location,
            address,
            identity_key,
            signing_key,
            published,
            expires,
            id_fingerprint,
            sk_fingerprint,
        };

        let mut signatures: Vec<Box<dyn pk::ValidatableSignature>> = Vec::new();
        signatures.push(Box::new(v_crosscert));
        signatures.push(Box::new(v_sig));

        let timed = timed::TimerangeBound::new(authcert, published..expires);
        let signed = signed::SignatureGated::new(timed, signatures);
        Ok(signed)
    }

    /// Skip tokens from the reader until the next token (if any) is
    /// the start of cert.
    fn advance_reader_to_next(reader: &mut NetDocReader<'_, AuthCertKW>) {
        use AuthCertKW::*;
        let iter = reader.iter();
        while let Some(Ok(item)) = iter.peek() {
            if item.kwd() == DIR_KEY_CERTIFICATE_VERSION {
                return;
            }
            iter.next();
        }
    }
}

/// Iterator type to read a series of concatenated certificates from a
/// string.
struct AuthCertIterator<'a>(NetDocReader<'a, AuthCertKW>);

impl<'a> Iterator for AuthCertIterator<'a> {
    type Item = Result<UncheckedAuthCert>;
    fn next(&mut self) -> Option<Result<UncheckedAuthCert>> {
        if self.0.is_exhausted() {
            return None;
        }

        let pos_orig = self.0.pos();
        let result = AuthCert::take_from_reader(&mut self.0);
        if result.is_err() {
            if self.0.pos() == pos_orig {
                // No tokens were consumed from the reader.  We need
                // to drop at least one token to ensure we aren't in
                // an infinite loop.
                //
                // (This might not be able to happen, but it's easier to
                // explicitly catch this case than it is to prove that
                // it's impossible.)
                let _ = self.0.iter().next();
            }
            AuthCert::advance_reader_to_next(&mut self.0);
        }
        Some(result.map_err(|e| e.within(self.0.str())))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Error, Pos};
    const TESTDATA: &str = include_str!("../../testdata/authcert1.txt");

    fn bad_data(fname: &str) -> String {
        use std::fs;
        use std::path::PathBuf;
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("testdata");
        path.push("bad-certs");
        path.push(fname);

        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn parse_one() -> Result<()> {
        use tor_checkable::{SelfSigned, Timebound};
        let _rd = AuthCert::parse(TESTDATA)?
            .check_signature()
            .unwrap()
            .dangerously_assume_timely();

        Ok(())
    }

    #[test]
    fn parse_bad() {
        fn check(fname: &str, err: Error) {
            let contents = bad_data(fname);
            let cert = AuthCert::parse(&contents);
            assert!(cert.is_err());
            assert_eq!(cert.err().unwrap(), err);
        }

        check("bad-cc-tag", Error::WrongObject(Pos::from_line(27, 12)));
        check(
            "bad-fingerprint",
            Error::BadArgument(
                Pos::from_line(2, 1),
                "fingerprint does not match RSA identity".into(),
            ),
        );
        check("bad-version", Error::BadDocumentVersion(4));
        check(
            "wrong-end",
            Error::WrongEndingToken("dir-key-crosscert".into(), Pos::from_line(37, 1)),
        );
        check(
            "wrong-start",
            Error::WrongStartingToken("fingerprint".into(), Pos::from_line(1, 1)),
        );
    }

    #[test]
    fn test_recovery_1() {
        let mut data = "<><><<><>\nfingerprint ABC\n".to_string();
        data += TESTDATA;

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_recovery_2() {
        let mut data = bad_data("bad-version");
        data += TESTDATA;

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }
}
