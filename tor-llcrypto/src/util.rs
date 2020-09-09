//! Utilities for cryptographic purposes
//!
//! For now, this just has a workaround for some other libraries'
//! lack of full x509 support

use simple_asn1::{oid, ASN1Block, BigUint, OID};

/// Given an X.509 certificate, return its SubjectPublicKey if that key
/// is an RSA key.
///
/// WARNING: Does not validate the X.509 certificate at all!
///
/// XXXXX This is a massive kludge.
pub fn x509_extract_rsa_subject_kludge(der: &[u8]) -> Option<crate::pk::rsa::PublicKey> {
    //use ASN1Block::*;
    let blocks = simple_asn1::from_der(der).ok()?;
    let block = Asn1(blocks.get(0)?);
    // TBSCertificate
    let tbs_cert: Asn1 = block.into_seq()?.get(0)?.into();
    // SubjectPublicKeyInfo
    let spki: Asn1 = tbs_cert.into_seq()?.get(6)?.into();
    let spki_members = spki.into_seq()?;
    // Is it an RSA key?
    let algid: Asn1 = spki_members.get(0)?.into();
    let oid: Asn1 = algid.into_seq()?.get(0)?.into();
    oid.must_be_rsa_oid()?;

    // try to get the RSA key.
    let key: Asn1 = spki_members.get(1)?.into();
    crate::pk::rsa::PublicKey::from_der(key.to_bitstr()?)
}

struct Asn1<'a>(&'a ASN1Block);
impl<'a> From<&'a ASN1Block> for Asn1<'a> {
    fn from(b: &'a ASN1Block) -> Asn1<'a> {
        Asn1(b)
    }
}
impl<'a> Asn1<'a> {
    fn into_seq(self) -> Option<&'a [ASN1Block]> {
        match self.0 {
            ASN1Block::Sequence(_, ref s) => Some(s),
            _ => None,
        }
    }
    fn must_be_rsa_oid(self) -> Option<()> {
        let oid = match self.0 {
            ASN1Block::ObjectIdentifier(_, ref oid) => Some(oid),
            _ => None,
        }?;
        if oid == oid!(1, 2, 840, 113549, 1, 1, 1) {
            Some(())
        } else {
            None
        }
    }
    fn to_bitstr(&self) -> Option<&[u8]> {
        match self.0 {
            ASN1Block::BitString(_, _, ref v) => Some(&v[..]),
            _ => None,
        }
    }
}
