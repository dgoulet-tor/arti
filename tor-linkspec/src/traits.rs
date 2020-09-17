use std::net::SocketAddr;
use tor_llcrypto::pk;

/// Information about a Tor relay used to connect to it.
///
/// Anything that implements 'ChanTarget' can be used as the
/// identity of a relay for the purposes of launching a new
/// channel.
pub trait ChanTarget {
    /// Return the addresses at which you can connect to this relay
    // TODO: bad API
    fn get_addrs(&self) -> &[SocketAddr];
    /// Return the ed25519 identity for this relay.
    fn get_ed_identity(&self) -> &pk::ed25519::PublicKey;
    /// Return the RSA identity for this relay.
    fn get_rsa_identity(&self) -> &pk::rsa::RSAIdentity;
}

/// Information about a Tor relay used to extend a circuit to it.
///
/// Anything that implements 'ExtendTarget' can be used as the
/// identity of a relay for the purposes of extending a circuit.
pub trait ExtendTarget: ChanTarget {
    /// Return a new vector of link specifiers for this relay.
    // TODO: bad API
    fn get_linkspecs(&self) -> Vec<crate::LinkSpec> {
        let mut result = Vec::new();
        result.push(self.get_ed_identity().clone().into());
        result.push(self.get_rsa_identity().clone().into());
        for addr in self.get_addrs().iter() {
            result.push(addr.into());
        }
        result
    }
    /// Return the ntor onion key for this relay
    fn get_ntor_onion_key(&self) -> &pk::curve25519::PublicKey;
    /// Return the subprotocols implemented by this relay.
    fn get_protovers(&self) -> &tor_protover::Protocols;
}
