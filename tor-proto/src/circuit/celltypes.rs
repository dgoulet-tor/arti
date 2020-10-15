//! Wrapper types for subsets of ChanMsg and RelayMsg types.
//!
//! These wrappers define types that are valid in response to particular
//! request, or when received in particular circumstances.  They're used
//! so that Rust's typesafety can help enforce protocol properties.

use crate::{Error, Result};
use tor_cell::chancell::msg::{self as chanmsg, ChanMsg};

use std::convert::TryFrom;

/// A subclass of ChanMsg that can arrive in response to a CREATE* cell
/// that we send.
pub(crate) enum CreateResponse {
    /// Destroy cell: the CREATE failed.
    Destroy(chanmsg::Destroy),
    /// CreatedFast: good response to a CREATE cell.
    CreatedFast(chanmsg::CreatedFast),
    /// Created2: good response to a CREATE2 cell.
    Created2(chanmsg::Created2),
}

impl TryFrom<ChanMsg> for CreateResponse {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<CreateResponse> {
        match m {
            ChanMsg::Destroy(m) => Ok(CreateResponse::Destroy(m)),
            ChanMsg::CreatedFast(m) => Ok(CreateResponse::CreatedFast(m)),
            ChanMsg::Created2(m) => Ok(CreateResponse::Created2(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} in response to circuit creation",
                m.cmd()
            ))),
        }
    }
}

/// A subclass of ChanMsg that can correctly arrive on a live client
/// circuit (one where a CREATED* has been received).
pub(crate) enum ClientCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    // Note: RelayEarly is not valid for clients!
}

impl TryFrom<ChanMsg> for ClientCircChanMsg {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<ClientCircChanMsg> {
        match m {
            ChanMsg::Destroy(m) => Ok(ClientCircChanMsg::Destroy(m)),
            ChanMsg::Relay(m) => Ok(ClientCircChanMsg::Relay(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} cell on an open circuit",
                m.cmd()
            ))),
        }
    }
}
