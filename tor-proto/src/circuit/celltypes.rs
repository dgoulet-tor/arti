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
