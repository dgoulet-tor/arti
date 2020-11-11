//! Testing stubs for the channel manager code.  Only enabled
//! with `cfg(test)`.

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::{Error, Result};
use tor_linkspec::ChanTarget;
use tor_llcrypto::pk::rsa::RSAIdentity;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct FakeChannel {
    chan: Arc<FakeChannelInner>,
}

#[derive(Debug)]
pub(crate) struct FakeChannelInner {
    closing: AtomicBool,
    want_rsa_id: Option<RSAIdentity>,
    addr: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct FakeChannelBuilder {
    addr: Option<SocketAddr>,
}

#[derive(Debug)]
pub(crate) struct FakeReactor {}

impl FakeChannelBuilder {
    pub fn new() -> Self {
        FakeChannelBuilder { addr: None }
    }
    pub fn set_declared_addr(&mut self, addr: SocketAddr) {
        self.addr = Some(addr);
    }
    pub fn launch<T>(self, _ignore: T) -> FakeChannel {
        FakeChannel::new(self.addr.unwrap())
    }
}

impl FakeChannel {
    pub fn new(addr: SocketAddr) -> Self {
        let inner = FakeChannelInner {
            closing: false.into(),
            want_rsa_id: None,
            addr,
        };
        FakeChannel {
            chan: Arc::new(inner),
        }
    }
    pub async fn connect(self) -> Result<Self> {
        Ok(self)
    }
    pub fn same_channel(&self, other: &FakeChannel) -> bool {
        Arc::ptr_eq(&self.chan, &other.chan)
    }
    pub fn check<T: ChanTarget>(self, _target: &T, _cert: &[u8]) -> Result<Self> {
        if self.chan.addr.port() == 8686 {
            Err(tor_proto::Error::ChanProto("86ed".into()).into())
        } else {
            Ok(self)
        }
    }
    pub(crate) async fn finish(self) -> Result<(Self, FakeReactor)> {
        Ok((self, FakeReactor {}))
    }
    pub async fn is_closing(&self) -> bool {
        self.chan.closing.load(Ordering::SeqCst)
    }
    pub fn mark_closing(&self) {
        self.chan.closing.store(true, Ordering::SeqCst)
    }
    pub async fn check_match<T: ChanTarget>(&self, target: &T) -> Result<()> {
        if let Some(ref id) = self.chan.want_rsa_id {
            if id != target.rsa_identity() {
                return Err(Error::UnusableTarget("Wrong RSA".into()).into());
            }
        }
        Ok(())
    }

    pub fn new_ref(&self) -> Self {
        FakeChannel {
            chan: Arc::clone(&self.chan),
        }
    }
}

impl FakeReactor {
    pub async fn run(self) -> Result<()> {
        Ok(())
    }
}
