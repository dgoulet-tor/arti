//! Implements a simple mock network for testing purposes.

// Note: There are lots of opportunities here for making the network
// more and more realistic, but please remember that this module only
// exists for writing unit tests.  Let's resist the temptation to add
// things we don't need.

use super::io::{stream_pair, LocalStream};
use crate::traits::*;

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::lock::Mutex as AsyncMutex;
use futures::sink::SinkExt;
use futures::stream::{Stream, StreamExt};
use futures::FutureExt;
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use thiserror::Error;

/// A channel sender that we use to send incoming connections to
/// listeners.
type ConnSender = mpsc::Sender<(LocalStream, SocketAddr)>;
/// A channel receiver that listeners use to receive incoming connections.
type ConnReceiver = mpsc::Receiver<(LocalStream, SocketAddr)>;

/// A simulated Internet, for testing.
///
/// We simulate TCP streams only, and skip all the details. Connection
/// are implemented using [`LocalStream`]. The MockNetwork object is
/// shared by a large set of MockNetworkProviders, each of which has
/// its own view of its address(es) on the network.
pub struct MockNetwork {
    /// A map from address to the  senders that need to be informed
    /// about connection attempts there.
    listening: Mutex<HashMap<SocketAddr, ConnSender>>,
}

/// A view of a single host's access to a MockNetwork.
///
/// Each simulated host has its own addresses that it's allowed to listen on,
/// and a reference to the network.
///
/// This type implements [`TCPProvider`] so that it can be used as a
/// drop-in replacement for testing code that uses the network.
///
/// # Limitations
///
/// There's no randomness here, so we can't simulate the weirdness of
/// real networks.
///
/// So far, there's no support for DNS or UDP.
///
/// We don't handle localhost specially, and we don't simulate providers
/// that can connect to some addresses but not all.
///
/// We use a simple `u16` counter to decide what arbitrary port
/// numbers to use: Once that counter is exhausted, we will fail with
/// an assertion.  We don't do anything to prevent those arbitrary
/// ports from colliding with specified ports, other than declare that
/// you can't have two listeners on the same addr:port at the same
/// time.
pub struct MockNetProvider {
    /// Actual implementation of this host's view of the network.
    ///
    /// We have to use a separate type here and refrence count it,
    /// since the `next_port` counter needs to be shared.
    inner: Arc<MockNetProviderInner>,
}

/// Shared part of a MockNetworkProvider.
///
/// This is separate because providers need to implement Clone, but
/// `next_port` can't be cloned.
struct MockNetProviderInner {
    /// List of public addresses
    addrs: Vec<IpAddr>,
    /// Shared reference to the network.
    net: Arc<MockNetwork>,
    /// Next port number to hand out when we're asked to listen on
    /// port 0.
    ///
    /// See discussion of limitations on `listen()` implementation.
    next_port: AtomicU16,
}

/// A [`TCPListener`] implementation returned by a [`MockNetProvider`].
///
/// Represents listening on a public address for incoming TCP connections.
pub struct MockNetListener {
    /// The address that we're listening on.
    addr: SocketAddr,
    /// The incoming channnnel that tells us about new connections.
    // TODO: I'm not thrilled to have to use an AsyncMutex and a
    // std Mutex in the same module.
    receiver: AsyncMutex<ConnReceiver>,
}

/// A builder object used to configure a [`MockNetworkProvider`]
///
/// Returned by [`MockNetwork::builder()`].
pub struct ProviderBuilder {
    /// The provider that we're building.
    inner: MockNetProviderInner,
}

impl MockNetwork {
    /// Make a new MockNetwork with no active listeners.
    pub fn new() -> Arc<Self> {
        Arc::new(MockNetwork {
            listening: Mutex::new(HashMap::new()),
        })
    }

    /// Return a [`ProviderBuilder`] for creating a [`MockNetProvider`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use tor_rtcompat::mock::net::*;
    /// # let mock_network = MockNetwork::new();
    /// let mut builder = mock_network.builder();
    /// builder.add_address("198.51.100.6".parse().unwrap());
    /// builder.add_address("2001:db8::7".parse().unwrap());
    /// let client = builder.finish();
    /// ```
    pub fn builder(self: &Arc<Self>) -> ProviderBuilder {
        let inner = MockNetProviderInner {
            addrs: vec![],
            net: Arc::clone(self),
            next_port: AtomicU16::new(1),
        };
        ProviderBuilder { inner }
    }

    /// Tell the listener at `target_addr` (if any) about an incoming
    /// connection from `source_addr` at `peer_stream`.
    ///
    /// Returns an error if there isn't any such listener.
    async fn send_connection(
        &self,
        source_addr: SocketAddr,
        target_addr: SocketAddr,
        peer_stream: LocalStream,
    ) -> IoResult<()> {
        let sender = {
            let listener_map = self.listening.lock().unwrap();
            listener_map.get(&target_addr).map(Clone::clone)
        };
        if let Some(mut sender) = sender {
            if sender.send((peer_stream, source_addr)).await.is_ok() {
                return Ok(());
            }
        }
        Err(err(ErrorKind::ConnectionRefused))
    }

    /// Register a listener at `addr` and return the ConnReceiver
    /// that it should use for connections.
    ///
    /// Returns an error if the address is alrady in use.
    fn add_listener(&self, addr: SocketAddr) -> IoResult<ConnReceiver> {
        let mut listener_map = self.listening.lock().unwrap();
        if listener_map.contains_key(&addr) {
            // TODO: Maybe this should ignore dangling Weak references?
            return Err(err(ErrorKind::AddrInUse));
        }

        let (send, recv) = mpsc::channel(16);

        listener_map.insert(addr, send);

        Ok(recv)
    }
}

impl ProviderBuilder {
    /// Add `addr` as a new address for the prrovider we're building.
    pub fn add_address(&mut self, addr: IpAddr) {
        self.inner.addrs.push(addr);
    }
    /// Consume this builder and return a new [`MockNetProvider`]
    pub fn finish(self) -> MockNetProvider {
        MockNetProvider {
            inner: Arc::new(self.inner),
        }
    }
}

#[async_trait]
impl TcpListener for MockNetListener {
    type TcpStream = LocalStream;

    type Incoming = Self;

    async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)> {
        let mut receiver = self.receiver.lock().await;
        receiver
            .next()
            .await
            .ok_or_else(|| err(ErrorKind::BrokenPipe))
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.addr)
    }

    fn incoming(self) -> Self {
        self
    }
}

impl Stream for MockNetListener {
    type Item = IoResult<(LocalStream, SocketAddr)>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut recv = futures::ready!(self.receiver.lock().poll_unpin(cx));
        match recv.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(v)) => Poll::Ready(Some(Ok(v))),
        }
    }
}

impl MockNetProvider {
    /// If we have a local addresses that is in the same family as `other`,
    /// return it.
    fn get_addr_in_family(&self, other: &IpAddr) -> Option<IpAddr> {
        self.inner
            .addrs
            .iter()
            .find(|a| a.is_ipv4() == other.is_ipv4())
            .copied()
    }

    /// Return an arbitrary port number that we haven't returned from
    /// this function before.
    ///
    /// # Panics
    ///
    /// We panic if we run out of unused port numbers here.
    fn arbitrary_port(&self) -> u16 {
        let next = self.inner.next_port.fetch_add(1, Ordering::Relaxed);
        assert!(next != 0);
        next
    }

    /// Helper for connecting: Picks the socketaddr to use
    /// when told to connect to `addr`.
    ///
    /// The IP is one of our own IPs with the same family as `addr`.
    /// The port is a port that we haven't used as an arbitrary port
    /// before.
    fn get_origin_addr_for(&self, addr: &SocketAddr) -> IoResult<SocketAddr> {
        let my_addr = self
            .get_addr_in_family(&addr.ip())
            .ok_or_else(|| err(ErrorKind::AddrNotAvailable))?;
        Ok(SocketAddr::new(my_addr, self.arbitrary_port()))
    }

    /// Helper for binding a listener: Picks the socketaddr to use
    /// when told to bind to `addr`.
    ///
    /// If addr is `0.0.0.0` or `[::]`, then we pick one of our own
    /// addresses with the same family. Otherwise we fail unless `addr` is
    /// one of our own addresses.
    ///
    /// If port is 0, we pick a new arbitrary port we haven't used as
    /// an arbitrary port before.
    fn get_listener_addr(&self, spec: &SocketAddr) -> IoResult<SocketAddr> {
        let ipaddr = {
            let ip = spec.ip();
            if ip.is_unspecified() {
                self.get_addr_in_family(&ip)
                    .ok_or_else(|| err(ErrorKind::AddrNotAvailable))?
            } else if self.inner.addrs.iter().any(|a| a == &ip) {
                ip
            } else {
                return Err(err(ErrorKind::AddrNotAvailable));
            }
        };
        let port = {
            if spec.port() == 0 {
                self.arbitrary_port()
            } else {
                spec.port()
            }
        };

        Ok(SocketAddr::new(ipaddr, port))
    }
}

#[async_trait]
impl TcpProvider for MockNetProvider {
    type TcpStream = LocalStream;
    type TcpListener = MockNetListener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<LocalStream> {
        let my_addr = self.get_origin_addr_for(addr)?;
        let (mine, theirs) = stream_pair();

        self.inner
            .net
            .send_connection(my_addr, *addr, theirs)
            .await?;

        Ok(mine)
    }

    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        let addr = self.get_listener_addr(addr)?;

        let receiver = AsyncMutex::new(self.inner.net.add_listener(addr)?);

        Ok(MockNetListener { addr, receiver })
    }
}

/// Inner error type returned when a `MockNetwork` operation fails.
#[derive(Clone, Error, Debug)]
#[non_exhaustive]
pub enum MockNetError {
    /// General-purpose error.  The real information is in `ErrorKind`.
    #[error("Invalid operation on mock network")]
    BadOp,
}

/// Wrap `k` in a new [`std::io::Error`].
fn err(k: ErrorKind) -> IoError {
    IoError::new(k, MockNetError::BadOp)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_with_runtime;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn end_to_end() -> IoResult<()> {
        let net = MockNetwork::new();
        let client1 = {
            let mut builder = net.builder();
            builder.add_address("192.0.2.55".parse().unwrap());
            builder.finish()
        };
        let client2 = {
            let mut builder = net.builder();
            builder.add_address("198.51.100.7".parse().unwrap());
            builder.finish()
        };

        test_with_runtime(|_rt| async {
            let lis = client2.listen(&"0.0.0.0:99".parse().unwrap()).await?;
            let address = lis.local_addr()?;

            let (r1, r2): (IoResult<()>, IoResult<()>) = futures::join!(
                async {
                    let mut conn = client1.connect(&address).await?;
                    conn.write_all(b"This is totally a network.").await?;
                    conn.close().await?;

                    // Nobody listening here...
                    let a2 = "192.0.2.200:99".parse().unwrap();
                    let cant_connect = client1.connect(&a2).await;
                    assert!(cant_connect.is_err());
                    Ok(())
                },
                async {
                    let (mut conn, a) = lis.accept().await?;
                    assert_eq!(a.ip(), "192.0.2.55".parse::<IpAddr>().unwrap());
                    let mut inp = Vec::new();
                    conn.read_to_end(&mut inp).await?;
                    assert_eq!(&inp[..], &b"This is totally a network."[..]);
                    Ok(())
                }
            );
            r1?;
            r2?;
            Ok(())
        })
    }

    #[test]
    fn pick_listener_addr() -> IoResult<()> {
        let net = MockNetwork::new();
        let ip4 = "192.0.2.55".parse().unwrap();
        let ip6 = "2001:db8::7".parse().unwrap();
        let client = {
            let mut builder = net.builder();
            builder.add_address(ip4);
            builder.add_address(ip6);
            builder.finish()
        };

        // Successful cases
        let a1 = client.get_listener_addr(&"0.0.0.0:99".parse().unwrap())?;
        assert_eq!(a1.ip(), ip4);
        assert_eq!(a1.port(), 99);
        let a2 = client.get_listener_addr(&"192.0.2.55:100".parse().unwrap())?;
        assert_eq!(a2.ip(), ip4);
        assert_eq!(a2.port(), 100);
        let a3 = client.get_listener_addr(&"192.0.2.55:0".parse().unwrap())?;
        assert_eq!(a3.ip(), ip4);
        assert!(a3.port() != 0);
        let a4 = client.get_listener_addr(&"0.0.0.0:0".parse().unwrap())?;
        assert_eq!(a4.ip(), ip4);
        assert!(a4.port() != 0);
        assert!(a4.port() != a3.port());
        let a5 = client.get_listener_addr(&"[::]:99".parse().unwrap())?;
        assert_eq!(a5.ip(), ip6);
        assert_eq!(a5.port(), 99);
        let a6 = client.get_listener_addr(&"[2001:db8::7]:100".parse().unwrap())?;
        assert_eq!(a6.ip(), ip6);
        assert_eq!(a6.port(), 100);

        // Failing cases
        let e1 = client.get_listener_addr(&"192.0.2.56:0".parse().unwrap());
        let e2 = client.get_listener_addr(&"[2001:db8::8]:0".parse().unwrap());
        assert!(e1.is_err());
        assert!(e2.is_err());

        Ok(())
    }

    #[test]
    fn listener_stream() -> IoResult<()> {
        // XXXX some copy-paste here on the setup.
        let net = MockNetwork::new();
        let client1 = {
            let mut builder = net.builder();
            builder.add_address("192.0.2.55".parse().unwrap());
            builder.finish()
        };
        let client2 = {
            let mut builder = net.builder();
            builder.add_address("198.51.100.7".parse().unwrap());
            builder.finish()
        };

        test_with_runtime(|_rt| async {
            let lis = client2.listen(&"0.0.0.0:99".parse().unwrap()).await?;
            let address = lis.local_addr()?;
            let mut incoming = lis.incoming();

            let (r1, r2): (IoResult<()>, IoResult<()>) = futures::join!(
                async {
                    for _ in 0..3_u8 {
                        let mut c = client1.connect(&address).await?;
                        c.close().await?;
                    }
                    Ok(())
                },
                async {
                    for _ in 0..3_u8 {
                        let (mut c, a) = incoming.next().await.unwrap()?;
                        let mut v = Vec::new();
                        let _ = c.read_to_end(&mut v).await?;
                        assert_eq!(a.ip(), "192.0.2.55".parse::<IpAddr>().unwrap());
                    }
                    Ok(())
                }
            );
            r1?;
            r2?;
            Ok(())
        })
    }
}
