use std::{
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::net::TcpListener;

pub mod auth;
pub mod connection;

pub use crate::{
    server::auth::{AuthAdaptor, AuthExecutor},
    server::connection::{
        ClientConnection, IncomingConnection,
        associate::{AssociatedUdpSocket, UdpAssociate},
        bind::Bind,
        connect::Connect,
    },
};

/// The socks5 server itself.
///
/// The server can be constructed on a given socket address, or be created on an existing TcpListener.
///
/// The authentication method can be configured with the
/// [`AuthExecutor`] trait.
pub struct Server<O> {
    listener: TcpListener,
    auth: AuthAdaptor<O>,
}

impl<O: 'static> Server<O> {
    /// Create a new socks5 server with the given TCP listener and authentication method.
    #[inline]
    pub fn new(listener: TcpListener, auth: AuthAdaptor<O>) -> Self {
        Self { listener, auth }
    }

    /// Create a new socks5 server on the given socket address and authentication method.
    #[inline]
    pub async fn bind(addr: SocketAddr, auth: AuthAdaptor<O>) -> std::io::Result<Self> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(1024)?;
        Ok(Self::new(listener, auth))
    }

    /// Accept an [`IncomingConnection`].
    /// The connection may not be a valid socks5 connection. You need to call
    /// [`IncomingConnection::authenticate`](crate::server::connection::IncomingConnection::authenticate)
    /// to hand-shake it into a proper socks5 connection.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(IncomingConnection<O>, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((IncomingConnection::new(stream, self.auth.clone()), addr))
    }

    /// Polls to accept an [`IncomingConnection<O>`](crate::server::connection::IncomingConnection).
    ///
    /// The connection is only a freshly created TCP connection and may not be a valid SOCKS5 connection.
    /// You should call
    /// [`IncomingConnection::authenticate`](crate::server::connection::IncomingConnection::authenticate)
    /// to perform a SOCKS5 authentication handshake.
    ///
    /// If there is no connection to accept, Poll::Pending is returned and the current task will be notified by a waker.
    /// Note that on multiple calls to poll_accept, only the Waker from the Context passed to the most recent call is scheduled to receive a wakeup.
    #[inline]
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<(IncomingConnection<O>, SocketAddr)>> {
        self.listener
            .poll_accept(cx)
            .map_ok(|(stream, addr)| (IncomingConnection::new(stream, self.auth.clone()), addr))
    }

    /// Get the the local socket address binded to this server
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl<O> From<(TcpListener, AuthAdaptor<O>)> for Server<O> {
    #[inline]
    fn from((listener, auth): (TcpListener, AuthAdaptor<O>)) -> Self {
        Self { listener, auth }
    }
}

impl<O> From<Server<O>> for (TcpListener, AuthAdaptor<O>) {
    #[inline]
    fn from(server: Server<O>) -> Self {
        (server.listener, server.auth)
    }
}
