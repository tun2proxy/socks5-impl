use std::{
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::net::{TcpListener, TcpStream};

pub mod auth;
pub mod connection;

use crate::protocol::{AsyncStreamOperation, Request};
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
pub struct Server {
    listener: TcpListener,
    auth: AuthAdaptor,
}

impl Server {
    /// Create a new socks5 server with the given TCP listener and authentication method.
    #[inline]
    pub fn new(listener: TcpListener, auth: AuthAdaptor) -> Self {
        Self { listener, auth }
    }

    /// Create a new socks5 server on the given socket address and authentication method.
    #[inline]
    pub async fn bind(addr: SocketAddr, auth: AuthAdaptor) -> std::io::Result<Self> {
        Self::bind_with_backlog(addr, auth, 1024).await
    }

    pub async fn bind_with_backlog(addr: SocketAddr, auth: AuthAdaptor, backlog: u32) -> std::io::Result<Self> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(backlog)?;
        Ok(Self::new(listener, auth))
    }

    /// Accept an [`IncomingConnection`].
    /// The connection may not be a valid socks5 connection. You need to call
    /// [`IncomingConnection::authenticate`](crate::server::connection::IncomingConnection::authenticate)
    /// to hand-shake it into a proper socks5 connection.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(IncomingConnection, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((IncomingConnection::new(stream, self.auth.clone()), addr))
    }

    /// Polls to accept an [`IncomingConnection`](crate::server::connection::IncomingConnection).
    ///
    /// The connection is only a freshly created TCP connection and may not be a valid SOCKS5 connection.
    /// You should call
    /// [`IncomingConnection::authenticate`](crate::server::connection::IncomingConnection::authenticate)
    /// to perform a SOCKS5 authentication handshake.
    ///
    /// If there is no connection to accept, Poll::Pending is returned and the current task will be notified by a waker.
    /// Note that on multiple calls to poll_accept, only the Waker from the Context passed to the most recent call is scheduled to receive a wakeup.
    #[inline]
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<(IncomingConnection, SocketAddr)>> {
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

impl From<(TcpListener, AuthAdaptor)> for Server {
    #[inline]
    fn from((listener, auth): (TcpListener, AuthAdaptor)) -> Self {
        Self { listener, auth }
    }
}

impl From<Server> for (TcpListener, AuthAdaptor) {
    #[inline]
    fn from(server: Server) -> Self {
        (server.listener, server.auth)
    }
}

pub async fn socks5_service_handshake(mut stream: &mut TcpStream, auth: auth::AuthAdaptor) -> std::io::Result<Request> {
    let request = crate::protocol::handshake::Request::retrieve_from_async_stream(&mut stream).await?;
    let auth_method = auth.auth_method();
    let supported = request.evaluate_method(auth_method);
    let method = if supported {
        auth_method
    } else {
        crate::protocol::AuthMethod::NoAcceptableMethods
    };
    let response = crate::protocol::handshake::Response::new(method);
    response.write_to_async_stream(&mut stream).await?;

    if !supported {
        return Err(std::io::Error::other("no acceptable SOCKS5 authentication method"));
    }

    if !auth.execute(stream).await? {
        return Err(std::io::Error::other("SOCKS5 authentication failed"));
    }

    let req = crate::protocol::Request::retrieve_from_async_stream(&mut stream).await?;
    Ok(req)
}
