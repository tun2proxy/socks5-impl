use self::{associate::UdpAssociate, bind::Bind, connect::Connect};
use crate::{
    protocol::{self, Address, AsyncStreamOperation, AuthMethod, Command, handshake},
    server::AuthAdaptor,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub mod associate;
pub mod bind;
pub mod connect;

/// An incoming connection. This may not be a valid socks5 connection. You need to call [`authenticate()`](#method.authenticate)
/// to perform the socks5 handshake. It will be converted to a proper socks5 connection after the handshake succeeds.
pub struct IncomingConnection {
    stream: TcpStream,
    auth: AuthAdaptor,
}

impl IncomingConnection {
    #[inline]
    pub fn new(stream: TcpStream, auth: AuthAdaptor) -> Self {
        IncomingConnection { stream, auth }
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Shutdown the TCP stream.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see
    /// [`set_nodelay`](#method.set_nodelay).
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.stream.nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that segments are always sent as soon as possible,
    /// even if there is only a small amount of data. When not set, data is buffered until there is a sufficient amount
    /// to send out, thereby avoiding the frequent sending of small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_ttl`](#method.set_ttl).
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.stream.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.stream.set_ttl(ttl)
    }

    /// Set a timeout for the SOCKS5 handshake.
    pub async fn authenticate_with_timeout(self, timeout: Duration) -> crate::Result<Authenticated> {
        tokio::time::timeout(timeout, self.authenticate())
            .await
            .map_err(|_| crate::Error::String("handshake timeout".into()))?
    }

    /// Perform a SOCKS5 authentication handshake using the given
    /// [`AuthExecutor`](crate::server::auth::AuthExecutor) adapter.
    ///
    /// If the handshake succeeds, an [`Authenticated`] stream is returned.
    /// Otherwise, the error and the original [`TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html) is returned.
    ///
    /// Note that this method will not implicitly close the connection even if the handshake failed.
    pub async fn authenticate(mut self) -> crate::Result<Authenticated> {
        let request = handshake::Request::retrieve_from_async_stream(&mut self.stream).await?;
        if let Some(method) = self.evaluate_request(&request) {
            let response = handshake::Response::new(method);
            response.write_to_async_stream(&mut self.stream).await?;
            if !self.auth.execute(&mut self.stream).await? {
                use std::io::{Error, ErrorKind::PermissionDenied};
                return Err(crate::Error::Io(Error::new(PermissionDenied, "authentication failed")));
            }
            Ok(Authenticated::new(self.stream))
        } else {
            let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
            response.write_to_async_stream(&mut self.stream).await?;
            let err = "No available handshake method provided by client";
            Err(crate::Error::Io(std::io::Error::new(std::io::ErrorKind::Unsupported, err)))
        }
    }

    fn evaluate_request(&self, req: &handshake::Request) -> Option<AuthMethod> {
        let method = self.auth.auth_method();
        if req.evaluate_method(method) { Some(method) } else { None }
    }
}

impl std::fmt::Debug for IncomingConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingConnection").field("stream", &self.stream).finish()
    }
}

impl From<IncomingConnection> for TcpStream {
    #[inline]
    fn from(conn: IncomingConnection) -> Self {
        conn.stream
    }
}

/// A TCP stream that has been authenticated.
///
/// To get the command from the SOCKS5 client, use
/// [`wait_request`](crate::server::connection::Authenticated::wait_request).
///
/// It can also be converted back into a raw [`tokio::TcpStream`](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html) with `From` trait.
pub struct Authenticated(TcpStream);

impl Authenticated {
    #[inline]
    fn new(stream: TcpStream) -> Self {
        Self(stream)
    }

    /// Waits the SOCKS5 client to send a request.
    ///
    /// This method will return a [`Command`] if the client sends a valid command.
    ///
    /// When encountering an error, the stream will be returned alongside the error.
    ///
    /// Note that this method will not implicitly close the connection even if the client sends an invalid request.
    pub async fn wait_request(mut self) -> crate::Result<ClientConnection> {
        let req = protocol::Request::retrieve_from_async_stream(&mut self.0).await?;

        match req.command {
            Command::UdpAssociate => Ok(ClientConnection::UdpAssociate(
                UdpAssociate::<associate::NeedReply>::new(self.0),
                req.address,
            )),
            Command::Bind => Ok(ClientConnection::Bind(Bind::<bind::NeedFirstReply>::new(self.0), req.address)),
            Command::Connect => Ok(ClientConnection::Connect(Connect::<connect::NeedReply>::new(self.0), req.address)),
        }
    }

    /// Causes the other peer to receive a read of length 0, indicating that no more data will be sent. This only closes the stream in one direction.
    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.shutdown().await
    }

    /// Returns the local address that this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see
    /// [`set_nodelay`](crate::server::connection::Authenticated::set_nodelay).
    #[inline]
    pub fn nodelay(&self) -> std::io::Result<bool> {
        self.0.nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that segments are always sent as soon as possible,
    /// even if there is only a small amount of data. When not set, data is buffered until there is a sufficient amount to send out,
    /// thereby avoiding the frequent sending of small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_ttl`](crate::server::connection::Authenticated::set_ttl).
    pub fn ttl(&self) -> std::io::Result<u32> {
        self.0.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.0.set_ttl(ttl)
    }
}

impl From<Authenticated> for TcpStream {
    #[inline]
    fn from(conn: Authenticated) -> Self {
        conn.0
    }
}

/// After the socks5 handshake succeeds, the connection may become:
///
/// - Associate
/// - Bind
/// - Connect
#[derive(Debug)]
pub enum ClientConnection {
    UdpAssociate(UdpAssociate<associate::NeedReply>, Address),
    Bind(Bind<bind::NeedFirstReply>, Address),
    Connect(Connect<connect::NeedReply>, Address),
}
