use crate::{
    error::{Error, Result},
    protocol::{Address, AddressType, AuthMethod, Command, Reply, StreamOperation, UserKey, Version},
};
use async_trait::async_trait;
use std::{
    fmt::Debug,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpStream, UdpSocket},
};

#[async_trait]
pub trait Socks5Reader: AsyncReadExt + Unpin {
    async fn read_version(&mut self) -> Result<()> {
        let value = Version::try_from(self.read_u8().await?)?;
        match value {
            Version::V4 => Err(Error::WrongVersion),
            Version::V5 => Ok(()),
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        let value = AuthMethod::from(self.read_u8().await?);
        match value {
            AuthMethod::NoAuth | AuthMethod::UserPass => Ok(value),
            _ => Err(Error::InvalidAuthMethod(value)),
        }
    }

    async fn read_command(&mut self) -> Result<Command> {
        let value = self.read_u8().await?;
        Ok(Command::try_from(value)?)
    }

    async fn read_atyp(&mut self) -> Result<AddressType> {
        let value = self.read_u8().await?;
        Ok(AddressType::try_from(value)?)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_fragment_id(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        if value == 0x00 {
            Ok(())
        } else {
            Err(Error::InvalidFragmentId(value))
        }
    }

    async fn read_reply(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        match Reply::try_from(value)? {
            Reply::Succeeded => Ok(()),
            reply => Err(format!("{}", reply).into()),
        }
    }

    async fn read_address(&mut self) -> Result<Address> {
        let atyp = self.read_atyp().await?;
        let addr = match atyp {
            AddressType::IPv4 => {
                let mut ip = [0; 4];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                Address::from((Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                let mut ip = [0; 16];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                Address::from((Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                let str = self.read_string().await?;
                let port = self.read_u16().await?;
                Address::from((str, port))
            }
        };

        Ok(addr)
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.read_u8().await? as usize;
        let mut str = vec![0; len];
        self.read_exact(&mut str).await?;
        let str = String::from_utf8(str)?;
        Ok(str)
    }

    async fn read_auth_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        if value != 0x01 {
            return Err(Error::InvalidAuthSubnegotiation(value));
        }
        Ok(())
    }

    async fn read_auth_status(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        if value != 0x00 {
            return Err(Error::InvalidAuthStatus(value));
        }
        Ok(())
    }

    async fn read_selection_msg(&mut self) -> Result<AuthMethod> {
        self.read_version().await?;
        self.read_method().await
    }

    async fn read_final(&mut self) -> Result<Address> {
        self.read_version().await?;
        self.read_reply().await?;
        self.read_reserved().await?;
        let addr = self.read_address().await?;
        Ok(addr)
    }
}

#[async_trait]
impl<T: AsyncReadExt + Unpin> Socks5Reader for T {}

#[async_trait]
pub trait Socks5Writer: AsyncWriteExt + Unpin {
    async fn write_version(&mut self) -> Result<()> {
        self.write_u8(0x05).await?;
        Ok(())
    }

    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        self.write_u8(u8::from(method)).await?;
        Ok(())
    }

    async fn write_command(&mut self, command: Command) -> Result<()> {
        self.write_u8(u8::from(command)).await?;
        Ok(())
    }

    async fn write_atyp(&mut self, atyp: AddressType) -> Result<()> {
        self.write_u8(u8::from(atyp)).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_fragment_id(&mut self, id: u8) -> Result<()> {
        self.write_u8(id).await?;
        Ok(())
    }

    async fn write_address(&mut self, address: &Address) -> Result<()> {
        match address {
            Address::SocketAddress(SocketAddr::V4(addr)) => {
                self.write_atyp(AddressType::IPv4).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            Address::SocketAddress(SocketAddr::V6(addr)) => {
                self.write_atyp(AddressType::IPv6).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            Address::DomainAddress(domain, port) => {
                self.write_atyp(AddressType::Domain).await?;
                self.write_string(domain).await?;
                self.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, string: &str) -> Result<()> {
        let bytes = string.as_bytes();
        if bytes.len() > 255 {
            return Err("Too long string".into());
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(*method).await?;
        }
        Ok(())
    }

    async fn write_selection_msg(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_version().await?;
        self.write_methods(methods).await?;
        self.flush().await?;
        Ok(())
    }

    async fn write_final(&mut self, command: Command, addr: &Address) -> Result<()> {
        self.write_version().await?;
        self.write_command(command).await?;
        self.write_reserved().await?;
        self.write_address(addr).await?;
        self.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl<T: AsyncWriteExt + Unpin> Socks5Writer for T {}

async fn username_password_auth<S>(stream: &mut S, auth: &UserKey) -> Result<()>
where
    S: Socks5Writer + Socks5Reader + Send,
{
    stream.write_auth_version().await?;
    stream.write_string(&auth.username).await?;
    stream.write_string(&auth.password).await?;
    stream.flush().await?;

    stream.read_auth_version().await?;
    stream.read_auth_status().await
}

async fn init<S, A>(stream: &mut S, command: Command, addr: A, auth: Option<UserKey>) -> Result<Address>
where
    S: Socks5Writer + Socks5Reader + Send,
    A: Into<Address>,
{
    let addr: Address = addr.into();

    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::NoAuth);
    if auth.is_some() {
        methods.push(AuthMethod::UserPass);
    }
    stream.write_selection_msg(&methods).await?;
    stream.flush().await?;

    let method: AuthMethod = stream.read_selection_msg().await?;
    match method {
        AuthMethod::NoAuth => {}
        // FIXME: until if let in match is stabilized
        AuthMethod::UserPass if auth.is_some() => {
            username_password_auth(stream, auth.as_ref().unwrap()).await?;
        }
        _ => return Err(Error::InvalidAuthMethod(method)),
    }

    stream.write_final(command, &addr).await?;
    stream.read_final().await
}

/// Proxifies a TCP connection. Performs the [`CONNECT`] command under the hood.
///
/// [`CONNECT`]: https://tools.ietf.org/html/rfc1928#page-6
///
/// ```no_run
/// # use socks5_impl::Result;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// use socks5_impl::client;
/// use tokio::{io::BufStream, net::TcpStream};
///
/// let stream = TcpStream::connect("my-proxy-server.com:54321").await?;
/// let mut stream = BufStream::new(stream);
/// client::connect(&mut stream, ("google.com", 80), None).await?;
///
/// # Ok(())
/// # }
/// ```
pub async fn connect<S, A>(socket: &mut S, addr: A, auth: Option<UserKey>) -> Result<Address>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
    A: Into<Address>,
{
    init(socket, Command::Connect, addr, auth).await
}

/// A listener that accepts TCP connections through a proxy.
///
/// ```no_run
/// # use socks5_impl::Result;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// use socks5_impl::client::SocksListener;
/// use tokio::{io::BufStream, net::TcpStream};
///
/// let stream = TcpStream::connect("my-proxy-server.com:54321").await?;
/// let mut stream = BufStream::new(stream);
/// let (stream, addr) = SocksListener::bind(stream, ("ftp-server.org", 21), None)
///     .await?
///     .accept()
///     .await?;
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SocksListener<S> {
    stream: S,
    proxy_addr: Address,
}

impl<S> SocksListener<S>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
{
    /// Creates `SocksListener`. Performs the [`BIND`] command under the hood.
    ///
    /// [`BIND`]: https://tools.ietf.org/html/rfc1928#page-6
    pub async fn bind<A>(mut stream: S, addr: A, auth: Option<UserKey>) -> Result<Self>
    where
        A: Into<Address>,
    {
        let addr = init(&mut stream, Command::Bind, addr, auth).await?;
        Ok(Self { stream, proxy_addr: addr })
    }

    pub fn proxy_addr(&self) -> &Address {
        &self.proxy_addr
    }

    pub async fn accept(mut self) -> Result<(S, Address)> {
        let addr = self.stream.read_final().await?;
        Ok((self.stream, addr))
    }
}

/// A UDP socket that sends packets through a proxy.
#[derive(Debug)]
pub struct SocksDatagram<S> {
    socket: UdpSocket,
    proxy_addr: Address,
    stream: S,
}

impl<S> SocksDatagram<S>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
{
    /// Creates `SocksDatagram`. Performs [`UDP ASSOCIATE`] under the hood.
    ///
    /// [`UDP ASSOCIATE`]: https://tools.ietf.org/html/rfc1928#page-7
    pub async fn udp_associate(mut stream: S, socket: UdpSocket, auth: Option<UserKey>) -> Result<Self> {
        let addr = if socket.local_addr()?.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let addr = addr.parse::<SocketAddr>()?;
        let proxy_addr = init(&mut stream, Command::UdpAssociate, addr, auth).await?;
        let addr = proxy_addr.to_socket_addrs()?.next().ok_or("InvalidAddress")?;
        socket.connect(addr).await?;
        Ok(Self {
            socket,
            proxy_addr,
            stream,
        })
    }

    /// Returns the address of the associated udp address.
    pub fn proxy_addr(&self) -> &Address {
        &self.proxy_addr
    }

    /// Returns a reference to the underlying udp socket.
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying udp socket.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// Returns the associated stream and udp socket.
    pub fn into_inner(self) -> (S, UdpSocket) {
        (self.stream, self.socket)
    }

    //  Builds a udp-based client request packet, the format is as follows:
    //  +----+------+------+----------+----------+----------+
    //  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    //  +----+------+------+----------+----------+----------+
    //  | 2  |  1   |  1   | Variable |    2     | Variable |
    //  +----+------+------+----------+----------+----------+
    //  The reference link is as follows:
    //  https://tools.ietf.org/html/rfc1928#page-8
    //
    pub async fn build_socks5_udp_datagram(buf: &[u8], addr: &Address) -> Result<Vec<u8>> {
        let bytes_size = Self::get_buf_size(addr.len(), buf.len());
        let bytes = Vec::with_capacity(bytes_size);

        let mut cursor = Cursor::new(bytes);
        cursor.write_reserved().await?;
        cursor.write_reserved().await?;
        cursor.write_fragment_id(0x00).await?;
        cursor.write_address(addr).await?;
        cursor.write_all(buf).await?;

        let bytes = cursor.into_inner();
        Ok(bytes)
    }

    /// Sends data via the udp socket to the given address.
    pub async fn send_to<A>(&self, buf: &[u8], addr: A) -> Result<usize>
    where
        A: Into<Address>,
    {
        let addr: Address = addr.into();
        let bytes = Self::build_socks5_udp_datagram(buf, &addr).await?;
        Ok(self.socket.send(&bytes).await?)
    }

    /// Parses the udp-based server response packet, the format is same as the client request packet.
    async fn parse_socks5_udp_response(bytes: &mut [u8], buf: &mut Vec<u8>) -> Result<(usize, Address)> {
        let len = bytes.len();
        let mut cursor = Cursor::new(bytes);
        cursor.read_reserved().await?;
        cursor.read_reserved().await?;
        cursor.read_fragment_id().await?;
        let addr = cursor.read_address().await?;
        let header_len = cursor.position() as usize;
        buf.resize(len - header_len, 0);
        _ = cursor.read_exact(buf).await?;
        Ok((len - header_len, addr))
    }

    /// Receives data from the udp socket and returns the number of bytes read and the origin of the data.
    pub async fn recv_from(&self, timeout: Duration, buf: &mut Vec<u8>) -> Result<(usize, Address)> {
        const UDP_MTU: usize = 1500;
        // let bytes_size = Self::get_buf_size(Address::max_serialized_len(), buf.len());
        let bytes_size = UDP_MTU;
        let mut bytes = vec![0; bytes_size];
        let len = tokio::time::timeout(timeout, self.socket.recv(&mut bytes)).await??;
        bytes.truncate(len);
        let (read, addr) = Self::parse_socks5_udp_response(&mut bytes, buf).await?;
        Ok((read, addr))
    }

    fn get_buf_size(addr_size: usize, buf_len: usize) -> usize {
        // reserved + fragment id + addr_size + buf_len
        2 + 1 + addr_size + buf_len
    }
}

pub type GuardTcpStream = BufStream<TcpStream>;
pub type SocksUdpClient = SocksDatagram<GuardTcpStream>;

#[async_trait]
pub trait UdpClientTrait {
    async fn send_to<A>(&mut self, buf: &[u8], addr: A) -> Result<usize>
    where
        A: Into<Address> + Send + Unpin;

    async fn recv_from(&mut self, timeout: Duration, buf: &mut Vec<u8>) -> Result<(usize, Address)>;
}

#[async_trait]
impl UdpClientTrait for SocksUdpClient {
    async fn send_to<A>(&mut self, buf: &[u8], addr: A) -> Result<usize, Error>
    where
        A: Into<Address> + Send + Unpin,
    {
        SocksDatagram::send_to(self, buf, addr).await
    }

    async fn recv_from(&mut self, timeout: Duration, buf: &mut Vec<u8>) -> Result<(usize, Address), Error> {
        SocksDatagram::recv_from(self, timeout, buf).await
    }
}

pub async fn create_udp_client<A: Into<SocketAddr>>(proxy_addr: A, auth: Option<UserKey>) -> Result<SocksUdpClient> {
    let proxy_addr = proxy_addr.into();
    let client_addr = if proxy_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let proxy = TcpStream::connect(proxy_addr).await?;
    let proxy = BufStream::new(proxy);
    let client = UdpSocket::bind(client_addr).await?;
    SocksDatagram::udp_associate(proxy, client, auth).await
}

pub struct UdpClientImpl<C> {
    client: C,
    server_addr: Address,
}

impl UdpClientImpl<SocksUdpClient> {
    pub async fn transfer_data(&self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let len = self.client.send_to(data, &self.server_addr).await?;
        let buf = SocksDatagram::<GuardTcpStream>::build_socks5_udp_datagram(data, &self.server_addr).await?;
        assert_eq!(len, buf.len());

        let mut buf = Vec::with_capacity(data.len());
        let (_len, _) = self.client.recv_from(timeout, &mut buf).await?;
        Ok(buf)
    }

    pub async fn datagram<A1, A2>(proxy_addr: A1, udp_server_addr: A2, auth: Option<UserKey>) -> Result<Self>
    where
        A1: Into<SocketAddr>,
        A2: Into<Address>,
    {
        let client = create_udp_client(proxy_addr, auth).await?;

        let server_addr = udp_server_addr.into();

        Ok(Self { client, server_addr })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::{self, SocksListener, SocksUdpClient, UdpClientTrait},
        protocol::{Address, UserKey},
        Error, Result,
    };
    use async_trait::async_trait;
    use std::{
        net::{SocketAddr, ToSocketAddrs},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, BufStream},
        net::{TcpStream, UdpSocket},
    };

    const PROXY_ADDR: &str = "127.0.0.1:1080";
    const PROXY_AUTH_ADDR: &str = "127.0.0.1:1081";
    const DATA: &[u8] = b"Hello, world!";

    async fn connect(addr: &str, auth: Option<UserKey>) {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut socket = BufStream::new(socket);
        client::connect(&mut socket, Address::from(("baidu.com", 80)), auth).await.unwrap();
    }

    #[ignore]
    #[tokio::test]
    async fn connect_auth() {
        connect(PROXY_AUTH_ADDR, Some(UserKey::new("hyper", "proxy"))).await;
    }

    #[ignore]
    #[tokio::test]
    async fn connect_no_auth() {
        connect(PROXY_ADDR, None).await;
    }

    #[ignore]
    #[should_panic = "InvalidAuthMethod(NoAcceptableMethods)"]
    #[tokio::test]
    async fn connect_no_auth_panic() {
        connect(PROXY_AUTH_ADDR, None).await;
    }

    #[ignore]
    #[tokio::test]
    async fn bind() {
        let run_block = async {
            let server_addr = Address::from(("127.0.0.1", 8000));

            let client = TcpStream::connect(PROXY_ADDR).await?;
            let client = BufStream::new(client);
            let client = SocksListener::bind(client, server_addr, None).await?;

            let server_addr = client.proxy_addr.to_socket_addrs()?.next().ok_or("Invalid address")?;
            let mut server = TcpStream::connect(&server_addr).await?;

            let (mut client, _) = client.accept().await?;

            server.write_all(DATA).await?;

            let mut buf = [0; DATA.len()];
            client.read_exact(&mut buf).await?;
            assert_eq!(buf, DATA);
            Ok::<_, Error>(())
        };
        if let Err(e) = run_block.await {
            println!("{:?}", e);
        }
    }

    type TestHalves = (Arc<SocksUdpClient>, Arc<SocksUdpClient>);

    #[async_trait]
    impl UdpClientTrait for TestHalves {
        async fn send_to<A>(&mut self, buf: &[u8], addr: A) -> Result<usize, Error>
        where
            A: Into<Address> + Send,
        {
            self.1.send_to(buf, addr).await
        }

        async fn recv_from(&mut self, timeout: Duration, buf: &mut Vec<u8>) -> Result<(usize, Address), Error> {
            self.0.recv_from(timeout, buf).await
        }
    }

    const SERVER_ADDR: &str = "127.0.0.1:23456";

    struct UdpTest<C> {
        client: C,
        server: UdpSocket,
        server_addr: Address,
    }

    impl<C: UdpClientTrait> UdpTest<C> {
        async fn test(mut self) {
            let mut buf = vec![0; DATA.len()];
            self.client.send_to(DATA, self.server_addr).await.unwrap();
            let (len, addr) = self.server.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(buf.as_slice(), DATA);

            let mut buf = vec![0; DATA.len()];
            self.server.send_to(DATA, addr).await.unwrap();
            let timeout = Duration::from_secs(5);
            let (len, _) = self.client.recv_from(timeout, &mut buf).await.unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(buf.as_slice(), DATA);
        }
    }

    impl UdpTest<SocksUdpClient> {
        async fn datagram() -> Self {
            let addr = PROXY_ADDR.parse::<SocketAddr>().unwrap();
            let client = client::create_udp_client(addr, None).await.unwrap();

            let server_addr: SocketAddr = SERVER_ADDR.parse().unwrap();
            let server = UdpSocket::bind(server_addr).await.unwrap();
            let server_addr = Address::from(server_addr);

            Self {
                client,
                server,
                server_addr,
            }
        }
    }

    impl UdpTest<TestHalves> {
        async fn halves() -> Self {
            let this = UdpTest::<SocksUdpClient>::datagram().await;
            let client = Arc::new(this.client);
            Self {
                client: (client.clone(), client),
                server: this.server,
                server_addr: this.server_addr,
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn udp_datagram_halves() {
        UdpTest::halves().await.test().await
    }
}
