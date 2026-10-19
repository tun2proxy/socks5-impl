#[cfg(feature = "tokio")]
use crate::stream::AsyncStreamOperation;
use crate::stream::StreamOperation;
use bytes::BufMut;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Default)]
#[repr(u8)]
pub enum AddressType {
    #[default]
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = std::io::Error;
    fn try_from(code: u8) -> core::result::Result<Self, Self::Error> {
        let err = format!("Unsupported address type code {code:#x}");
        match code {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::Domain),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err)),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(addr_type: AddressType) -> Self {
        match addr_type {
            AddressType::IPv4 => 0x01,
            AddressType::Domain => 0x03,
            AddressType::IPv6 => 0x04,
        }
    }
}

/// SOCKS5 Address Format
///
/// ```plain
/// +------+----------+----------+
/// | ATYP | DST.ADDR | DST.PORT |
/// +------+----------+----------+
/// |  1   | Variable |    2     |
/// +------+----------+----------+
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub enum Address {
    /// Represents an IPv4 or IPv6 socket address.
    SocketAddress(SocketAddr),
    /// Represents a domain name and a port.
    DomainAddress(Box<str>, u16),
}

impl Default for Address {
    fn default() -> Self {
        Address::unspecified_v4()
    }
}

impl Address {
    /// Returns an unspecified IPv4 address (0.0.0.0:0).
    #[deprecated(since = "0.10.3", note = "Use 'unspecified_v4' instead")]
    pub fn unspecified() -> Self {
        Address::unspecified_v4()
    }

    /// Returns an unspecified IPv4 address (0.0.0.0:0).
    pub fn unspecified_v4() -> Self {
        Address::SocketAddress(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    /// Returns an unspecified IPv6 address (::0:0).
    pub fn unspecified_v6() -> Self {
        Address::SocketAddress(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    }

    /// Returns the type of the address (IPv4, IPv6, or Domain).
    pub fn get_type(&self) -> AddressType {
        match self {
            Self::SocketAddress(SocketAddr::V4(_)) => AddressType::IPv4,
            Self::SocketAddress(SocketAddr::V6(_)) => AddressType::IPv6,
            Self::DomainAddress(_, _) => AddressType::Domain,
        }
    }

    /// Returns the port number.
    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddress(addr) => addr.port(),
            Self::DomainAddress(_, port) => *port,
        }
    }

    /// Returns the host name or IP address as a string.
    pub fn host(&self) -> String {
        match self {
            Self::SocketAddress(addr) => addr.ip().to_string(),
            Self::DomainAddress(addr, _) => addr.to_string(),
        }
    }

    /// Returns the host name or IP address as a string.
    #[deprecated(note = "use host() instead")]
    pub fn domain(&self) -> String {
        self.host()
    }

    /// Returns `true` if it is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::SocketAddress(SocketAddr::V4(_)))
    }

    /// Returns `true` if it is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::SocketAddress(SocketAddr::V6(_)))
    }

    /// Returns `true` if it is a domain address.
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::DomainAddress(_, _))
    }

    /// Returns the maximum possible serialized length of a SOCKS5 address.
    pub const fn max_serialized_len() -> usize {
        1 + 1 + u8::MAX as usize + 2
    }

    /// Resolves the address using Tokio's asynchronous DNS resolution.
    /// Returns an iterator over the resolved socket addresses.
    #[cfg(feature = "tokio")]
    pub async fn resolve_using_tokio(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        match self {
            Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
            Address::DomainAddress(host, port) => {
                let host = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return Ok(vec![SocketAddr::new(ip, *port)].into_iter());
                }
                Ok(tokio::net::lookup_host((host, *port)).await?.collect::<Vec<_>>().into_iter())
            }
        }
    }

    #[cfg(feature = "tokio")]
    #[deprecated(since = "0.10.3", note = "Use 'resolve_using_tokio' instead.")]
    #[inline]
    pub async fn resolve_tokio(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        self.resolve_using_tokio().await
    }

    /// Resolves the address using the standard library's DNS resolution.
    /// Returns an iterator over the resolved socket addresses.
    /// # Errors
    ///
    /// Returns an `std::io::Error` if address resolution fails.
    /// # Examples
    ///
    /// ```
    /// let addr = socks5_impl::Address::from(("www.qq.com", 80));
    /// for socket_addr in addr.resolve().unwrap() {
    ///     println!("Resolved address: {}", socket_addr);
    /// }
    ///
    /// let addr = socks5_impl::Address::from(("127.0.0.1", 8080));
    /// for socket_addr in addr.resolve().unwrap() {
    ///     println!("Resolved address: {}", socket_addr);
    /// }
    /// ```
    pub fn resolve(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        self.to_socket_addrs()
    }
}

impl StreamOperation for Address {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut atyp_buf = [0; 1];
        stream.read_exact(&mut atyp_buf)?;
        match AddressType::try_from(atyp_buf[0])? {
            AddressType::IPv4 => {
                let mut buf = [0; 6];
                stream.read_exact(&mut buf)?;
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Self::SocketAddress(SocketAddr::from((addr, port))))
            }
            AddressType::Domain => {
                let mut len_buf = [0; 1];
                stream.read_exact(&mut len_buf)?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0; len];
                stream.read_exact(&mut domain_buf)?;

                let mut port_buf = [0; 2];
                stream.read_exact(&mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);

                let addr = String::from_utf8(domain_buf)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid address encoding: {err}")))?;
                Ok(Self::DomainAddress(addr.into_boxed_str(), port))
            }
            AddressType::IPv6 => {
                let mut buf = [0; 18];
                stream.read_exact(&mut buf)?;
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                let mut addr_bytes = [0; 16];
                addr_bytes.copy_from_slice(&buf[..16]);
                Ok(Self::SocketAddress(SocketAddr::from((Ipv6Addr::from(addr_bytes), port))))
            }
        }
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u8(AddressType::IPv4.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u8(AddressType::IPv6.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::DomainAddress(addr, port) => {
                let addr = addr.as_bytes();
                buf.put_u8(AddressType::Domain.into());
                buf.put_u8(u8::try_from(addr.len()).expect("domain address too long for SOCKS5"));
                buf.put_slice(addr);
                buf.put_u16(*port);
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::DomainAddress(addr, _) => 1 + 1 + addr.len() + 2,
        }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl AsyncStreamOperation for Address {
    async fn retrieve_from_async_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let atyp = stream.read_u8().await?;
        match AddressType::try_from(atyp)? {
            AddressType::IPv4 => {
                let mut addr_bytes = [0; 4];
                stream.read_exact(&mut addr_bytes).await?;
                let port = stream.read_u16().await?;
                let addr = Ipv4Addr::from(addr_bytes);
                Ok(Self::SocketAddress(SocketAddr::from((addr, port))))
            }
            AddressType::Domain => {
                let len = stream.read_u8().await? as usize;
                let mut domain_buf = vec![0; len];
                stream.read_exact(&mut domain_buf).await?;
                let port = stream.read_u16().await?;

                let addr = String::from_utf8(domain_buf)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid address encoding: {err}")))?;
                Ok(Self::DomainAddress(addr.into_boxed_str(), port))
            }
            AddressType::IPv6 => {
                let mut addr_bytes = [0; 16];
                stream.read_exact(&mut addr_bytes).await?;
                let port = stream.read_u16().await?;
                Ok(Self::SocketAddress(SocketAddr::from((Ipv6Addr::from(addr_bytes), port))))
            }
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match self {
            Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
            Address::DomainAddress(host, port) => {
                let host = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return Ok(vec![SocketAddr::new(ip, *port)].into_iter());
                }
                Ok((host, *port).to_socket_addrs()?)
            }
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::DomainAddress(hostname, port) => write!(f, "{hostname}:{port}"),
            Address::SocketAddress(socket_addr) => write!(f, "{socket_addr}"),
        }
    }
}

impl TryFrom<String> for Address {
    type Error = crate::Error;

    fn try_from(addr: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(addr.as_str())
    }
}

impl TryFrom<&String> for Address {
    type Error = crate::Error;

    fn try_from(addr: &String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(addr.as_str())
    }
}

impl From<Address> for String {
    fn from(addr: Address) -> Self {
        addr.to_string()
    }
}

impl From<&Address> for String {
    fn from(addr: &Address) -> Self {
        addr.to_string()
    }
}

impl TryFrom<&Address> for SocketAddr {
    type Error = std::io::Error;

    fn try_from(address: &Address) -> std::result::Result<Self, Self::Error> {
        match address {
            Address::SocketAddress(addr) => Ok(*addr),
            Address::DomainAddress(host, port) => {
                let host = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
                if let Ok(addr) = host.parse::<IpAddr>() {
                    return Ok(SocketAddr::from((addr, *port)));
                }
                let err = format!("domain address {host} cannot be converted to a SocketAddr without DNS, use to_socket_addrs instead");
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
            }
        }
    }
}

impl TryFrom<Address> for SocketAddr {
    type Error = std::io::Error;

    fn try_from(address: Address) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&address)
    }
}

impl From<Address> for Vec<u8> {
    fn from(addr: Address) -> Self {
        let mut buf = Vec::with_capacity(addr.len());
        addr.write_to_buf(&mut buf);
        buf
    }
}

impl TryFrom<Vec<u8>> for Address {
    type Error = std::io::Error;

    fn try_from(data: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        let mut rdr = Cursor::new(data);
        Self::retrieve_from_stream(&mut rdr)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut rdr = Cursor::new(data);
        Self::retrieve_from_stream(&mut rdr)
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::SocketAddress(addr)
    }
}

impl From<&SocketAddr> for Address {
    fn from(addr: &SocketAddr) -> Self {
        Address::SocketAddress(*addr)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    fn from((addr, port): (Ipv4Addr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    fn from((addr, port): (Ipv6Addr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((addr, port): (IpAddr, u16)) -> Self {
        Address::SocketAddress(SocketAddr::from((addr, port)))
    }
}

impl From<(String, u16)> for Address {
    fn from((addr, port): (String, u16)) -> Self {
        Address::from((addr.as_str(), port))
    }
}

impl From<(&String, u16)> for Address {
    fn from((addr, port): (&String, u16)) -> Self {
        Address::from((addr.as_str(), port))
    }
}

impl From<(&str, u16)> for Address {
    fn from((addr, port): (&str, u16)) -> Self {
        if let Ok(addr) = addr.parse::<IpAddr>() {
            return Address::SocketAddress(SocketAddr::from((addr, port)));
        }
        Address::DomainAddress(addr.into(), port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Self {
        addr.clone()
    }
}

impl TryFrom<&str> for Address {
    type Error = crate::Error;

    fn try_from(addr: &str) -> std::result::Result<Self, Self::Error> {
        if let Ok(addr) = addr.parse::<SocketAddr>() {
            Ok(Address::SocketAddress(addr))
        } else {
            if addr.matches(':').count() > 1 {
                let err = format!("invalid socket address format: {addr}");
                return Err(crate::Error::InvalidAddress(err));
            }

            let Some(pos) = addr.rfind(':') else {
                let err = format!("missing port in address: {addr}");
                return Err(crate::Error::InvalidAddress(err));
            };

            let (addr, port) = (&addr[..pos], &addr[pos + 1..]);
            let port = port.parse::<u16>()?;
            Ok(Address::from((addr, port)))
        }
    }
}

impl std::str::FromStr for Address {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

#[test]
fn test_address() {
    let addr = Address::from((Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut buf = Vec::new();
    addr.write_to_buf(&mut buf);
    assert_eq!(buf, vec![0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_stream(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(addr, addr2);

    let addr = Address::from((Ipv6Addr::new(0x45, 0xff89, 0, 0, 0, 0, 0, 1), 8080));
    let mut buf = Vec::new();
    addr.write_to_buf(&mut buf);
    assert_eq!(buf, vec![0x04, 0, 0x45, 0xff, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_stream(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(addr, addr2);

    let addr = Address::from(("sex.com", 8080));
    let mut buf = Vec::new();
    addr.write_to_buf(&mut buf);
    assert_eq!(buf, vec![0x03, 0x07, b's', b'e', b'x', b'.', b'c', b'o', b'm', 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_stream(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(addr, addr2);

    let addr = Address::try_from("example.com:8080").unwrap();
    assert_eq!(addr.host(), "example.com");
    assert!(Address::try_from("example.com").is_err());

    let addr = Address::try_from("123.45.67.89:8080").unwrap();
    assert!(addr.is_ipv4());
    assert!(Address::try_from("123.45.67.89").is_err());

    let addr = Address::try_from("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080").unwrap();
    assert_eq!(addr.host(), "2001:db8:85a3::8a2e:370:7334");
    assert!(addr.is_ipv6());

    let addr = Address::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 8080));
    assert_eq!(addr.host(), "2001:db8::1");

    assert!(Address::try_from("2001:0db8:85a3:0000:0000:8a2e:0370:7334:8080").is_err());
}

#[test]
fn test_address_display_for_ipv6() {
    let addr = Address::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 8080));
    assert_eq!(addr.to_string(), "[2001:db8::1]:8080");
}

#[cfg(feature = "serde")]
#[test]
fn test_address_serde_string_roundtrip() {
    for value in ["127.0.0.1:8080", "example.com:8080", "[2001:db8::1]:8080"] {
        let address = value.parse::<Address>().unwrap();
        let serialized = serde_json::to_string(&address).unwrap();

        assert_eq!(serialized, serde_json::to_string(&address.to_string()).unwrap());
        assert_eq!(serde_json::from_str::<Address>(&serialized).unwrap(), address);
    }
    assert!(serde_json::from_str::<Address>(r#""example.com""#).is_err());
}

#[test]
fn test_try_from_address_for_socketaddr() {
    let addr = Address::from((Ipv4Addr::new(127, 0, 0, 1), 8080));
    let socket_addr = SocketAddr::try_from(addr.clone()).unwrap();
    assert_eq!(socket_addr, SocketAddr::from(([127, 0, 0, 1], 8080)));

    let addr = Address::from(("192.168.1.1", 8080));
    let socket_addr = SocketAddr::try_from(addr).unwrap();
    assert_eq!(socket_addr, SocketAddr::from(([192, 168, 1, 1], 8080)));

    let addr = Address::from(("example.com", 8080));
    let err = SocketAddr::try_from(addr).unwrap_err();
    assert!(format!("{err}").contains("cannot be converted to a SocketAddr without DNS"));

    let addr = Address::from(("baidu.com", 8080));
    let err = SocketAddr::try_from(addr).unwrap_err();
    assert!(format!("{err}").contains("cannot be converted to a SocketAddr without DNS"));

    let addr = Address::from(("baidu.com", 8080));
    let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs().unwrap().collect();
    assert!(!socket_addrs.is_empty());
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn test_address_async() {
    let addr = Address::from((Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut buf = Vec::new();
    addr.write_to_async_stream(&mut buf).await.unwrap();
    assert_eq!(buf, vec![0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_async_stream(&mut Cursor::new(&buf)).await.unwrap();
    assert_eq!(addr, addr2);

    let addr = Address::from((Ipv6Addr::new(0x45, 0xff89, 0, 0, 0, 0, 0, 1), 8080));
    let mut buf = Vec::new();
    addr.write_to_async_stream(&mut buf).await.unwrap();
    assert_eq!(buf, vec![0x04, 0, 0x45, 0xff, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_async_stream(&mut Cursor::new(&buf)).await.unwrap();
    assert_eq!(addr, addr2);

    let addr = Address::from(("sex.com", 8080));
    let mut buf = Vec::new();
    addr.write_to_async_stream(&mut buf).await.unwrap();
    assert_eq!(buf, vec![0x03, 0x07, b's', b'e', b'x', b'.', b'c', b'o', b'm', 0x1f, 0x90]);
    let addr2 = Address::retrieve_from_async_stream(&mut Cursor::new(&buf)).await.unwrap();
    assert_eq!(addr, addr2);
}
