mod command;
pub mod handshake;
mod reply;
mod request;
mod response;
mod udp;

pub use self::{
    command::Command,
    handshake::{AuthMethod, password_method},
    reply::Reply,
    request::Request,
    response::Response,
    udp::UdpHeader,
};
pub use ::bytes::BufMut;
pub use ::url::Url;

/// SOCKS protocol version, either 4 or 5
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Version {
    V4 = 4,
    #[default]
    V5 = 5,
}

impl TryFrom<u8> for Version {
    type Error = std::io::Error;

    fn try_from(value: u8) -> std::io::Result<Self> {
        match value {
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid version")),
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> Self {
        v as u8
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: u8 = (*self).into();
        write!(f, "{v}")
    }
}
