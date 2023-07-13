mod address;
mod command;
mod reply;
mod request;
mod response;
mod udp;

pub mod handshake;

pub use self::{
    address::{Address, AddressType},
    command::Command,
    handshake::{password_method::UserKey, AuthMethod, HandshakeRequest, HandshakeResponse},
    reply::Reply,
    request::Request,
    response::Response,
    udp::UdpHeader,
};

pub const SOCKS_VERSION: u8 = 0x05;
