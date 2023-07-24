mod address;
mod command;
pub mod handshake;
mod reply;
mod request;
mod response;
mod udp;

pub use self::{
    address::{Address, AddressType},
    command::Command,
    handshake::{
        password_method::{self, UserKey},
        AuthMethod,
    },
    reply::Reply,
    request::Request,
    response::Response,
    udp::UdpHeader,
};

pub const SOCKS_VERSION_V5: u8 = 0x05;
pub const SOCKS_VERSION_V4: u8 = 0x04;
