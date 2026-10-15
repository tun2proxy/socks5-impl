#[cfg(feature = "protocol")]
mod request;
#[cfg(feature = "protocol")]
mod response;

#[cfg(feature = "protocol")]
pub use self::{
    request::Request,
    response::{Response, Status},
};

#[cfg(feature = "protocol")]
pub const SUBNEGOTIATION_VERSION: u8 = 0x01;
