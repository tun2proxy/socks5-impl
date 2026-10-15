#![doc = include_str!("../README.md")]

#[cfg(feature = "address")]
mod address;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "address")]
pub(crate) mod error;
#[cfg(feature = "protocol")]
pub mod protocol;
#[cfg(feature = "proxy-parameters")]
mod proxy_parameters;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "address")]
mod stream;
#[cfg(feature = "user-key")]
mod user_key;

#[cfg(feature = "address")]
pub use crate::error::{Error, Result};
#[cfg(feature = "address")]
pub use address::{Address, AddressType};
#[cfg(feature = "proxy-parameters")]
pub use proxy_parameters::{ProxyParameters, ProxyType};
#[cfg(all(feature = "address", feature = "tokio"))]
pub use stream::AsyncStreamOperation;
#[cfg(feature = "address")]
pub use stream::StreamOperation;
#[cfg(feature = "user-key")]
pub use user_key::UserKey;
