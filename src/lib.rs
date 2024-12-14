#![doc = include_str!("../README.md")]

#[cfg(feature = "client")]
pub mod client;
pub(crate) mod error;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;

pub use crate::error::{Error, Result};
