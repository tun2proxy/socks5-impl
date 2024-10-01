#![doc = include_str!("../README.md")]

#[cfg(feature = "tokio")]
pub mod client;
pub(crate) mod error;
pub mod protocol;
#[cfg(feature = "tokio")]
pub mod server;

pub use crate::error::{Error, Result};
