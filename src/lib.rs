#![doc = include_str!("../README.md")]

#[cfg(feature = "tokio")]
pub mod client;
pub mod error;
pub mod protocol;
#[cfg(feature = "tokio")]
pub mod server;

pub use crate::error::{Error, Result};
