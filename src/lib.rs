#![doc = include_str!("../README.md")]

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;

pub use crate::error::{Error, Result};
