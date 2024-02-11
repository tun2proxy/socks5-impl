mod request;
mod response;

use serde::{Deserialize, Serialize};

pub use self::{
    request::Request,
    response::{Response, Status},
};

pub const SUBNEGOTIATION_VERSION: u8 = 0x01;

/// Required for a username + password authentication.
#[derive(Default, Debug, Eq, PartialEq, Clone, Hash, Deserialize, Serialize)]
pub struct UserKey {
    pub username: String,
    pub password: String,
}

impl std::fmt::Display for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.username.is_empty(), self.password.is_empty()) {
            (true, true) => write!(f, ""),
            (true, false) => write!(f, ":{}", self.password),
            (false, true) => write!(f, "{}", self.username),
            (false, false) => write!(f, "{}:{}", self.username, self.password),
        }
    }
}

impl UserKey {
    /// Constructs `UserKey` with the specified username and a password.
    pub fn new<U, P>(username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn username_arr(&self) -> Vec<u8> {
        self.username.as_bytes().to_vec()
    }

    pub fn password_arr(&self) -> Vec<u8> {
        self.password.as_bytes().to_vec()
    }
}
