use crate::protocol::{AsyncStreamOperation, AuthMethod, UserKey, handshake::password_method};
use std::sync::Arc;
use tokio::net::TcpStream;

/// This trait is for defining the socks5 authentication method.
///
/// Pre-defined authentication methods can be found in the [`auth`](crate::server::auth) module.
///
/// You can create your own authentication method by implementing this trait. Since GAT is not stabled yet,
/// [async_trait](https://docs.rs/async-trait/latest/async_trait/index.html) needs to be used.
///
/// # Example
/// ```rust
/// use socks5_impl::protocol::AuthMethod;
/// use socks5_impl::server::AuthExecutor;
/// use tokio::net::TcpStream;
///
/// pub struct MyAuth;
///
/// #[async_trait::async_trait]
/// impl AuthExecutor for MyAuth {
///     fn auth_method(&self) -> AuthMethod {
///         AuthMethod::from(0x80)
///     }
///
///     async fn execute(&self, stream: &mut TcpStream) -> std::io::Result<bool> {
///         // do something
///         Ok(true)
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait AuthExecutor {
    fn auth_method(&self) -> AuthMethod;
    async fn execute(&self, stream: &mut TcpStream) -> std::io::Result<bool>;
}

pub type AuthAdaptor = Arc<dyn AuthExecutor + Send + Sync>;

/// No authentication as the socks5 handshake method.
#[derive(Debug, Default)]
pub struct NoAuth;

#[async_trait::async_trait]
impl AuthExecutor for NoAuth {
    fn auth_method(&self) -> AuthMethod {
        AuthMethod::NoAuth
    }

    async fn execute(&self, _: &mut TcpStream) -> std::io::Result<bool> {
        Ok(true)
    }
}

/// Username and password as the socks5 handshake method.
#[derive(Debug, Clone)]
pub struct UserKeyAuth {
    user_key: UserKey,
}

impl From<UserKey> for UserKeyAuth {
    fn from(user_key: UserKey) -> Self {
        Self { user_key }
    }
}

impl From<&UserKey> for UserKeyAuth {
    fn from(value: &UserKey) -> Self {
        Self { user_key: value.clone() }
    }
}

impl From<(&str, &str)> for UserKeyAuth {
    fn from(value: (&str, &str)) -> Self {
        Self::new(value.0, value.1)
    }
}

impl UserKeyAuth {
    pub fn new(username: &str, password: &str) -> Self {
        let user_key = UserKey::new(username, password);
        Self { user_key }
    }
}

#[async_trait::async_trait]
impl AuthExecutor for UserKeyAuth {
    fn auth_method(&self) -> AuthMethod {
        AuthMethod::UserPass
    }

    async fn execute(&self, stream: &mut TcpStream) -> std::io::Result<bool> {
        use password_method::{Request, Response, Status::*};
        let req = Request::retrieve_from_async_stream(stream).await?;

        let is_equal = req.user_key == self.user_key;
        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            Ok(true)
        } else {
            Err(std::io::Error::other("username or password is incorrect"))
        }
    }
}
