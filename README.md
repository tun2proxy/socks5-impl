# socks5-impl

Fundamental abstractions and async read / write functions for SOCKS5 protocol and Relatively low-level asynchronized SOCKS5 server implementation based on tokio.

This repo hosts at [socks5-impl](https://github.com/ssrlive/socks5-impl/tree/master/)

[![Version](https://img.shields.io/crates/v/socks5-impl.svg?style=flat)](https://crates.io/crates/socks5-impl)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/socks5-impl)
[![License](https://img.shields.io/crates/l/socks5-impl.svg?style=flat)](https://github.com/ssrlive/socks5-impl/blob/master/LICENSE)

## Features

- Fully asynchronized
- Supports all SOCKS5 commands
  - CONNECT
  - BIND
  - ASSOCIATE
- Customizable authentication
    - No authentication
    - Username / password
    - GSSAPI

## Usage

The entry point of this crate is [`socks5_impl::server::Server`](src/server/mod.rs).

Check [examples](https://github.com/ssrlive/socks5-impl/tree/master/examples) for usage examples.

## Example

This example uses the `server` feature. When that feature is disabled, the doctest still compiles with an empty fallback `main`.

```rust no_run
#[cfg(feature = "server")]
use std::{net::SocketAddr, sync::Arc};
#[cfg(feature = "server")]
use socks5_impl::{
    Result,
    protocol::{Address, Reply},
    server::{auth, ClientConnection, IncomingConnection, Server},
};

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> Result<()> {
    let listen_addr: SocketAddr = "127.0.0.1:5000".parse()?;
    let auth = Arc::new(auth::NoAuth);
    let server = Server::bind(listen_addr, auth).await?;

    loop {
        let (conn, _) = server.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = handle(conn).await {
                eprintln!("{err}");
            }
        });
    }
}

#[cfg(feature = "server")]
async fn handle(conn: IncomingConnection) -> Result<()> {
    let conn = conn.authenticate().await?;

    match conn.wait_request().await? {
        ClientConnection::Connect(connect, addr) => {
            let mut conn = connect.reply(Reply::Succeeded, Address::unspecified()).await?;
            let _ = addr;
            conn.shutdown().await?;
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        ClientConnection::UdpAssociate(associate, _) => {
            let mut conn = associate.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
    }

    Ok(())
}

#[cfg(not(feature = "server"))]
fn main() {}
```

## License
GNU General Public License v3.0
