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

The entry point of this crate is [`socks5_impl::server::Server`](https://docs.rs/socks5-impl/latest/socks5_impl/server/struct.Server.html).

Check [examples](https://github.com/ssrlive/socks5-impl/tree/master/examples) for usage examples.

## Example

```rust no_run
use socks5_impl::protocol::{
    Address, AuthMethod, HandshakeRequest, HandshakeResponse, Reply, Request, Response,
};
use std::io;
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    let (mut stream, _) = listener.accept().await?;

    let hs_req = HandshakeRequest::rebuild_from_stream(&mut stream).await?;

    if hs_req.methods.contains(&AuthMethod::NoAuth) {
        let hs_resp = HandshakeResponse::new(AuthMethod::NoAuth);
        hs_resp.write_to_stream(&mut stream).await?;
    } else {
        let hs_resp = HandshakeResponse::new(AuthMethod::NoAcceptableMethods);
        hs_resp.write_to_stream(&mut stream).await?;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "No available handshake method provided by client",
        ));
    }

    let req = match Request::rebuild_from_stream(&mut stream).await {
        Ok(req) => req,
        Err(err) => {
            let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
            resp.write_to(&mut stream).await?;
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };

    match req.command {
        _ => {} // process request
    }

    Ok(())
}
```

## License
GNU General Public License v3.0
