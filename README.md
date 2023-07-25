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
use socks5_impl::protocol::{handshake, Address, AuthMethod, Reply, Request, Response, StreamOperation};

fn main() -> socks5_impl::Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:5000")?;
    let (mut stream, _) = listener.accept()?;

    let request = handshake::Request::retrieve_from_stream(&mut stream)?;

    if request.evaluate_method(AuthMethod::NoAuth) {
        let response = handshake::Response::new(AuthMethod::NoAuth);
        response.write_to_stream(&mut stream)?;
    } else {
        let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
        response.write_to_stream(&mut stream)?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        let err = "No available handshake method provided by client";
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err).into());
    }

    let req = match Request::retrieve_from_stream(&mut stream) {
        Ok(req) => req,
        Err(err) => {
            let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
            resp.write_to_stream(&mut stream)?;
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(err.into());
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
