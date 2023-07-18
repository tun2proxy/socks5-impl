use socks5_impl::protocol::{handshake, Address, AuthMethod, Reply, Request, Response};
use std::io;
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    let (mut stream, _) = listener.accept().await?;

    let request = handshake::Request::async_rebuild_from_stream(&mut stream).await?;

    if request.methods.contains(&AuthMethod::NoAuth) {
        let response = handshake::Response::new(AuthMethod::NoAuth);
        response.async_write_to_stream(&mut stream).await?;
    } else {
        let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
        response.async_write_to_stream(&mut stream).await?;
        let _ = stream.shutdown().await;
        let err = "No available handshake method provided by client";
        return Err(io::Error::new(io::ErrorKind::Unsupported, err));
    }

    let _req = match Request::async_rebuild_from_stream(&mut stream).await {
        Ok(req) => req,
        Err(err) => {
            let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
            resp.async_write_to_stream(&mut stream).await?;
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };

    // match _req.command {
    //     _ => {} // process request
    // }

    Ok(())
}
