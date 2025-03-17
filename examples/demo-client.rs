use socks5_impl::{Result, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    let s5_proxy = TcpStream::connect("127.0.0.1:1080").await?;
    let mut stream = BufStream::new(s5_proxy);
    let addr = client::connect(&mut stream, ("google.com", 80), None).await?;
    println!("connected {addr}");

    // write http request
    let req = b"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n";
    stream.write_all(req).await?;
    stream.flush().await?;

    // read http response
    let mut buf = vec![0; 1024];
    let n = stream.read(&mut buf).await?;
    println!("read {} bytes", n);
    println!("{}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
