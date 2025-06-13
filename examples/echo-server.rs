use std::{error::Error, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, ToSocketAddrs, UdpSocket},
};

/// Simple echo server.
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Simple echo server.", long_about = None)]
pub struct CmdOpt {
    /// Echo server listen address.
    #[clap(short, long, value_name = "address:port", default_value = "127.0.0.1:8080")]
    listen_addr: SocketAddr,

    /// timeout for TCP connection
    #[clap(short, long, value_name = "seconds", default_value = "10")]
    tcp_timeout: u64,
}

async fn tcp_main<A: ToSocketAddrs>(addr: A, tcp_timeout: u64) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    log::info!("[TCP] listening on: {}", listener.local_addr()?);
    loop {
        let (mut socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let block = async move {
                let mut buf = vec![0; 1024];
                log::info!("[TCP] incoming peer {}", peer);
                loop {
                    let duration = std::time::Duration::from_secs(tcp_timeout);
                    let n = tokio::time::timeout(duration, socket.read(&mut buf)).await??;
                    if n == 0 {
                        log::info!("[TCP] {} exit", peer);
                        break;
                    }
                    let amt = socket.write(&buf[0..n]).await?;
                    log::info!("[TCP] Echoed {}/{} bytes to {}", amt, n, peer);
                }
                Ok::<(), std::io::Error>(())
            };
            if let Err(err) = block.await {
                log::info!("[TCP] {}", err);
            }
        });
    }
}

async fn udp_main<A: ToSocketAddrs>(addr: A) -> std::io::Result<()> {
    let socket = UdpSocket::bind(&addr).await?;
    log::info!("[UDP] Listening on: {}", socket.local_addr()?);

    let mut buf = vec![0; 1024];
    let mut to_send = None;

    loop {
        if let Some((size, peer)) = to_send {
            let amt = socket.send_to(&buf[..size], &peer).await?;
            log::info!("[UDP] Echoed {}/{} bytes to {}", amt, size, peer);
        }

        to_send = Some(socket.recv_from(&mut buf).await?);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let opt: CmdOpt = clap::Parser::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let addr = opt.listen_addr;
    let _tcp = tokio::spawn(async move {
        tcp_main(&addr, opt.tcp_timeout).await?;
        Ok::<(), std::io::Error>(())
    });

    let _udp = tokio::spawn(async move {
        udp_main(&addr).await?;
        Ok::<(), std::io::Error>(())
    });

    let ctrlc = ctrlc2::AsyncCtrlC::new(|| {
        log::info!("Ctrl-C received, shutting down...");
        true
    })?;

    ctrlc.await?;
    log::info!("Exiting...");

    Ok(())
}
