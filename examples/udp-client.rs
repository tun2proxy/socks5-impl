use socks5_impl::{client::UdpClientImpl, protocol::UserKey, Result};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::net::UdpSocket;

/// Udp client through socks5 proxy.
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Udp client through socks5 proxy", long_about = None)]
pub struct CmdOpt {
    /// Udp target server address.
    #[clap(short, long, value_name = "addr:port")]
    target_addr: SocketAddr,

    /// Data string to send.
    #[clap(short, long, value_name = "data")]
    data: String,

    /// Via socks5 proxy server.
    #[clap(short, long)]
    via_proxy: bool,

    /// Socket5 proxy server address.
    #[clap(short, long, value_name = "addr:port")]
    proxy_addr: Option<SocketAddr>,

    /// User name for authentication.
    #[clap(short, long, value_name = "user name")]
    username: Option<String>,

    /// Password for authentication.
    #[clap(short = 'w', long, value_name = "password")]
    password: Option<String>,

    /// Timeout in seconds.
    #[clap(short = 'm', long, value_name = "seconds", default_value = "2")]
    timeout: u64,
}

impl CmdOpt {
    pub fn validate(&self) -> Result<(), String> {
        if self.via_proxy && self.proxy_addr.is_none() {
            return Err("proxy_addr is required when via_proxy is true".into());
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: CmdOpt = clap::Parser::parse();
    opt.validate()?;

    let user_key = match (opt.username, opt.password) {
        (Some(username), Some(password)) => Some(UserKey::new(username, password)),
        _ => None,
    };
    let timeout = Duration::from_secs(opt.timeout);
    if !opt.via_proxy {
        let target_addr = opt.target_addr.to_socket_addrs()?.next().ok_or("invalid address")?;
        let zero_addr = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let zero_addr = zero_addr.to_socket_addrs()?.next().ok_or("invalid address")?;
        let udp = UdpSocket::bind(zero_addr).await?;
        udp.send_to(opt.data.as_bytes(), target_addr).await?;

        let mut buf = [0u8; 1024];
        let (len, _) = tokio::time::timeout(timeout, udp.recv_from(&mut buf)).await??;

        println!("{}", std::str::from_utf8(&buf[..len])?);
    } else {
        let proxy_addr = opt.proxy_addr.ok_or("proxy_addr is required")?;
        let data = UdpClientImpl::datagram(proxy_addr, opt.target_addr, user_key)
            .await?
            .transfer_data(opt.data.as_bytes(), timeout)
            .await?;
        println!("{}", std::str::from_utf8(data.as_slice())?);
    }
    Ok(())
}
