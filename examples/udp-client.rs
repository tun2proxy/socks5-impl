use socks5_impl::{
    Result,
    client::UdpClientImpl,
    protocol::{ProxyParameters, ProxyType},
};
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
    #[clap(short, long, requires = "proxy_parameters")]
    via_proxy: bool,

    /// Socket5 proxy server parameters, likes `socks5://[user[:password]@]addr:port`
    #[clap(short, long, value_name = "parameters")]
    proxy_parameters: Option<ProxyParameters>,

    /// Timeout in seconds.
    #[clap(short = 'm', long, value_name = "seconds", default_value = "2")]
    timeout: u64,
}

impl CmdOpt {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(proxy_parameters) = &self.proxy_parameters
            && proxy_parameters.proxy_type != ProxyType::Socks5
        {
            return Err("only socks5 proxy is supported".into());
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: CmdOpt = clap::Parser::parse();
    opt.validate()?;

    let timeout = Duration::from_secs(opt.timeout);
    if opt.via_proxy {
        let proxy_parameters = opt.proxy_parameters.ok_or("proxy_parameters is required")?;
        let proxy_addr = std::net::SocketAddr::try_from(proxy_parameters.addr)?;
        let user_key = proxy_parameters.credentials.clone();
        let data = UdpClientImpl::datagram(proxy_addr, opt.target_addr, user_key)
            .await?
            .transfer_data(opt.data.as_bytes(), timeout)
            .await?;
        println!("{}", std::str::from_utf8(data.as_slice())?);
    } else {
        let target_addr = opt.target_addr.to_socket_addrs()?.next().ok_or("invalid address")?;
        let zero_addr = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let zero_addr = zero_addr.to_socket_addrs()?.next().ok_or("invalid address")?;
        let udp = UdpSocket::bind(zero_addr).await?;
        udp.send_to(opt.data.as_bytes(), target_addr).await?;

        let mut buf = [0u8; 1024];
        let (len, _) = tokio::time::timeout(timeout, udp.recv_from(&mut buf)).await??;

        println!("{}", std::str::from_utf8(&buf[..len])?);
    }
    Ok(())
}
