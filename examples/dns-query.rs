mod util;

use hickory_proto::rr::RecordType;
use socks5_impl::{
    Result, client,
    protocol::{ProxyParameters, ProxyType},
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use util::dns;

/// DNS query through socks5 proxy.
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "DNS query through socks5 proxy or not", long_about = None)]
pub struct CmdOpt {
    /// DNS server address.
    #[clap(short, long, value_name = "address:port", default_value = "8.8.8.8:53")]
    remote_dns_server: SocketAddr,

    /// Domain name for query.
    #[clap(short, long, value_name = "domain name")]
    domain: String,

    /// Via socks5 proxy server, the parameters like `socks5://[user[:password]@]addr:port`
    #[clap(short, long, value_name = "via proxy", default_value = "false")]
    via_proxy: Option<ProxyParameters>,

    /// Use TCP protocol.
    #[clap(short, long, value_name = "tcp", default_value = "false")]
    tcp: bool,

    /// Timeout in seconds.
    #[clap(short = 'm', long, value_name = "seconds", default_value = "5")]
    timeout: u64,
}

impl CmdOpt {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(proxy_parameters) = &self.via_proxy
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

    let is_ipv4 = opt.remote_dns_server.is_ipv4();
    let query_type = if is_ipv4 { RecordType::A } else { RecordType::AAAA };
    let msg_buf = dns::build_dns_query(&opt.domain, query_type, opt.tcp)?;

    let message = dns::parse_data_to_dns_message(&msg_buf, opt.tcp)?;
    let domain = dns::extract_domain_from_dns_message(&message)?.trim_end_matches('.').to_string();
    assert_eq!(&domain, &opt.domain);

    let buf = dns_query_from_server(&opt, &msg_buf).await?;

    let message = dns::parse_data_to_dns_message(&buf, opt.tcp)?;
    let domain = dns::extract_domain_from_dns_message(&message)?.trim_end_matches('.').to_string();
    assert_eq!(&domain, &opt.domain);

    let addr = dns::extract_ipaddr_from_dns_message(&message)?;
    println!("{addr}");

    Ok(())
}

async fn dns_query_from_server(opt: &CmdOpt, msg_buf: &[u8]) -> Result<Vec<u8>> {
    let timeout = Duration::from_secs(opt.timeout);
    let buf = match (opt.tcp, opt.via_proxy.clone()) {
        (true, Some(proxy_parameters)) => {
            let proxy_addr: SocketAddr = proxy_parameters.addr.try_into()?;
            let proxy = TcpStream::connect(proxy_addr).await?;
            let mut stream = tokio::io::BufStream::new(proxy);
            let addr = client::connect(&mut stream, &opt.remote_dns_server, proxy_parameters.credentials).await?;
            log::trace!("connected {addr}");

            // write dns request
            stream.write_all(msg_buf).await?;
            stream.flush().await?;

            // read dns response
            let mut buf = vec![0; 1500];
            let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await??;
            log::trace!("read {n} bytes");
            buf.truncate(n);
            buf
        }
        (true, None) => {
            let mut stream = TcpStream::connect(&opt.remote_dns_server).await?;
            stream.write_all(msg_buf).await?;
            stream.flush().await?;
            let mut buf = vec![0; 1500];
            let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await??;
            buf.truncate(n);
            buf
        }
        (false, Some(proxy_parameters)) => {
            let proxy_addr: SocketAddr = proxy_parameters.addr.try_into()?;
            let user_key = proxy_parameters.credentials;
            let udp_server_addr = opt.remote_dns_server;
            client::ClientWrapper::datagram(proxy_addr, user_key)
                .await?
                .transfer_data(udp_server_addr, msg_buf, timeout)
                .await?
        }
        (false, None) => {
            let client_addr = if opt.remote_dns_server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let client = tokio::net::UdpSocket::bind(client_addr).await?;
            client.send_to(msg_buf, &opt.remote_dns_server).await?;
            let mut buf = vec![0u8; 1500];
            let (len, _) = tokio::time::timeout(timeout, client.recv_from(&mut buf)).await??;
            buf.truncate(len);
            buf
        }
    };
    Ok(buf)
}
