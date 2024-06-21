mod util;

use hickory_proto::rr::record_type::RecordType;
use socks5_impl::{client, protocol::UserKey, Result};
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

    /// Via socks5 proxy.
    #[clap(short, long, value_name = "via proxy", default_value = "false")]
    via_proxy: bool,

    /// Socks5 proxy server address.
    #[clap(short, long, value_name = "address:port")]
    proxy_addr: Option<SocketAddr>,

    /// User name for SOCKS5 authentication.
    #[clap(short, long, value_name = "user name")]
    username: Option<String>,

    /// Password for SOCKS5 authentication.
    #[clap(short = 'w', long, value_name = "password")]
    password: Option<String>,

    /// Use TCP protocol.
    #[clap(short, long, value_name = "tcp", default_value = "false")]
    tcp: bool,

    /// Timeout in seconds.
    #[clap(short = 'm', long, value_name = "seconds", default_value = "5")]
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
    println!("{}", addr);

    Ok(())
}

async fn dns_query_from_server(opt: &CmdOpt, msg_buf: &[u8]) -> Result<Vec<u8>> {
    let user_key = match (&opt.username, &opt.password) {
        (Some(username), Some(password)) => Some(UserKey::new(username, password)),
        _ => None,
    };
    let timeout = Duration::from_secs(opt.timeout);
    let buf = match (opt.tcp, opt.via_proxy) {
        (true, true) => {
            let proxy = TcpStream::connect(opt.proxy_addr.as_ref().unwrap()).await?;
            let mut stream = tokio::io::BufStream::new(proxy);
            let addr = client::connect(&mut stream, &opt.remote_dns_server, user_key).await?;
            log::trace!("connected {addr}");

            // write dns request
            stream.write_all(msg_buf).await?;
            stream.flush().await?;

            // read dns response
            let mut buf = vec![0; 1500];
            let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await??;
            log::trace!("read {} bytes", n);
            buf.truncate(n);
            buf
        }
        (true, false) => {
            let mut stream = TcpStream::connect(&opt.remote_dns_server).await?;
            stream.write_all(msg_buf).await?;
            stream.flush().await?;
            let mut buf = vec![0; 1500];
            let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await??;
            buf.truncate(n);
            buf
        }
        (false, true) => {
            let proxy_addr = *opt.proxy_addr.as_ref().unwrap();
            let udp_server_addr = opt.remote_dns_server;
            client::UdpClientImpl::datagram(proxy_addr, udp_server_addr, user_key)
                .await?
                .transfer_data(msg_buf, timeout)
                .await?
        }
        (false, false) => {
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
