use socks5_impl::{client, protocol::UserKey, Result};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, query::Query, Message, ResponseCode::NoError},
    rr::{record_type::RecordType, Name, RData},
};

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

    let is_ipv4 = opt.remote_dns_server.is_ipv4();
    let query_type = if is_ipv4 { RecordType::A } else { RecordType::AAAA };
    let msg_buf = build_dns_query(&opt.domain, query_type, opt.tcp)?;

    let domain = parse_dns_request(&msg_buf, opt.tcp)?.trim_end_matches('.').to_string();
    assert_eq!(&domain, &opt.domain);

    let buf = dns_query_from_server(&opt, &msg_buf).await?;

    let addr = parse_dns_response(&buf, opt.tcp)?;

    let domain = parse_dns_request(&buf, opt.tcp)?.trim_end_matches('.').to_string();
    assert_eq!(&domain, &opt.domain);

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
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            let mut buf = vec![0; 1500];
            let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await??;
            buf.truncate(n);
            buf
        }
        (false, true) => {
            let proxy_addr = &opt.proxy_addr.as_ref().unwrap().to_string();
            let udp_server_addr = &opt.remote_dns_server.to_string();
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

fn build_dns_query(domain: &str, query_type: RecordType, used_by_tcp: bool) -> Result<Vec<u8>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    let query = Query::query(name, query_type);
    let mut msg = Message::new();
    msg.add_query(query)
        .set_id(StdRng::from_entropy().gen())
        .set_op_code(OpCode::Query)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
    let mut msg_buf = msg.to_vec().map_err(|e| e.to_string())?;
    if used_by_tcp {
        let mut buf = (msg_buf.len() as u16).to_be_bytes().to_vec();
        buf.append(&mut msg_buf);
        Ok(buf)
    } else {
        Ok(msg_buf)
    }
}

fn parse_dns_response(response: &[u8], from_tcp: bool) -> Result<IpAddr> {
    if from_tcp {
        if response.len() < 2 {
            return Err("invalid dns response".into());
        }
        let len = u16::from_be_bytes([response[0], response[1]]) as usize;
        let response = response.get(2..len + 2).ok_or("invalid dns response")?;
        return parse_dns_response(response, false);
    }
    let message = Message::from_vec(response).map_err(|e| e.to_string())?;
    if message.response_code() != NoError {
        return Err("Error::DnsResponse(message.response_code())".into());
    }
    for answer in message.answers() {
        match answer.data().ok_or("Error::DnsResponse(answer.data())")? {
            RData::A(addr) => {
                return Ok(IpAddr::V4(*addr));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6(*addr));
            }
            RData::CNAME(name) => {
                log::trace!("{}: {}", answer.name(), name);
            }
            _ => {}
        }
    }
    Err("Error::DnsResponse(NoError)".into())
}

fn parse_dns_request(request: &[u8], used_by_tcp: bool) -> Result<String> {
    if used_by_tcp {
        if request.len() < 2 {
            return Err("invalid dns request".into());
        }
        let len = u16::from_be_bytes([request[0], request[1]]) as usize;
        let request = request.get(2..len + 2).ok_or("invalid dns request")?;
        return parse_dns_request(request, false);
    }
    let message = Message::from_vec(request).map_err(|e| e.to_string())?;
    let query = message.queries().get(0).ok_or("Error::DnsRequest(message.queries())")?;
    let name = query.name().to_string();
    Ok(name)
}
