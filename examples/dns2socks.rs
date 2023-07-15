use moka::future::Cache;
use socks5_impl::{client, protocol::UserKey, Result};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, UdpSocket},
};
use trust_dns_proto::{
    op::{Message, Query, ResponseCode::NoError},
    rr::RData,
};

/// Proxy server to routing DNS query to SOCKS5 server
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Proxy server to routing DNS query to SOCKS5 server", long_about = None)]
pub struct CmdOpt {
    /// Listen address
    #[clap(short, long, value_name = "address:port", default_value = "0.0.0.0:53")]
    listen_addr: SocketAddr,

    /// Remote DNS server address
    #[clap(short, long, value_name = "address:port", default_value = "8.8.8.8:53")]
    dns_remote_server: SocketAddr,

    /// SOCKS5 proxy server address
    #[clap(short, long, value_name = "address:port", default_value = "127.0.0.1:1080")]
    socks5_server: SocketAddr,

    /// User name for SOCKS5 authentication
    #[clap(short, long, value_name = "user name")]
    username: Option<String>,

    /// Password for SOCKS5 authentication
    #[clap(short, long, value_name = "password")]
    password: Option<String>,

    /// Cache dns query records
    #[clap(short, long)]
    cache_records: bool,

    /// Verbose mode.
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: CmdOpt = clap::Parser::parse();

    dotenvy::dotenv().ok();

    let level = if opt.verbose { "trace" } else { "info" };
    let default = format!("off,{}={}", module_path!(), level);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let user_key = match (&opt.username, &opt.password) {
        (Some(username), Some(password)) => Some(UserKey::new(username, password)),
        _ => None,
    };

    let cache: Cache<Vec<Query>, Message> = Cache::builder()
        .time_to_live(Duration::from_secs(30 * 60))
        .time_to_idle(Duration::from_secs(5 * 60))
        .build();

    tokio::select! {
        res = tokio::spawn(udp_thread(opt.clone(), user_key.clone(), cache.clone())) => {
            match res {
                Ok(Err(e)) => log::error!("UDP error: {}", e),
                Err(e) => log::error!("UDP error: {}", e),
                _ => {}
            }
        },
        res = tokio::spawn(tcp_thread(opt, user_key, cache)) => {
            match res {
                Ok(Err(e)) => log::error!("TCP error: {}", e),
                Err(e) => log::error!("TCP error: {}", e),
                _ => {}
            }
        },
    }

    Ok(())
}

async fn udp_thread(opt: CmdOpt, user_key: Option<UserKey>, cache: Cache<Vec<Query>, Message>) -> Result<()> {
    async fn _udp_thread(opt: CmdOpt, user_key: Option<UserKey>, cache: Cache<Vec<Query>, Message>) -> Result<()> {
        let listener = UdpSocket::bind(&opt.listen_addr).await?;
        log::info!("Udp listening on: {}", opt.listen_addr);

        let timeout = Duration::from_secs(5);

        let mut buf = [0u8; 4096];
        loop {
            let (len, src) = listener.recv_from(&mut buf).await?;

            let message = parse_data_to_dns_message(&buf[..len], false)?;
            let domain = extract_domain_from_dns_message(&message)?;

            if opt.cache_records {
                if let Some(mut cached_message) = cache.get(&message.queries().to_vec()) {
                    cached_message.set_id(message.id());
                    let data = cached_message.to_vec().map_err(|e| e.to_string())?;
                    listener.send_to(&data, &src).await?;
                    log_dns_message("dns cache hit", &domain, &cached_message);
                    continue;
                }
            }

            let proxy_addr = opt.socks5_server;
            let udp_server_addr = opt.dns_remote_server;
            let auth = user_key.clone();
            let data = client::UdpClientImpl::datagram(proxy_addr, udp_server_addr, auth)
                .await?
                .transfer_data(&buf[..len], timeout)
                .await?;
            listener.send_to(&data, &src).await?;

            let message = parse_data_to_dns_message(&data, false)?;
            log_dns_message("dns query", &domain, &message);
            if opt.cache_records {
                cache.insert(message.queries().to_vec(), message).await;
            }
        }
    }

    loop {
        if let Err(e) = _udp_thread(opt.clone(), user_key.clone(), cache.clone()).await {
            log::error!("UDP error \"{}\"", e);
        }
    }
}

async fn tcp_thread(opt: CmdOpt, user_key: Option<UserKey>, cache: Cache<Vec<Query>, Message>) -> Result<()> {
    let listener = TcpListener::bind(&opt.listen_addr).await?;
    log::info!("TCP listening on: {}", opt.listen_addr);

    while let Ok((mut incoming, _)) = listener.accept().await {
        let opt = opt.clone();
        let user_key = user_key.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_incoming(&opt, user_key, cache, &mut incoming).await {
                log::error!("{}", e);
            }
        });
    }
    Ok(())
}

async fn handle_tcp_incoming(
    opt: &CmdOpt,
    user_key: Option<UserKey>,
    cache: Cache<Vec<Query>, Message>,
    incoming: &mut TcpStream,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = incoming.read(&mut buf).await?;

    let s5_proxy = TcpStream::connect(&opt.socks5_server).await?;
    let mut stream = BufStream::new(s5_proxy);

    let _addr = client::connect(&mut stream, &opt.dns_remote_server, user_key).await?;

    let message = parse_data_to_dns_message(&buf[..n], true)?;
    let domain = extract_domain_from_dns_message(&message)?;

    if opt.cache_records {
        if let Some(mut cached_message) = cache.get(&message.queries().to_vec()) {
            cached_message.set_id(message.id());
            let data = cached_message.to_vec().map_err(|e| e.to_string())?;
            incoming.write_all(&data).await?;
            log_dns_message("dns via TCP cache hit", &domain, &cached_message);
            return Ok(());
        }
    }

    stream.write_all(&buf[..n]).await?;
    stream.flush().await?;

    let mut buf = vec![0; 4096];
    let n = stream.read(&mut buf).await?;

    incoming.write_all(&buf[..n]).await?;

    let message = parse_data_to_dns_message(&buf[..n], true)?;
    log_dns_message("dns query via TCP", &domain, &message);

    if opt.cache_records {
        cache.insert(message.queries().to_vec(), message).await;
    }

    Ok(())
}

fn log_dns_message(prefix: &str, domain: &str, message: &Message) {
    let ipaddr = match extract_ipaddr_from_dns_message(message) {
        Ok(ipaddr) => {
            format!("{:?}", ipaddr)
        }
        Err(e) => e,
    };
    log::trace!("{} {:?} <==> {:?}", prefix, domain, ipaddr);
}

fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    for answer in message.answers() {
        match answer.data().ok_or("DnsResponse no answer data")? {
            RData::A(addr) => {
                return Ok(IpAddr::V4(*addr));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6(*addr));
            }
            RData::CNAME(_name) => {
                // log::trace!("{}: {}", answer.name(), _name);
            }
            _ => {}
        }
    }
    Err(format!("{:?}", message.answers()))
}

fn extract_domain_from_dns_message(message: &Message) -> Result<String> {
    let query = message.queries().get(0).ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}
