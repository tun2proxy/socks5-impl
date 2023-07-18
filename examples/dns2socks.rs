use moka::future::Cache;
use socks5_impl::{client, protocol::UserKey, Error, Result};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc::{self, Receiver},
};
use trust_dns_proto::{
    op::{Message, Query, ResponseCode::NoError},
    rr::RData,
};

const MAX_BUFFER_SIZE: usize = 4096;

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

    /// Cache DNS query records
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
                Ok(Err(e)) => log::error!("UDP error \"{}\"", e),
                Err(e) => log::error!("UDP error \"{}\"", e),
                _ => {}
            }
        },
        res = tokio::spawn(tcp_thread(opt, user_key, cache)) => {
            match res {
                Ok(Err(e)) => log::error!("TCP error \"{}\"", e),
                Err(e) => log::error!("TCP error \"{}\"", e),
                _ => {}
            }
        },
    }

    Ok(())
}

async fn udp_thread(opt: CmdOpt, user_key: Option<UserKey>, cache: Cache<Vec<Query>, Message>) -> Result<()> {
    let udp_listener = Arc::new(UdpSocket::bind(&opt.listen_addr).await?);
    log::info!("Udp listening on: {}", opt.listen_addr);
    let (sender, mut receiver) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);

    let timeout = Duration::from_secs(5);

    let listener = udp_listener.clone();

    // to avoid move semantic occurs, we defined a function instead of a closure
    async fn channel_end(
        receiver: &mut Receiver<(SocketAddr, Vec<u8>)>,
        opt: &CmdOpt,
        cache: &Cache<Vec<Query>, Message>,
        listener: &Arc<UdpSocket>,
        user_key: &Option<UserKey>,
        timeout: Duration,
    ) -> Result<()> {
        while let Some((src, buf)) = receiver.recv().await {
            let message = parse_data_to_dns_message(&buf, false)?;
            let domain = extract_domain_from_dns_message(&message)?;

            if opt.cache_records {
                if let Some(mut cached_message) = cache.get(&message.queries().to_vec()) {
                    cached_message.set_id(message.id());
                    let data = cached_message.to_vec().map_err(|e| e.to_string())?;
                    listener.send_to(&data, &src).await?;
                    log_dns_message("DNS query via UDP cache hit", &domain, &cached_message);
                    continue;
                }
            }

            let proxy_addr = opt.socks5_server;
            let udp_server_addr = opt.dns_remote_server;
            let auth = user_key.clone();
            let data = client::UdpClientImpl::datagram(proxy_addr, udp_server_addr, auth)
                .await?
                .transfer_data(&buf, timeout)
                .await?;
            listener.send_to(&data, &src).await?;

            let message = parse_data_to_dns_message(&data, false)?;
            log_dns_message("DNS query via UDP", &domain, &message);
            if opt.cache_records {
                cache.insert(message.queries().to_vec(), message).await;
            }
        }
        Ok::<(), Error>(())
    }

    tokio::spawn(async move {
        loop {
            if let Err(e) = channel_end(&mut receiver, &opt, &cache, &listener, &user_key, timeout).await {
                log::error!("UDP channel_end thread error \"{}\"", e);
            }
        }
    });

    loop {
        let udp_listener = udp_listener.clone();
        let sender = sender.clone();
        let block = async move {
            let mut buf = vec![0u8; MAX_BUFFER_SIZE];
            let (len, src) = udp_listener.recv_from(&mut buf).await?;
            buf.resize(len, 0);
            sender.send((src, buf)).await.map_err(|e| e.to_string())?;
            Ok::<(), Error>(())
        };
        if let Err(e) = block.await {
            log::error!("UDP listener error \"{}\"", e);
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
                log::error!("TCP error \"{}\"", e);
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
    let mut buf = [0u8; MAX_BUFFER_SIZE];
    let n = incoming.read(&mut buf).await?;

    let message = parse_data_to_dns_message(&buf[..n], true)?;
    let domain = extract_domain_from_dns_message(&message)?;

    if opt.cache_records {
        if let Some(mut cached_message) = cache.get(&message.queries().to_vec()) {
            cached_message.set_id(message.id());
            let data = cached_message.to_vec().map_err(|e| e.to_string())?;
            let len = u16::try_from(data.len()).map_err(|e| e.to_string())?.to_be_bytes().to_vec();
            let data = [len, data].concat();
            incoming.write_all(&data).await?;
            log_dns_message("DNS query via TCP cache hit", &domain, &cached_message);
            return Ok(());
        }
    }

    let s5_proxy = TcpStream::connect(&opt.socks5_server).await?;
    let mut stream = BufStream::new(s5_proxy);

    let _addr = client::connect(&mut stream, &opt.dns_remote_server, user_key).await?;

    stream.write_all(&buf[..n]).await?;
    stream.flush().await?;

    let mut buf = vec![0; 4096];
    let n = stream.read(&mut buf).await?;

    incoming.write_all(&buf[..n]).await?;

    let message = parse_data_to_dns_message(&buf[..n], true)?;
    log_dns_message("DNS query via TCP", &domain, &message);

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
        match answer.data().ok_or("DNS response not contains answer data")? {
            RData::A(addr) => {
                return Ok(IpAddr::V4(*addr));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6(*addr));
            }
            _ => {}
        }
    }
    Err(format!("{:?}", message.answers()))
}

fn extract_domain_from_dns_message(message: &Message) -> Result<String> {
    let query = message.queries().get(0).ok_or("DNS request not contains query body")?;
    let name = query.name().to_string();
    Ok(name)
}

fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("Invalid DNS data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("Invalid DNS data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}
