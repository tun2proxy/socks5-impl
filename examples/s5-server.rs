use socks5_impl::{
    Error, Result,
    protocol::{Address, Reply, UdpHeader},
    server::{AssociatedUdpSocket, ClientConnection, IncomingConnection, Server, UdpAssociate, auth, connection::associate},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io,
    net::{TcpStream, UdpSocket},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

/// Simple socks5 proxy server.
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Simple socks5 proxy server.", long_about = None)]
pub struct CmdOpt {
    /// Socks5 server listen address.
    #[clap(short, long, value_name = "address:port", default_value = "127.0.0.1:1080")]
    listen_addr: SocketAddr,

    /// Username for socks5 authentication.
    #[clap(short, long, value_name = "username")]
    username: Option<String>,

    /// Password for socks5 authentication.
    #[clap(short, long, value_name = "password")]
    password: Option<String>,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    verbosity: ArgVerbosity,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgVerbosity {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub(crate) static MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

#[tokio::main]
async fn main() -> Result<()> {
    let opt: CmdOpt = clap::Parser::parse();

    dotenvy::dotenv().ok();

    let default = format!("{}={:?}", module_path!(), opt.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let token = CancellationToken::new();
    let cloned_token = token.clone();

    let ctrlc = ctrlc2::AsyncCtrlC::new(move || {
        log::info!("");
        log::info!("Ctrl-C received, shutting down...");
        cloned_token.cancel();
        true
    })?;

    match (opt.username, opt.password) {
        (Some(username), password) => {
            let password = password.unwrap_or_default();
            let auth = Arc::new(auth::UserKeyAuth::new(&username, &password));
            main_loop(auth, opt.listen_addr, token).await?;
        }
        _ => {
            let auth = Arc::new(auth::NoAuth);
            main_loop(auth, opt.listen_addr, token).await?;
        }
    }

    ctrlc.await?;

    Ok(())
}

async fn main_loop<S>(auth: auth::AuthAdaptor<S>, listen_addr: SocketAddr, token: CancellationToken) -> Result<()>
where
    S: Send + Sync + 'static,
{
    let server = Server::bind(listen_addr, auth).await?;

    loop {
        let (conn, _) = tokio::select! {
            _ = token.cancelled() => {
                log::info!("CancellationToken fired, session will be closed");
                break;
            }
            conn = server.accept() => conn?,
        };
        tokio::spawn(async move {
            if let Err(err) = handle(conn).await {
                log::error!("{err}");
            }
        });
    }
    Ok(())
}

async fn handle<S>(conn: IncomingConnection<S>) -> Result<()>
where
    S: Send + Sync + 'static,
{
    let (conn, res) = conn.authenticate().await?;

    use std::any::Any;
    let res = &res as &dyn Any;
    if let Some(res) = res.downcast_ref::<std::io::Result<bool>>() {
        let res = *res.as_ref().map_err(|err| err.to_string())?;
        if !res {
            log::info!("authentication failed");
            return Ok(());
        }
    }

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            handle_s5_upd_associate(associate).await?;
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            let target = match addr {
                Address::DomainAddress(domain, port) => TcpStream::connect((domain, port)).await,
                Address::SocketAddress(addr) => TcpStream::connect(addr).await,
            };

            if let Ok(mut target) = target {
                let mut conn = connect.reply(Reply::Succeeded, Address::unspecified()).await?;
                log::trace!("{} -> {}", conn.peer_addr()?, target.peer_addr()?);
                io::copy_bidirectional(&mut target, &mut conn).await?;
            } else {
                let mut conn = connect.reply(Reply::HostUnreachable, Address::unspecified()).await?;
                conn.shutdown().await?;
            }
        }
    }

    Ok(())
}

pub(crate) async fn handle_s5_upd_associate(associate: UdpAssociate<associate::NeedReply>) -> Result<()> {
    // listen on a random port
    let listen_ip = associate.local_addr()?.ip();
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Err(err) => {
            let mut conn = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            conn.shutdown().await?;
            Err(err.into())
        }
        Ok((listen_udp, listen_addr)) => {
            log::info!("[UDP] {listen_addr} listen on");

            let s5_listen_addr = Address::from(listen_addr);
            let mut reply_listener = associate.reply(Reply::Succeeded, s5_listen_addr).await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));

            let zero_ip: IpAddr = match listen_addr {
                SocketAddr::V4(_) => std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };

            let zero_addr = SocketAddr::from((zero_ip, 0));

            let incoming_addr = Arc::new(Mutex::new(zero_addr));

            let dispatch_socket = UdpSocket::bind(zero_addr).await?;

            let res = loop {
                tokio::select! {
                    res = async {
                        let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
                        listen_udp.set_max_packet_size(buf_size);

                        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
                        if frag != 0 {
                            return Err("[UDP] packet fragment is not supported".into());
                        }

                        *incoming_addr.lock().await = src_addr;

                        log::trace!("[UDP] {src_addr} -> {dst_addr} incoming packet size {}", pkt.len());
                        let dst_addr = dst_addr.to_socket_addrs()?.next().ok_or("Invalid address")?;
                        dispatch_socket.send_to(&pkt, dst_addr).await?;
                        Ok::<_, Error>(())
                    } => {
                        if res.is_err() {
                            break res;
                        }
                    },
                    res = async {
                        let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
                        let (len, remote_addr) = dispatch_socket.recv_from(&mut buf).await?;
                        let incoming_addr = *incoming_addr.lock().await;
                        log::trace!("[UDP] {incoming_addr} <- {remote_addr} feedback to incoming");
                        listen_udp.send_to(&buf[..len], 0, remote_addr.into(), incoming_addr).await?;
                        Ok::<_, Error>(())
                    } => {
                        if res.is_err() {
                            break res;
                        }
                    },
                    _ = reply_listener.wait_until_closed() => {
                        log::trace!("[UDP] {} listener closed", listen_addr);
                        break Ok::<_, Error>(());
                    },
                };
            };

            reply_listener.shutdown().await?;

            res
        }
    }
}
