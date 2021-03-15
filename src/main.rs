use std::{convert::{TryFrom}, net::{Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use tokio::{io::{self, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpSocket, TcpStream, lookup_host}, task, time::sleep, try_join};
use log::{debug, error, info, trace};
use structopt::StructOpt;

const SOCKS5_VERSION: u8 = 0x05;

enum Socks5AuthMethod {
    NoAuth = 0x00,
    // GSSAPI = 0x01,
    // UsernamePassword = 0x02,
    Invalid = 0xff,
}

enum Socks5Command {
    Connect = 0x01,
    // Bind = 0x02,
    // UDPAssociate = 0x03,
}

enum Socks5AddressType {
    V4 = 0x01,
    DomainName = 0x03,
    V6 = 0x04,
}

impl TryFrom<u8> for Socks5AddressType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == Socks5AddressType::V4 as u8 {
            Ok(Socks5AddressType::V4)
        } else if value == Socks5AddressType::DomainName as u8 {
            Ok(Socks5AddressType::DomainName)
        } else if value == Socks5AddressType::V6 as u8 {
            Ok(Socks5AddressType::V6)
        } else {
            Err("address type not supported")
        }
    }
}

enum Socks5Reply {
    Success = 0x00,
    GeneralFailure = 0x01,
    // ConnectionNotAllowed = 0x02,
    // NetworkUnreachable = 0x03,
    // HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    // TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

async fn send_error(stream: &mut TcpStream, reply: Socks5Reply) -> io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, reply as u8, /* reserved */ 0x00,
        /* addr */ Socks5AddressType::V4 as u8, 0, 0, 0, 0,
        /* port */ 0, 0]).await?;
    stream.flush().await
}

async fn send_auth_response(stream: &mut TcpStream, auth_method: Socks5AuthMethod) -> io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, auth_method as u8]).await?;
    stream.flush().await
}

async fn check_auth_method(stream: &mut TcpStream) -> io::Result<Socks5AuthMethod> {
    let mut buf = [0u8; 256];

    stream.read_exact(&mut buf[0..2]).await?;
    if buf[0] != SOCKS5_VERSION {
        return Ok(Socks5AuthMethod::Invalid);
    }

    let nmethods = buf[1] as usize;

    stream.read_exact(&mut buf[0..nmethods]).await?;
    for b in &buf[0..nmethods] {
        if *b == Socks5AuthMethod::NoAuth as u8 {
            return Ok(Socks5AuthMethod::NoAuth);
        }
    }

    Ok(Socks5AuthMethod::Invalid)
}

fn get_port(s: &[u8]) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(s); // slice better be 2 bytes or we panic!
    u16::from_be_bytes(buf) // network order is big endian
}

async fn check_socks_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = [0u8; 257]; // max 255 for domain + 2 for port

    stream.read_exact(&mut buf[0..4]).await?;
    if buf[0] != SOCKS5_VERSION {
        send_error(stream, Socks5Reply::GeneralFailure).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid request"));
    }
    if buf[1] != Socks5Command::Connect as u8 {
        send_error(stream, Socks5Reply::CommandNotSupported).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "command not supported"));
    }
    if buf[2] != 0x00u8 {
        send_error(stream, Socks5Reply::GeneralFailure).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid request"));
    }

    // Now for the address...
    let sock_addr: String;
    match Socks5AddressType::try_from(buf[3]) {
        Ok(Socks5AddressType::V4) => {
            stream.read_exact(&mut buf[0..6]).await?; // 4 bytes IP address + 2 for port

            // Is there no way to go from slice -> Ipv4Addr directly?
            let mut addr_buf = [0u8; 4];
            addr_buf.copy_from_slice(&buf[0..4]);
            let addr = Ipv4Addr::from(addr_buf);

            let port = get_port(&buf[4..6]);

            // Gotta be a better way...
            sock_addr = format!("{}:{}", addr, port);
        }
        Ok(Socks5AddressType::V6) => {
            stream.read_exact(&mut buf[0..18]).await?; // 16 bytes for IPv6 address + 2 for port

            let mut addr_buf = [0u8; 16];
            addr_buf.copy_from_slice(&buf[0..16]);
            let addr = Ipv6Addr::from(addr_buf);

            let port = get_port(&buf[16..18]);

            sock_addr = format!("{}:{}", addr, port);
        }
        Ok(Socks5AddressType::DomainName) => {
            stream.read_exact(&mut buf[0..1]).await?;

            let len = buf[0] as usize;

            stream.read_exact(&mut buf[0..len+2]).await?; // +2 more for port

            // No where does RFC1928 mention unicode, but whatever...
            if let Ok(addr) = std::str::from_utf8(&buf[0..len]) {
                let port = get_port(&buf[len..len+2]);

                sock_addr = format!("{}:{}", addr, port);
            } else {
                send_error(stream, Socks5Reply::AddressTypeNotSupported).await?;
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "address type not supported"));
            }
        }
        _ => {
            send_error(stream, Socks5Reply::AddressTypeNotSupported).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "address type not supported"));
        }
    }

    Ok(sock_addr)
}

async fn bind_and_connect_to_addr(bind_addr: &str, addr: &str) -> io::Result<TcpStream> {
    match try_join!(
        // Perform the lookups concurrently...
        lookup_host(bind_addr),
        lookup_host(addr)
    ) {
        Ok((bind_addrs, addrs_raw)) => {
            let addrs: Vec<SocketAddr> = addrs_raw.collect();

            for baddr in bind_addrs {
                for addr in &addrs {
                    // Only if bind address type == target address type
                    if baddr.is_ipv4() == addr.is_ipv4() {
                        let socket = if baddr.is_ipv4() {
                            TcpSocket::new_v4()
                        } else {
                            TcpSocket::new_v6()
                        }?;

                        socket.set_reuseaddr(true)?;

                        if socket.bind(baddr).is_ok() {
                            if let Ok(stream) = socket.connect(*addr).await {
                                return Ok(stream);
                            }
                        }
                    }
                }
            }

            Err(io::Error::new(io::ErrorKind::InvalidInput, format!("failed to resolve address {}", addr)))
        }
        Err(e) => Err(e)
    }
}

async fn connect_socks_target(stream: &mut TcpStream, bind_addr: Option<String>, target_addr: &str) -> io::Result<TcpStream> {
    // Attempt the connection
    let remote_result = match bind_addr {
        Some(ip_addr) => {
            bind_and_connect_to_addr(ip_addr.as_str(), target_addr).await
        },
        None => TcpStream::connect(target_addr).await
    };

    // And return the appropriate reply
    if let Ok(remote_stream) = remote_result {
        // FIXME we currently don't send the bind addr/bind port. But browsers don't seem to care.
        send_error(stream, Socks5Reply::Success).await?;
        Ok(remote_stream)
    } else {
        // FIXME map errors to appropriate SOCKS5 replies
        send_error(stream, Socks5Reply::ConnectionRefused).await?;
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("failed to connect to {}", target_addr)))
    }
}

async fn copy_loop(mut stream: TcpStream, mut remote_stream: TcpStream, client_id: &str) -> io::Result<()> {
    let mut client_buf = vec![0u8; 2048];
    let mut remote_buf = vec![0u8; 2048];

    loop {
        tokio::select! {
            res = stream.read(&mut client_buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        if remote_stream.write_all(&client_buf[..n]).await.is_err() {
                            debug!("client {} remote write error", client_id);
                            break;
                        }
                    }
                    Ok(_) => {
                        trace!("client {} client EOF", client_id);
                        break;
                    }
                    Err(e) => {
                        debug!("client {} client read error: {}", client_id, e);
                        break;
                    }
                }
            }
            res = remote_stream.read(&mut remote_buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        if stream.write_all(&remote_buf[..n]).await.is_err() {
                            debug!("client {} client write error", client_id);
                            break;
                        }
                    }
                    Ok(_) => {
                        trace!("client {} remote EOF", client_id);
                        break;
                    }
                    Err(e) => {
                        debug!("client {} remote read error: {} ", client_id, e);
                        break;
                    }
                }
            }
            _ = sleep(Duration::from_millis(900_000)) => { // 15 minutes
                // Timeout
                debug!("client {} timed out", client_id);
                break;
            }
        }
    }

    let _ = stream.shutdown().await.is_ok();
    let _ = remote_stream.shutdown().await.is_ok();

    Ok(())
}

async fn process_client(mut stream: TcpStream, client_id: &str, bind_addr: Option<String>) -> io::Result<()> {
    let auth_method = check_auth_method(&mut stream).await?;
    send_auth_response(&mut stream, auth_method).await?;

    // If we actually required authentication, we would do that here.

    let sock_addr = check_socks_request(&mut stream).await?;
    let remote_stream = connect_socks_target(&mut stream, bind_addr, sock_addr.as_str()).await?;
    debug!("client {} connected to {}", client_id, sock_addr.as_str());

    // From this point onward, it's as if the client is directly connected to the remote

    copy_loop(stream, remote_stream, client_id).await?;

    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(about)]
struct Opt {
    #[structopt(short, long, default_value = "0.0.0.0")]
    listen: String,

    #[structopt(short, long, default_value = "1080")]
    port: u16,

    #[structopt(short, long)]
    bind: Option<String>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opt = Opt::from_args();

    env_logger::init();

    let listen_addr_port = format!("{}:{}", opt.listen, opt.port);
    let listener = TcpListener::bind(listen_addr_port).await?;
    info!("Listening on {}", listener.local_addr().unwrap());

    let bind_addr = match opt.bind {
        Some(addr) => {
            // Do a trial resolution of the address
            let sock_addr = format!("{}:0", addr);
            let addrs = lookup_host(&sock_addr).await?;
            if addrs.count() == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("failed to resolve bind address {}", addr)));
            } else {
                info!("Binding on {}", addr);
                Some(sock_addr)
            }
        }
        None => None
    };

    loop {
        match listener.accept().await {
            Ok((socket, sock_addr)) => {
                let client_id = format!("{}", sock_addr);
                let bind_addr = bind_addr.clone();
                task::spawn(async move {
                    match process_client(socket, client_id.as_str(), bind_addr).await {
                        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => { /* ignore */ }
                        Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => { /* ignore */ }
                        Err(e) => debug!("client {} error: {}", client_id, e),
                        Ok(_) => {}
                    }
                });
            },
            Err(e) => {
                error!("accept error: {}", e);
                // Avoid hard spinning in the accept loop
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
