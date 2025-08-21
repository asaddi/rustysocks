use clap::Parser;
use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpSocket, TcpStream},
    task,
    time::{sleep, timeout},
    try_join,
};
use tracing::{event, Level};

const IO_BUFFER_SIZE: usize = 32768;

const SOCKS5_VERSION: u8 = 0x05;

#[derive(Debug)]
enum Socks5AuthMethod {
    NoAuth = 0x00,
    // GSSAPI = 0x01,
    // UsernamePassword = 0x02,
    Invalid = 0xff,
}

#[derive(Debug)]
enum Socks5Command {
    Connect = 0x01,
    // Bind = 0x02,
    // UDPAssociate = 0x03,
}

#[derive(Debug)]
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

#[derive(Debug)]
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

struct Socks5Protocol {
    stream: TcpStream,
    client_id: String,
    bind_addr: Option<String>,
}

impl Socks5Protocol {
    pub fn new(stream: TcpStream, client_id: String, bind_addr: Option<String>) -> Socks5Protocol {
        Socks5Protocol {
            stream,
            client_id,
            bind_addr,
        }
    }

    async fn check_auth_method(&mut self) -> io::Result<Socks5AuthMethod> {
        let mut buf = [0u8; 256];

        self.stream.read_exact(&mut buf[0..2]).await?;
        if buf[0] != SOCKS5_VERSION {
            return Ok(Socks5AuthMethod::Invalid);
        }

        let nmethods = buf[1] as usize;

        self.stream.read_exact(&mut buf[0..nmethods]).await?;
        for b in &buf[0..nmethods] {
            if *b == Socks5AuthMethod::NoAuth as u8 {
                return Ok(Socks5AuthMethod::NoAuth);
            }
        }

        Ok(Socks5AuthMethod::Invalid)
    }

    async fn send_auth_response(&mut self, auth_method: Socks5AuthMethod) -> io::Result<()> {
        self.stream
            .write_all(&[SOCKS5_VERSION, auth_method as u8])
            .await?;
        self.stream.flush().await
    }

    async fn check_socks_request(&mut self) -> io::Result<String> {
        let mut buf = [0u8; 257]; // max 255 for domain + 2 for port

        self.stream.read_exact(&mut buf[0..4]).await?;
        if buf[0] != SOCKS5_VERSION {
            self.send_error(Socks5Reply::GeneralFailure).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid request",
            ));
        }
        if buf[1] != Socks5Command::Connect as u8 {
            self.send_error(Socks5Reply::CommandNotSupported).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command not supported",
            ));
        }
        if buf[2] != 0x00u8 {
            self.send_error(Socks5Reply::GeneralFailure).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid request",
            ));
        }

        // Now for the address...
        let sock_addr: String;
        match Socks5AddressType::try_from(buf[3]) {
            Ok(Socks5AddressType::V4) => {
                self.stream.read_exact(&mut buf[0..6]).await?; // 4 bytes IP address + 2 for port

                // Can't convert to Ipv4Addr directly from slice, so first convert to array...
                let raw: [u8; 4] = buf[0..4].try_into().unwrap();
                let addr = Ipv4Addr::from(raw);

                let port = Socks5Protocol::get_port(&buf[4..6]);

                // Gotta be a better way...
                sock_addr = format!("{}:{}", addr, port);
            }
            Ok(Socks5AddressType::V6) => {
                self.stream.read_exact(&mut buf[0..18]).await?; // 16 bytes for IPv6 address + 2 for port

                // Can't convert to Ipv6Addr directly from slice, so first convert to array...
                let raw: [u8; 16] = buf[0..16].try_into().unwrap();
                let addr = Ipv6Addr::from(raw);

                let port = Socks5Protocol::get_port(&buf[16..18]);

                sock_addr = format!("{}:{}", addr, port);
            }
            Ok(Socks5AddressType::DomainName) => {
                self.stream.read_exact(&mut buf[0..1]).await?;

                let len = buf[0] as usize;

                self.stream.read_exact(&mut buf[0..len + 2]).await?; // +2 more for port

                // No where does RFC1928 mention unicode, but whatever...
                if let Ok(addr) = std::str::from_utf8(&buf[0..len]) {
                    let port = Socks5Protocol::get_port(&buf[len..len + 2]);

                    sock_addr = format!("{}:{}", addr, port);
                } else {
                    self.send_error(Socks5Reply::AddressTypeNotSupported)
                        .await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "address type not supported",
                    ));
                }
            }
            _ => {
                self.send_error(Socks5Reply::AddressTypeNotSupported)
                    .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "address type not supported",
                ));
            }
        }

        Ok(sock_addr)
    }

    async fn connect_socks_target(&mut self, target_addr: &str) -> io::Result<TcpStream> {
        // Attempt the connection
        let remote_result = match &self.bind_addr {
            Some(ip_addr) => {
                Socks5Protocol::bind_and_connect_to_addr(ip_addr.as_str(), target_addr).await
            }
            None => TcpStream::connect(target_addr).await,
        };

        // And return the appropriate reply
        if let Ok(remote_stream) = remote_result {
            event!(
                Level::DEBUG,
                "client {} connected to {}",
                self.client_id,
                target_addr
            );
            self.send_success(&remote_stream).await?;
            Ok(remote_stream)
        } else {
            // FIXME map errors to appropriate SOCKS5 replies
            self.send_error(Socks5Reply::ConnectionRefused).await?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("failed to connect to {}", target_addr),
            ))
        }
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

                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("failed to resolve address {}", addr),
                ))
            }
            Err(e) => Err(e),
        }
    }

    async fn copy_loop(
        mut self,
        mut remote_stream: TcpStream,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        let mut client_buf = vec![0u8; IO_BUFFER_SIZE];
        let mut remote_buf = vec![0u8; IO_BUFFER_SIZE];

        loop {
            tokio::select! {
                res = self.stream.read(&mut client_buf) => {
                    match res {
                        Ok(n) if n > 0 => {
                            if remote_stream.write_all(&client_buf[..n]).await.is_err() {
                                event!(Level::DEBUG, "client {} remote write error", self.client_id);
                                break;
                            }
                        }
                        Ok(_) => {
                            event!(Level::TRACE, "client {} client EOF", self.client_id);
                            break;
                        }
                        Err(e) => {
                            event!(Level::TRACE, "client {} client read error: {}", self.client_id, e);
                            break;
                        }
                    }
                }
                res = remote_stream.read(&mut remote_buf) => {
                    match res {
                        Ok(n) if n > 0 => {
                            if self.stream.write_all(&remote_buf[..n]).await.is_err() {
                                event!(Level::DEBUG, "client {} client write error", self.client_id);
                                break;
                            }
                        }
                        Ok(_) => {
                            event!(Level::TRACE, "client {} remote EOF", self.client_id);
                            break;
                        }
                        Err(e) => {
                            event!(Level::DEBUG, "client {} remote read error: {} ", self.client_id, e);
                            break;
                        }
                    }
                }
                _ = sleep(idle_timeout) => {
                    // Timeout
                    event!(Level::DEBUG, "client {} timed out", self.client_id);
                    break;
                }
            }
        }

        let _ = self.stream.shutdown().await.is_ok();
        let _ = remote_stream.shutdown().await.is_ok();

        Ok(())
    }

    async fn send_error(&mut self, reply: Socks5Reply) -> io::Result<()> {
        event!(Level::TRACE, "sending reply {:?}", reply);
        self.stream
            .write_all(&[
                SOCKS5_VERSION,
                reply as u8,
                /* reserved */ 0x00,
                /* addr */ Socks5AddressType::V4 as u8,
                0,
                0,
                0,
                0,
                /* port */ 0,
                0,
            ])
            .await?;
        self.stream.flush().await
    }

    async fn send_success(&mut self, stream: &TcpStream) -> io::Result<()> {
        self.stream
            .write_all(&[
                SOCKS5_VERSION,
                Socks5Reply::Success as u8,
                /* reserved */ 0x00,
            ])
            .await?;
        let addr = stream.local_addr().unwrap();
        match addr {
            SocketAddr::V4(addr_v4) => {
                event!(Level::TRACE, "sending success {:?}", &addr_v4);
                // TODO would it be better to write this out as a single operation? write_vectored?
                self.stream
                    .write_all(&[Socks5AddressType::V4 as u8])
                    .await?;
                self.stream.write_all(&addr_v4.ip().octets()).await?;
                self.stream.write_u16(addr_v4.port()).await?;
            }
            SocketAddr::V6(addr_v6) => {
                event!(Level::TRACE, "sending success {:?}", &addr_v6);
                // TODO see above
                self.stream
                    .write_all(&[Socks5AddressType::V6 as u8])
                    .await?;
                self.stream.write_all(&addr_v6.ip().octets()).await?;
                self.stream.write_u16(addr_v6.port()).await?;
            }
        }
        self.stream.flush().await
    }

    fn get_port(s: &[u8]) -> u16 {
        // slice better be 2 bytes or we panic!
        u16::from_be_bytes(s.try_into().unwrap()) // network order is big endian
    }
}

struct Socks5Client {
    protocol: Socks5Protocol,
    negotiation_timeout: Duration,
    idle_timeout: Duration,
}

impl Socks5Client {
    pub fn new(stream: TcpStream, client_id: String, bind_addr: Option<String>) -> Socks5Client {
        Socks5Client {
            protocol: Socks5Protocol::new(stream, client_id, bind_addr),
            negotiation_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(900),
        }
    }

    pub fn with_negotiation_timeout(mut self, timeout: Duration) -> Socks5Client {
        self.negotiation_timeout = timeout;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Socks5Client {
        self.idle_timeout = timeout;
        self
    }

    pub async fn handle(mut self) -> io::Result<()> {
        let negotiation_timeout = self.negotiation_timeout;

        let negotiation = async {
            let auth_method = self.protocol.check_auth_method().await?;
            self.protocol.send_auth_response(auth_method).await?;

            // If we actually required authentication, we would do that at this point.

            let sock_addr = self.protocol.check_socks_request().await?;
            let remote_stream = self
                .protocol
                .connect_socks_target(sock_addr.as_str())
                .await?;

            io::Result::Ok(remote_stream)
        };

        // Give client a fixed amount of time to complete negotiation.
        // This also includes the time it takes to connect to the target! (TODO Should it?)
        match timeout(negotiation_timeout, negotiation).await {
            Ok(res) => {
                let remote_stream = res?;

                // From this point onward, it's as if the client is directly connected to the remote

                self.protocol
                    .copy_loop(remote_stream, self.idle_timeout)
                    .await?;

                Ok(())
            }
            Err(_) => {
                // Negotiation timed out
                Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(about)]
struct Opt {
    #[arg(short, long, value_name = "ADDRESS", default_value = "0.0.0.0")]
    listen: String,

    #[arg(short, long, default_value = "1080")]
    port: u16,

    #[arg(short, long, value_name = "ADDRESS")]
    bind: Option<String>,

    #[arg(
        short = 't',
        long = "timeout",
        value_name = "SECONDS",
        default_value = "30"
    )]
    negotiation_timeout: u64,

    #[arg(
        short = 'T',
        long = "idle-timeout",
        value_name = "SECONDS",
        default_value = "900"
    )]
    idle_timeout: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    let listen_addr_port = format!("{}:{}", opt.listen, opt.port);
    let listener = TcpListener::bind(listen_addr_port).await?;
    event!(
        Level::INFO,
        "Listening on {}",
        listener.local_addr().unwrap()
    );

    let bind_addr = match opt.bind {
        Some(addr) => {
            // Do a trial resolution of the address
            let sock_addr = format!("{}:0", addr);
            let addrs = lookup_host(&sock_addr).await?;
            if addrs.count() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("failed to resolve bind address {}", addr),
                ));
            } else {
                event!(Level::INFO, "Binding on {}", addr);
                Some(sock_addr)
            }
        }
        None => None,
    };

    let negotiation_timeout = Duration::from_secs(opt.negotiation_timeout);
    let idle_timeout = Duration::from_secs(opt.idle_timeout);

    loop {
        match listener.accept().await {
            Ok((socket, sock_addr)) => {
                let client_id = format!("{}", sock_addr);
                let bind_addr = bind_addr.clone();
                task::spawn(async move {
                    let client = Socks5Client::new(socket, client_id.clone(), bind_addr)
                        .with_negotiation_timeout(negotiation_timeout)
                        .with_idle_timeout(idle_timeout);
                    match client.handle().await {
                        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => { /* ignore */ }
                        Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => { /* ignore */ }
                        Err(e) => event!(Level::DEBUG, "client {} error: {}", client_id, e),
                        Ok(_) => {}
                    }
                });
            }
            Err(e) => {
                event!(Level::ERROR, "accept error: {}", e);
                // Avoid hard spinning in the accept loop
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
