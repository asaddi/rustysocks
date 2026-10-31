use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use snafu::{whatever, ResultExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpSocket, TcpStream},
    time::sleep,
    try_join,
};
use tracing::{event, Level};

type Result<T, E = snafu::Whatever> = std::result::Result<T, E>;

const IO_BUFFER_SIZE: usize = 32768;

const SOCKS5_VERSION: u8 = 0x05;

#[derive(Debug)]
pub enum Socks5AuthMethod {
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

pub struct Socks5Protocol {
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

    pub async fn check_auth_method(&mut self) -> Result<Socks5AuthMethod> {
        let mut buf = [0u8; 256];

        self.stream
            .read_exact(&mut buf[0..2])
            .await
            .whatever_context("read_exact")?;
        if buf[0] != SOCKS5_VERSION {
            return Ok(Socks5AuthMethod::Invalid);
        }

        let nmethods = buf[1] as usize;

        self.stream
            .read_exact(&mut buf[0..nmethods])
            .await
            .whatever_context("read_exact")?;
        for b in &buf[0..nmethods] {
            if *b == Socks5AuthMethod::NoAuth as u8 {
                return Ok(Socks5AuthMethod::NoAuth);
            }
        }

        Ok(Socks5AuthMethod::Invalid)
    }

    pub async fn send_auth_response(&mut self, auth_method: Socks5AuthMethod) -> Result<()> {
        self.stream
            .write_all(&[SOCKS5_VERSION, auth_method as u8])
            .await
            .whatever_context("write_all")?;
        self.stream.flush().await.whatever_context("flush")
    }

    pub async fn check_socks_request(&mut self) -> Result<String> {
        let mut buf = [0u8; 257]; // max 255 for domain + 2 for port

        self.stream
            .read_exact(&mut buf[0..4])
            .await
            .whatever_context("read_exact")?;
        if buf[0] != SOCKS5_VERSION {
            self.send_error(Socks5Reply::GeneralFailure).await?;
            whatever!("invalid request");
        }
        if buf[1] != Socks5Command::Connect as u8 {
            self.send_error(Socks5Reply::CommandNotSupported).await?;
            whatever!("command not supported");
        }
        if buf[2] != 0x00u8 {
            self.send_error(Socks5Reply::GeneralFailure).await?;
            whatever!("invalid request");
        }

        // Now for the address...
        let sock_addr: String;
        match Socks5AddressType::try_from(buf[3]) {
            Ok(Socks5AddressType::V4) => {
                self.stream
                    .read_exact(&mut buf[0..6])
                    .await
                    .whatever_context("read_exact")?; // 4 bytes IP address + 2 for port

                // Can't convert to Ipv4Addr directly from slice, so first convert to array...
                let raw: [u8; 4] = buf[0..4].try_into().unwrap();
                let addr = Ipv4Addr::from(raw);

                let port = Socks5Protocol::get_port(&buf[4..6]);

                // Gotta be a better way...
                sock_addr = format!("{addr}:{port}");
            }
            Ok(Socks5AddressType::V6) => {
                self.stream
                    .read_exact(&mut buf[0..18])
                    .await
                    .whatever_context("read_exact")?; // 16 bytes for IPv6 address + 2 for port

                // Can't convert to Ipv6Addr directly from slice, so first convert to array...
                let raw: [u8; 16] = buf[0..16].try_into().unwrap();
                let addr = Ipv6Addr::from(raw);

                let port = Socks5Protocol::get_port(&buf[16..18]);

                sock_addr = format!("{addr}:{port}");
            }
            Ok(Socks5AddressType::DomainName) => {
                self.stream
                    .read_exact(&mut buf[0..1])
                    .await
                    .whatever_context("read_exact")?;

                let len = buf[0] as usize;

                self.stream
                    .read_exact(&mut buf[0..len + 2])
                    .await
                    .whatever_context("read_exact")?; // +2 more for port

                // No where does RFC1928 mention unicode, but whatever...
                if let Ok(addr) = std::str::from_utf8(&buf[0..len]) {
                    let port = Socks5Protocol::get_port(&buf[len..len + 2]);

                    sock_addr = format!("{addr}:{port}");
                } else {
                    self.send_error(Socks5Reply::AddressTypeNotSupported)
                        .await?;
                    whatever!("address type not supported");
                }
            }
            _ => {
                self.send_error(Socks5Reply::AddressTypeNotSupported)
                    .await?;
                whatever!("address type not supported");
            }
        }

        Ok(sock_addr)
    }

    pub async fn connect_socks_target(&mut self, target_addr: &str) -> Result<TcpStream> {
        // Attempt the connection
        let remote_result = match &self.bind_addr {
            Some(ip_addr) => {
                Socks5Protocol::bind_and_connect_to_addr(ip_addr.as_str(), target_addr).await
            }
            None => TcpStream::connect(target_addr)
                .await
                .whatever_context("TcpStream::connect"),
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
            whatever!("failed to connect to {target_addr}")
        }
    }

    async fn bind_and_connect_to_addr(bind_addr: &str, addr: &str) -> Result<TcpStream> {
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
                            }
                            .whatever_context("TcpSocket::new_v?")?;

                            socket
                                .set_reuseaddr(true)
                                .whatever_context("set_reuseaddr")?;

                            if socket.bind(baddr).is_ok() {
                                if let Ok(stream) = socket.connect(*addr).await {
                                    return Ok(stream);
                                }
                            }
                        }
                    }
                }

                whatever!("failed to resolve address {addr}")
            }
            Err(e) => Err(e).whatever_context("lookup_host"),
        }
    }

    pub async fn copy_loop(
        mut self,
        mut remote_stream: TcpStream,
        idle_timeout: Duration,
    ) -> Result<()> {
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
                () = sleep(idle_timeout) => {
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

    async fn send_error(&mut self, reply: Socks5Reply) -> Result<()> {
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
            .await
            .whatever_context("write_all")?;
        self.stream.flush().await.whatever_context("flush")
    }

    async fn send_success(&mut self, stream: &TcpStream) -> Result<()> {
        self.stream
            .write_all(&[
                SOCKS5_VERSION,
                Socks5Reply::Success as u8,
                /* reserved */ 0x00,
            ])
            .await
            .whatever_context("write_all")?;
        let addr = stream.local_addr().unwrap();
        match addr {
            SocketAddr::V4(addr_v4) => {
                event!(Level::TRACE, "sending success {:?}", &addr_v4);
                // TODO would it be better to write this out as a single operation? write_vectored?
                self.stream
                    .write_all(&[Socks5AddressType::V4 as u8])
                    .await
                    .whatever_context("write_all")?;
                self.stream
                    .write_all(&addr_v4.ip().octets())
                    .await
                    .whatever_context("write_all")?;
                self.stream
                    .write_u16(addr_v4.port())
                    .await
                    .whatever_context("write_u16")?;
            }
            SocketAddr::V6(addr_v6) => {
                event!(Level::TRACE, "sending success {:?}", &addr_v6);
                // TODO see above
                self.stream
                    .write_all(&[Socks5AddressType::V6 as u8])
                    .await
                    .whatever_context("write_all")?;
                self.stream
                    .write_all(&addr_v6.ip().octets())
                    .await
                    .whatever_context("write_all")?;
                self.stream
                    .write_u16(addr_v6.port())
                    .await
                    .whatever_context("write_u16")?;
            }
        }
        self.stream.flush().await.whatever_context("flush")
    }

    fn get_port(s: &[u8]) -> u16 {
        // slice better be 2 bytes or we panic!
        u16::from_be_bytes(s.try_into().unwrap()) // network order is big endian
    }
}
