use clap::Parser;
use snafu::{whatever, ResultExt};
use std::{error::Error, time::Duration};
use tokio::{
    io::{self},
    net::{lookup_host, TcpListener, TcpStream},
    task,
    time::{sleep, timeout},
};
use tracing::{event, Level};

use crate::protocol::Socks5Protocol;

mod protocol;

type Result<T, E = snafu::Whatever> = std::result::Result<T, E>;

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
            idle_timeout: Duration::from_mins(15),
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

    pub async fn handle(mut self) -> Result<()> {
        let negotiation_timeout = self.negotiation_timeout;

        let negotiation = async {
            let auth_method = self.protocol.check_auth_method().await?;
            self.protocol.send_auth_response(auth_method).await?;

            // If we actually required authentication, we would do that at this point.

            let sock_addr = self.protocol.check_socks_request().await?;
            let remote_stream = self
                .protocol
                .connect_socks_target((sock_addr.0.as_str(), sock_addr.1))
                .await?;

            Ok(remote_stream)
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
                whatever!("timed out")
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
#[snafu::report]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    let listen_addr_port = format!("{}:{}", opt.listen, opt.port);
    let listener = TcpListener::bind(listen_addr_port)
        .await
        .whatever_context("bind")?;
    event!(
        Level::INFO,
        "Listening on {}",
        listener.local_addr().unwrap()
    );

    let bind_addr = match opt.bind {
        Some(addr) => {
            // Do a trial resolution of the address
            let sock_addr = format!("{addr}:0");
            let addrs = lookup_host(&sock_addr)
                .await
                .whatever_context("lookup_host")?;
            if addrs.count() == 0 {
                whatever!("failed to resolve bind address {addr}");
            }
            event!(Level::INFO, "Binding on {}", addr);
            Some(sock_addr)
        }
        None => None,
    };

    let negotiation_timeout = Duration::from_secs(opt.negotiation_timeout);
    let idle_timeout = Duration::from_secs(opt.idle_timeout);

    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("listening for CTRL-C");
    };

    let main_loop = async {
        loop {
            match listener.accept().await {
                Ok((socket, sock_addr)) => {
                    let client_id = format!("{sock_addr}");
                    let bind_addr = bind_addr.clone();
                    task::spawn(async move {
                        let client = Socks5Client::new(socket, client_id.clone(), bind_addr)
                            .with_negotiation_timeout(negotiation_timeout)
                            .with_idle_timeout(idle_timeout);
                        match client.handle().await {
                            Err(ref e)
                                if let Some(ioe) =
                                    e.source().and_then(|s| s.downcast_ref::<io::Error>())
                                    && (ioe.kind() == io::ErrorKind::BrokenPipe
                                        || ioe.kind() == io::ErrorKind::ConnectionReset) =>
                            { /* ignore */ }
                            Err(e) => event!(Level::DEBUG, "client {} error: {}", client_id, e),
                            Ok(()) => {}
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
    };

    tokio::select! {
        () = ctrl_c => {},
        () = main_loop => {},
    }

    Ok(())
}
