use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{routing, Router};
use clap::Parser;

use dnsmasq::DnsMasq;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use std::net::SocketAddr;
use std::sync::Arc;
use std::{env, thread};

mod dnsmasq;
mod internet_check;
mod packet_monitor;

#[derive(Parser, Debug)] // requires `derive` feature
#[command(term_width = 0)] // Just to make testing across clap features easier
struct Args {
    /// Bind Address
    #[arg(long, default_value_t = ("127.0.0.1:9155").parse().unwrap())]
    bind_addr: SocketAddr,

    /// network interface to monitor
    #[arg(long, default_value_t = format!("en0"))]
    interface: String,

    /// BPF filter
    #[arg(long, default_value_t = format!(""))]
    bpf: String,

    /// DNS leases path
    #[arg(long, default_value_t = format!("/var/lib/misc/dnsmasq.leases"))]
    leases_path: String,

    /// dnsmasq host:port address
    #[arg(long, default_value_t = format!("127.0.0.1:53").parse().unwrap())]
    dnsmasq_addr: String,
    // /// Implicitly using `std::str::FromStr`
    // #[arg(short = 'O')]
    // optimization: Option<usize>,

    // /// Allow invalid UTF-8 paths
    // #[arg(short = 'I', value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    // include: Option<std::path::PathBuf>,

    // /// Handle IP addresses
    // #[arg(long)]
    // bind: Option<std::net::IpAddr>,

    // /// Allow human-readable durations
    // #[arg(long)]
    // sleep: Option<humantime::Duration>,

    // /// Hand-written parser for tuples
    // #[arg(short = 'D', value_parser = parse_key_val::<String, i32>)]
    // defines: Vec<(String, i32)>,

    // /// Support enums from a foreign crate that don't implement `ValueEnum`
    // #[arg(
    //     long,
    //     default_value_t = foreign_crate::LogLevel::Info,
    //     value_parser = clap::builder::PossibleValuesParser::new(["info", "debug", "info", "warn", "error"])
    //         .map(|s| s.parse::<foreign_crate::LogLevel>().unwrap()),
    // )]
    // log_level: foreign_crate::LogLevel,
}

#[tokio::main]
async fn main() {
    // set RUST_LOG=trace
    if !env::var("RUST_LOG").is_ok() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();
    let args = Args::parse();
    log::info!("Starting with args: {:?}", args);

    let mut registry = Registry::default();
    // let registry = Arc::new(RwLock::new(registry));

    let packet_monitor = packet_monitor::PacketMonitor::new();
    packet_monitor.register(&mut registry);
    {
        let interface = args.interface.clone();
        // let bpf = args.bpf.clone();
        thread::spawn(move || {
            packet_monitor.run(&interface);
        });
    }

    let internet_check = internet_check::InternetCheck::new();
    internet_check.register(&mut registry);
    thread::spawn(move || {
        internet_check.start();
    });

    let dnsmasq = dnsmasq::DnsMasq::new(args.leases_path, args.dnsmasq_addr);
    dnsmasq.register(&mut registry);

    let server_state = Arc::new(ServerState::new(registry, dnsmasq));
    {
        let listen_addr = args.bind_addr.clone();
        let app = Router::new()
            .route("/", routing::get(Server::root))
            .route("/metrics", routing::get(Server::metrics).with_state(server_state.clone()));

        tracing::debug!("listening on {}", listen_addr);
        axum::Server::bind(&listen_addr).serve(app.into_make_service()).await.unwrap();
    }
}

struct ServerState {
    registry: Registry,
    dnsmasq: DnsMasq,
}

impl ServerState {
    pub fn new(registry: Registry, dnsmasq: DnsMasq) -> Self {
        Self { registry, dnsmasq }
    }
}

struct Server {}

impl Server {
    async fn root() -> String {
        "Hello, World!".to_string()
    }

    async fn metrics(State(server): State<Arc<ServerState>>) -> Result<String, AppError> {
        server.dnsmasq.update_lease_metrics().await.map_err(|_| DnsError::UpdateLeaseMetricsError)?;
        server.dnsmasq.update_dns_metrics().await.map_err(|_| DnsError::UpdateDnsMetricsError)?;

        let mut buffer = String::new();
        encode(&mut buffer, &server.registry).unwrap();

        Ok(buffer)
    }
}

#[derive(Debug)]
enum AppError {
    Dns(DnsError),
}

#[derive(Debug)]
enum DnsError {
    UpdateLeaseMetricsError,
    UpdateDnsMetricsError,
}

impl From<DnsError> for AppError {
    fn from(inner: DnsError) -> Self {
        AppError::Dns(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Dns(DnsError::UpdateLeaseMetricsError) => (StatusCode::INTERNAL_SERVER_ERROR, "Update lease metris error"),
            AppError::Dns(DnsError::UpdateDnsMetricsError) => (StatusCode::INTERNAL_SERVER_ERROR, "Update dns metrics error"),
        };

        (status, error_message).into_response()
    }
}
