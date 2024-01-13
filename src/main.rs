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

mod ddns_cloudflare;
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

    /// Cloudflare DDNS API Token
    #[arg(long)]
    ddns_cloudflare_api_token: Option<String>,
    /// Cloudflare DDNS email
    #[arg(long)]
    ddns_cloudflare_email: Option<String>,
    /// Cloudflare DDNS domain
    #[arg(long)]
    ddns_cloudflare_domain: Option<String>,
    /// Cloudflare DDNS record
    #[arg(long)]
    ddns_cloudflare_record: Option<String>,
    /// Cloudflare DDNS TTL
    #[arg(long, default_value = "5m")]
    ddns_cloudflare_ttl: Option<humantime::Duration>,
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
            match packet_monitor.run(&interface) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("packet_monitor error: {}", e);
                }
            };
        });
    }

    let internet_check = internet_check::InternetCheck::new();
    internet_check.register(&mut registry);
    thread::spawn(move || {
        internet_check.start();
    });

    if let (
        Some(ddns_cloudflare_api_token),
        Some(ddns_cloudflare_email),
        Some(ddns_cloudflare_domain),
        Some(ddns_cloudflare_record),
        Some(ddns_cloudflare_ttl),
    ) = (
        args.ddns_cloudflare_api_token.clone(),
        args.ddns_cloudflare_email.clone(),
        args.ddns_cloudflare_domain.clone(),
        args.ddns_cloudflare_record.clone(),
        args.ddns_cloudflare_ttl.clone(),
    ) {
        let ddns_cloudflare = ddns_cloudflare::DdnsCloudflare::new(
            ddns_cloudflare_api_token,
            ddns_cloudflare_email,
            ddns_cloudflare_domain,
            ddns_cloudflare_record,
            ddns_cloudflare_ttl.into(),
        );
        ddns_cloudflare.register(&mut registry);
        thread::spawn(move || {
            match ddns_cloudflare.start() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("ddns_cloudflare error: {:#}", e);
                }
            };
        });
    }

    let dnsmasq = dnsmasq::DnsMasq::new(args.leases_path);
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
        // server.dnsmasq.update_lease_metrics().await.map_err(|_| DnsError::UpdateLeaseMetricsError)?;

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
}

impl From<DnsError> for AppError {
    fn from(inner: DnsError) -> Self {
        AppError::Dns(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Dns(DnsError::UpdateLeaseMetricsError) => (StatusCode::INTERNAL_SERVER_ERROR, "Update lease metrics error"),
        };

        (status, error_message).into_response()
    }
}
