use clap::Parser;
use futures::StreamExt;
use pnet::datalink;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream as TokioTcpStream;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::op::{Message, MessageType, OpCode, Query};
use trust_dns_client::proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_client::proto::xfer::{DnsRequest, DnsRequestOptions};
use trust_dns_client::proto::DnsHandle;
use trust_dns_client::rr::{DNSClass, Name, RData, RecordType};
use trust_dns_client::tcp::TcpClientStream;
use warp::Filter;

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

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

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    src: String,
    dst: String,
}

fn network_monitor(registry: &RwLock<Registry>, iface_name: &str) {
    let packets_total = Family::<Labels, Counter>::default();
    let bytes_total = Family::<Labels, Counter>::default();
    // Register the metric family with the registry.
    registry.write().unwrap().register("ntm_packets_total", "Packets transferred", packets_total.clone());
    registry.write().unwrap().register("ntm_bytes_total", "Bytes transferred", bytes_total.clone());

    use pnet::datalink::Channel::Ethernet;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    println!("Available interfaces: ");
    for iface in interfaces.iter() {
        println!("{}: {:?}", iface.name, iface.ips);
    }
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == iface_name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let interface_name = &interface.name;
                let ips = &interface.ips;
                let ethernet = &EthernetPacket::new(packet).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let header = Ipv4Packet::new(ethernet.payload());
                        if let Some(header) = header {
                            let mut src = "internet".to_string();
                            let mut dst = "internet".to_string();
                            for ip in ips {
                                if ip.contains(IpAddr::V4(header.get_source())) {
                                    src = header.get_source().to_string()
                                }
                                if ip.contains(IpAddr::V4(header.get_destination())) {
                                    dst = header.get_destination().to_string()
                                }
                            }
                            let labels = Labels { src, dst };
                            packets_total.get_or_create(&labels).inc();
                            bytes_total.get_or_create(&labels).inc_by(header.packet().len() as u64);
                        } else {
                            println!("[{}]: Malformed IPv4 Packet", interface_name);
                        }
                    }
                    EtherTypes::Ipv6 => {
                        let header = Ipv6Packet::new(ethernet.payload());
                        if let Some(header) = header {
                            let mut src = "internet".to_string();
                            let mut dst = "internet".to_string();
                            for ip in ips {
                                if ip.contains(IpAddr::V6(header.get_source())) {
                                    src = header.get_source().to_string()
                                }
                                if ip.contains(IpAddr::V6(header.get_destination())) {
                                    dst = header.get_destination().to_string()
                                }
                            }
                            let labels = Labels { src, dst };
                            packets_total.get_or_create(&labels).inc();
                            bytes_total.get_or_create(&labels).inc_by(header.packet().len() as u64);
                        } else {
                            println!("[{}]: Malformed IPv6 Packet", interface_name);
                        }
                    }
                    _ => {}
                }

                // handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DnsMasqServerLabels {
    server: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DnsMasqLeaseLabels {
    mac: String,
    ip: String,
    devicename: String,
}

#[derive(Debug, Default, Clone)]
struct DnsMasqRegistry {
    dnsmasq_cachesize: Gauge,
    dnsmasq_insertions: Gauge,
    dnsmasq_evictions: Gauge,
    dnsmasq_misses: Gauge,
    dnsmasq_hits: Gauge,
    dnsmasq_auth: Gauge,

    dnsmasq_servers_queries: Family<DnsMasqServerLabels, Gauge>,
    dnsmasq_servers_queries_failed: Family<DnsMasqServerLabels, Gauge>,

    dnsmasq_leases: Gauge,
    dnsmasq_lease_info: Family<DnsMasqLeaseLabels, Gauge>,
}

impl DnsMasqRegistry {
    fn register(&self, registry: &mut Registry) {
        registry.register("dnsmasq_cachesize", "configured size of the DNS cache", self.dnsmasq_cachesize.clone());
        registry.register("dnsmasq_insertions", "DNS cache insertions", self.dnsmasq_insertions.clone());
        registry.register(
            "dnsmasq_evictions",
            "DNS cache evictions: numbers of entries which replaced an unexpired cache entry",
            self.dnsmasq_evictions.clone(),
        );
        registry.register("dnsmasq_misses", "DNS cache misses: queries which had to be forwarded", self.dnsmasq_misses.clone());
        registry.register("dnsmasq_hits", "DNS queries answered locally (cache hits)", self.dnsmasq_hits.clone());
        registry.register("dnsmasq_auth", "DNS queries for authoritative zones", self.dnsmasq_auth.clone());
        registry.register("dnsmasq_servers_queries", "DNS queries on upstream server", self.dnsmasq_servers_queries.clone());
        registry.register(
            "dnsmasq_servers_queries_failed",
            "DNS queries failed on upstream server",
            self.dnsmasq_servers_queries_failed.clone(),
        );

        registry.register("dnsmasq_leases", "Number of DHCP leases handed out", self.dnsmasq_leases.clone());
        registry.register("dnsmasq_lease_info", "DHCP leases handed out", self.dnsmasq_lease_info.clone());
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    let registry = Registry::default();
    let registry = Arc::new(RwLock::new(registry));

    {
        let registry = registry.clone();
        let interface = args.interface;
        thread::spawn(move || {
            network_monitor(registry.as_ref(), &interface);
        });
    }

    let address = args.dnsmasq_addr.parse().unwrap();
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(address);
    let client = AsyncClient::new(stream, sender, None);
    let (client, bg) = client.await.expect("connection failed");
    tokio::spawn(bg);

    {
        let registry = registry.clone();
        let dnsmasq_registry = DnsMasqRegistry::default();
        dnsmasq_registry.register(&mut registry.write().unwrap());

        let p1 = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));
        let p2 = warp::path!("metrics").then(move || {
            let registry = registry.clone();
            let mut client = client.clone();
            let dnsmasq_registry = dnsmasq_registry.clone();
            let leases_path = args.leases_path.clone();

            async move {
                let f = File::open(&leases_path).await.unwrap();
                let mut scanner = BufReader::new(f).lines();
                let mut lines = 0;
                // for line in scanner {
                while let Some(line) = scanner.next_line().await.unwrap() {
                    let arr: Vec<&str> = line.split(" ").collect();
                    if arr.len() < 4 {
                        panic!("stats DHCP lease record: unexpected number of argument in record");
                    }
                    let expiry: i64 = arr[0].parse().unwrap();
                    dnsmasq_registry
                        .dnsmasq_lease_info
                        .get_or_create(&DnsMasqLeaseLabels {
                            mac: arr[1].to_string(),
                            ip: arr[2].to_string(),
                            devicename: arr[3].to_string(),
                        })
                        .set(expiry);
                    lines += 1;
                }
                dnsmasq_registry.dnsmasq_leases.set(lines);

                // let name = Name::from_str("cachesize.bind.").unwrap();
                // let response = client.query(&name, DNSClass::CH, RecordType::TXT).unwrap();
                let mut msg = Message::new();
                let question = |name| {
                    let mut q = Query::new();
                    q.set_name(Name::from_str(name).unwrap());
                    q.set_query_type(RecordType::TXT);
                    q.set_query_class(DNSClass::CH);
                    q
                };
                msg.set_id(rand::random());
                msg.set_recursion_desired(true);
                msg.set_message_type(MessageType::Query);
                msg.set_op_code(OpCode::Query);
                msg.add_queries(vec![
                    question("cachesize.bind."),
                    question("insertions.bind."),
                    question("evictions.bind."),
                    question("misses.bind."),
                    question("hits.bind."),
                    question("auth.bind."),
                    question("servers.bind."),
                ]);
                let mut results = client.send(DnsRequest::new(msg, DnsRequestOptions::default()));
                let result = results.next().await;
                // while let Some(result) = results.next().await {
                let response = match result.unwrap() {
                    Ok(response) => response,
                    Err(e) => {
                        panic!("error: {}", e);
                    }
                };
                let answers = response.answers();
                for answer in answers {
                    if let Some(RData::TXT(ref txt)) = answer.data() {
                        // let txt = txt.iter().map(|s| s.to_string()).collect::<Vec<String>>().join(" ");
                        // let txt = txt.trim_start_matches("\"").trim_end_matches("\"");
                        // let txt = txt.parse::<u64>().unwrap();
                        let header_name = answer.name().to_string();
                        match header_name.as_str() {
                            "servers.bind." => {
                                for txt in txt.iter() {
                                    let txt = String::from_utf8_lossy(txt);
                                    let arr = txt.split(" ").collect::<Vec<&str>>();
                                    assert_eq!(arr.len(), 3, "Expected 3 TXT records, got {}", arr.len());
                                    let server = arr[0].to_string();
                                    let queries = arr[1].parse::<i64>().unwrap();
                                    let failed = arr[2].parse::<i64>().unwrap();
                                    dnsmasq_registry
                                        .dnsmasq_servers_queries
                                        .get_or_create(&DnsMasqServerLabels { server: server.clone() })
                                        .set(queries);
                                    dnsmasq_registry
                                        .dnsmasq_servers_queries_failed
                                        .get_or_create(&DnsMasqServerLabels { server: server.clone() })
                                        .set(failed);
                                }
                            }
                            _ => {
                                assert_eq!(txt.iter().len(), 1, "Expected 1 TXT record, got {}", txt.iter().len());
                                let txt = txt.iter().next().unwrap();
                                let txt = String::from_utf8_lossy(txt);
                                let txt = txt.parse::<i64>().unwrap();
                                match header_name.as_str() {
                                    "cachesize.bind." => dnsmasq_registry.dnsmasq_cachesize.set(txt),
                                    "insertions.bind." => dnsmasq_registry.dnsmasq_insertions.set(txt),
                                    "evictions.bind." => dnsmasq_registry.dnsmasq_evictions.set(txt),
                                    "misses.bind." => dnsmasq_registry.dnsmasq_misses.set(txt),
                                    "hits.bind." => dnsmasq_registry.dnsmasq_hits.set(txt),
                                    "auth.bind." => dnsmasq_registry.dnsmasq_auth.set(txt),
                                    _ => 0,
                                };
                            }
                        }
                    }
                }
                let mut buffer = String::new();
                encode(&mut buffer, &registry.as_ref().read().unwrap()).unwrap();

                buffer
            }
        });
        let hello = p1.or(p2);

        warp::serve(hello).run(args.bind_addr).await;
    }
}

#[derive(Clone)]
pub struct InternetCheck {
    connection_duration: Histogram,
    connection_is_up: Gauge,
}

impl InternetCheck {
    pub fn new() -> Self {
        Self {
            connection_duration: Histogram::new(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0].into_iter()),
            connection_is_up: Gauge::default(),
        }
    }

    pub fn start(&self) {
        let ticker = crossbeam::channel::tick(Duration::from_secs(10));
        self.is_internet_connection_up();
        loop {
            let _ = ticker.recv();
            self.is_internet_connection_up();
        }
    }

    pub async fn register(&self, registry: &mut Registry) {
        registry.register(
            "ntm_internet_connection_duration_seconds",
            "Time taken to establish tcp connection",
            self.connection_duration.clone(),
        );
        registry.register("ntm_internet_connection_is_up", "Whether internet connection is up", self.connection_is_up.clone());
    }

    fn is_internet_connection_up(&self) {
        let start_time = Instant::now();
        match TcpStream::connect_timeout(&"1.1.1.1:443".parse::<SocketAddr>().unwrap(), Duration::from_secs(5)) {
            Ok(_) => {
                println!("Connected to the server!");
                self.connection_is_up.set(1);
                self.connection_duration.observe((Instant::now() - start_time).as_secs_f64());
            }
            Err(err) => {
                println!("Internet is down: {}", err);
                self.connection_is_up.set(0);
                self.connection_duration.observe((Instant::now() - start_time).as_secs_f64());
            }
        }
    }
}
