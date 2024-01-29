use std::time::{Duration, Instant};

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use tokio::net::TcpStream;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct InternetUpLabels {
    addr: String,
}

pub struct InternetCheck {
    connection_duration: Family<InternetUpLabels, Histogram>,
    connection_is_up: Family<InternetUpLabels, Gauge>,
}

impl InternetCheck {
    pub fn new() -> Self {
        Self {
            connection_duration: Family::new_with_constructor(|| {
                Histogram::new(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0].into_iter())
            }),
            connection_is_up: Default::default(),
        }
    }

    pub async fn start(&self) {
        let ticker = crossbeam::channel::tick(Duration::from_secs(10));
        self.is_internet_connection_up().await;
        loop {
            let _ = ticker.recv();
            self.is_internet_connection_up().await;
        }
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "router_monitor_internet_connection_duration_seconds",
            "Time taken to establish tcp connection",
            self.connection_duration.clone(),
        );
        registry.register("router_monitor_internet_connection_is_up", "Whether internet connection is up", self.connection_is_up.clone());
    }

    async fn is_internet_connection_up(&self) {
        let start_time = Instant::now();
        let addrs = [
            // https://www.reddit.com/r/sysadmin/comments/uo36rh/10_to_20_safe_high_performance_ip_addresses_that/
            "1.1.1.1:53",
            "64.6.64.6:53",
            "8.8.8.8:53",
            "208.67.222.222:53",
            "9.9.9.9:53",
        ];
        for addr in addrs.iter() {
            let labels = &InternetUpLabels { addr: addr.to_string() };
            match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
                Ok(_) => {
                    self.connection_is_up.get_or_create(labels).set(1);
                    self.connection_duration.get_or_create(labels).observe((Instant::now() - start_time).as_secs_f64());
                }
                Err(err) => {
                    log::error!("Failed to connect to {}: {}", addr, err);
                    self.connection_is_up.get_or_create(labels).set(0);
                    self.connection_duration.get_or_create(labels).observe((Instant::now() - start_time).as_secs_f64());
                }
            }
        }
    }
}
