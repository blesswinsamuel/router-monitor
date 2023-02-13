use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use prometheus_client::{
    metrics::{gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

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

    pub fn register(&self, registry: &mut Registry) {
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
