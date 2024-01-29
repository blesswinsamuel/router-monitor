use std::{sync::Arc, time::Duration};

use anyhow::Result;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};
use ttl_cache::TtlCache;

// https://github.com/prometheus/node_exporter/blob/master/collector/arp_linux.go
// https://github.com/prometheus/procfs/blob/master/arp.go

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ArpDeviceLabels {
    ip_addr: String,
    hw_addr: String,
    device: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ArpDeviceHostnameLabels {
    ip_addr: String,
    hostname: String,
}

#[derive(Default, Clone)]
struct ArpRegistry {
    arp_devices: Family<ArpDeviceLabels, Gauge>,
    hostnames: Family<ArpDeviceHostnameLabels, Gauge>,
}

impl ArpRegistry {
    fn register(&self, registry: &mut Registry) {
        registry.register("router_monitor_arp_devices", "ARP cache", self.arp_devices.clone());
        registry.register("router_monitor_hostnames", "Host names", self.hostnames.clone());
    }
}

#[derive(Clone)]
pub struct Arp {
    host_cache: Arc<Mutex<TtlCache<String, String>>>,
    registry: ArpRegistry,
}

impl Arp {
    pub fn new() -> Self {
        Self { registry: ArpRegistry::default(), host_cache: Arc::new(Mutex::new(TtlCache::new(255))) }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }

    pub async fn update_arp_metrics(&self) -> Result<()> {
        // let router_hostname = gethostname::gethostname();
        // let router_hostname = router_hostname.to_str().unwrap();
        // log::info!("router_hostname: {}", router_hostname);
        // let domain_name = router_hostname.split('.').collect::<Vec<_>>()[1..].join(".");
        log::debug!("Updating arp metrics");
        let domain_name = ".home.local";
        let f = File::open("/proc/net/arp").await?;
        let mut scanner = BufReader::new(f).lines();
        self.registry.arp_devices.clear();
        self.registry.hostnames.clear();
        let mut host_cache = self.host_cache.lock().await;
        while let Some(line) = scanner.next_line().await? {
            let arr: Vec<&str> = line.split_whitespace().collect();
            if arr.len() != 6 {
                continue;
            }
            let hw_addr = arr[3].to_string();
            if hw_addr == "00:00:00:00:00:00" {
                continue;
            }
            let ip_addr = arr[0].to_string();
            let ip_parsed: std::net::IpAddr = ip_addr.parse().unwrap();
            let host = match host_cache.get(&ip_addr) {
                Some(v) => v.clone(),
                None => {
                    log::debug!("Looking up hostname of {}", ip_addr);
                    let host = dns_lookup::lookup_addr(&ip_parsed).unwrap_or("unknown".to_string());
                    let host = host.strip_suffix(&domain_name).unwrap_or(&host).to_string();
                    host_cache.insert(ip_addr.clone(), host.clone(), Duration::from_secs(60 * 60));
                    host
                }
            };
            let flags = arr[2].to_string();
            let flags = format!("{}f", flags.trim_start_matches("0x"));
            let flags = i64::from_str_radix(&flags, 16).unwrap_or(-1);
            self.registry
                .arp_devices
                .get_or_create(&ArpDeviceLabels { ip_addr: ip_addr.to_string(), hw_addr: hw_addr.to_string(), device: arr[5].to_string() })
                .set(flags);
            self.registry
                .hostnames
                .get_or_create(&ArpDeviceHostnameLabels { ip_addr: ip_addr.to_string(), hostname: host.to_string() })
                .set(1);
        }
        Ok(())
    }
}

// IP address       HW type     Flags       HW address            Mask     Device
// 192.168.1.15     0x1         0x0         00:00:00:00:00:00     *        lan
// 192.168.1.106    0x1         0x0         90:11:95:3e:cf:5d     *        lan
