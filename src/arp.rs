use anyhow::Result;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

// https://github.com/prometheus/node_exporter/blob/master/collector/arp_linux.go
// https://github.com/prometheus/procfs/blob/master/arp.go

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ArpDeviceLabels {
    ip_addr: String,
    hw_addr: String,
    device: String,
    flags: String,
}

#[derive(Default, Clone)]
struct ArpRegistry {
    arp_devices: Family<ArpDeviceLabels, Gauge>,
}

impl ArpRegistry {
    fn register(&self, registry: &mut Registry) {
        registry.register("router_monitor_arp_devices", "ARP cache", self.arp_devices.clone());
    }
}

#[derive(Clone)]
pub struct Arp {
    registry: ArpRegistry,
}

impl Arp {
    pub fn new(leases_path: String) -> Self {
        Self { registry: ArpRegistry::default() }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }

    pub async fn update_arp_metrics(&self) -> Result<()> {
        let f = File::open("/proc/net/arp").await?;
        let mut scanner = BufReader::new(f).lines();
        self.registry.arp_devices.clear();
        while let Some(line) = scanner.next_line().await? {
            let arr: Vec<&str> = line.split_whitespace().collect();
            if arr.len() != 6 {
                continue;
            }
            let expiry: i64 = arr[0].parse()?;
            self.registry
                .arp_devices
                .get_or_create(&ArpDeviceLabels {
                    ip_addr: arr[0].to_string(),
                    hw_addr: arr[3].to_string(),
                    flags: arr[2].to_string(),
                    device: arr[5].to_string(),
                })
                .set(expiry);
        }
        Ok(())
    }
}
