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

#[derive(Default, Clone)]
struct DnsMasqRegistry {
    dnsmasq_leases: Gauge,
    dnsmasq_lease_info: Family<DnsMasqLeaseLabels, Gauge>,
}

impl DnsMasqRegistry {
    fn register(&self, registry: &mut Registry) {
        registry.register("router_monitor_dnsmasq_leases", "Number of DHCP leases handed out", self.dnsmasq_leases.clone());
        registry.register("router_monitor_dnsmasq_lease_info", "DHCP leases handed out", self.dnsmasq_lease_info.clone());
    }
}

#[derive(Clone)]
pub struct DnsMasq {
    registry: DnsMasqRegistry,

    leases_path: String,
}

impl DnsMasq {
    pub fn new(leases_path: String) -> Self {
        Self { registry: DnsMasqRegistry::default(), leases_path }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }

    pub async fn update_lease_metrics(&self) -> Result<()> {
        let f = File::open(&self.leases_path).await?;
        let mut scanner = BufReader::new(f).lines();
        let mut lines = 0;
        // for line in scanner {
        while let Some(line) = scanner.next_line().await? {
            let arr: Vec<&str> = line.split(" ").collect();
            if arr.len() < 4 {
                panic!("stats DHCP lease record: unexpected number of argument in record");
            }
            let expiry: i64 = arr[0].parse()?;
            self.registry
                .dnsmasq_lease_info
                .get_or_create(&DnsMasqLeaseLabels { mac: arr[1].to_string(), ip: arr[2].to_string(), devicename: arr[3].to_string() })
                .set(expiry);
            lines += 1;
        }
        self.registry.dnsmasq_leases.set(lines);
        Ok(())
    }
}
