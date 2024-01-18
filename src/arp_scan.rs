use anyhow::Result;
// use arp_scan_rs::;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use crate::arp_scan_rs::args::{ProfileType, ScanOptions};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DnsMasqServerLabels {
    server: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ArpScanDeviceLabels {
    mac: String,
    ip: String,
}

#[derive(Default, Clone)]
struct ArpScanRegistry {
    arp_scan_active_devices: Family<ArpScanDeviceLabels, Gauge>,
}

impl ArpScanRegistry {
    fn register(&self, registry: &mut Registry) {
        registry.register("router_monitor_arp_scan_active_devices", "Active devices", self.arp_scan_active_devices.clone());
    }
}

#[derive(Clone)]
pub struct ArpScan {
    registry: ArpScanRegistry,
}

// https://github.com/kongbytes/arp-scan-rs/blob/master/src/main.rs

impl ArpScan {
    pub fn new() -> Self {
        Self { registry: ArpScanRegistry::default() }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }

    pub async fn update_metrics(&self) -> Result<()> {
        let network_range = ipnetwork::IpNetwork::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 0)), 24)?;
        // let scan_options = ScanOptions {
        //     profile: ProfileType::Default,
        //     interface_name: Some("eth0".to_string()),
        //     network_range: Some(vec![network_range]),
        //     timeout_ms: 4000,
        //     resolve_hostname: true,
        //     source_mac: None,
        //     destination_mac: None,
        //     vlan_id: None,
        //     retry_count: 1,
        //     scan_timing: None,
        //     randomize_targets: (),
        //     output: (),
        //     oui_file: (),
        //     hw_type: (),
        //     hw_addr: (),
        //     proto_type: (),
        //     proto_addr: (),
        //     arp_operation: (),
        //     packet_help: (),
        // };

        // let f = File::open(&self.leases_path).await?;
        // let mut scanner = BufReader::new(f).lines();
        // let mut lines = 0;
        // // for line in scanner {
        // while let Some(line) = scanner.next_line().await? {
        //     let arr: Vec<&str> = line.split(" ").collect();
        //     if arr.len() < 4 {
        //         panic!("stats DHCP lease record: unexpected number of argument in record");
        //     }
        //     let expiry: i64 = arr[0].parse()?;
        //     self.registry
        //         .dnsmasq_lease_info
        //         .get_or_create(&ArpScanDeviceLabels { mac: arr[1].to_string(), ip: arr[2].to_string() })
        //         .set(expiry);
        //     lines += 1;
        // }
        // self.registry.arp_scan_devices.set(lines);
        Ok(())
    }
}
