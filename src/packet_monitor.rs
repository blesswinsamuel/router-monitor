use std::net::IpAddr;

use pnet::{
    datalink,
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        Packet,
    },
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    src: String,
    dst: String,
}

pub struct PacketMonitor {
    packets_total: Family<Labels, Counter>,
    bytes_total: Family<Labels, Counter>,
}

impl PacketMonitor {
    pub fn new() -> Self {
        Self { packets_total: Default::default(), bytes_total: Default::default() }
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register("ntm_packets_total", "Packets transferred", self.packets_total.clone());
        registry.register("ntm_bytes_total", "Bytes transferred", self.bytes_total.clone());
    }

    pub fn run(&self, iface_name: &str) {
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
                                self.packets_total.get_or_create(&labels).inc();
                                self.bytes_total.get_or_create(&labels).inc_by(header.packet().len() as u64);
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
                                self.packets_total.get_or_create(&labels).inc();
                                self.bytes_total.get_or_create(&labels).inc_by(header.packet().len() as u64);
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
}
