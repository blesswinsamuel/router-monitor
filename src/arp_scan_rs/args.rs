use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::sync::Arc;

use clap::builder::PossibleValue;
use clap::{Arg, ArgAction, ArgMatches, Command};
use ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use pnet_datalink::MacAddr;

use super::time::parse_to_milliseconds;

const TIMEOUT_MS_FAST: u64 = 800;
const TIMEOUT_MS_DEFAULT: u64 = 2000;

const HOST_RETRY_DEFAULT: usize = 1;
const REQUEST_MS_INTERVAL: u64 = 10;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

const EXAMPLES_HELP: &str = "EXAMPLES:

    # Launch a default scan with on the first working interface
    arp-scan

    # List network interfaces
    arp-scan -l

    # Launch a scan on a specific range
    arp-scan -i eth0 -n 10.37.3.1,10.37.4.55/24

    # Launch a scan on WiFi interface with fake IP and stealth profile
    arp-scan -i eth0 --source-ip 192.168.0.42 --profile stealth

    # Launch a scan on VLAN 45 with JSON output
    arp-scan -Q 45 -o json

";

pub enum OutputFormat {
    Plain,
    Json,
    Yaml,
    Csv,
}

pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos,
}

pub enum ScanTiming {
    Interval(u64),
    Bandwidth(u64),
}

pub struct ScanOptions {
    pub profile: ProfileType,
    pub interface_name: Option<String>,
    pub network_range: Option<Vec<ipnetwork::IpNetwork>>,
    pub timeout_ms: u64,
    pub resolve_hostname: bool,
    pub source_mac: Option<MacAddr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>,
    pub retry_count: usize,
    pub scan_timing: ScanTiming,
    pub randomize_targets: bool,
    pub output: OutputFormat,
    pub oui_file: String,
    pub hw_type: Option<ArpHardwareType>,
    pub hw_addr: Option<u8>,
    pub proto_type: Option<EtherType>,
    pub proto_addr: Option<u8>,
    pub arp_operation: Option<ArpOperation>,
    pub packet_help: bool,
}

impl ScanOptions {
    fn list_required_networks(file_value: Option<&String>, network_value: Option<&String>) -> Result<Option<Vec<String>>, String> {
        let network_options = (file_value, network_value);
        match network_options {
            (Some(file_path), None) => {
                let path = Path::new(file_path);
                fs::read_to_string(path)
                    .map(|content| Some(content.lines().map(|line| line.to_string()).collect()))
                    .map_err(|err| format!("Could not open file {} - {}", file_path, err))
            }
            (None, Some(raw_ranges)) => Ok(Some(raw_ranges.split(',').map(|line| line.to_string()).collect())),
            _ => Ok(None),
        }
    }

    /**
     * Computes the whole network range requested by the user through CLI
     * arguments or files. This method will fail of a failure has been detected
     * (either on the IO level or the network syntax parsing)
     */
    fn compute_networks(file_value: Option<&String>, network_value: Option<&String>) -> Result<Option<Vec<IpNetwork>>, String> {
        let required_networks: Option<Vec<String>> = ScanOptions::list_required_networks(file_value, network_value)?;
        if required_networks.is_none() {
            return Ok(None);
        }

        let mut networks: Vec<IpNetwork> = vec![];
        for network_text in required_networks.unwrap() {
            match IpNetwork::from_str(&network_text) {
                Ok(parsed_network) => {
                    networks.push(parsed_network);
                    Ok(())
                }
                Err(err) => Err(format!("Expected valid IPv4 network range ({})", err)),
            }?;
        }
        Ok(Some(networks))
    }

    /**
     * Computes scan timing constraints, as requested by the user through CLI
     * arguments. The scan timing constraints will be either expressed in bandwidth
     * (bits per second) or interval between ARP requests (in milliseconds).
     */
    fn compute_scan_timing(matches: &ArgMatches, profile: &ProfileType) -> ScanTiming {
        match (matches.get_one::<String>("bandwidth"), matches.get_one::<String>("interval")) {
            (Some(bandwidth_text), None) => {
                let bits_second: u64 = bandwidth_text.parse().unwrap_or_else(|err| {
                    eprintln!("Expected positive number, {}", err);
                    process::exit(1);
                });
                ScanTiming::Bandwidth(bits_second)
            }
            (None, Some(interval_text)) => parse_to_milliseconds(interval_text).map(ScanTiming::Interval).unwrap_or_else(|err| {
                eprintln!("Expected correct interval, {}", err);
                process::exit(1);
            }),
            _ => match profile {
                ProfileType::Stealth => ScanTiming::Interval(REQUEST_MS_INTERVAL * 2),
                ProfileType::Fast => ScanTiming::Interval(0),
                _ => ScanTiming::Interval(REQUEST_MS_INTERVAL),
            },
        }
    }

    pub fn is_plain_output(&self) -> bool {
        matches!(&self.output, OutputFormat::Plain)
    }

    pub fn has_vlan(&self) -> bool {
        matches!(&self.vlan_id, Some(_))
    }

    pub fn request_protocol_print(&self) -> bool {
        self.packet_help
    }
}
