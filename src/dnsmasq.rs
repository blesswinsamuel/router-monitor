use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use futures::StreamExt;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use trust_dns_client::{
    client::AsyncClient,
    op::{Message, MessageType, OpCode, Query},
    proto::{
        xfer::{DnsRequest, DnsRequestOptions},
        DnsHandle,
    },
    rr::{DNSClass, Name, RData, RecordType},
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

#[derive(Clone)]
pub struct DnsMasq {
    registry: DnsMasqRegistry,

    leases_path: String,
    client: Arc<Mutex<AsyncClient>>,
}

impl DnsMasq {
    pub fn new(leases_path: String, client: AsyncClient) -> Self {
        Self { registry: DnsMasqRegistry::default(), leases_path, client: Arc::new(Mutex::new(client)) }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }

    pub async fn update_lease_metrics(&self) {
        let f = File::open(&self.leases_path).await.unwrap();
        let mut scanner = BufReader::new(f).lines();
        let mut lines = 0;
        // for line in scanner {
        while let Some(line) = scanner.next_line().await.unwrap() {
            let arr: Vec<&str> = line.split(" ").collect();
            if arr.len() < 4 {
                panic!("stats DHCP lease record: unexpected number of argument in record");
            }
            let expiry: i64 = arr[0].parse().unwrap();
            self.registry
                .dnsmasq_lease_info
                .get_or_create(&DnsMasqLeaseLabels { mac: arr[1].to_string(), ip: arr[2].to_string(), devicename: arr[3].to_string() })
                .set(expiry);
            lines += 1;
        }
        self.registry.dnsmasq_leases.set(lines);
    }

    pub async fn update_dns_metrics(&self) {
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
        let mut results = self.client.lock().unwrap().send(DnsRequest::new(msg, DnsRequestOptions::default()));
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
                            self.registry
                                .dnsmasq_servers_queries
                                .get_or_create(&DnsMasqServerLabels { server: server.clone() })
                                .set(queries);
                            self.registry
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
                            "cachesize.bind." => self.registry.dnsmasq_cachesize.set(txt),
                            "insertions.bind." => self.registry.dnsmasq_insertions.set(txt),
                            "evictions.bind." => self.registry.dnsmasq_evictions.set(txt),
                            "misses.bind." => self.registry.dnsmasq_misses.set(txt),
                            "hits.bind." => self.registry.dnsmasq_hits.set(txt),
                            "auth.bind." => self.registry.dnsmasq_auth.set(txt),
                            _ => 0,
                        };
                    }
                }
            }
        }
    }
}
