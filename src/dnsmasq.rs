use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
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

pub struct DnsMasq {
    registry: DnsMasqRegistry,
}

impl DnsMasq {
    pub fn new() -> Self {
        Self { registry: DnsMasqRegistry::default() }
    }

    pub fn register(&self, registry: &mut Registry) {
        self.registry.register(registry);
    }
}
