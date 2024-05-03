//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

struct packet_stats_key {
  __u32 srcip;
  __u32 dstip;
  __be16 eth_proto;
};

struct packet_stats_value {
  __u64 packets;
  __u64 bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct packet_stats_key);
  __type(value, struct packet_stats_value);
} packet_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 255);
  __type(key, __u32);
  __type(value, __u32);
} allowed_ips SEC(".maps");

static inline void update_packet_stats(__u32 srcip, __u32 dstip, __be16 eth_proto, int bytes) {
  // https://docs.kernel.org/bpf/map_hash.html#examples
  struct packet_stats_key key = {
      .srcip = srcip,
      .dstip = dstip,
      .eth_proto = eth_proto,
  };
  struct packet_stats_value *value = bpf_map_lookup_elem(&packet_stats, &key);

  if (value) {
    __sync_fetch_and_add(&value->packets, 1);
    __sync_fetch_and_add(&value->bytes, bytes);
  } else {
    struct packet_stats_value newval = {1, bytes};

    bpf_map_update_elem(&packet_stats, &key, &newval, BPF_NOEXIST);
  }
}

static inline int is_ip_in_subnet(__u32 ip, __u32 subnet_ip, __u32 subnet_mask) { return (ip & subnet_mask) == subnet_ip; }

static inline void process_eth(void *data, void *data_end, __u64 pkt_len) {
  __u32 key0 = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &key0);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  // Define a pointer to the Ethernet header at the start of the packet data
  struct ethhdr *eth = data;
  // Ensure the packet includes a full Ethernet header; if not, we let it continue up the stack
  if ((void *)eth + sizeof(struct ethhdr) > data_end) {
    return;
  }

  // Access the IP header positioned right after the Ethernet header
  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)ip + sizeof(struct iphdr) > data_end) {
    return;
  }
  __u32 ip_saddr = ip->saddr;
  __u32 ip_daddr = ip->daddr;

  __be16 eth_proto = bpf_ntohs(eth->h_proto);

  // process only IPv4 and IPv6
  switch (eth_proto) {
    case ETH_P_IP: {
      __u32 lan_subnet_mask = 0x00FFFFFF;
      __u32 lan_subnet_ip = 0x0001A8C0;
      // bpf_printk("IP packet: %x -> %x", ip_saddr, ip_daddr);
      // bpf_printk("is_ip_in_subnet: %d -> %d", is_ip_in_subnet(ip_saddr, lan_subnet_ip, lan_subnet_mask), is_ip_in_subnet(ip_daddr, lan_subnet_ip, lan_subnet_mask));
      if (!is_ip_in_subnet(ip_saddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_saddr = 0x00;
      }
      if (!is_ip_in_subnet(ip_daddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_daddr = 0x00;
      }
      update_packet_stats(ip_saddr, ip_daddr, eth_proto, pkt_len);
    } break;
    case ETH_P_IPV6: {
      update_packet_stats(ip_saddr, ip_daddr, eth_proto, pkt_len);
    } break;
    default:
      return;
  }
}

// xdp_firewall - main eBPF XDP program
SEC("xdp")
int xdp_firewall(struct xdp_md *xdp) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  // process_eth(data, data_end, xdp->data_end - xdp->data);

  // return XDP_PASS;

  // Define a pointer to the Ethernet header at the start of the packet data
  struct ethhdr *eth = data;
  // Ensure the packet includes a full Ethernet header; if not, we let it continue up the stack
  if ((void *)eth + sizeof(struct ethhdr) > data_end) {
    return XDP_PASS;
  }

  // Check if the packet's protocol indicates it's an IP packet
  if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    // If not IP, continue with regular packet processing
    return XDP_PASS;
  }

  // Access the IP header positioned right after the Ethernet header
  struct iphdr *ip = data + sizeof(struct ethhdr);
  // Ensure the packet includes the full IP header; if not, pass it up the stack
  if ((void *)ip + sizeof(struct iphdr) > data_end) {
    return XDP_PASS;
  }

  // Confirm the packet uses TCP by checking the protocol field in the IP header
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  __u32 ip_saddr = ip->saddr;
  __u32 ip_daddr = ip->daddr;
  // update_packet_stats(ip_saddr, ip_daddr, xdp->data_end - xdp->data);

  // Locate the TCP header that follows the IP header
  struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  // Validate that the packet is long enough to include the full TCP header
  if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
    return XDP_PASS;
  }

  // Check if the destination port of the packet is the one we're monitoring (SSH port, typically port 22, here set as 3333 for the example)
  if (tcp->dest != __constant_htons(3333)) {
    return XDP_PASS;
  }

  // Attempt to find this key in the 'allowed_ips' map
  __u32 *value = bpf_map_lookup_elem(&allowed_ips, &ip_saddr);
  bpf_printk("Value addr: %d!", value);
  //   bpf_printk("Value: %d!", *value);
  if (value) {
    // If a matching key is found, the packet is from an allowed IP and can proceed
    bpf_printk("Authorized TCP packet to ssh: %d!", ip_saddr);
    return XDP_PASS;
  }

  // If no matching key is found, the packet is not from an allowed IP and will be dropped
  bpf_printk("Unauthorized TCP packet to ssh: %d!", ip_saddr);
  return XDP_DROP;
}

// tc_packet_counter - main eBPF TC program
SEC("tc")
int tc_packet_counter(struct __sk_buff *skb) {
  // https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";

// cat /sys/kernel/debug/tracing/trace_pipe
