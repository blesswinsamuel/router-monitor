//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

struct packet_stats_key {
  __u16 eth_proto;
  __u32 srcip;
  __u32 dstip;
  __u8 ip_proto;
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
} packet_stats_ingress SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct packet_stats_key);
  __type(value, struct packet_stats_value);
} packet_stats_egress SEC(".maps");

const volatile __u32 lan_subnet_mask = 0x0000FFFF;  // 255.255.0.0
const volatile __u32 lan_subnet_ip = 0x0000640A;    // 10.100.0.0

static __always_inline void update_packet_stats(void *packet_stats, struct packet_stats_key *key, __u64 bytes) {
  struct packet_stats_value *value = bpf_map_lookup_elem(packet_stats, key);

  if (value) {
    __sync_fetch_and_add(&value->packets, 1);
    __sync_fetch_and_add(&value->bytes, bytes);
  } else {
    struct packet_stats_value newval = {1, bytes};

    int ret = bpf_map_update_elem(packet_stats, key, &newval, BPF_NOEXIST);
    if (ret != 0) {
      // In case of concurrent insert on another CPU, lookup again and add atomically
      value = bpf_map_lookup_elem(packet_stats, key);
      if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
      }
    }
  }
}

static __always_inline int is_ip_in_subnet(__u32 ip, __u32 subnet_ip, __u32 subnet_mask) { return (ip & subnet_mask) == subnet_ip; }

static __always_inline void process_eth(void *packet_stats, void *data, void *data_end, __u64 pkt_len) {
  // Define a pointer to the Ethernet header at the start of the packet data
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(struct ethhdr) > data_end) {
    return;
  }
  __u16 eth_proto = bpf_ntohs(eth->h_proto);
  void *l3_data = (void *)eth + sizeof(struct ethhdr);

  // Unwrap 802.1Q or 802.1ad VLAN tags if present
  if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
    struct vlan_hdr *vlan = l3_data;
    if ((void *)vlan + sizeof(struct vlan_hdr) > data_end) {
      return;
    }
    eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    l3_data = (void *)vlan + sizeof(struct vlan_hdr);
  }

  // Process IPv4 and IPv6
  switch (eth_proto) {
    case ETH_P_IP: {
      struct iphdr *ip = l3_data;
      if ((void *)ip + sizeof(struct iphdr) > data_end) {
        return;
      }
      if (ip->ihl < 5) {
        return;
      }
      __u32 ip_hdr_len = ((__u32)ip->ihl) * 4;
      if ((void *)ip + ip_hdr_len > data_end) {
        return;
      }

      __u32 ip_saddr = ip->saddr;
      __u32 ip_daddr = ip->daddr;
      __u8 ip_proto = ip->protocol;

      if (!is_ip_in_subnet(ip_saddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_saddr = 0;
      }
      if (!is_ip_in_subnet(ip_daddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_daddr = 0;
      }

      struct packet_stats_key key;
      __builtin_memset(&key, 0, sizeof(key));
      key.eth_proto = eth_proto;
      key.srcip = ip_saddr;
      key.dstip = ip_daddr;
      key.ip_proto = ip_proto;

      update_packet_stats(packet_stats, &key, pkt_len);
    } break;

    case ETH_P_IPV6: {
      struct ipv6hdr *ip6 = l3_data;
      if ((void *)ip6 + sizeof(struct ipv6hdr) > data_end) {
        return;
      }
      struct packet_stats_key key;
      __builtin_memset(&key, 0, sizeof(key));
      key.eth_proto = eth_proto;
      key.srcip = 0;
      key.dstip = 0;
      key.ip_proto = ip6->nexthdr;

      update_packet_stats(packet_stats, &key, pkt_len);
    } break;

    default:
      return;
  }
}

SEC("tc")
int tc_packet_counter_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(&packet_stats_ingress, data, data_end, skb->len);

  return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_packet_counter_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(&packet_stats_egress, data, data_end, skb->len);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";
