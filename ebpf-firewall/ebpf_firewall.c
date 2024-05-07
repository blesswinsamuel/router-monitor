//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

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
} packet_stats SEC(".maps");

static inline void update_packet_stats(__u16 eth_proto, __u32 srcip, __u32 dstip, __u8 ip_proto, __u64 bytes) {
  struct packet_stats_key key = {
      .eth_proto = eth_proto,
      .srcip = srcip,
      .dstip = dstip,
      .ip_proto = ip_proto,
  };
  struct packet_stats_value *value = bpf_map_lookup_elem(&packet_stats, &key);

  // bpf_printk("Packet (0x%04X): 0x%08X -> 0x%08X (0x%04X), %d %d", eth_proto, srcip, dstip, ip_proto, &packet_stats, value);
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
  // Define a pointer to the Ethernet header at the start of the packet data
  struct ethhdr *eth = data;
  // Ensure the packet includes a full Ethernet header; if not, we let it continue up the stack
  if ((void *)eth + sizeof(struct ethhdr) > data_end) {
    return;
  }
  __u16 eth_proto = bpf_ntohs(eth->h_proto);

  // Access the IP header positioned right after the Ethernet header
  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)ip + sizeof(struct iphdr) > data_end) {
    return;
  }
  __u32 ip_saddr = ip->saddr;
  __u32 ip_daddr = ip->daddr;
  __u8 ip_proto = ip->protocol;

  // process only IPv4 and IPv6
  switch (eth_proto) {
    case ETH_P_IP: {
      __u32 lan_subnet_mask = 0x00FFFFFF;
      __u32 lan_subnet_ip = 0x0001A8C0;
      // bpf_printk("IP packet: %x -> %x", ip_saddr, ip_daddr);
      // bpf_printk("is_ip_in_subnet: %d -> %d", is_ip_in_subnet(ip_saddr, lan_subnet_ip, lan_subnet_mask), is_ip_in_subnet(ip_daddr, lan_subnet_ip, lan_subnet_mask));
      if (!is_ip_in_subnet(ip_saddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_saddr = 0;
      }
      if (!is_ip_in_subnet(ip_daddr, lan_subnet_ip, lan_subnet_mask)) {
        ip_daddr = 0;
      }
      // if (!(ip_saddr == 0 && ip_daddr == 167880896) && !(ip_saddr == 167880896 && ip_daddr == 0)) {
      //   // for testing
      //   return;
      // }

      update_packet_stats(eth_proto, ip_saddr, ip_daddr, ip_proto, pkt_len);
    } break;
    case ETH_P_IPV6: {
      // update_packet_stats(eth_proto, ip_saddr, ip_daddr, ip_proto, pkt_len);
    } break;
    default:
      return;
  }
}

SEC("tc")
int tc_packet_counter(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";
