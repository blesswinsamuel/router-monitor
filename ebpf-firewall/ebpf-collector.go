package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
)

type ebpfFirewallCollector struct {
	objs *ebpfFirewallObjects

	packetsTotal *prometheus.Desc
	bytesTotal   *prometheus.Desc
}

func newEbpfFirewallCollector(objs *ebpfFirewallObjects) *ebpfFirewallCollector {
	return &ebpfFirewallCollector{
		objs: objs,
		packetsTotal: prometheus.NewDesc("ebpf_firewall_packets_total",
			"",
			[]string{"direction", "ethproto", "src", "dst", "ipproto"},
			nil,
		),
		bytesTotal: prometheus.NewDesc("ebpf_firewall_bytes_total",
			"",
			[]string{"direction", "ethproto", "src", "dst", "ipproto"},
			nil,
		),
	}
}

func (collector *ebpfFirewallCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.packetsTotal
	ch <- collector.bytesTotal
}

// Collect implements required collect function for all promehteus collectors
func (collector *ebpfFirewallCollector) Collect(ch chan<- prometheus.Metric) {
	collect := func(trafficDirection string, packetStats *ebpf.Map) {
		iter := packetStats.Iterate()
		var key ebpfFirewallPacketStatsKey
		var value ebpfFirewallPacketStatsValue
		for iter.Next(&key, &value) {
			if err := iter.Err(); err != nil {
				log.Panic("Map lookup:", err)
			}

			srcIP := ""
			dstIP := ""
			if layers.EthernetType(key.EthProto) == layers.EthernetTypeIPv6 {
				srcIP = int2ip6(key.Srcip).String()
				dstIP = int2ip6(key.Dstip).String()
			} else {
				srcIP = int2ip4(key.Srcip).String()
				dstIP = int2ip4(key.Dstip).String()
			}
			if key.Srcip == 0 {
				srcIP = "internet"
			}
			if key.Dstip == 0 {
				dstIP = "internet"
			}
			ethProto := layers.EthernetType(key.EthProto).String()
			ipProto := layers.IPProtocol(key.IpProto).String()
			// fmt.Println(ethProto, srcIP, dstIP, ipProto, ethProto, value.Packets, value.Bytes)
			ch <- prometheus.MustNewConstMetric(collector.packetsTotal, prometheus.CounterValue, float64(value.Packets), trafficDirection, ethProto, srcIP, dstIP, ipProto)
			ch <- prometheus.MustNewConstMetric(collector.bytesTotal, prometheus.CounterValue, float64(value.Bytes), trafficDirection, ethProto, srcIP, dstIP, ipProto)
		}
	}
	collect("ingress", collector.objs.PacketStatsIngress)
	collect("egress", collector.objs.PacketStatsEgress)
}

func int2ip4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, nn)
	return ip
}

func int2ip6(nn uint32) net.IP {
	ip := make(net.IP, 16)
	binary.NativeEndian.PutUint32(ip, nn)
	return ip
}
