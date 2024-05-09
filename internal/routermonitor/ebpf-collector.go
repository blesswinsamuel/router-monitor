package routermonitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
)

type ebpfCollectorCollector struct {
	objs  *ebpfCollectorObjects
	links []link.Link

	packetsTotal *prometheus.Desc
	bytesTotal   *prometheus.Desc
}

func NewEbpfCollector() *ebpfCollectorCollector {
	return &ebpfCollectorCollector{
		packetsTotal: prometheus.NewDesc("router_monitor_packets_total",
			"",
			[]string{"direction", "ethproto", "src", "dst", "ipproto"},
			nil,
		),
		bytesTotal: prometheus.NewDesc("router_monitor_bytes_total",
			"",
			[]string{"direction", "ethproto", "src", "dst", "ipproto"},
			nil,
		),
	}
}

func (collector *ebpfCollectorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.packetsTotal
	ch <- collector.bytesTotal
}

// Collect implements required collect function for all promehteus collectors
func (collector *ebpfCollectorCollector) Collect(ch chan<- prometheus.Metric) {
	collect := func(trafficDirection string, packetStats *ebpf.Map) {
		iter := packetStats.Iterate()
		var key ebpfCollectorPacketStatsKey
		var value ebpfCollectorPacketStatsValue
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

func (collector *ebpfCollectorCollector) Load() error {
	// Load the compiled eBPF ELF and load it into the kernel.
	collector.objs = &ebpfCollectorObjects{}
	if err := loadEbpfCollectorObjects(collector.objs, nil); err != nil {
		return err
	}
	return nil
}

func (collector *ebpfCollectorCollector) Close() {
	for _, link := range collector.links {
		link.Close()
	}
	collector.objs.Close()
}

func (collector *ebpfCollectorCollector) Attach(iface *net.Interface) error {
	err := features.HaveProgramType(ebpf.SchedACT)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("SchedACT not supported on this kernel")
	}
	if err != nil {
		return fmt.Errorf("error checking SchedACT support: %w", err)
	}

	// {
	// 	link, err := link.AttachXDP(link.XDPOptions{
	// 		Program:   objs.XdpFirewall,
	// 		Interface: iface.Index,
	// 	})
	// 	if err != nil {
	// 		log.Panicf("could not attach XDP program: %s", err)
	// 	}
	//  collector.links = append(collector.links, link)
	// }

	{
		link, err := link.AttachTCX(link.TCXOptions{
			Program:   collector.objs.TcPacketCounterIngress,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("could not attach XDP program: %w", err)
		}
		collector.links = append(collector.links, link)
	}
	{
		link, err := link.AttachTCX(link.TCXOptions{
			Program:   collector.objs.TcPacketCounterEgress,
			Attach:    ebpf.AttachTCXEgress,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("could not attach XDP program: %w", err)
		}
		collector.links = append(collector.links, link)
	}
	return nil
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
