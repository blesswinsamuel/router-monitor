package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
			[]string{"src", "dst", "ethproto"},
			nil,
		),
		bytesTotal: prometheus.NewDesc("ebpf_firewall_bytes_total",
			"",
			[]string{"src", "dst", "ethproto"},
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
	iter := collector.objs.PacketStats.Iterate()
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
		fmt.Println(srcIP, dstIP, key.EthProto, ethProto, value.Packets, value.Bytes)
		ch <- prometheus.MustNewConstMetric(collector.packetsTotal, prometheus.CounterValue, float64(value.Packets), srcIP, dstIP, ethProto)
		ch <- prometheus.MustNewConstMetric(collector.bytesTotal, prometheus.CounterValue, float64(value.Bytes), srcIP, dstIP, ethProto)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Panicf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Panicf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs ebpfFirewallObjects
	if err := loadEbpfFirewallObjects(&objs, nil); err != nil {
		log.Panic("Loading eBPF objects:", err)
	}
	defer objs.Close()

	err = features.HaveProgramType(ebpf.SchedACT)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("SchedACT not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking SchedACT support: %v", err)
	}
	// xdpOrTc := os.Getenv("XDP_OR_TC")
	// if xdpOrTc == "" {
	// 	xdpOrTc = "xdp"
	// }
	// switch xdpOrTc {
	// case "xdp":
	// {
	// 	link, err := link.AttachXDP(link.XDPOptions{
	// 		Program:   objs.XdpFirewall,
	// 		Interface: iface.Index,
	// 	})
	// 	if err != nil {
	// 		log.Panicf("could not attach XDP program: %s", err)
	// 	}
	// 	defer link.Close()
	// }
	// {
	// 	link, err := link.AttachTCX(link.TCXOptions{
	// 		Program:   objs.TcPacketCounter,
	// 		Attach:    ebpf.AttachTCXIngress,
	// 		Interface: iface.Index,
	// 	})
	// 	if err != nil {
	// 		log.Panicf("could not attach XDP program: %s", err)
	// 	}
	// 	defer link.Close()
	// }
	{
		link, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.TcPacketCounter,
			Attach:    ebpf.AttachTCXEgress,
			Interface: iface.Index,
		})
		if err != nil {
			log.Panicf("could not attach XDP program: %s", err)
		}
		defer link.Close()
	}

	log.Printf("Attached program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	go func() {
		ebpfFirewallCollector := newEbpfFirewallCollector(&objs)
		prometheus.MustRegister(ebpfFirewallCollector)

		http.Handle("/metrics", promhttp.Handler())
		log.Panic(http.ListenAndServe(":8080", nil))
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("Received signal, exiting..")
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
