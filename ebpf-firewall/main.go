package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	promPacketsTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_firewall_packets_total",
		Help: "The total number of processed events",
	}, []string{"src", "dst"})
	promBytesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_firewall_bytes_total",
		Help: "The total number of processed events",
	}, []string{"src", "dst"})
)

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
	var objs routerMonitorObjects
	if err := loadRouterMonitorObjects(&objs, nil); err != nil {
		log.Panic("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Panicf("could not attach XDP program: %s", err)
	}
	defer link.Close()

	allowedIPs := []string{"192.168.1.10"}
	for _, ip := range allowedIPs {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			log.Panicf("invalid IP address %q", ip)
		}
		ipParsed := net.ParseIP(ip).To4()
		ipInt := binary.NativeEndian.Uint32(ipParsed)
		fmt.Println(ipParsed, ipInt)
		if err := objs.AllowedIps.Put(ipInt, uint32(1)); err != nil {
			log.Panicf("inserting allowed IP %q: %s", ip, err)
		}
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Panic(http.ListenAndServe(":8080", nil))
	}()

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Panic("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)

			info, err := objs.PacketStats.Info()
			if err != nil {
				log.Panic("Map info:", err)
			}
			log.Println("objs.PacketStats.Length()", info)
			iter := objs.PacketStats.Iterate()
			var key routerMonitorPacketStatsKey
			var value routerMonitorPacketStatsValue
			for iter.Next(&key, &value) {
				srcIP := int2ip(key.Srcip).String()
				dstIP := int2ip(key.Dstip).String()
				promPacketsTotal.WithLabelValues(srcIP, dstIP).Set(float64(value.Packets))
				promBytesTotal.WithLabelValues(srcIP, dstIP).Set(float64(value.Bytes))
			}
			if err := iter.Err(); err != nil {
				log.Panic("Map lookup:", err)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, nn)
	return ip
}
