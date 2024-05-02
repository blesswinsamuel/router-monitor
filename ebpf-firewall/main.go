package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs routerMonitorObjects
	if err := loadRouterMonitorObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer link.Close()

	allowedIPs := []string{"192.168.1.10"}
	for _, ip := range allowedIPs {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			log.Fatalf("invalid IP address %q", ip)
		}
		ipParsed := net.ParseIP(ip).To4()
		ipInt := binary.NativeEndian.Uint32(ipParsed)
		fmt.Println(ipParsed, ipInt)
		if err := objs.AllowedIps.Put(ipInt, uint32(1)); err != nil {
			log.Fatalf("inserting allowed IP %q: %s", ip, err)
		}
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

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
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
