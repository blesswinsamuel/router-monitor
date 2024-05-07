package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	var objs ebpfFirewallObjects
	if err := loadEbpfFirewallObjects(&objs, nil); err != nil {
		log.Panic("Loading eBPF objects:", err)
	}
	defer objs.Close()

	err = features.HaveProgramType(ebpf.SchedACT)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Panic("SchedACT not supported on this kernel")
	}

	if err != nil {
		log.Panicf("Error checking SchedACT support: %v", err)
	}
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
	{
		link, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.TcPacketCounterIngress,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
		if err != nil {
			log.Panicf("could not attach XDP program: %s", err)
		}
		defer link.Close()
	}
	{
		link, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.TcPacketCounterEgress,
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
		prometheus.MustRegister(newEbpfFirewallCollector(&objs))
		prometheus.MustRegister(newArpCollector("/proc/net/arp", ".home.lan"))
		internetChecker := newInternetChecker(10 * time.Second)
		internetChecker.Register(prometheus.DefaultRegisterer)
		internetChecker.Start(context.Background())

		http.Handle("/metrics", promhttp.Handler())
		port := os.Getenv("PORT")
		if port == "" {
			port = "9156"
		}
		host := os.Getenv("HOST")
		if host == "" {
			host = "localhost"
		}
		log.Panic(http.ListenAndServe(host+":"+port, nil))
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("Received signal, exiting..")
}
