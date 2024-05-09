package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
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

	ebpfFirewallCollector := routermonitor.NewEbpfCollector()
	if err := ebpfFirewallCollector.Load(); err != nil {
		log.Panicf("could not load ebpfFirewall: %s", err)
	}
	defer ebpfFirewallCollector.Close()
	if err := ebpfFirewallCollector.Attach(iface); err != nil {
		log.Panicf("could not attach ebpfFirewall to iface %q: %s", iface.Name, err)
	}

	log.Printf("Attached program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	go func() {
		prometheus.MustRegister(ebpfFirewallCollector)
		prometheus.MustRegister(routermonitor.NewArpCollector("/proc/net/arp", os.Getenv("DOMAIN_SUFFIX")))
		internetChecker := routermonitor.NewInternetChecker(10 * time.Second)
		internetChecker.Register(prometheus.DefaultRegisterer)
		go internetChecker.Start(context.Background())

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
