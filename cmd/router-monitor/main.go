package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var defaultPingAddrs = []string{"1.1.1.1:53", "8.8.8.8:53"}

func parsePingAddrs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return append([]string(nil), defaultPingAddrs...), nil
	}

	parts := strings.Split(raw, ",")
	addrs := make([]string, 0, len(parts))
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid ping address %q: %w", addr, err)
		}
		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		return nil, errors.New("no valid ping addresses configured")
	}

	return addrs, nil
}

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

	pingAddrs, err := parsePingAddrs(os.Getenv("INTERNET_CONNECTION_CHECK_PING_ADDRS"))
	if err != nil {
		log.Fatalf("invalid INTERNET_CONNECTION_CHECK_PING_ADDRS: %v", err)
	}

	ebpfFirewallCollector := routermonitor.NewEbpfCollector()
	if err := ebpfFirewallCollector.Load(); err != nil {
		log.Fatalf("could not load ebpfFirewall: %s", err)
	}
	defer ebpfFirewallCollector.Close()
	if err := ebpfFirewallCollector.Attach(iface); err != nil {
		log.Fatalf("could not attach ebpfFirewall to iface %q: %s", iface.Name, err)
	}

	log.Printf("Attached program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	prometheus.MustRegister(ebpfFirewallCollector)
	prometheus.MustRegister(routermonitor.NewArpCollector("/proc/net/arp", os.Getenv("DOMAIN_SUFFIX")))
	internetChecker := routermonitor.NewInternetChecker(10*time.Second, pingAddrs)
	internetChecker.Register(prometheus.DefaultRegisterer)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go internetChecker.Start(ctx)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9156"
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("Serving metrics on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Print("Received signal, shutting down")
	case err := <-serverErrCh:
		log.Fatalf("metrics server failed: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
