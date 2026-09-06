package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blesswinsamuel/router-monitor/gen/go/routermonitor/v1/routermonitorv1connect"
	"github.com/blesswinsamuel/router-monitor/internal/api"
	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
	"github.com/blesswinsamuel/router-monitor/internal/tsdb"
	"github.com/blesswinsamuel/router-monitor/internal/web"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
)

var defaultPingAddrs = []string{"1.1.1.1:53", "8.8.8.8:53"}

const defaultLANSubnetCIDR = "10.100.0.0/16"

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

func parseLANSubnet(raw string) (uint32, uint32, error) {
	cidr := strings.TrimSpace(raw)
	if cidr == "" {
		cidr = defaultLANSubnetCIDR
	}

	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	ip := subnet.IP.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("LAN_SUBNET_CIDR must be IPv4, got %q", cidr)
	}
	if len(subnet.Mask) != net.IPv4len {
		return 0, 0, fmt.Errorf("unexpected subnet mask size for %q", cidr)
	}

	lanSubnetIP := binary.LittleEndian.Uint32(ip)
	lanSubnetMask := binary.LittleEndian.Uint32(subnet.Mask)
	return lanSubnetIP, lanSubnetMask, nil
}

func parseDurationWithDefault(raw string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	return duration, nil
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

	lanSubnetIP, lanSubnetMask, err := parseLANSubnet(os.Getenv("LAN_SUBNET_CIDR"))
	if err != nil {
		log.Fatalf("invalid LAN_SUBNET_CIDR: %v", err)
	}

	arpCacheTTL, err := parseDurationWithDefault(os.Getenv("ARP_HOST_CACHE_TTL"), 30*time.Minute)
	if err != nil {
		log.Fatalf("invalid ARP_HOST_CACHE_TTL: %v", err)
	}

	ebpfFirewallCollector := routermonitor.NewEbpfCollector()
	ebpfFirewallCollector.SetLANSubnet(lanSubnetIP, lanSubnetMask)
	if err := ebpfFirewallCollector.Load(); err != nil {
		log.Fatalf("could not load ebpfFirewall: %s", err)
	}
	defer ebpfFirewallCollector.Close()
	if err := ebpfFirewallCollector.Attach(iface); err != nil {
		log.Fatalf("could not attach ebpfFirewall to iface %q: %s", iface.Name, err)
	}

	log.Printf("Attached program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	arpCollector := routermonitor.NewArpCollector("/proc/net/arp", os.Getenv("DOMAIN_SUFFIX"), arpCacheTTL)
	internetChecker := routermonitor.NewInternetChecker(10*time.Second, pingAddrs)

	prometheus.MustRegister(ebpfFirewallCollector)
	prometheus.MustRegister(arpCollector)
	internetChecker.Register(prometheus.DefaultRegisterer)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go internetChecker.Start(ctx)

	// Initialize SQLite TSDB
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/router-monitor/router-monitor.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		dbPath = "./router-monitor.db"
	}
	tsdbDB, err := tsdb.Open(dbPath)
	if err != nil {
		log.Printf("warn: failed to open TSDB at %s, falling back to in-memory: %v", dbPath, err)
		tsdbDB, err = tsdb.Open(":memory:")
		if err != nil {
			log.Fatalf("failed to open in-memory TSDB: %v", err)
		}
	}
	defer tsdbDB.Close()
	tsdbDB.StartRetentionWorker(ctx, 1*time.Hour, 7*24*time.Hour)

	sampleInterval, err := parseDurationWithDefault(os.Getenv("SAMPLE_INTERVAL"), 15*time.Second)
	if err != nil {
		log.Fatalf("invalid SAMPLE_INTERVAL: %v", err)
	}

	sampler := tsdb.NewSampler(tsdbDB, ebpfFirewallCollector, arpCollector, internetChecker, sampleInterval)
	sampler.Start(ctx)

	routerService := api.NewRouterMonitorService(
		iface.Name,
		os.Getenv("LAN_SUBNET_CIDR"),
		ebpfFirewallCollector,
		arpCollector,
		internetChecker,
		tsdbDB,
		sampler,
	)
	rpcPath, rpcHandler := routermonitorv1connect.NewRouterMonitorServiceHandler(routerService)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9156"
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{
			"Accept-Encoding",
			"Content-Encoding",
			"Content-Type",
			"Connect-Protocol-Version",
			"Connect-Timeout-Ms",
			"Connect-Accept-Encoding",
			"Connect-Content-Encoding",
			"Grpc-Timeout",
			"X-Grpc-Web",
			"X-User-Agent",
		},
		ExposedHeaders: []string{
			"Content-Encoding",
			"Connect-Content-Encoding",
			"Grpc-Status",
			"Grpc-Message",
			"Grpc-Status-Details-Bin",
		},
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle(rpcPath, rpcHandler)
	mux.Handle("/", web.Handler())

	server := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           corsHandler.Handler(mux),
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
