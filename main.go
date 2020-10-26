package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listen      = flag.String("listen", "localhost:9154", "listen address")
	metricsPath = flag.String("metrics_path", "/metrics", "path under which metrics are served")

	dhcpLeasesFile = flag.String("dhcp-leases-file", "/var/lib/misc/dnsmasq.leases", "dnsmasq DHCP leases file")
	iface          = flag.String("interface", "eth0", "network interface to monitor")
	filter         = flag.String("bpf", "", "BPF filter")
)

var (
	labelNames   = []string{"src", "dst"}
	packetsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_packets_total", Help: "Packets transferred",
	}, labelNames)
	bytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_bytes_total", Help: "Bytes transferred",
	}, labelNames)
)

func init() {
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
}

var ipNets []*net.IPNet
var ipHostnameLookup map[string]string
var log *logger.Logger

type server struct {
	promHandler http.Handler
}

func listenPacket(ifaceName string, ctx context.Context) {
	go func() {
		handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Failed to OpenLive by pcap, err: %s", err)
		}

		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("Failed to set BPF filter, err: %s", err)
		}
		defer handle.Close()

		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-ps.Packets():
				go packetHandler(p)
			}
		}
	}()
}

func packetHandler(pkt gopacket.Packet) {
	var srcAddr, dstAddr net.IP
	var payloadLen int

	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}
	l, ok := nl.(*layers.IPv4)
	if !ok {
		return
	}
	srcAddr = l.SrcIP
	dstAddr = l.DstIP
	payloadLen = len(l.LayerPayload())

	src := "internet"
	dst := "internet"
	for _, n := range ipNets {
		if n.Contains(srcAddr) {
			src = srcAddr.String()
			if hn, ok := ipHostnameLookup[src]; ok {
				src = hn
			}
		}
		if n.Contains(dstAddr) {
			dst = dstAddr.String()
			if hn, ok := ipHostnameLookup[dst]; ok {
				dst = hn
			}
		}
	}
	labels := map[string]string{
		"src": src,
		"dst": dst,
	}
	packetsTotal.With(labels).Inc()
	bytesTotal.With(labels).Add(float64(payloadLen))
}

func getIpNets(iface string) ([]*net.IPNet, error) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("localAddresses: %w", err)
	}
	addrs, err := i.Addrs()
	if err != nil {
		return nil, fmt.Errorf("localAddresses: %w", err)
	}
	ipNets := []*net.IPNet{}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ipNets = append(ipNets, v)
		}
	}
	if len(ipNets) > 0 {
		return ipNets, nil
	}
	return nil, fmt.Errorf("localAddresses: interface not found")
}

func loadLeasesFile() error {
	ipHostnameLookup = make(map[string]string)
	file, err := os.Open(*dhcpLeasesFile)
	if err != nil {
		return fmt.Errorf("ReadFile error: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) < 4 {
			continue
		}
		ip := line[2]
		hostname := line[3]
		if hostname == "*" {
			continue
		}
		ipHostnameLookup[ip] = hostname
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}
	return nil
}

func listenLeasesFile(ctx context.Context) {
	err := loadLeasesFile()
	if err != nil {
		log.Fatalf("loadLeasesFile failed: %v", err)
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := loadLeasesFile()
				if err != nil {
					log.Errorf("loadLeasesFile failed: %v", err)
				}
			}
		}
	}()
}

func main() {
	log = logger.Init("network_traffice_exporter", true, false, ioutil.Discard)
	flag.Parse()
	s := &server{
		promHandler: promhttp.Handler(),
	}

	if os.Geteuid() != 0 {
		log.Fatalln("Must run as root")
	}

	var err error
	ipNets, err = getIpNets(*iface)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	listenLeasesFile(ctx)
	listenPacket(*iface, ctx)

	r := http.NewServeMux()
	r.HandleFunc(*metricsPath, s.promHandler.ServeHTTP)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Network Traffic Exporter</title></head>
			<body>
			<h1>Network Traffic Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body></html>`))
	})
	h := &http.Server{Addr: *listen, Handler: r}
	log.Infoln("Listening on", *listen)
	log.Infoln("Serving metrics under", *metricsPath)
	go h.ListenAndServe()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	<-signalChan

	cancel()
	h.Shutdown(context.Background())
}
