package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	iface        = flag.String("interface", "eth0", "network interface to monitor")
	filter       = flag.String("bpf", "", "BPF filter")
	enableLayer4 = flag.Bool("l4", false, "Show transport layer flows")
)

var (
	l3MetricLabels = []string{"src", "dst"}
	packetsTotal   = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l3_packets_total", Help: "L3 Packets transferred",
	}, l3MetricLabels)
	bytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l3_bytes_total", Help: "L3 Bytes transferred",
	}, l3MetricLabels)
)

func init() {
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
}

var ipNets []*net.IPNet
var log *logger.Logger

type server struct {
	promHandler http.Handler
}

func listenPacket(ifaceName string, ctx context.Context) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("Failed to OpenLive by pcap, err: %s\n", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Errorf("Failed to set BPF filter, err: %s\n", err.Error())
		os.Exit(0)
	}

	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			go packetHandler(p, *enableLayer4)
		}
	}
}

func packetHandler(pkt gopacket.Packet, enableLayer4 bool) {
	var srcAddr, dstAddr net.IP
	var payloadLen int

	for _, ly := range pkt.Layers() {
		layerType := ly.LayerType()
		switch layerType {
		case layers.LayerTypeIPv4:
			l := ly.(*layers.IPv4)
			srcAddr = l.SrcIP
			dstAddr = l.DstIP
			payloadLen = len(l.LayerPayload())
		}
	}

	if srcAddr == nil || dstAddr == nil {
		return
	}

	src := "internet"
	dst := "internet"
	for _, n := range ipNets {
		if n.Contains(srcAddr) {
			src = srcAddr.String()
		}
		if n.Contains(dstAddr) {
			dst = dstAddr.String()
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
	go listenPacket(*iface, ctx)

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
