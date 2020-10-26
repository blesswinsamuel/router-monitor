package main

import (
	"bufio"
	"context"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
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
	l3MetricLabels = []string{"src", "dst", "type"}
	l3Packets      = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l3_packets_total", Help: "L3 Packets transferred",
	}, l3MetricLabels)
	l3Throughput = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l3_bytes_total", Help: "L3 Bytes transferred",
	}, l3MetricLabels)

	l4MetricLabels = []string{"src", "dst", "service", "proto"}
	l4Packets      = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l4_packets_total", Help: "L4 Packets transferred",
	}, l4MetricLabels)
	l4Throughput = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_l4_bytes_total", Help: "L4 Bytes transferred",
	}, l4MetricLabels)
)

var services map[string]bool
var serviceMap map[int]map[string]string
var fqdn = false
var log *logger.Logger

func init() {
	prometheus.MustRegister(l3Packets)
	prometheus.MustRegister(l3Throughput)
	prometheus.MustRegister(l4Packets)
	prometheus.MustRegister(l4Throughput)
}

type server struct {
	promHandler http.Handler
}

func isNumeric(s string) bool {
	if _, err := strconv.Atoi(s); err != nil {
		return false
	}
	return true
}
func toNumeric(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func lookupService(port int, proto string) string {
	if _, ok := serviceMap[port]; !ok {
		return ""
	}
	if _, ok := serviceMap[port][proto]; !ok {
		return ""
	}
	return serviceMap[port][proto]
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
			go PacketHandler(ifaceName, p, *enableLayer4)
		}
	}
}

func loadServices() {
	matcher := regexp.MustCompile(`^(?P<service>[\w-]+)\s*(?P<port>\d+)\/(?P<proto>\w+)$`)
	file, err := os.Open("/etc/services")
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	serviceMap = make(map[int]map[string]string)
	services = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		match := FindStringSubmatchMap(matcher, scanner.Text())
		if match == nil {
			continue
		}
		port := toNumeric(match["port"])
		if _, ok := serviceMap[port]; !ok {
			serviceMap[port] = map[string]string{}
		}
		serviceMap[port][match["proto"]] = match["service"]
		services[match["service"]] = true
	}
}

func FindStringSubmatchMap(re *regexp.Regexp, str string) map[string]string {
	match := re.FindStringSubmatch(str)
	if match == nil {
		return nil
	}
	paramsMap := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			paramsMap[name] = match[i]
		}
	}
	return paramsMap
}

func main() {
	log = logger.Init("network_traffice_exporter", true, false, ioutil.Discard)
	flag.Parse()
	s := &server{
		promHandler: promhttp.Handler(),
	}
	loadServices()

	if os.Geteuid() != 0 {
		log.Fatalln("Must run as root")
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	// tickStatsDuration := time.Tick(time.Duration(1) * time.Second)

	// Stats.ifaces[ifaceName] = NewIface(ifaceName)
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

	<-signalChan
	cancel()
	h.Shutdown(context.Background())
}
