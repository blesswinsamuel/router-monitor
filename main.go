package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listen = flag.String("listen",
		"localhost:9154",
		"listen address")
	metricsPath = flag.String("metrics_path",
		"/metrics",
		"path under which metrics are served")

	iface = flag.String("interface",
		"eth0",
		"network interface to monitor")
	filters = flag.String("filters",
		"",
		"TCPdump filters, e.g., \"src net 192.168.1.1/24\"")
)

var (
	metricLabels = []string{"src", "dst", "service", "proto"}

	packets = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_packets_total", Help: "Packets transferred",
	}, metricLabels)
	throughput = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_bytes_total", Help: "Bytes transferred",
	}, metricLabels)
)

var services map[string]bool
var serviceMap map[int]map[string]string
var fqdn = false
var log *logger.Logger

func init() {
	prometheus.MustRegister(packets)
	prometheus.MustRegister(throughput)
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

func extractDomain(s string) string {
	if fqdn {
		return s
	}
	parts := strings.Split(s, ".")
	l := len(parts)
	allNumeric := true
	for _, p := range parts {
		if !isNumeric(p) {
			allNumeric = false
		}
	}
	if l == 4 && allNumeric {
		return s // IP address
	}
	if l > 2 {
		return strings.Join(parts[l-2:], ".")
	} else {
		return s
	}
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

var dumpMatcher *regexp.Regexp

func init() {
	reParam := func(name, pattern string) string {
		return fmt.Sprintf("(?P<%s>%s)", name, pattern)
	}
	pattern := ".*" + strings.Join([]string{
		"proto " + reParam("proto", "\\w+") + " ",
		"length " + reParam("length", "\\d+"),
		"\n\\s*" + reParam("src", "[\\w\\d\\.-]+") + "\\." + reParam("srcp", "[\\w\\d-]+") +
			" > " +
			reParam("dst", "[\\w\\d\\.-]+") + "\\." + reParam("dstp", "[\\w\\d-]+"),
	}, ".*") + ".*"
	dumpMatcher = regexp.MustCompile(pattern)
}

func parsePacket(line string) error {
	match := dumpMatcher.FindStringSubmatch(line)
	if len(match) == 0 {
		log.Warning("[SKIP] " + strings.ReplaceAll(line, "\n", "\\n"))
		return nil
	}

	paramsMap := make(map[string]string)
	for i, name := range dumpMatcher.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}

	labels := map[string]string{
		"src":     extractDomain(paramsMap["src"]),
		"dst":     extractDomain(paramsMap["dst"]),
		"proto":   strings.ToLower(paramsMap["proto"]),
		"service": "",
	}
	// If the last part of the src/dst is a service, just use the literal service name:
	if _, ok := services[paramsMap["dstp"]]; ok {
		labels["service"] = paramsMap["dstp"]
	} else if _, ok := services[paramsMap["srcp"]]; ok {
		labels["service"] = paramsMap["srcp"]
	}
	// Otherwise, do a lookup of port/proto to the service:
	if labels["service"] == "" && isNumeric(paramsMap["dstp"]) {
		labels["service"] = lookupService(
			toNumeric(paramsMap["dstp"]), labels["proto"])
	}
	if labels["service"] == "" && isNumeric(paramsMap["srcp"]) {
		labels["service"] = lookupService(
			toNumeric(paramsMap["srcp"]), labels["proto"])
	}
	if labels["service"] == "" {
		labels["service"] = ""
	}

	packets.With(labels).Inc()
	throughput.With(labels).Add(float64(toNumeric(paramsMap["length"])))
	return nil
}

func streamPackets() {
	cmd := exec.Command(
		"tcpdump", "-i", *iface, "-v", "-l", *filters)
	log.Infof("tcpdump command: %v", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("cmd.StdoutPipe failed: %v", err)
	}
	// var stderr bytes.Buffer
	// cmd.Stderr = &stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("cmd.Start failed: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Split(bufio.ScanLines)
	twoLineBuf := []string{}
	for scanner.Scan() {
		// When tcpdump is run with -v, it outputs two lines per packet;
		// readuntil ensures that each "line" is actually a parse-able string of output.
		line := scanner.Text()
		if len(line) == 0 {
			log.Info("No output from tcpdump... waiting.")
			time.Sleep(time.Second)
			continue
		}
		twoLineBuf = append(twoLineBuf, line)
		if strings.Contains(line, " IP ") || strings.Contains(line, " IP6 ") {
			continue
		}

		twoLineStr := strings.Join(twoLineBuf, "\n")
		// log.Info(twoLineStr)
		if err := parsePacket(twoLineStr); err != nil {
			log.Errorf("Failed to parse line \"%s\": %v", line, err)
		}
		twoLineBuf = nil
	}
	if err := cmd.Wait(); err != nil {
		// log.Errorf("stderr: %s", stderr.String())
		log.Fatalf("cmd.Wait failed: %v", err)
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

	go streamPackets()

	http.HandleFunc(*metricsPath, s.promHandler.ServeHTTP)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Network Traffic Exporter</title></head>
			<body>
			<h1>Network Traffic Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body></html>`))
	})
	log.Infoln("Listening on", *listen)
	log.Infoln("Serving metrics under", *metricsPath)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
