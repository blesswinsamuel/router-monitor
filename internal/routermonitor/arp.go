package routermonitor

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type hostCacheValue struct {
	Hostname string
	Expiry   time.Time
}

type ArpCollector struct {
	filename          string
	stripDomainSuffix string
	hostCacheTTL      time.Duration
	lookupTimeout     time.Duration
	hostCache         map[string]hostCacheValue
	pendingLookups    map[string]struct{}
	lookupQueue       chan string
	hostCacheMutex    sync.RWMutex

	arpDevices *prometheus.Desc
}

func autoDetectDomainSuffix() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "domain" || fields[0] == "search") {
			suffix := strings.TrimPrefix(fields[1], ".")
			suffix = strings.TrimSuffix(suffix, ".")
			if suffix != "" {
				return "." + suffix
			}
		}
	}
	return ""
}

func CleanHostname(raw string, domainSuffix string) string {
	h := strings.TrimSpace(raw)
	h = strings.TrimSuffix(h, ".")
	if domainSuffix != "" {
		s := strings.TrimSpace(domainSuffix)
		s = strings.TrimSuffix(s, ".")
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		h = strings.TrimSuffix(h, s)
	}
	return h
}

func NewArpCollector(filename string, stripDomainSuffix string, hostCacheTTL time.Duration) *ArpCollector {
	if hostCacheTTL <= 0 {
		hostCacheTTL = 30 * time.Minute
	}
	if stripDomainSuffix == "" {
		stripDomainSuffix = autoDetectDomainSuffix()
	}

	collector := &ArpCollector{
		filename:          filename,
		stripDomainSuffix: stripDomainSuffix,
		hostCacheTTL:      hostCacheTTL,
		lookupTimeout:     2 * time.Second,
		hostCache:         make(map[string]hostCacheValue),
		pendingLookups:    make(map[string]struct{}),
		lookupQueue:       make(chan string, 256),
		arpDevices: prometheus.NewDesc("router_monitor_arp_devices", "ARP entries discovered from /proc/net/arp.",
			[]string{"ip_addr", "hw_addr", "hostname", "device"}, nil,
		),
	}
	go collector.lookupLoop()

	return collector
}

func (collector *ArpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.arpDevices
}

type ArpDeviceEntry struct {
	IPAddr   string
	HWAddr   string
	Hostname string
	Device   string
	Flag     int64
	IsValid  bool
}

func (collector *ArpCollector) GetDevices() []ArpDeviceEntry {
	file, err := os.Open(collector.filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var devices []ArpDeviceEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 6 {
			continue
		}

		hwAddr := fields[3]
		if hwAddr == "00:00:00:00:00:00" {
			continue
		}

		ipAddr := fields[0]
		var hostname string
		collector.hostCacheMutex.RLock()
		host, ok := collector.hostCache[ipAddr]
		collector.hostCacheMutex.RUnlock()
		hostname = host.Hostname
		if hostname == "" {
			hostname = "unknown:" + ipAddr
		}
		if !ok || host.Expiry.Before(time.Now()) {
			collector.enqueueLookup(ipAddr)
		}
		flag, err := strconv.ParseInt(fields[2], 0, 0)
		if err != nil {
			log.Printf("Error parsing flag: %v", err)
		}
		device := fields[5]
		devices = append(devices, ArpDeviceEntry{
			IPAddr:   ipAddr,
			HWAddr:   hwAddr,
			Hostname: hostname,
			Device:   device,
			Flag:     flag,
			IsValid:  flag == 2,
		})
	}

	return devices
}

// Collect implements required collect function for all promehteus collectors
func (collector *ArpCollector) Collect(ch chan<- prometheus.Metric) {
	devices := collector.GetDevices()
	for _, d := range devices {
		ch <- prometheus.MustNewConstMetric(collector.arpDevices, prometheus.GaugeValue, float64(d.Flag), d.IPAddr, d.HWAddr, d.Hostname, d.Device)
	}
}

func (collector *ArpCollector) enqueueLookup(ipAddr string) {
	collector.hostCacheMutex.Lock()
	if _, ok := collector.pendingLookups[ipAddr]; ok {
		collector.hostCacheMutex.Unlock()
		return
	}
	collector.pendingLookups[ipAddr] = struct{}{}
	collector.hostCacheMutex.Unlock()

	select {
	case collector.lookupQueue <- ipAddr:
	default:
		collector.hostCacheMutex.Lock()
		delete(collector.pendingLookups, ipAddr)
		collector.hostCacheMutex.Unlock()
	}
}

func (collector *ArpCollector) lookupLoop() {
	for ipAddr := range collector.lookupQueue {
		hostname := "unknown:" + ipAddr

		ctx, cancel := context.WithTimeout(context.Background(), collector.lookupTimeout)
		hosts, err := net.DefaultResolver.LookupAddr(ctx, ipAddr)
		cancel()
		if err == nil && len(hosts) > 0 {
			hostname = CleanHostname(hosts[0], collector.stripDomainSuffix)
		}

		collector.hostCacheMutex.Lock()
		collector.hostCache[ipAddr] = hostCacheValue{Hostname: hostname, Expiry: time.Now().Add(collector.hostCacheTTL)}
		delete(collector.pendingLookups, ipAddr)
		collector.hostCacheMutex.Unlock()
	}
}
