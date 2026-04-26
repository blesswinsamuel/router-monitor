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

type arpCollector struct {
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

func NewArpCollector(filename string, stripDomainSuffix string, hostCacheTTL time.Duration) *arpCollector {
	if hostCacheTTL <= 0 {
		hostCacheTTL = 30 * time.Minute
	}

	collector := &arpCollector{
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

func (collector *arpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.arpDevices
}

// Collect implements required collect function for all promehteus collectors
func (collector *arpCollector) Collect(ch chan<- prometheus.Metric) {
	collect := func() error {
		file, err := os.Open(collector.filename)
		if err != nil {
			return err
		}
		defer file.Close()

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
			ch <- prometheus.MustNewConstMetric(collector.arpDevices, prometheus.GaugeValue, float64(flag), ipAddr, hwAddr, hostname, device)
		}

		if err := scanner.Err(); err != nil {
			return err
		}

		return nil
	}
	if err := collect(); err != nil {
		log.Printf("Error collecting ARP stats: %v", err)
	}
}

func (collector *arpCollector) enqueueLookup(ipAddr string) {
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

func (collector *arpCollector) lookupLoop() {
	for ipAddr := range collector.lookupQueue {
		hostname := "unknown:" + ipAddr

		ctx, cancel := context.WithTimeout(context.Background(), collector.lookupTimeout)
		hosts, err := net.DefaultResolver.LookupAddr(ctx, ipAddr)
		cancel()
		if err == nil && len(hosts) > 0 {
			hostname = hosts[0]
		}

		hostname = strings.TrimSuffix(hostname, collector.stripDomainSuffix)

		collector.hostCacheMutex.Lock()
		collector.hostCache[ipAddr] = hostCacheValue{Hostname: hostname, Expiry: time.Now().Add(collector.hostCacheTTL)}
		delete(collector.pendingLookups, ipAddr)
		collector.hostCacheMutex.Unlock()
	}
}
