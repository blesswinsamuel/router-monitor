package routermonitor

import (
	"bufio"
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
	hostCache         map[string]hostCacheValue
	hostCacheMutex    sync.Mutex

	arpDevices *prometheus.Desc
}

func NewArpCollector(filename string, stripDomainSuffix string) *arpCollector {
	return &arpCollector{
		filename:          filename,
		stripDomainSuffix: stripDomainSuffix,
		hostCache:         make(map[string]hostCacheValue),
		arpDevices: prometheus.NewDesc("router_monitor_arp_devices", "",
			[]string{"ip_addr", "hw_addr", "hostname", "device"}, nil,
		),
	}
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
			host, ok := collector.hostCache[ipAddr]
			hostname = host.Hostname
			if !ok || host.Expiry.Before(time.Now()) {
				hosts, err := net.LookupAddr(ipAddr)
				if err != nil {
					hostname = "unknown:" + ipAddr
				} else if len(hosts) > 0 {
					hostname = hosts[0]
				}
				if hosts == nil {
					hostname = "unknown"
				}
				hostname = strings.TrimSuffix(hostname, collector.stripDomainSuffix)
				collector.hostCacheMutex.Lock()
				collector.hostCache[ipAddr] = hostCacheValue{Hostname: hostname, Expiry: time.Now().Add(30 * time.Minute)}
				collector.hostCacheMutex.Unlock()
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
