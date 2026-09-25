package lanpilot

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type ArpCollector struct {
	filename   string
	arpDevices *prometheus.Desc
}

func NewArpCollector(filename string) *ArpCollector {
	return &ArpCollector{
		filename: filename,
		arpDevices: prometheus.NewDesc("lanpilot_arp_devices", "ARP entries discovered from /proc/net/arp.",
			[]string{"ip_addr", "hw_addr", "device"}, nil,
		),
	}
}

func (collector *ArpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.arpDevices
}

type ArpDeviceEntry struct {
	IPAddr  string
	HWAddr  string
	Device  string
	Flag    int64
	IsValid bool
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
		flag, err := strconv.ParseInt(fields[2], 0, 0)
		if err != nil {
			log.Printf("Error parsing flag: %v", err)
		}
		device := fields[5]
		devices = append(devices, ArpDeviceEntry{
			IPAddr:  ipAddr,
			HWAddr:  hwAddr,
			Device:  device,
			Flag:    flag,
			IsValid: flag == 2,
		})
	}

	return devices
}

// Collect implements required collect function for all prometheus collectors
func (collector *ArpCollector) Collect(ch chan<- prometheus.Metric) {
	devices := collector.GetDevices()
	for _, d := range devices {
		ch <- prometheus.MustNewConstMetric(collector.arpDevices, prometheus.GaugeValue, float64(d.Flag), d.IPAddr, d.HWAddr, d.Device)
	}
}
