package tsdb

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
)

type LiveRates struct {
	DownloadBytesPerSec   float64
	UploadBytesPerSec     float64
	DownloadPacketsPerSec float64
	UploadPacketsPerSec   float64

	TotalDownloadBytes   uint64
	TotalUploadBytes     uint64
	TotalDownloadPackets uint64
	TotalUploadPackets   uint64

	WanDownloadBytesPerSec float64
	WanUploadBytesPerSec   float64
	LanDownloadBytesPerSec float64
	LanUploadBytesPerSec   float64

	TotalWanDownloadBytes uint64
	TotalWanUploadBytes   uint64
	TotalLanDownloadBytes uint64
	TotalLanUploadBytes   uint64

	InternetIsUp           bool
	InternetLatencySeconds float64
	ConnectedDevicesCount  int32
	LastSampleTime         time.Time
}

type DeviceRate struct {
	DownloadBytesPerSec      float64
	UploadBytesPerSec        float64
	WanDownloadBytesPerSec   float64
	WanUploadBytesPerSec     float64
	LanDownloadBytesPerSec   float64
	LanUploadBytesPerSec     float64
	DownloadPacketsPerSec    float64
	UploadPacketsPerSec      float64
	WanDownloadPacketsPerSec float64
	WanUploadPacketsPerSec   float64
	LanDownloadPacketsPerSec float64
	LanUploadPacketsPerSec   float64
}

type devByteCounts struct {
	wanDl uint64
	wanUl uint64
	lanDl uint64
	lanUl uint64
}

type devPacketCounts struct {
	wanDl uint64
	wanUl uint64
	lanDl uint64
	lanUl uint64
}

type Sampler struct {
	db              *DB
	ebpfCollector   *routermonitor.EbpfCollector
	arpCollector    *routermonitor.ArpCollector
	internetChecker *routermonitor.InternetChecker
	interval        time.Duration

	mu          sync.RWMutex
	liveRates   LiveRates
	deviceRates map[string]DeviceRate

	prevIngressBytes   uint64
	prevEgressBytes    uint64
	prevWanDlBytes     uint64
	prevWanUlBytes     uint64
	prevLanDlBytes     uint64
	prevLanUlBytes     uint64
	prevIngressPackets uint64
	prevEgressPackets  uint64
	prevTime           time.Time

	prevDeviceBytes   map[string]devByteCounts
	prevDevicePackets map[string]devPacketCounts

	lastDeviceUpsert time.Time
	knownDeviceState map[string]string
}

func NewSampler(
	db *DB,
	ebpf *routermonitor.EbpfCollector,
	arp *routermonitor.ArpCollector,
	checker *routermonitor.InternetChecker,
	interval time.Duration,
) *Sampler {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	db.SetSampleInterval(interval)
	return &Sampler{
		db:                db,
		ebpfCollector:     ebpf,
		arpCollector:      arp,
		internetChecker:   checker,
		interval:          interval,
		deviceRates:       make(map[string]DeviceRate),
		prevDeviceBytes:   make(map[string]devByteCounts),
		prevDevicePackets: make(map[string]devPacketCounts),
		knownDeviceState:  make(map[string]string),
	}
}

func (s *Sampler) GetLiveRates() LiveRates {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveRates
}

func (s *Sampler) GetDeviceRates() map[string]DeviceRate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]DeviceRate, len(s.deviceRates))
	for k, v := range s.deviceRates {
		res[k] = v
	}
	return res
}

func (s *Sampler) SampleOnce() {
	now := time.Now()
	var samples []Sample

	// 1. Gather Traffic Stats
	flows := s.ebpfCollector.GetFlowStats()
	var curWanDlBytes, curWanUlBytes uint64
	var curLanDlBytes, curLanUlBytes uint64
	var curIngressPackets, curEgressPackets uint64
	curDeviceBytes := make(map[string]devByteCounts)
	curDevicePackets := make(map[string]devPacketCounts)

	for _, f := range flows {
		if f.Direction == "ingress" {
			curIngressPackets += f.Packets
		} else if f.Direction == "egress" {
			curEgressPackets += f.Packets
		}

		isLanToLan := f.SrcIP != "" && f.SrcIP != "internet" && f.DstIP != "" && f.DstIP != "internet"

		if isLanToLan {
			// Device-to-Device (LAN)
			curLanDlBytes += f.Bytes
			curLanUlBytes += f.Bytes

			sDevB := curDeviceBytes[f.SrcIP]
			sDevB.lanUl += f.Bytes
			curDeviceBytes[f.SrcIP] = sDevB

			dDevB := curDeviceBytes[f.DstIP]
			dDevB.lanDl += f.Bytes
			curDeviceBytes[f.DstIP] = dDevB

			sDevP := curDevicePackets[f.SrcIP]
			sDevP.lanUl += f.Packets
			curDevicePackets[f.SrcIP] = sDevP

			dDevP := curDevicePackets[f.DstIP]
			dDevP.lanDl += f.Packets
			curDevicePackets[f.DstIP] = dDevP
		} else if f.SrcIP != "" && f.SrcIP != "internet" && (f.DstIP == "internet" || f.DstIP == "") {
			// Device uploading to Internet (WAN Upload)
			curWanUlBytes += f.Bytes

			sDevB := curDeviceBytes[f.SrcIP]
			sDevB.wanUl += f.Bytes
			curDeviceBytes[f.SrcIP] = sDevB

			sDevP := curDevicePackets[f.SrcIP]
			sDevP.wanUl += f.Packets
			curDevicePackets[f.SrcIP] = sDevP
		} else if f.DstIP != "" && f.DstIP != "internet" && (f.SrcIP == "internet" || f.SrcIP == "") {
			// Device downloading from Internet (WAN Download)
			curWanDlBytes += f.Bytes

			dDevB := curDeviceBytes[f.DstIP]
			dDevB.wanDl += f.Bytes
			curDeviceBytes[f.DstIP] = dDevB

			dDevP := curDevicePackets[f.DstIP]
			dDevP.wanDl += f.Packets
			curDevicePackets[f.DstIP] = dDevP
		}
	}

	curIngressBytes := curWanDlBytes + curLanDlBytes
	curEgressBytes := curWanUlBytes + curLanUlBytes

	var dlBytesRate, ulBytesRate, dlPktsRate, ulPktsRate float64
	var wanDlRate, wanUlRate, lanDlRate, lanUlRate float64
	var devSamples []Sample
	s.mu.Lock()
	if !s.prevTime.IsZero() {
		dt := now.Sub(s.prevTime).Seconds()
		if dt > 0 {
			if curWanDlBytes >= s.prevWanDlBytes {
				wanDlRate = float64(curWanDlBytes-s.prevWanDlBytes) / dt
			}
			if curWanUlBytes >= s.prevWanUlBytes {
				wanUlRate = float64(curWanUlBytes-s.prevWanUlBytes) / dt
			}
			if curLanDlBytes >= s.prevLanDlBytes {
				lanDlRate = float64(curLanDlBytes-s.prevLanDlBytes) / dt
			}
			if curLanUlBytes >= s.prevLanUlBytes {
				lanUlRate = float64(curLanUlBytes-s.prevLanUlBytes) / dt
			}
			dlBytesRate = wanDlRate + lanDlRate
			ulBytesRate = wanUlRate + lanUlRate

			if curIngressPackets >= s.prevIngressPackets {
				dlPktsRate = float64(curIngressPackets-s.prevIngressPackets) / dt
			}
			if curEgressPackets >= s.prevEgressPackets {
				ulPktsRate = float64(curEgressPackets-s.prevEgressPackets) / dt
			}

			// Calculate per-device rates
			curDevRates := make(map[string]DeviceRate)
			allIPs := make(map[string]struct{})
			for ip := range curDeviceBytes {
				allIPs[ip] = struct{}{}
			}
			for ip := range s.prevDeviceBytes {
				allIPs[ip] = struct{}{}
			}

			for ip := range allIPs {
				curB := curDeviceBytes[ip]
				prevB := s.prevDeviceBytes[ip]
				var dWanDl, dWanUl, dLanDl, dLanUl float64
				if curB.wanDl >= prevB.wanDl {
					dWanDl = float64(curB.wanDl-prevB.wanDl) / dt
				}
				if curB.wanUl >= prevB.wanUl {
					dWanUl = float64(curB.wanUl-prevB.wanUl) / dt
				}
				if curB.lanDl >= prevB.lanDl {
					dLanDl = float64(curB.lanDl-prevB.lanDl) / dt
				}
				if curB.lanUl >= prevB.lanUl {
					dLanUl = float64(curB.lanUl-prevB.lanUl) / dt
				}

				curP := curDevicePackets[ip]
				prevP := s.prevDevicePackets[ip]
				var dWanDlP, dWanUlP, dLanDlP, dLanUlP float64
				if curP.wanDl >= prevP.wanDl {
					dWanDlP = float64(curP.wanDl-prevP.wanDl) / dt
				}
				if curP.wanUl >= prevP.wanUl {
					dWanUlP = float64(curP.wanUl-prevP.wanUl) / dt
				}
				if curP.lanDl >= prevP.lanDl {
					dLanDlP = float64(curP.lanDl-prevP.lanDl) / dt
				}
				if curP.lanUl >= prevP.lanUl {
					dLanUlP = float64(curP.lanUl-prevP.lanUl) / dt
				}

				devDlRate := dWanDl + dLanDl
				devUlRate := dWanUl + dLanUl
				devDlPktsRate := dWanDlP + dLanDlP
				devUlPktsRate := dWanUlP + dLanUlP

				prevRate := s.deviceRates[ip]
				if devDlRate > 0 || devUlRate > 0 || devDlPktsRate > 0 || devUlPktsRate > 0 || prevRate.DownloadBytesPerSec > 0 || prevRate.UploadBytesPerSec > 0 {
					curDevRates[ip] = DeviceRate{
						DownloadBytesPerSec:      devDlRate,
						UploadBytesPerSec:        devUlRate,
						WanDownloadBytesPerSec:   dWanDl,
						WanUploadBytesPerSec:     dWanUl,
						LanDownloadBytesPerSec:   dLanDl,
						LanUploadBytesPerSec:     dLanUl,
						DownloadPacketsPerSec:    devDlPktsRate,
						UploadPacketsPerSec:      devUlPktsRate,
						WanDownloadPacketsPerSec: dWanDlP,
						WanUploadPacketsPerSec:   dWanUlP,
						LanDownloadPacketsPerSec: dLanDlP,
						LanUploadPacketsPerSec:   dLanUlP,
					}
					if devDlRate > 0 || prevRate.DownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_traffic_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     devDlRate,
						})
					}
					if devUlRate > 0 || prevRate.UploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_traffic_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     devUlRate,
						})
					}
					if dWanDl > 0 || prevRate.WanDownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_wan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     dWanDl,
						})
					}
					if dWanUl > 0 || prevRate.WanUploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_wan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     dWanUl,
						})
					}
					if dLanDl > 0 || prevRate.LanDownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_lan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     dLanDl,
						})
					}
					if dLanUl > 0 || prevRate.LanUploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_lan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     dLanUl,
						})
					}
				}
			}
			s.deviceRates = curDevRates
		}
	}
	s.prevDeviceBytes = curDeviceBytes
	s.prevDevicePackets = curDevicePackets
	s.prevWanDlBytes = curWanDlBytes
	s.prevWanUlBytes = curWanUlBytes
	s.prevLanDlBytes = curLanDlBytes
	s.prevLanUlBytes = curLanUlBytes
	s.prevIngressBytes = curIngressBytes
	s.prevEgressBytes = curEgressBytes
	s.prevIngressPackets = curIngressPackets
	s.prevEgressPackets = curEgressPackets
	s.prevTime = now
	s.mu.Unlock()

	samples = append(samples,
		Sample{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: dlBytesRate},
		Sample{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: ulBytesRate},
		Sample{Metric: "traffic_packets_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: dlPktsRate},
		Sample{Metric: "traffic_packets_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: ulPktsRate},
	)
	samples = append(samples, devSamples...)

	// 2. Gather Internet Check Stats
	targets := s.internetChecker.GetStatus()
	anyUp := false
	var latencySum float64
	var latencyCount int

	for _, t := range targets {
		if t.IsUp {
			anyUp = true
		}
		isUpVal := 0.0
		if t.IsUp {
			isUpVal = 1.0
		}
		samples = append(samples,
			Sample{Metric: "internet_is_up", Labels: map[string]string{"target": t.Addr}, Timestamp: now, Value: isUpVal},
			Sample{Metric: "internet_latency_seconds", Labels: map[string]string{"target": t.Addr}, Timestamp: now, Value: t.LastLatencySec},
		)
		if t.LastLatencySec > 0 {
			latencySum += t.LastLatencySec
			latencyCount++
		}
	}
	avgLatency := 0.0
	if latencyCount > 0 {
		avgLatency = latencySum / float64(latencyCount)
	}

	// 3. Gather Devices
	devices := s.arpCollector.GetDevices()
	var validDevices int32
	var devicesToUpsert []PersistedDevice
	needsPeriodicRefresh := now.Sub(s.lastDeviceUpsert) >= 5*time.Minute

	for _, d := range devices {
		if d.IsValid {
			validDevices++
		}
		if d.HWAddr != "" && d.HWAddr != "00:00:00:00:00:00" && (d.Flag&2 != 0 || d.Flag&4 != 0) {
			stateSig := d.IPAddr + "|" + d.Hostname + "|" + d.Device
			if needsPeriodicRefresh || s.knownDeviceState[d.HWAddr] != stateSig {
				s.knownDeviceState[d.HWAddr] = stateSig
				devicesToUpsert = append(devicesToUpsert, PersistedDevice{
					HWAddr:    d.HWAddr,
					IPAddr:    d.IPAddr,
					Hostname:  d.Hostname,
					Device:    d.Device,
					FirstSeen: now,
					LastSeen:  now,
				})
			}
		}
	}

	if len(devicesToUpsert) > 0 {
		if err := s.db.UpsertDevices(devicesToUpsert); err != nil {
			log.Printf("error upserting devices to tsdb: %v", err)
		} else {
			s.lastDeviceUpsert = now
		}
	}

	samples = append(samples,
		Sample{Metric: "connected_devices_count", Labels: map[string]string{}, Timestamp: now, Value: float64(validDevices)},
	)

	// Update LiveRates cache
	s.mu.Lock()
	s.liveRates = LiveRates{
		DownloadBytesPerSec:    dlBytesRate,
		UploadBytesPerSec:      ulBytesRate,
		DownloadPacketsPerSec:  dlPktsRate,
		UploadPacketsPerSec:    ulPktsRate,
		TotalDownloadBytes:     curIngressBytes,
		TotalUploadBytes:       curEgressBytes,
		InternetIsUp:           anyUp,
		InternetLatencySeconds: avgLatency,
		ConnectedDevicesCount:  validDevices,
		LastSampleTime:         now,

		WanDownloadBytesPerSec: wanDlRate,
		WanUploadBytesPerSec:   wanUlRate,
		LanDownloadBytesPerSec: lanDlRate,
		LanUploadBytesPerSec:   lanUlRate,

		TotalWanDownloadBytes: curWanDlBytes,
		TotalWanUploadBytes:   curWanUlBytes,
		TotalLanDownloadBytes: curLanDlBytes,
		TotalLanUploadBytes:   curLanUlBytes,
	}
	s.mu.Unlock()

	// Write batch to SQLite TSDB
	if err := s.db.InsertSamples(samples); err != nil {
		log.Printf("error inserting metric samples to tsdb: %v", err)
	}
}

func (s *Sampler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	// Sample immediately on start
	go s.SampleOnce()

	go func() {
		for {
			select {
			case <-ticker.C:
				s.SampleOnce()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
