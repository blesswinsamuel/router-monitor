package tsdb

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
)

type LiveRates struct {
	DownloadBytesPerSec  float64
	UploadBytesPerSec    float64
	DownloadPacketsPerSec float64
	UploadPacketsPerSec   float64

	TotalDownloadBytes   uint64
	TotalUploadBytes     uint64
	TotalDownloadPackets uint64
	TotalUploadPackets   uint64

	InternetIsUp           bool
	InternetLatencySeconds float64
	ConnectedDevicesCount  int32
	LastSampleTime         time.Time
}

type Sampler struct {
	db              *DB
	ebpfCollector   *routermonitor.EbpfCollector
	arpCollector    *routermonitor.ArpCollector
	internetChecker *routermonitor.InternetChecker
	interval        time.Duration

	mu        sync.RWMutex
	liveRates LiveRates

	prevIngressBytes   uint64
	prevEgressBytes    uint64
	prevIngressPackets uint64
	prevEgressPackets  uint64
	prevTime           time.Time
}

func NewSampler(
	db *DB,
	ebpf *routermonitor.EbpfCollector,
	arp *routermonitor.ArpCollector,
	checker *routermonitor.InternetChecker,
	interval time.Duration,
) *Sampler {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Sampler{
		db:              db,
		ebpfCollector:   ebpf,
		arpCollector:    arp,
		internetChecker: checker,
		interval:        interval,
	}
}

func (s *Sampler) GetLiveRates() LiveRates {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveRates
}

func (s *Sampler) SampleOnce() {
	now := time.Now()
	var samples []Sample

	// 1. Gather Traffic Stats
	flows := s.ebpfCollector.GetFlowStats()
	var curIngressBytes, curEgressBytes, curIngressPackets, curEgressPackets uint64

	for _, f := range flows {
		if f.Direction == "ingress" {
			curIngressBytes += f.Bytes
			curIngressPackets += f.Packets
		} else if f.Direction == "egress" {
			curEgressBytes += f.Bytes
			curEgressPackets += f.Packets
		}
	}

	var dlBytesRate, ulBytesRate, dlPktsRate, ulPktsRate float64
	s.mu.Lock()
	if !s.prevTime.IsZero() {
		dt := now.Sub(s.prevTime).Seconds()
		if dt > 0 {
			if curIngressBytes >= s.prevIngressBytes {
				dlBytesRate = float64(curIngressBytes-s.prevIngressBytes) / dt
			}
			if curEgressBytes >= s.prevEgressBytes {
				ulBytesRate = float64(curEgressBytes-s.prevEgressBytes) / dt
			}
			if curIngressPackets >= s.prevIngressPackets {
				dlPktsRate = float64(curIngressPackets-s.prevIngressPackets) / dt
			}
			if curEgressPackets >= s.prevEgressPackets {
				ulPktsRate = float64(curEgressPackets-s.prevEgressPackets) / dt
			}
		}
	}
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
	for _, d := range devices {
		if d.IsValid {
			validDevices++
		}
	}
	samples = append(samples,
		Sample{Metric: "connected_devices_count", Labels: map[string]string{}, Timestamp: now, Value: float64(validDevices)},
	)

	// Update LiveRates cache
	s.mu.Lock()
	s.liveRates = LiveRates{
		DownloadBytesPerSec:   dlBytesRate,
		UploadBytesPerSec:     ulBytesRate,
		DownloadPacketsPerSec: dlPktsRate,
		UploadPacketsPerSec:   ulPktsRate,
		TotalDownloadBytes:    curIngressBytes,
		TotalUploadBytes:      curEgressBytes,
		TotalDownloadPackets:  curIngressPackets,
		TotalUploadPackets:    curEgressPackets,
		InternetIsUp:          anyUp,
		InternetLatencySeconds: avgLatency,
		ConnectedDevicesCount: validDevices,
		LastSampleTime:        now,
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
