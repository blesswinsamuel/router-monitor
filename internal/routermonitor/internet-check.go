package routermonitor

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type PingTargetStatus struct {
	Addr            string
	IsUp            bool
	LastLatencySec  float64
	AvgLatencySec   float64
	RecentLatencies []float64
}

type targetState struct {
	addr            string
	isUp            bool
	lastLatency     float64
	recentLatencies []float64
}

type InternetChecker struct {
	interval  time.Duration
	pingAddrs []string

	internetConnectionDuration *prometheus.HistogramVec
	internetConnectionIsUp     *prometheus.GaugeVec

	statusMu sync.RWMutex
	targets  map[string]*targetState
}

func NewInternetChecker(interval time.Duration, pingAddrs []string) *InternetChecker {
	checker := &InternetChecker{
		interval:  interval,
		pingAddrs: pingAddrs,
		targets:   make(map[string]*targetState),
		internetConnectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "router_monitor_internet_connection_duration_seconds",
			Help:    "Time taken to perform TCP connectivity checks.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		}, []string{"addr"}),
		internetConnectionIsUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "router_monitor_internet_connection_is_up",
			Help: "Whether TCP connectivity checks are currently succeeding (1) or failing (0).",
		}, []string{"addr"}),
	}
	for _, addr := range pingAddrs {
		checker.targets[addr] = &targetState{addr: addr}
	}
	return checker
}

func (collector *InternetChecker) Register(registry prometheus.Registerer) {
	registry.MustRegister(collector.internetConnectionDuration)
	registry.MustRegister(collector.internetConnectionIsUp)
}

func (collector *InternetChecker) GetStatus() []PingTargetStatus {
	collector.statusMu.RLock()
	defer collector.statusMu.RUnlock()

	res := make([]PingTargetStatus, 0, len(collector.pingAddrs))
	for _, addr := range collector.pingAddrs {
		st, ok := collector.targets[addr]
		if !ok {
			res = append(res, PingTargetStatus{Addr: addr})
			continue
		}
		var sum float64
		for _, l := range st.recentLatencies {
			sum += l
		}
		avg := 0.0
		if len(st.recentLatencies) > 0 {
			avg = sum / float64(len(st.recentLatencies))
		}
		latenciesCopy := make([]float64, len(st.recentLatencies))
		copy(latenciesCopy, st.recentLatencies)

		res = append(res, PingTargetStatus{
			Addr:            addr,
			IsUp:            st.isUp,
			LastLatencySec:  st.lastLatency,
			AvgLatencySec:   avg,
			RecentLatencies: latenciesCopy,
		})
	}
	return res
}

func (collector *InternetChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(collector.interval)
	log.Println("Checking if internet connection is up.")

	check := func() {
		for _, addr := range collector.pingAddrs {
			connectionIsUp := 0
			startTime := time.Now()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				log.Printf("Failed to connect to %s: %v", addr, err)
			} else {
				conn.Close()
				connectionIsUp = 1
			}
			timeSinceStart := time.Since(startTime).Seconds()
			collector.internetConnectionDuration.WithLabelValues(addr).Observe(timeSinceStart)
			collector.internetConnectionIsUp.WithLabelValues(addr).Set(float64(connectionIsUp))

			collector.statusMu.Lock()
			st, ok := collector.targets[addr]
			if !ok {
				st = &targetState{addr: addr}
				collector.targets[addr] = st
			}
			st.isUp = connectionIsUp == 1
			st.lastLatency = timeSinceStart
			st.recentLatencies = append(st.recentLatencies, timeSinceStart)
			if len(st.recentLatencies) > 20 {
				st.recentLatencies = st.recentLatencies[len(st.recentLatencies)-20:]
			}
			collector.statusMu.Unlock()
		}
	}

	// Run first check immediately on start
	go check()

	for {
		select {
		case <-ticker.C:
			check()
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
