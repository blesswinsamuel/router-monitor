package routermonitor

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type internetChecker struct {
	interval  time.Duration
	pingAddrs []string

	internetConnectionDuration *prometheus.HistogramVec
	internetConnectionIsUp     *prometheus.GaugeVec
}

func NewInternetChecker(interval time.Duration, pingAddrs []string) *internetChecker {
	return &internetChecker{
		interval:  interval,
		pingAddrs: pingAddrs,
		internetConnectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "router_monitor_internet_connection_duration_seconds",
			Help:    "",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		}, []string{"addr"}),
		internetConnectionIsUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "router_monitor_internet_connection_is_up",
			Help: "",
		}, []string{"addr"}),
	}
}

func (collector *internetChecker) Register(registry prometheus.Registerer) {
	registry.MustRegister(collector.internetConnectionDuration)
	registry.MustRegister(collector.internetConnectionIsUp)
}

func (collector *internetChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(collector.interval)
	log.Println("Checking if internet connection is up.")
	for {
		select {
		case <-ticker.C:
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
			}
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
