package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type internetChecker struct {
	interval time.Duration

	connectionDuration *prometheus.HistogramVec
	connectionIsUp     *prometheus.GaugeVec
}

func newInternetChecker(interval time.Duration) *internetChecker {
	return &internetChecker{
		interval: interval,
		connectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ebpf_firewall_connection_duration_seconds",
			Help:    "",
			Buckets: prometheus.DefBuckets,
		}, []string{"addr"}),
		connectionIsUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_firewall_connection_is_up",
			Help: "",
		}, []string{"addr"}),
	}
}

func (collector *internetChecker) Register(registry prometheus.Registerer) {
	registry.MustRegister(collector.connectionDuration)
	registry.MustRegister(collector.connectionIsUp)
}

func (collector *internetChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(collector.interval)
	addrs := []string{
		"1.1.1.1:53",
		"64.6.64.6:53",
		"8.8.8.8:53",
		"208.67.222.222:53",
		"9.9.9.9:53",
	}
	log.Println("Checking if internet connection is up.")
	for {
		select {
		case <-ticker.C:
			startTime := time.Now()
			connectionIsUp := 0
			for _, addr := range addrs {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					log.Printf("Failed to connect to %s: %v", addr, err)
				} else {
					conn.Close()
					connectionIsUp = 1
				}
				timeSinceStart := time.Since(startTime).Seconds()
				collector.connectionDuration.WithLabelValues(addr).Observe(timeSinceStart)
				collector.connectionIsUp.WithLabelValues(addr).Set(float64(connectionIsUp))
			}
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
