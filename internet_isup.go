package main

import (
	"context"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	connectionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "ntm_internet_connection_duration_seconds", Help: "Time taken to establish tcp connection",
	})
	connectionIsUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntm_internet_connection_is_up", Help: "Whether internet connection is up",
	})
)

func init() {
	prometheus.MustRegister(connectionDuration)
	prometheus.MustRegister(connectionIsUp)
}

func continuouslyCheckInternetConnectionIsUp(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		IsInternetConnectionUp()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				IsInternetConnectionUp()
			}
		}
	}()
}

func IsInternetConnectionUp() {
	host := "1.1.1.1"
	port := "80"
	timeout := 5 * time.Second

	startTime := time.Now()
	_, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		log.Warningf("Internet is down: %v", err)
		connectionIsUp.Set(0)
		connectionDuration.Observe(time.Since(startTime).Seconds())
		return
	}
	connectionDuration.Observe(time.Since(startTime).Seconds())
	connectionIsUp.Set(1)
}
