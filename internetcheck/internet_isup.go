package internetcheck

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
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

type InternetCheck struct {
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewInternetCheck() *InternetCheck {
	return &InternetCheck{}
}

func isInternetConnectionUp() {
	host := "1.1.1.1"
	port := "80"
	timeout := 5 * time.Second

	startTime := time.Now()
	_, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		log.Warn().Msgf("Internet is down: %v", err)
		connectionIsUp.Set(0)
		connectionDuration.Observe(time.Since(startTime).Seconds())
		return
	}
	connectionDuration.Observe(time.Since(startTime).Seconds())
	connectionIsUp.Set(1)
}

func (ic *InternetCheck) Start() {
	ic.wg.Add(1)
	go func() {
		defer ic.wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		isInternetConnectionUp()
		for {
			select {
			case <-ic.stopCh:
				return
			case <-ticker.C:
				isInternetConnectionUp()
			}
		}
	}()
}

func (ic *InternetCheck) Stop() {
	close(ic.stopCh)
	ic.wg.Wait()
}
