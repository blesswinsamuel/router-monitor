package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/blesswinsamuel/router-monitor/internal/dnsmasq"
	"github.com/blesswinsamuel/router-monitor/internal/internetcheck"
	"github.com/blesswinsamuel/router-monitor/internal/traffic"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	listen      = flag.String("listen", "localhost:9154", "listen address")
	metricsPath = flag.String("metrics_path", "/metrics", "path under which metrics are served")
)

type server struct {
	*http.Server
}

func NewServer(r http.Handler) *server {
	return &server{
		&http.Server{Addr: *listen, Handler: r},
	}
}

func (s *server) Serve() {
	go func() {
		log.Info().Msgf("Listening on %s", *listen)
		log.Info().Msgf("Serving metrics under %s", *metricsPath)
		if err := s.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				return
			}
			log.Error().Err(err).Msg("ListenAndServe failed")
			return
		}
	}()
}

func (s *server) Stop() {
	log.Info().Msg("Shutting down server...")
	s.Shutdown(context.Background())
	log.Info().Msg("Server shut down")
}

func main() {
	flag.Parse()
	if os.Geteuid() != 0 {
		log.Fatal().Msg("Must run as root")
	}

	de := dnsmasq.NewDnsmasqExporter()

	ic := internetcheck.NewInternetCheck()
	ic.Start()
	defer ic.Stop()

	nte := traffic.NewNetworkTrafficExporter()
	nte.Start()
	defer nte.Stop()

	r := http.NewServeMux()
	r.HandleFunc(*metricsPath, de.Handler(promhttp.Handler()))
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Router Monitor</title></head>
			<body>
			<h1>Router Monitor</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body></html>`))
	})
	s := NewServer(r)

	s.Serve()
	defer s.Stop()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	<-signalChan
}
