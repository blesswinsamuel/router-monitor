package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/blesswinsamuel/router-monitor/dnsmasq"
	"github.com/blesswinsamuel/router-monitor/internetcheck"
	"github.com/blesswinsamuel/router-monitor/traffic"
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
		s.ListenAndServe()
	}()
}

func (s *server) Stop() {
	s.Shutdown(context.Background())
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
	defer s.Close()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	<-signalChan
}
