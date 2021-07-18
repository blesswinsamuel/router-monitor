// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary dnsmasq_exporter is a Prometheus exporter for dnsmasq statistics.
package dnsmasq

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

var (
	leasesPath  = flag.String("leases_path", "/var/lib/misc/dnsmasq.leases", "path to the dnsmasq leases file")
	dnsmasqAddr = flag.String("dnsmasq", "localhost:53", "dnsmasq host:port address")
)

var (
	// floatMetrics contains prometheus Gauges, keyed by the stats DNS record
	// they correspond to.
	floatMetrics = map[string]prometheus.Gauge{
		"cachesize.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_cachesize",
			Help: "configured size of the DNS cache",
		}),
		"insertions.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_insertions",
			Help: "DNS cache insertions",
		}),
		"evictions.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_evictions",
			Help: "DNS cache evictions: numbers of entries which replaced an unexpired cache entry",
		}),
		"misses.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_misses",
			Help: "DNS cache misses: queries which had to be forwarded",
		}),
		"hits.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_hits",
			Help: "DNS queries answered locally (cache hits)",
		}),
		"auth.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_auth",
			Help: "DNS queries for authoritative zones",
		}),
	}

	serversMetrics = map[string]*prometheus.GaugeVec{
		"queries": prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dnsmasq_servers_queries",
			Help: "DNS queries on upstream server",
		}, []string{"server"}),
		"queries_failed": prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dnsmasq_servers_queries_failed",
			Help: "DNS queries failed on upstream server",
		}, []string{"server"}),
	}

	leases = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsmasq_leases",
		Help: "Number of DHCP leases handed out",
	})
	leaseInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dnsmasq_lease_info",
		Help: "DHCP leases handed out",
	}, []string{"expiry", "mac", "ip", "devicename"})
)

func init() {
	for _, g := range floatMetrics {
		prometheus.MustRegister(g)
	}
	for _, g := range serversMetrics {
		prometheus.MustRegister(g)
	}
	prometheus.MustRegister(leases)
	prometheus.MustRegister(leaseInfo)
}

// From https://manpages.debian.org/stretch/dnsmasq-base/dnsmasq.8.en.html:
// The cache statistics are also available in the DNS as answers to queries of
// class CHAOS and type TXT in domain bind. The domain names are cachesize.bind,
// insertions.bind, evictions.bind, misses.bind, hits.bind, auth.bind and
// servers.bind. An example command to query this, using the dig utility would
// be:
//     dig +short chaos txt cachesize.bind

type DnsmasqExporter struct {
	promHandler http.Handler
	dnsClient   *dns.Client
	dnsmasqAddr string
	leasesPath  string
}

func NewDnsmasqExporter() *DnsmasqExporter {
	de := &DnsmasqExporter{
		promHandler: promhttp.Handler(),
		dnsClient: &dns.Client{
			SingleInflight: true,
		},
		dnsmasqAddr: *dnsmasqAddr,
		leasesPath:  *leasesPath,
	}
	return de
}

func question(name string) dns.Question {
	return dns.Question{
		Name:   name,
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassCHAOS,
	}
}

func (s *DnsmasqExporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var eg errgroup.Group

	eg.Go(func() error {
		msg := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
			},
			Question: []dns.Question{
				question("cachesize.bind."),
				question("insertions.bind."),
				question("evictions.bind."),
				question("misses.bind."),
				question("hits.bind."),
				question("auth.bind."),
				question("servers.bind."),
			},
		}
		in, _, err := s.dnsClient.Exchange(msg, s.dnsmasqAddr)
		if err != nil {
			return err
		}
		for _, a := range in.Answer {
			txt, ok := a.(*dns.TXT)
			if !ok {
				continue
			}
			switch txt.Hdr.Name {
			case "servers.bind.":
				for _, str := range txt.Txt {
					arr := strings.Fields(str)
					if got, want := len(arr), 3; got != want {
						return fmt.Errorf("stats DNS record servers.bind.: unexpected number of argument in record: got %d, want %d", got, want)
					}
					queries, err := strconv.ParseFloat(arr[1], 64)
					if err != nil {
						return err
					}
					failedQueries, err := strconv.ParseFloat(arr[2], 64)
					if err != nil {
						return err
					}
					serversMetrics["queries"].WithLabelValues(arr[0]).Set(queries)
					serversMetrics["queries_failed"].WithLabelValues(arr[0]).Set(failedQueries)
				}
			default:
				g, ok := floatMetrics[txt.Hdr.Name]
				if !ok {
					continue // ignore unexpected answer from dnsmasq
				}
				if got, want := len(txt.Txt), 1; got != want {
					return fmt.Errorf("stats DNS record %q: unexpected number of replies: got %d, want %d", txt.Hdr.Name, got, want)
				}
				f, err := strconv.ParseFloat(txt.Txt[0], 64)
				if err != nil {
					return err
				}
				g.Set(f)
			}
		}
		return nil
	})

	eg.Go(func() error {
		f, err := os.Open(s.leasesPath)
		if err != nil {
			log.Warnln("could not open leases file:", err)
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		var lines float64
		leaseInfo.Reset()
		for scanner.Scan() {
			arr := strings.Fields(scanner.Text())
			if got, want := len(arr), 4; got < want {
				return fmt.Errorf("stats DHCP lease record: unexpected number of argument in record: got %d, want at least %d", got, want)
			}
			leaseInfo.WithLabelValues(arr[0], arr[1], arr[2], arr[3]).Set(1)
			lines++
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		leases.Set(lines)
		return nil
	})

	if err := eg.Wait(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.promHandler.ServeHTTP(w, r)
}
