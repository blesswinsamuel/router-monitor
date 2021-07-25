package traffic

import (
	"flag"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	iface  = flag.String("interface", "eth0", "network interface to monitor")
	filter = flag.String("bpf", "", "BPF filter")
)

var (
	labelNames   = []string{"src", "dst"}
	packetsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_packets_total", Help: "Packets transferred",
	}, labelNames)
	bytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntm_bytes_total", Help: "Bytes transferred",
	}, labelNames)
)

func init() {
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
}

var ipNets []*net.IPNet

type NetworkTrafficExporter struct {
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewNetworkTrafficExporter() *NetworkTrafficExporter {
	return &NetworkTrafficExporter{
		stopCh: make(chan struct{}),
	}
}

func packetHandler(pkt gopacket.Packet) {
	var srcAddr, dstAddr net.IP
	var payloadLen uint16

	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}
	l, ok := nl.(*layers.IPv4)
	if !ok {
		return
	}
	srcAddr = l.SrcIP
	dstAddr = l.DstIP
	payloadLen = l.Length

	src := "internet"
	dst := "internet"
	for _, n := range ipNets {
		if n.Contains(srcAddr) {
			src = srcAddr.String()
		}
		if n.Contains(dstAddr) {
			dst = dstAddr.String()
		}
	}
	packetsTotal.WithLabelValues(src, dst).Inc()
	bytesTotal.WithLabelValues(src, dst).Add(float64(payloadLen))
}

func getIpNets(iface string) ([]*net.IPNet, error) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("localAddresses: %w", err)
	}
	addrs, err := i.Addrs()
	if err != nil {
		return nil, fmt.Errorf("localAddresses: %w", err)
	}
	ipNets := []*net.IPNet{}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ipNets = append(ipNets, v)
		}
	}
	if len(ipNets) > 0 {
		return ipNets, nil
	}
	return nil, fmt.Errorf("localAddresses: interface not found")
}

func (nte *NetworkTrafficExporter) Start() {
	var err error
	ipNets, err = getIpNets(*iface)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	nte.wg.Add(1)
	go func() {
		defer nte.wg.Done()
		handle, err := pcap.OpenLive(*iface, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal().Msgf("Failed to OpenLive by pcap, err: %s", err)
		}

		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal().Msgf("Failed to set BPF filter, err: %s", err)
		}
		defer handle.Close()

		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-nte.stopCh:
				return
			case p := <-ps.Packets():
				go packetHandler(p)
			}
		}
	}()
}

func (nte *NetworkTrafficExporter) Stop() {
	close(nte.stopCh)
	nte.wg.Wait()
}
