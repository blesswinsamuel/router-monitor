package main

import (
	"strconv"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PacketHandler(ifaceName string, pkt gopacket.Packet, enableLayer4 bool) {
	// iface := s.GetIface(ifaceName)
	var l3Type, l4Protocol string
	var srcAddr, dstAddr string
	var srcPort, dstPort string
	var l3Len, l4Len int

	for _, ly := range pkt.Layers() {
		switch ly.LayerType() {
		case layers.LayerTypeIPv4:
			l := ly.(*layers.IPv4)
			l3Type = "ipv4"
			srcAddr = l.SrcIP.String()
			dstAddr = l.DstIP.String()
			l3Len = len(l.LayerPayload())
		case layers.LayerTypeTCP:
			if !enableLayer4 {
				continue
			}
			l := ly.(*layers.TCP)
			l4Protocol = "tcp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeUDP:
			if !enableLayer4 {
				continue
			}
			l := ly.(*layers.UDP)
			l4Protocol = "udp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeICMPv4:
			if !enableLayer4 {
				continue
			}
			l := ly.(*layers.ICMPv4)
			l4Protocol = "icmp"
			l4Len = len(l.LayerPayload())
		}
	}

	if l3Type == "" || l4Protocol == "" {
		return
	}

	l3Labels := map[string]string{
		"src":  srcAddr,
		"dst":  dstAddr,
		"type": l3Type,
	}
	l3Packets.With(l3Labels).Inc()
	l3Throughput.With(l3Labels).Add(float64(l3Len))

	if enableLayer4 {
		l4Labels := map[string]string{
			"src":   srcAddr,
			"dst":   dstAddr,
			"proto": l4Protocol,
		}
		// If the last part of the src/dst is a service, just use the literal service name:
		if _, ok := services[dstPort]; ok {
			l4Labels["service"] = dstPort
		}
		if _, ok := services[srcPort]; ok {
			l4Labels["service"] = srcPort
		}
		// Otherwise, do a lookup of port/proto to the service:
		srcPortInt, srcPortErr := strconv.Atoi(getDigits(srcPort))
		dstPortInt, dstPortErr := strconv.Atoi(getDigits(dstPort))
		if l4Labels["service"] == "" && dstPortErr == nil {
			l4Labels["service"] = lookupService(dstPortInt, l4Protocol)
		}
		if l4Labels["service"] == "" && srcPortErr == nil {
			l4Labels["service"] = lookupService(srcPortInt, l4Protocol)
		}
		if l4Labels["service"] == "" {
			l4Labels["service"] = ""
		}
		l4Throughput.With(l4Labels).Add(float64(l4Len))
		l4Packets.With(l4Labels).Inc()
	}
}

func getDigits(s string) string {
	var v []rune
	for _, c := range s {
		if !unicode.IsDigit(c) {
			break
		}
		v = append(v, c)
	}
	return string(v)
}
