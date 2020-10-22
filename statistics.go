package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// const TotalBytesQueueLen = 61

// var Stats = &Statistics{
// 	ifaces: make(map[string]*Iface),
// }

// type FlowSnapshot struct {
// 	Protocol           string
// 	SourceAddress      string // Include port if it is L4 flow
// 	DestinationAddress string // Include port if it is L4 flow
// }

// var L3FlowSnapshots = make([]*FlowSnapshot, 0, 0)
// var L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)

// type Flow struct {
// 	Protocol         string
// 	Addr             [2]string
// 	Port             [2]string
// 	TotalBytes       [2]int64
// 	ZeroDeltaCounter int
// }

// func (f *Flow) GetSnapshot() (ss *FlowSnapshot) {
// 	var srcAddr, dstAddr string
// 	if f.Port[0] == "" && f.Port[1] == "" {
// 		srcAddr = f.Addr[0]
// 		dstAddr = f.Addr[1]
// 	} else {
// 		srcAddr = f.Addr[0] + ":" + f.Port[0]
// 		dstAddr = f.Addr[1] + ":" + f.Port[1]
// 	}

// 	fss := FlowSnapshot{
// 		Protocol:           f.Protocol,
// 		SourceAddress:      srcAddr,
// 		DestinationAddress: dstAddr,
// 	}

// 	ss = &fss
// 	return
// }

// func NewIface(ifaceName string) (iface *Iface) {
// 	return &Iface{
// 		Name:    ifaceName,
// 		L3Flows: make(map[string]*Flow),
// 		L4Flows: make(map[string]*Flow),
// 	}
// }

// type Iface struct {
// 	Name    string
// 	L3Flows map[string]*Flow
// 	L4Flows map[string]*Flow
// 	Lock    sync.Mutex
// }

// func (i *Iface) UpdateL3Flow(l3Type string, srcAddr string, dstAddr string, length int) {
// 	i.Lock.Lock()
// 	var l3f *Flow
// 	var ok bool
// 	if l3f, ok = i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr]; ok {
// 		l3f.TotalBytes[0] += int64(length)
// 	} else if l3f, ok = i.L3Flows[l3Type+"_"+dstAddr+"_"+srcAddr]; ok {
// 		l3f.TotalBytes[1] += int64(length)
// 	} else {
// 		l3f = &Flow{
// 			Protocol:   l3Type,
// 			Addr:       [2]string{srcAddr, dstAddr},
// 			TotalBytes: [2]int64{int64(length), 0},
// 		}
// 		i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr] = l3f
// 	}
// 	i.Lock.Unlock()
// }

// func (i *Iface) UpdateL4Flow(l4Protocol string, srcAddr string, dstAddr string, srcPort string, dstPort string, length int) {
// 	i.Lock.Lock()
// 	var l4f *Flow
// 	var ok bool
// 	if l4f, ok = i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort]; ok {
// 		l4f.TotalBytes[0] += int64(length)
// 	} else if l4f, ok = i.L4Flows[l4Protocol+"_"+dstAddr+":"+dstPort+"_"+srcAddr+":"+srcPort]; ok {
// 		l4f.TotalBytes[1] += int64(length)
// 	} else {
// 		l4f = &Flow{
// 			Protocol:   l4Protocol,
// 			Addr:       [2]string{srcAddr, dstAddr},
// 			Port:       [2]string{srcPort, dstPort},
// 			TotalBytes: [2]int64{int64(length), 0},
// 		}
// 		i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort] = l4f
// 	}
// 	i.Lock.Unlock()
// }

// type Statistics struct {
// 	ifaces map[string]*Iface
// }

// func (s *Statistics) GetIface(ifaceName string) (iface *Iface) {
// 	var ok bool
// 	iface, ok = s.ifaces[ifaceName]
// 	if !ok {
// 		iface = &Iface{
// 			Name:    ifaceName,
// 			L3Flows: make(map[string]*Flow),
// 			L4Flows: make(map[string]*Flow),
// 		}
// 		s.ifaces[ifaceName] = iface
// 	}

// 	return
// }

// func (s *Statistics) PacketHandler(ifaceName string, pkt gopacket.Packet, enableLayer4 bool) {
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
			l := ly.(*layers.TCP)
			l4Protocol = "tcp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeUDP:
			l := ly.(*layers.UDP)
			l4Protocol = "udp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeICMPv4:
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

	l4Labels := map[string]string{
		"src":      srcAddr,
		"dst":      dstAddr,
		"src_port": srcPort,
		"dst_port": dstPort,
		"proto":    l4Protocol,
	}
	l4Packets.With(l4Labels).Inc()
	l4Throughput.With(l4Labels).Add(float64(l4Len))

	// iface.UpdateL3Flow(l3Type, srcAddr, dstAddr, l3Len)
	// if enableLayer4 {
	// 	iface.UpdateL4Flow(l4Protocol, srcAddr, dstAddr, srcPort, dstPort, l4Len)
	// }
}
