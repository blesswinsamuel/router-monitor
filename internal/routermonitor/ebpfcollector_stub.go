//go:build !386 && !amd64

package routermonitor

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type ebpfCollectorPacketStatsKey struct {
	EthProto uint16
	_        [2]byte
	Srcip    uint32
	Dstip    uint32
	IpProto  uint8
	_        [3]byte
}

type ebpfCollectorPacketStatsValue struct {
	Packets uint64
	Bytes   uint64
}

type ebpfCollectorObjects struct {
	ebpfCollectorPrograms
	ebpfCollectorMaps
}

func (o *ebpfCollectorObjects) Close() error {
	return nil
}

type ebpfCollectorMaps struct {
	PacketStatsEgress  *ebpf.Map `ebpf:"packet_stats_egress"`
	PacketStatsIngress *ebpf.Map `ebpf:"packet_stats_ingress"`
}

type ebpfCollectorPrograms struct {
	TcPacketCounterEgress  *ebpf.Program `ebpf:"tc_packet_counter_egress"`
	TcPacketCounterIngress *ebpf.Program `ebpf:"tc_packet_counter_ingress"`
}

func loadEbpfCollector() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("ebpf collector is only supported on x86 (386/amd64) targets")
}

func loadEbpfCollectorObjects(interface{}, *ebpf.CollectionOptions) error {
	return fmt.Errorf("ebpf collector is only supported on x86 (386/amd64) targets")
}
