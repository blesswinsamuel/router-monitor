package traffic

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Benchmark_packetHandler(b *testing.B) {
	type args struct {
		pkt gopacket.Packet
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "1", args: args{pkt: gopacket.NewPacket(nil, layers.LayerTypeIPv4, gopacket.Default)}},
	}
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				packetHandler(tt.args.pkt)
			}
		})
	}
}
