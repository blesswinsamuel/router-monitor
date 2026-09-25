package lanpilot

import (
	"bytes"
	"net"
	"testing"
)

func TestBuildMagicPacket(t *testing.T) {
	mac, err := net.ParseMAC("00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("ParseMAC failed: %v", err)
	}

	pkt, err := BuildMagicPacket(mac, nil)
	if err != nil {
		t.Fatalf("BuildMagicPacket failed: %v", err)
	}

	// AMD magic packet must be exactly 102 bytes without password
	if len(pkt) != 102 {
		t.Fatalf("expected packet length 102, got %d", len(pkt))
	}

	// First 6 bytes must be 0xFF
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xFF {
			t.Errorf("expected 0xFF at index %d, got %02x", i, pkt[i])
		}
	}

	// Followed by 16 repetitions of the 6-byte MAC
	for rep := 0; rep < 16; rep++ {
		offset := 6 + (rep * 6)
		if !bytes.Equal(pkt[offset:offset+6], mac) {
			t.Errorf("rep %d: expected MAC %v at offset %d, got %v", rep, mac, offset, pkt[offset:offset+6])
		}
	}
}

func TestBuildMagicPacket_WithPassword(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("ParseMAC failed: %v", err)
	}

	pwd4 := []byte{192, 168, 1, 1}
	pkt, err := BuildMagicPacket(mac, pwd4)
	if err != nil {
		t.Fatalf("BuildMagicPacket with 4-byte password failed: %v", err)
	}
	if len(pkt) != 106 {
		t.Fatalf("expected length 106, got %d", len(pkt))
	}
	if !bytes.Equal(pkt[102:], pwd4) {
		t.Fatalf("password mismatch: expected %v, got %v", pwd4, pkt[102:])
	}

	pwd6 := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pkt6, err := BuildMagicPacket(mac, pwd6)
	if err != nil {
		t.Fatalf("BuildMagicPacket with 6-byte password failed: %v", err)
	}
	if len(pkt6) != 108 {
		t.Fatalf("expected length 108, got %d", len(pkt6))
	}
}

func TestBuildMagicPacket_InvalidMACs(t *testing.T) {
	// All-zero MAC should be rejected
	zeroMAC, _ := net.ParseMAC("00:00:00:00:00:00")
	if _, err := BuildMagicPacket(zeroMAC, nil); err == nil {
		t.Errorf("expected error for all-zero MAC, got nil")
	}

	// 8-byte EUI-64 MAC should be rejected
	eui64MAC, _ := net.ParseMAC("00:11:22:33:44:55:66:77")
	if _, err := BuildMagicPacket(eui64MAC, nil); err == nil {
		t.Errorf("expected error for 8-byte MAC, got nil")
	}
}

func TestCalculateBroadcastIP(t *testing.T) {
	tests := []struct {
		cidr     string
		expected string
	}{
		{"192.168.1.1/24", "192.168.1.255"},
		{"10.100.0.1/16", "10.100.255.255"},
		{"172.16.50.2/28", "172.16.50.15"},
		{"10.0.0.1/8", "10.255.255.255"},
	}

	for _, tc := range tests {
		_, ipNet, err := net.ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", tc.cidr, err)
		}
		bcast := CalculateBroadcastIP(ipNet)
		if bcast == nil || bcast.String() != tc.expected {
			t.Errorf("CalculateBroadcastIP(%q) = %v, expected %s", tc.cidr, bcast, tc.expected)
		}
	}
}

func TestResolveBroadcastTarget_Fallback(t *testing.T) {
	bcast, iface := ResolveBroadcastTarget("", "", "10.100.0.0/16")
	if bcast == nil || bcast.String() != "10.100.255.255" {
		t.Errorf("expected broadcast 10.100.255.255, got %v", bcast)
	}
	_ = iface

	// No fallback, should default to 255.255.255.255
	bcastDef, _ := ResolveBroadcastTarget("", "", "")
	if !bcastDef.Equal(net.IPv4bcast) {
		t.Errorf("expected 255.255.255.255, got %v", bcastDef)
	}
}
