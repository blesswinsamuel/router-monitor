package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParsePingAddrs_DefaultsWhenEmpty(t *testing.T) {
	got, err := parsePingAddrs("")
	if err != nil {
		t.Fatalf("parsePingAddrs returned error: %v", err)
	}
	if len(got) != len(defaultPingAddrs) {
		t.Fatalf("expected %d defaults, got %d", len(defaultPingAddrs), len(got))
	}
	for i := range defaultPingAddrs {
		if got[i] != defaultPingAddrs[i] {
			t.Fatalf("default index %d mismatch: got %q want %q", i, got[i], defaultPingAddrs[i])
		}
	}
}

func TestParsePingAddrs_ValidList(t *testing.T) {
	got, err := parsePingAddrs(" 1.1.1.1:53,8.8.8.8:53 ")
	if err != nil {
		t.Fatalf("parsePingAddrs returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 addrs, got %d", len(got))
	}
	if got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Fatalf("unexpected parsed addrs: %#v", got)
	}
}

func TestParsePingAddrs_Invalid(t *testing.T) {
	if _, err := parsePingAddrs("not-an-addr"); err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestParseLANSubnet_DefaultsWhenEmpty(t *testing.T) {
	gotIP, gotMask, err := parseLANSubnet("")
	if err != nil {
		t.Fatalf("parseLANSubnet returned error: %v", err)
	}

	_, parsed, err := net.ParseCIDR(defaultLANSubnetCIDR)
	if err != nil {
		t.Fatalf("ParseCIDR failed for test default: %v", err)
	}
	wantIP := binary.LittleEndian.Uint32(parsed.IP.To4())
	wantMask := binary.LittleEndian.Uint32(parsed.Mask)

	if gotIP != wantIP || gotMask != wantMask {
		t.Fatalf("unexpected subnet values: got (%#x, %#x) want (%#x, %#x)", gotIP, gotMask, wantIP, wantMask)
	}
}

func TestParseLANSubnet_InvalidIPv6CIDR(t *testing.T) {
	if _, _, err := parseLANSubnet("2001:db8::/64"); err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
}

func TestParseDurationWithDefault(t *testing.T) {
	fallback := 30 * time.Minute
	got, err := parseDurationWithDefault("", fallback)
	if err != nil {
		t.Fatalf("parseDurationWithDefault returned error: %v", err)
	}
	if got != fallback {
		t.Fatalf("expected fallback %v, got %v", fallback, got)
	}

	got, err = parseDurationWithDefault("10m", fallback)
	if err != nil {
		t.Fatalf("parseDurationWithDefault returned error: %v", err)
	}
	if got != 10*time.Minute {
		t.Fatalf("expected 10m, got %v", got)
	}

	if _, err := parseDurationWithDefault("not-a-duration", fallback); err == nil {
		t.Fatal("expected parse error for invalid duration")
	}
}
