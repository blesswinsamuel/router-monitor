package lanpilot

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

// WakeOnLanResult holds the result of a Wake-on-LAN dispatch.
type WakeOnLanResult struct {
	MAC           string
	BroadcastAddr string
	Interface     string
	BytesSent     int
}

// BuildMagicPacket constructs a 102-byte AMD Magic Packet payload for the specified MAC address,
// with an optional 4- or 6-byte SecureOn password.
func BuildMagicPacket(mac net.HardwareAddr, password []byte) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("invalid MAC address length: expected 6 bytes, got %d", len(mac))
	}

	// Reject all-zero MAC
	isAllZero := true
	for _, b := range mac {
		if b != 0 {
			isAllZero = false
			break
		}
	}
	if isAllZero {
		return nil, errors.New("all-zero MAC address is invalid for Wake-on-LAN")
	}

	// 6 bytes of 0xFF followed by 16 repetitions of the 6-byte MAC address
	pktLen := 6 + (16 * 6) + len(password)
	pkt := make([]byte, 0, pktLen)

	// Sync stream: 6 bytes of 0xFF
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xFF)
	}

	// Target MAC repeated 16 times
	for i := 0; i < 16; i++ {
		pkt = append(pkt, mac...)
	}

	// Optional SecureOn password
	if len(password) > 0 {
		if len(password) != 4 && len(password) != 6 {
			return nil, fmt.Errorf("SecureOn password must be either 4 or 6 bytes, got %d bytes", len(password))
		}
		pkt = append(pkt, password...)
	}

	return pkt, nil
}

// CalculateBroadcastIP computes the directed broadcast address for a given IPNet.
func CalculateBroadcastIP(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	if ip == nil || len(ipNet.Mask) != 4 {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^ipNet.Mask[i]
	}
	return bcast
}

// parseSecureOnPassword attempts to parse a hex-encoded SecureOn password.
func parseSecureOnPassword(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	// Strip common delimiters
	clean := strings.ReplaceAll(trimmed, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	data, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid SecureOn password hex: %w", err)
	}
	if len(data) != 4 && len(data) != 6 {
		return nil, fmt.Errorf("SecureOn password must be 4 or 6 bytes (got %d)", len(data))
	}
	return data, nil
}

// FindInterfaceBroadcast finds the broadcast IPv4 address for a named network interface.
func FindInterfaceBroadcast(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				bcast := CalculateBroadcastIP(ipNet)
				if bcast != nil {
					return bcast, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 broadcast address found for interface %q", ifaceName)
}

// ResolveBroadcastTarget determines the destination broadcast IP and interface for a WoL packet.
func ResolveBroadcastTarget(ifaceName, targetIPStr, fallbackSubnetCIDR string) (net.IP, string) {
	// 1. If explicit interface name given, check it
	if ifaceName != "" {
		if bcast, err := FindInterfaceBroadcast(ifaceName); err == nil {
			return bcast, ifaceName
		}
	}

	// 2. If target IP given, try finding the interface whose subnet contains it
	if targetIPStr != "" {
		targetIP := net.ParseIP(strings.TrimSpace(targetIPStr)).To4()
		if targetIP != nil {
			ifaces, err := net.Interfaces()
			if err == nil {
				for _, ifc := range ifaces {
					addrs, err := ifc.Addrs()
					if err != nil {
						continue
					}
					for _, addr := range addrs {
						if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
							if ipNet.Contains(targetIP) {
								bcast := CalculateBroadcastIP(ipNet)
								if bcast != nil {
									return bcast, ifc.Name
								}
							}
						}
					}
				}
			}
		}
	}

	// 3. Fallback to configured LAN subnet CIDR
	if fallbackSubnetCIDR != "" {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(fallbackSubnetCIDR))
		if err == nil && ipNet != nil {
			bcast := CalculateBroadcastIP(ipNet)
			if bcast != nil {
				return bcast, ifaceName
			}
		}
	}

	// 4. Default limited broadcast
	return net.IPv4bcast, ifaceName
}

// SendWakeOnLan generates and transmits a Wake-on-LAN magic packet.
func SendWakeOnLan(
	macStr string,
	targetIPStr string,
	ifaceName string,
	port int,
	passwordStr string,
	fallbackSubnetCIDR string,
) (*WakeOnLanResult, error) {
	hwAddr, err := net.ParseMAC(strings.TrimSpace(macStr))
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", macStr, err)
	}

	pwd, err := parseSecureOnPassword(passwordStr)
	if err != nil {
		return nil, err
	}

	packet, err := BuildMagicPacket(hwAddr, pwd)
	if err != nil {
		return nil, err
	}

	if port <= 0 || port > 65535 {
		port = 9
	}

	bcastIP, resolvedIface := ResolveBroadcastTarget(ifaceName, targetIPStr, fallbackSubnetCIDR)
	dstAddr := &net.UDPAddr{
		IP:   bcastIP,
		Port: port,
	}

	conn, err := net.DialUDP("udp4", nil, dstAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP broadcast socket: %w", err)
	}
	defer conn.Close()

	n, err := conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send magic packet to %s: %w", dstAddr.String(), err)
	}

	// Also send to limited broadcast (255.255.255.255) if directed broadcast was different,
	// ensuring coverage across unrouted local segments.
	if !bcastIP.Equal(net.IPv4bcast) {
		limitedDst := &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: port,
		}
		if lConn, lErr := net.DialUDP("udp4", nil, limitedDst); lErr == nil {
			_, _ = lConn.Write(packet)
			_ = lConn.Close()
		}
	}

	return &WakeOnLanResult{
		MAC:           hwAddr.String(),
		BroadcastAddr: dstAddr.String(),
		Interface:     resolvedIface,
		BytesSent:     n,
	}, nil
}
