package ddns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPPair holds detected IPv4 and IPv6 addresses.
type IPPair struct {
	IPv4 string
	IPv6 string
}

// IPDetector detects WAN IP addresses.
type IPDetector interface {
	DetectIPs(ctx context.Context, checkIPv4, checkIPv6 bool) (IPPair, error)
}

// Default external endpoints for WAN IP discovery
var (
	DefaultIPv4Endpoints = []string{
		"https://1.1.1.1/cdn-cgi/trace",
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	DefaultIPv6Endpoints = []string{
		"https://[2606:4700:4700::1111]/cdn-cgi/trace",
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
	}
)

// DetectorConfig defines options for IP detection.
type DetectorConfig struct {
	Source        string // "external" or "interface:<iface>"
	IPv4Endpoints []string
	IPv6Endpoints []string
	HTTPClient    *http.Client
}

// StandardDetector implements IPDetector.
type StandardDetector struct {
	cfg        DetectorConfig
	httpClient *http.Client
}

// NewDetector creates a new StandardDetector.
func NewDetector(cfg DetectorConfig) *StandardDetector {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	if len(cfg.IPv4Endpoints) == 0 {
		cfg.IPv4Endpoints = DefaultIPv4Endpoints
	}
	if len(cfg.IPv6Endpoints) == 0 {
		cfg.IPv6Endpoints = DefaultIPv6Endpoints
	}
	return &StandardDetector{
		cfg:        cfg,
		httpClient: client,
	}
}

// DetectIPs queries either the network interface or external discovery endpoints.
func (d *StandardDetector) DetectIPs(ctx context.Context, checkIPv4, checkIPv6 bool) (IPPair, error) {
	if strings.HasPrefix(d.cfg.Source, "interface:") {
		ifaceName := strings.TrimPrefix(d.cfg.Source, "interface:")
		return d.detectFromInterface(ifaceName, checkIPv4, checkIPv6)
	}

	var pair IPPair
	var errs []string

	if checkIPv4 {
		ip4, err := d.fetchIPFromEndpoints(ctx, d.cfg.IPv4Endpoints, false)
		if err != nil {
			errs = append(errs, fmt.Sprintf("ipv4 detection: %v", err))
		} else {
			pair.IPv4 = ip4
		}
	}

	if checkIPv6 {
		ip6, err := d.fetchIPFromEndpoints(ctx, d.cfg.IPv6Endpoints, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("ipv6 detection: %v", err))
		} else {
			pair.IPv6 = ip6
		}
	}

	if (checkIPv4 && pair.IPv4 == "") && (checkIPv6 && pair.IPv6 == "") {
		return pair, fmt.Errorf("failed to detect WAN IP: %s", strings.Join(errs, "; "))
	}

	return pair, nil
}

func (d *StandardDetector) fetchIPFromEndpoints(ctx context.Context, endpoints []string, wantIPv6 bool) (string, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		ip, err := d.fetchIPFromURL(ctx, endpoint, wantIPv6)
		if err == nil && ip != "" {
			return ip, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no endpoints returned a valid IP")
}

func (d *StandardDetector) fetchIPFromURL(ctx context.Context, url string, wantIPv6 bool) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "router-monitor-ddns/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status code %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}

	ipStr := parseIPFromBody(string(body))
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP %q from %s", ipStr, url)
	}

	isIPv4 := parsed.To4() != nil
	if wantIPv6 && isIPv4 {
		return "", fmt.Errorf("expected IPv6, got IPv4 %s", ipStr)
	}
	if !wantIPv6 && !isIPv4 {
		return "", fmt.Errorf("expected IPv4, got IPv6 %s", ipStr)
	}

	return parsed.String(), nil
}

// parseIPFromBody extracts the IP address whether raw string or Cloudflare trace format (ip=x.x.x.x).
func parseIPFromBody(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}
	return strings.TrimSpace(body)
}

func (d *StandardDetector) detectFromInterface(ifaceName string, checkIPv4, checkIPv6 bool) (IPPair, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return IPPair{}, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return IPPair{}, fmt.Errorf("get interface %q addrs: %w", ifaceName, err)
	}

	var pair IPPair
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}

		if ip4 := ipNet.IP.To4(); ip4 != nil {
			if checkIPv4 && pair.IPv4 == "" {
				pair.IPv4 = ip4.String()
			}
		} else if checkIPv6 && pair.IPv6 == "" {
			// Globally routable IPv6: not link-local (fe80::/10), not unique-local (fc00::/7)
			if isGlobalUnicastIPv6(ipNet.IP) {
				pair.IPv6 = ipNet.IP.String()
			}
		}
	}

	if checkIPv4 && pair.IPv4 == "" {
		return pair, fmt.Errorf("no IPv4 address found on interface %q", ifaceName)
	}
	return pair, nil
}

func isGlobalUnicastIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	// Check if global unicast (2000::/3)
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}
