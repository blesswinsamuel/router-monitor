package ddns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DuckDNSConfig struct {
	Token      string
	BaseURL    string // Defaults to "https://www.duckdns.org/update"
	HTTPClient *http.Client
}

type DuckDNSProvider struct {
	cfg        DuckDNSConfig
	baseURL    string
	httpClient *http.Client
}

func NewDuckDNSProvider(cfg DuckDNSConfig) (*DuckDNSProvider, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("duckdns token is required")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = "https://www.duckdns.org/update"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &DuckDNSProvider{
		cfg:        cfg,
		baseURL:    baseURL,
		httpClient: client,
	}, nil
}

func (p *DuckDNSProvider) Name() string {
	return "duckdns"
}

func (p *DuckDNSProvider) Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("no domains specified")
	}

	var subdomains []string
	for _, d := range req.Domains {
		d = strings.TrimSpace(strings.ToLower(d))
		d = strings.TrimSuffix(d, ".duckdns.org")
		d = strings.TrimSuffix(d, ".")
		if d != "" {
			subdomains = append(subdomains, d)
		}
	}
	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no valid DuckDNS subdomains extracted")
	}

	params := url.Values{}
	params.Set("domains", strings.Join(subdomains, ","))
	params.Set("token", p.cfg.Token)
	if req.IPv4 != "" {
		params.Set("ip", req.IPv4)
	}
	if req.IPv6 != "" {
		params.Set("ipv6", req.IPv6)
	}

	reqURL := fmt.Sprintf("%s?%s", p.baseURL, params.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("User-Agent", "lanpilot-ddns/1.0")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("duckdns request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return nil, fmt.Errorf("read duckdns response: %w", err)
	}

	respStr := strings.TrimSpace(string(body))
	if respStr != "OK" {
		return nil, fmt.Errorf("duckdns returned error: %q", respStr)
	}

	return &UpdateResult{
		UpdatedRecords: len(subdomains),
		Message:        fmt.Sprintf("DuckDNS updated for %s", strings.Join(subdomains, ",")),
		Success:        true,
	}, nil
}
