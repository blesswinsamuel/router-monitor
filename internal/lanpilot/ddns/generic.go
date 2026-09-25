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

type GenericConfig struct {
	URLTemplate string // e.g. "https://user:pass@dyn.example.com/nic/update?hostname={domain}&myip={ipv4}"
	HTTPMethod  string // GET (default) or POST
	HTTPClient  *http.Client
}

type GenericProvider struct {
	cfg        GenericConfig
	httpClient *http.Client
}

func NewGenericProvider(cfg GenericConfig) (*GenericProvider, error) {
	if strings.TrimSpace(cfg.URLTemplate) == "" {
		return nil, fmt.Errorf("generic DDNS URL template is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.HTTPMethod))
	if method == "" {
		method = http.MethodGet
	}
	cfg.HTTPMethod = method

	return &GenericProvider{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

func (p *GenericProvider) Name() string {
	return "generic_http"
}

func (p *GenericProvider) Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("no domains specified")
	}

	totalUpdated := 0
	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		u := p.cfg.URLTemplate
		u = strings.ReplaceAll(u, "{domain}", url.QueryEscape(domain))
		u = strings.ReplaceAll(u, "{ipv4}", url.QueryEscape(req.IPv4))
		u = strings.ReplaceAll(u, "{ipv6}", url.QueryEscape(req.IPv6))
		ip := req.IPv4
		if ip == "" {
			ip = req.IPv6
		}
		u = strings.ReplaceAll(u, "{ip}", url.QueryEscape(ip))

		httpReq, err := http.NewRequestWithContext(ctx, p.cfg.HTTPMethod, u, nil)
		if err != nil {
			return nil, fmt.Errorf("create request for %s: %w", domain, err)
		}
		httpReq.Header.Set("User-Agent", "lanpilot-ddns/1.0")

		resp, err := p.httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("http request failed for %s: %w", domain, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("request for %s failed with status %d: %s", domain, resp.StatusCode, string(body))
		}
		totalUpdated++
	}

	return &UpdateResult{
		UpdatedRecords: totalUpdated,
		Message:        fmt.Sprintf("Generic HTTP update succeeded for %d domains", totalUpdated),
		Success:        true,
	}, nil
}
