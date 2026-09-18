package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudflareConfig configures the Cloudflare provider.
type CloudflareConfig struct {
	APIToken   string
	ZoneID     string
	Proxied    bool
	BaseURL    string // Defaults to "https://api.cloudflare.com/client/v4"
	HTTPClient *http.Client
}

type CloudflareProvider struct {
	cfg        CloudflareConfig
	httpClient *http.Client
	baseURL    string

	zoneMu     sync.RWMutex
	cachedZone string
}

func NewCloudflareProvider(cfg CloudflareConfig) (*CloudflareProvider, error) {
	if strings.TrimSpace(cfg.APIToken) == "" {
		return nil, fmt.Errorf("cloudflare API token is required")
	}
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &CloudflareProvider{
		cfg:        cfg,
		httpClient: client,
		baseURL:    baseURL,
		cachedZone: cfg.ZoneID,
	}, nil
}

func (p *CloudflareProvider) Name() string {
	return "cloudflare"
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfZonesResponse struct {
	Success bool     `json:"success"`
	Errors  []cfErr  `json:"errors"`
	Result  []cfZone `json:"result"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type cfRecordsResponse struct {
	Success bool       `json:"success"`
	Errors  []cfErr    `json:"errors"`
	Result  []cfRecord `json:"result"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (p *CloudflareProvider) getZoneID(ctx context.Context, domain string) (string, error) {
	p.zoneMu.RLock()
	if p.cachedZone != "" {
		zone := p.cachedZone
		p.zoneMu.RUnlock()
		return zone, nil
	}
	p.zoneMu.RUnlock()

	p.zoneMu.Lock()
	defer p.zoneMu.Unlock()
	if p.cachedZone != "" {
		return p.cachedZone, nil
	}

	reqURL := fmt.Sprintf("%s/zones?status=active", p.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	p.setHeaders(req)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch zones: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var zonesResp cfZonesResponse
	if err := json.Unmarshal(body, &zonesResp); err != nil {
		return "", fmt.Errorf("unmarshal zones response: %w", err)
	}
	if !zonesResp.Success {
		return "", fmt.Errorf("zones api returned error: %s", formatCFErrors(zonesResp.Errors))
	}

	// Match longest zone suffix
	var bestMatch cfZone
	normDomain := strings.ToLower(strings.TrimRight(domain, "."))
	for _, z := range zonesResp.Result {
		zName := strings.ToLower(strings.TrimRight(z.Name, "."))
		if normDomain == zName || strings.HasSuffix(normDomain, "."+zName) {
			if len(zName) > len(bestMatch.Name) {
				bestMatch = z
			}
		}
	}

	if bestMatch.ID == "" {
		return "", fmt.Errorf("no matching active Cloudflare zone found for domain %q", domain)
	}

	p.cachedZone = bestMatch.ID
	return bestMatch.ID, nil
}

func (p *CloudflareProvider) Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("no domains specified")
	}

	totalUpdated := 0
	var updateDetails []string

	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		zoneID, err := p.getZoneID(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("resolve zone for %s: %w", domain, err)
		}

		// Fetch existing records for this domain
		records, err := p.listRecords(ctx, zoneID, domain)
		if err != nil {
			return nil, fmt.Errorf("list dns records for %s: %w", domain, err)
		}

		// Update IPv4 (A record)
		if req.IPv4 != "" {
			updated, msg, err := p.syncRecord(ctx, zoneID, domain, "A", req.IPv4, records)
			if err != nil {
				return nil, fmt.Errorf("sync A record for %s: %w", domain, err)
			}
			if updated {
				totalUpdated++
				updateDetails = append(updateDetails, msg)
			}
		}

		// Update IPv6 (AAAA record)
		if req.IPv6 != "" {
			updated, msg, err := p.syncRecord(ctx, zoneID, domain, "AAAA", req.IPv6, records)
			if err != nil {
				return nil, fmt.Errorf("sync AAAA record for %s: %w", domain, err)
			}
			if updated {
				totalUpdated++
				updateDetails = append(updateDetails, msg)
			}
		}
	}

	msg := fmt.Sprintf("Successfully synced %d records", totalUpdated)
	if len(updateDetails) > 0 {
		msg += ": " + strings.Join(updateDetails, ", ")
	} else {
		msg += " (no changes needed)"
	}

	return &UpdateResult{
		UpdatedRecords: totalUpdated,
		Message:        msg,
		Success:        true,
	}, nil
}

func (p *CloudflareProvider) listRecords(ctx context.Context, zoneID, domain string) ([]cfRecord, error) {
	reqURL := fmt.Sprintf("%s/zones/%s/dns_records?name=%s", p.baseURL, zoneID, url.QueryEscape(domain))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var recordsResp cfRecordsResponse
	if err := json.Unmarshal(body, &recordsResp); err != nil {
		return nil, err
	}
	if !recordsResp.Success {
		return nil, fmt.Errorf("records api error: %s", formatCFErrors(recordsResp.Errors))
	}
	return recordsResp.Result, nil
}

func (p *CloudflareProvider) syncRecord(
	ctx context.Context,
	zoneID, domain, recordType, targetIP string,
	existing []cfRecord,
) (bool, string, error) {
	var found *cfRecord
	for i := range existing {
		if strings.EqualFold(existing[i].Type, recordType) && strings.EqualFold(existing[i].Name, domain) {
			found = &existing[i]
			break
		}
	}

	payload := map[string]interface{}{
		"type":    recordType,
		"name":    domain,
		"content": targetIP,
		"proxied": p.cfg.Proxied,
		"ttl":     1, // 1 = Auto
	}
	payloadBytes, _ := json.Marshal(payload)

	if found != nil {
		if strings.TrimSpace(found.Content) == strings.TrimSpace(targetIP) && found.Proxied == p.cfg.Proxied {
			return false, "", nil
		}

		// Update existing record
		reqURL := fmt.Sprintf("%s/zones/%s/dns_records/%s", p.baseURL, zoneID, found.ID)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(payloadBytes))
		if err != nil {
			return false, "", err
		}
		p.setHeaders(httpReq)

		resp, err := p.httpClient.Do(httpReq)
		if err != nil {
			return false, "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			return false, "", fmt.Errorf("update record status %d: %s", resp.StatusCode, string(b))
		}
		return true, fmt.Sprintf("%s (%s -> %s)", domain, recordType, targetIP), nil
	}

	// Create new record
	reqURL := fmt.Sprintf("%s/zones/%s/dns_records", p.baseURL, zoneID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return false, "", err
	}
	p.setHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return false, "", fmt.Errorf("create record status %d: %s", resp.StatusCode, string(b))
	}
	return true, fmt.Sprintf("created %s (%s -> %s)", domain, recordType, targetIP), nil
}

func (p *CloudflareProvider) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "router-monitor-ddns/1.0")
}

func formatCFErrors(errs []cfErr) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return strings.Join(msgs, ", ")
}
