package ddns

import "context"

// UpdateRequest contains information for updating DNS records.
type UpdateRequest struct {
	Domains []string
	IPv4    string
	IPv6    string
	Force   bool
}

// UpdateResult contains the result of a DNS update operation.
type UpdateResult struct {
	UpdatedRecords int
	Message        string
	Success        bool
}

// Provider represents a DNS provider capable of updating A and AAAA records.
type Provider interface {
	Name() string
	Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error)
}
