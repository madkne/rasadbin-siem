// Package asset maintains the inventory of hosts Rasadbin knows about.
//
// Assets are discovered passively from collected events (network packets and
// syslog today) and can later also be created by hand: both paths feed the same
// Service and share the same deterministic asset IDs, so a manually added host
// is enriched by discovery instead of being duplicated.
package asset

import (
	"context"
	"time"
)

const (
	OriginDiscovered = "discovered"
	OriginManual     = "manual"

	SourceNetwork = "network-packets"
	SourceSyslog  = "syslog-files"
	SourceManual  = "manual"
)

// Asset is one host-like entity. ID is "ip:<addr>" or "host:<name>".
//
// Discovery owns IPs, Ports, Sources, timestamps and EventCount.
// Analysts own Name, Tags and Criticality (set by AddManual; discovery never
// overwrites them).
type Asset struct {
	ID                 string               `json:"id"`
	Origin             string               `json:"origin"`
	Name               string               `json:"name"`
	Hostname           string               `json:"hostname,omitempty"`
	IPs                []string             `json:"ips"`
	Ports              []int                `json:"ports"` // TCP source ports observed in SYN-ACK packets
	Sources            []string             `json:"sources"`
	Tags               []string             `json:"tags"`
	Criticality        string               `json:"criticality,omitempty"` // "", low, medium, high, critical
	MACAddresses       []string             `json:"mac_addresses"`
	Services           []ServiceInfo        `json:"services"`
	Protocols          []string             `json:"protocols"`
	DeviceType         string               `json:"device_type,omitempty"`
	DeviceRole         string               `json:"device_role,omitempty"`
	Manufacturer       string               `json:"manufacturer,omitempty"`
	Model              string               `json:"model,omitempty"`
	OperatingSystem    string               `json:"operating_system,omitempty"`
	OSVersion          string               `json:"os_version,omitempty"`
	EnrichmentStatus   string               `json:"enrichment_status"` // pending | enriching | partial | enriched | failed
	EnrichmentAttempts int                  `json:"enrichment_attempts"`
	EnrichmentError    string               `json:"enrichment_error,omitempty"`
	LastEnrichedAt     time.Time            `json:"last_enriched_at,omitempty"`
	NextEnrichmentAt   time.Time            `json:"next_enrichment_at,omitempty"`
	EnrichmentEvidence []EnrichmentEvidence `json:"enrichment_evidence"`
	FirstSeen          time.Time            `json:"first_seen"`
	LastSeen           time.Time            `json:"last_seen"`
	Archived           bool                 `json:"archived,omitempty"`
	EventCount         int64                `json:"event_count"`
}

// ServiceInfo is a passive service fingerprint. Confidence describes the
// strength of observed evidence; a port-only match is deliberately low.
type ServiceInfo struct {
	Port       int       `json:"port"`
	Transport  string    `json:"transport"`
	Name       string    `json:"name"`
	Protocol   string    `json:"protocol,omitempty"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
}

// EnrichmentEvidence records provenance for an enrichment decision.
type EnrichmentEvidence struct {
	Field      string    `json:"field"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence"`
	ObservedAt time.Time `json:"observed_at"`
}

// EnrichmentResult is the mergeable output of one passive provider.
type EnrichmentResult struct {
	Hostname     string
	MACAddresses []string
	Services     []ServiceInfo
	Protocols    []string
	Evidence     []EnrichmentEvidence
}

// Filter narrows List results. All fields are optional.
type Filter struct {
	Search string `json:"search"`
	Source string `json:"source"`
	Origin string `json:"origin"`
	Limit  int    `json:"limit"`
}

// Store is the durability boundary, implemented by internal/storage.
type Store interface {
	LoadAssets(ctx context.Context) ([]Asset, error)
	SaveAssets(ctx context.Context, items []Asset) error
}