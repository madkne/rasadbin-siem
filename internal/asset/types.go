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
	ID          string    `json:"id"`
	Origin      string    `json:"origin"`
	Name        string    `json:"name"`
	Hostname    string    `json:"hostname,omitempty"`
	IPs         []string  `json:"ips"`
	Ports       []int     `json:"ports"` // TCP services observed accepting connections
	Sources     []string  `json:"sources"`
	Tags        []string  `json:"tags"`
	Criticality string    `json:"criticality,omitempty"` // "", low, medium, high, critical
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	EventCount  int64     `json:"event_count"`
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