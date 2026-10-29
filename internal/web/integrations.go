package web

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Integration describes a built-in, independently managed telemetry module.
// Collector implementation is deliberately separate from the UI/control plane.
type Integration struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Enabled     bool      `json:"enabled"`
	Collector   string    `json:"collector"`
	Processor   string    `json:"processor"`
	Detections  []string  `json:"detections"`
	Alerting    bool      `json:"alerting"`
	Status      string    `json:"status"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type IntegrationStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]Integration
}

func builtinIntegrations() []Integration {
	return []Integration{
		{ID: "network-packets", Name: "Network packets", Description: "Observe Linux interface traffic and derive packet/flow metadata.", Category: "Network", Collector: "packet capture (libpcap/AF_PACKET)", Processor: "L2-L4 protocol normalization and flow enrichment", Detections: []string{"Port-scan heuristics", "Unexpected listening-service traffic", "High-rate connection bursts"}, Alerting: true, Status: "not_configured"},
		{ID: "systemd-journal", Name: "systemd journal", Description: "Collect host and service logs from journald.", Category: "Host", Collector: "journalctl follow stream", Processor: "Journal field normalization and severity mapping", Detections: []string{"Repeated authentication failures", "Privilege escalation", "Service crash loop"}, Alerting: true, Status: "not_configured"},
		{ID: "syslog-files", Name: "Syslog files", Description: "Watch common Linux syslog/authentication files.", Category: "Host", Collector: "file tail with rotation tracking", Processor: "Syslog timestamp, facility and severity parsing", Detections: []string{"SSH brute force", "Sudo policy failures", "Repeated kernel errors"}, Alerting: true, Status: "not_configured"},
		{ID: "service-logs", Name: "Service logs", Description: "Parse logs from Nginx, SSH, Docker and configured services.", Category: "Services", Collector: "configured file/journald sources", Processor: "Service-specific parser adapters", Detections: []string{"HTTP error spikes", "Repeated upstream failures", "Container restart bursts"}, Alerting: true, Status: "not_configured"},
	}
}

func LoadIntegrationStore(dataDir string) (*IntegrationStore, error) {
	st := &IntegrationStore{path: filepath.Join(dataDir, "integrations.json"), items: map[string]Integration{}}
	for _, i := range builtinIntegrations() {
		st.items[i.ID] = i
	}
	b, err := os.ReadFile(st.path)
	if err == nil {
		var saved map[string]Integration
		if err := json.Unmarshal(b, &saved); err != nil {
			return nil, err
		}
		for id, v := range saved {
			if base, ok := st.items[id]; ok {
				base.Enabled = v.Enabled
				base.Alerting = v.Alerting
				base.UpdatedAt = v.UpdatedAt
				if v.Enabled {
					base.Status = "enabled_waiting_for_collector"
				} else {
					base.Status = "disabled"
				}
				st.items[id] = base
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return st, nil
}
func (st *IntegrationStore) List() []Integration {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]Integration, 0, len(st.items))
	for _, v := range st.items {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Category == out[j].Category && out[i].Name < out[j].Name || out[i].Category < out[j].Category
	})
	return out
}
func (st *IntegrationStore) Update(id string, enabled, alerting bool) (Integration, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.items[id]
	if !ok {
		return Integration{}, errors.New("unknown integration")
	}
	v.Enabled = enabled
	v.Alerting = alerting
	v.UpdatedAt = time.Now().UTC()
	if enabled {
		v.Status = "enabled_waiting_for_collector"
	} else {
		v.Status = "disabled"
	}
	st.items[id] = v
	b, err := json.MarshalIndent(st.items, "", "  ")
	if err != nil {
		return Integration{}, err
	}
	if err = os.MkdirAll(filepath.Dir(st.path), 0700); err != nil {
		return Integration{}, err
	}
	tmp := st.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return Integration{}, err
	}
	if err = os.Rename(tmp, st.path); err != nil {
		return Integration{}, err
	}
	return v, nil
}
func (st *IntegrationStore) Get(id string) (Integration, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	v, ok := st.items[id]
	return v, ok
}

// ProcessEvent is the integration-specific processing seam. Source IDs are
// stable so collector adapters can be added without coupling them to WebSocket.
func (st *IntegrationStore) ProcessEvent(e Event) (Event, bool) {
	id := strings.ToLower(strings.TrimSpace(e.Source))
	switch {
	case strings.Contains(id, "network") || strings.Contains(id, "packet"):
		id = "network-packets"
	case strings.Contains(id, "journal") || strings.Contains(id, "systemd"):
		id = "systemd-journal"
	case strings.Contains(id, "syslog") || strings.Contains(id, "auth.log"):
		id = "syslog-files"
	case strings.Contains(id, "nginx") || strings.Contains(id, "docker") || strings.Contains(id, "service"):
		id = "service-logs"
	default:
		return e, true // preserve platform/internal events
	}
	i, ok := st.Get(id)
	if !ok || !i.Enabled {
		return Event{}, false
	}
	e.Source = id
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	return e, true
}
