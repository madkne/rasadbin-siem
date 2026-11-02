package asset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxIPsPerAsset = 16
	defaultList    = 500
	maxList        = 2000
)

// Options tunes the Service. Zero values select safe defaults.
type Options struct {
	IncludePublic bool          // also track public IPs (default: private ranges only)
	MaxAssets     int           // inventory cap, default 10000
	MaxPorts      int           // per-asset open-port cap, default 64
	FlushInterval time.Duration // persistence/notification batching, default 5s
	MaxLinks      int           // live topology links kept in memory, default 5000
	LinkTTL       time.Duration // idle links expire after this, default 1h
	LinkInterval  time.Duration // topology push batching, default 2s
}

// Service is the in-memory inventory with batched persistence. Observing an
// event is a short mutex-protected map update; the database is only touched by
// Flush, so packet-rate traffic cannot stall collectors.
type Service struct {
	opts     Options
	onChange func([]Asset)

	mu      sync.RWMutex
	assets  map[string]*Asset
	dirty   map[string]struct{}
	store   Store
	dropped uint64

	// Live topology (memory only, see topology.go).
	links        map[string]*Link
	dirtyLinks   map[string]struct{}
	removedLinks map[string]struct{}
	onLinks      func(changed []Link, removed []string)
	lastPrune    time.Time
	droppedLinks uint64
}

// NewService creates a Service. onChange (optional) receives each flushed batch
// of new/updated assets, e.g. to push them to connected UI clients.
func NewService(opts Options, onChange func([]Asset)) *Service {
	if opts.MaxAssets <= 0 {
		opts.MaxAssets = 10000
	}
	if opts.MaxPorts <= 0 {
		opts.MaxPorts = 64
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 5 * time.Second
	}
	if opts.MaxLinks <= 0 {
		opts.MaxLinks = 5000
	}
	if opts.LinkTTL <= 0 {
		opts.LinkTTL = time.Hour
	}
	if opts.LinkInterval <= 0 {
		opts.LinkInterval = 2 * time.Second
	}
	return &Service{
		opts: opts, onChange: onChange,
		assets: map[string]*Asset{}, dirty: map[string]struct{}{},
		links: map[string]*Link{}, dirtyLinks: map[string]struct{}{}, removedLinks: map[string]struct{}{},
	}
}

// Attach loads persisted assets and enables persistence. Call it before
// collectors start so discovery merges into the stored inventory.
func (s *Service) Attach(ctx context.Context, store Store) error {
	if s == nil || store == nil {
		return nil
	}
	items, err := store.LoadAssets(ctx)
	if err != nil {
		return fmt.Errorf("load assets: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
	for _, a := range items {
		if a.ID == "" {
			continue
		}
		if _, exists := s.assets[a.ID]; !exists {
			c := clone(a)
			s.assets[a.ID] = &c
		}
	}
	return nil
}

// Run flushes dirty assets periodically until ctx is cancelled. Call Flush once
// more during shutdown (before closing the store) to persist the tail.
func (s *Service) Run(ctx context.Context) {
	if s == nil {
		return
	}
	assets := time.NewTicker(s.opts.FlushInterval)
	links := time.NewTicker(s.opts.LinkInterval)
	defer assets.Stop()
	defer links.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-assets.C:
			if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
				slog.Error("asset flush failed", "error", err)
			}
		case <-links.C:
			s.FlushLinks()
		}
	}
}

// ObserveEvent derives assets from one collected event. Unknown sources and
// unparseable messages are ignored. Port fingerprints are only recorded from
// SYN-ACK packets; a bare SYN is not evidence that a service is listening.
func (s *Service) ObserveEvent(source, message string, at time.Time) {
	if s == nil {
		return
	}
	obs := extract(source, message, s.opts.IncludePublic)
	var fl flow
	hasFlow := false
	if source == SourceNetwork {
		fl, hasFlow = extractFlow(message, s.opts.IncludePublic)
	}
	if len(obs) == 0 && !hasFlow {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range obs {
		s.apply(source, o, at)
	}
	if hasFlow {
		s.recordLink(fl, at)
	}
}

func (s *Service) apply(source string, o observation, at time.Time) {
	var id, name string
	switch {
	case o.ip != "":
		id, name = "ip:"+o.ip, o.ip
	case o.hostname != "":
		id, name = "host:"+o.hostname, o.hostname
	default:
		return
	}
	a := s.assets[id]
	if a == nil {
		if len(s.assets) >= s.opts.MaxAssets {
			s.dropped++
			return
		}
		a = &Asset{ID: id, Origin: OriginDiscovered, Name: name, FirstSeen: at, LastSeen: at,
			EnrichmentStatus: "pending"}
		s.assets[id] = a
	}
	if at.After(a.LastSeen) {
		a.LastSeen = at
	}
	if at.Before(a.FirstSeen) {
		a.FirstSeen = at
	}
	a.EventCount++
	a.Sources = addUnique(a.Sources, source, 8)
	if o.ip != "" {
		a.IPs = addUnique(a.IPs, o.ip, maxIPsPerAsset)
	}
	if o.mac != "" {
		before := len(a.MACAddresses)
		a.MACAddresses = addUnique(a.MACAddresses, o.mac, 8)
		if len(a.MACAddresses) != before {
			a.EnrichmentStatus = "pending"
		}
	}
	if o.hostname != "" && a.Hostname == "" {
		a.Hostname = o.hostname
	}
	if o.port > 0 {
		before := len(a.Ports)
		a.Ports = addPort(a.Ports, o.port, s.opts.MaxPorts)
		if len(a.Ports) != before {
			a.EnrichmentStatus = "pending"
		}
	}
	s.dirty[id] = struct{}{}
}

// AddManual creates or updates an asset by hand. It is the extension point for
// the future "add asset" UI/WebSocket message. The ID derives from the first IP
// (or the hostname), identical to discovery, so later observations of the same
// host enrich this record while Name, Tags and Criticality stay as entered.
func (s *Service) AddManual(in Asset) (Asset, error) {
	if s == nil {
		return Asset{}, errors.New("asset service unavailable")
	}
	var ips []string
	for _, raw := range in.IPs {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return Asset{}, fmt.Errorf("invalid IP address %q", raw)
	}
	a = a.Unmap()
	if a.Is4() && a.As4()[3] == 255 {
		return Asset{}, fmt.Errorf("broadcast address %q is not an asset", raw)
	}
		ips = addUnique(ips, a.Unmap().String(), maxIPsPerAsset)
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Hostname), "."))
	if host != "" && !hostRe.MatchString(host) {
		return Asset{}, fmt.Errorf("invalid hostname %q", in.Hostname)
	}
	var id, fallback string
	switch {
	case len(ips) > 0:
		id, fallback = "ip:"+ips[0], ips[0]
	case host != "":
		id, fallback = "host:"+host, host
	default:
		return Asset{}, errors.New("an IP address or hostname is required")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = fallback
	}
	if len(name) > 128 {
		return Asset{}, errors.New("name is too long (maximum 128 characters)")
	}
	crit := strings.ToLower(strings.TrimSpace(in.Criticality))
	switch crit {
	case "", "low", "medium", "high", "critical":
	default:
		return Asset{}, fmt.Errorf("invalid criticality %q", in.Criticality)
	}
	var tags []string
	for _, t := range in.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > 64 {
			return Asset{}, errors.New("tag is too long (maximum 64 characters)")
		}
		tags = addUnique(tags, t, 16)
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.assets[id]
	if a == nil {
		if len(s.assets) >= s.opts.MaxAssets {
			return Asset{}, errors.New("asset inventory is full")
		}
		a = &Asset{ID: id, FirstSeen: now, LastSeen: now}
		s.assets[id] = a
	}
	a.DeviceType = strings.TrimSpace(in.DeviceType)
	a.DeviceRole = strings.TrimSpace(in.DeviceRole)
	a.Manufacturer = strings.TrimSpace(in.Manufacturer)
	a.Model = strings.TrimSpace(in.Model)
	a.OperatingSystem = strings.TrimSpace(in.OperatingSystem)
	a.OSVersion = strings.TrimSpace(in.OSVersion)
	a.Origin, a.Name, a.Criticality, a.Tags = OriginManual, name, crit, tags

	if host != "" {
		a.Hostname = host
	}
	for _, ip := range ips {
		a.IPs = addUnique(a.IPs, ip, maxIPsPerAsset)
	}
	a.Sources = addUnique(a.Sources, SourceManual, 8)
	s.dirty[id] = struct{}{}
	return clone(*a), nil
}

// Get returns a detached asset snapshot.
func (s *Service) Get(id string) (Asset, bool) {
	if s == nil {
		return Asset{}, false
	}
	s.mu.RLock()
	a := s.assets[id]
	if a == nil {
		s.mu.RUnlock()
		return Asset{}, false
	}
	out := clone(*a)
	s.mu.RUnlock()
	return out, true
}

// Snapshot returns detached inventory snapshots for background schedulers.
func (s *Service) Snapshot() []Asset {
	if s == nil {
		return []Asset{}
	}
	s.mu.RLock()
	out := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, clone(*a))
	}
	s.mu.RUnlock()
	return out
}

// MarkEnriching updates only enrichment-owned metadata.
func (s *Service) MarkEnriching(id string) (Asset, bool) {
	if s == nil {
		return Asset{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.assets[id]
	if a == nil {
		return Asset{}, false
	}
	a.EnrichmentStatus = "enriching"
	a.EnrichmentError = ""
	s.dirty[id] = struct{}{}
	return clone(*a), true
}

// CompleteEnrichment merges evidence without overwriting analyst-managed
// Name, Tags or Criticality. Existing non-empty identity fields are preserved.
func (s *Service) CompleteEnrichment(id string, result EnrichmentResult, status, message string, attempts int, next time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.assets[id]
	if a == nil {
		return false
	}
	if a.Hostname == "" && result.Hostname != "" {
		a.Hostname = result.Hostname
	}
	for _, mac := range result.MACAddresses {
		a.MACAddresses = addUnique(a.MACAddresses, mac, 8)
	}
	for _, proto := range result.Protocols {
		a.Protocols = addUnique(a.Protocols, proto, 32)
	}
	for _, svc := range result.Services {
		found := false
		for i := range a.Services {
			if a.Services[i].Port == svc.Port && a.Services[i].Transport == svc.Transport && a.Services[i].Name == svc.Name {
				if svc.Confidence > a.Services[i].Confidence {
					a.Services[i] = svc
				}
				found = true
				break
			}
		}
		if !found && len(a.Services) < 128 {
			a.Services = append(a.Services, svc)
		}
	}
	for _, ev := range result.Evidence {
		duplicate := false
		for _, old := range a.EnrichmentEvidence {
			if old.Field == ev.Field && old.Value == ev.Value && old.Source == ev.Source {
				duplicate = true
				break
			}
		}
		if !duplicate && len(a.EnrichmentEvidence) < 256 {
			a.EnrichmentEvidence = append(a.EnrichmentEvidence, ev)
		}
	}
	a.EnrichmentStatus, a.EnrichmentError = status, message
	a.EnrichmentAttempts, a.NextEnrichmentAt = attempts, next.UTC()
	if status == "enriched" || status == "partial" {
		a.LastEnrichedAt = time.Now().UTC()
	}
	s.dirty[id] = struct{}{}
	return true
}

// List returns matching assets, most recently seen first, and the number of
// matches before Limit was applied.
func (s *Service) List(f Filter) ([]Asset, int) {
	if s == nil {
		return []Asset{}, 0
	}
	q := strings.ToLower(strings.TrimSpace(f.Search))
	s.mu.RLock()
	out := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		if f.Origin != "" && a.Origin != f.Origin {
			continue
		}
		if f.Archived {
			if !a.Archived {
				continue
			}
		} else {
			if a.Archived {
				continue
			}
		}
		if f.Source != "" && !contains(a.Sources, f.Source) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(a.Name + " " + a.Hostname + " " + strings.Join(a.IPs, " ") + " " + strings.Join(a.Tags, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, clone(*a))
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	limit := f.Limit
	if limit <= 0 {
		limit = defaultList
	}
	if limit > maxList {
		limit = maxList
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

// Dropped reports observations discarded because the inventory was full.
func (s *Service) Dropped() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropped
}

// Flush persists dirty assets, then notifies onChange. On a store error the
// assets stay dirty and are retried on the next flush.
func (s *Service) Flush(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if len(s.dirty) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := make([]Asset, 0, len(s.dirty))
	for id := range s.dirty {
		if a := s.assets[id]; a != nil {
			batch = append(batch, clone(*a))
		}
	}
	s.dirty = map[string]struct{}{}
	store := s.store
	s.mu.Unlock()

	if store != nil {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := store.SaveAssets(wctx, batch)
		cancel()
		if err != nil {
			s.mu.Lock()
			for _, a := range batch {
				s.dirty[a.ID] = struct{}{}
			}
			s.mu.Unlock()
			return fmt.Errorf("save assets: %w", err)
		}
	}
	if s.onChange != nil {
		s.onChange(batch)
	}
	return nil
}

// ArchiveDuplicates marks all but the most recently seen asset as archived when
// multiple assets share an IP or hostname. Returns the number archived.
func (s *Service) ArchiveDuplicates() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// group by shared key
	groups := map[string][]string{}
	for id, a := range s.assets {
		if a.Archived {
			continue
		}
		keys := []string{}
		for _, ip := range a.IPs {
			keys = append(keys, "ip:"+ip)
		}
		if a.Hostname != "" {
			keys = append(keys, "host:"+a.Hostname)
		}
		for _, k := range keys {
			groups[k] = append(groups[k], id)
		}
	}
	toArchive := map[string]bool{}
	for _, ids := range groups {
		if len(ids) < 2 {
			continue
		}
		// keep most recently seen
		keep := ids[0]
		for _, id := range ids[1:] {
			if s.assets[id].LastSeen.After(s.assets[keep].LastSeen) {
				keep = id
			}
		}
		for _, id := range ids {
			if id != keep {
				toArchive[id] = true
			}
		}
	}
	n := 0
	for id := range toArchive {
		if a := s.assets[id]; a != nil && !a.Archived {
			a.Archived = true
			s.dirty[id] = struct{}{}
			n++
		}
	}
	return n
}

func (s *Service) UpdateMetadata(id string, in Asset) (Asset, error) {
	if s == nil {
		return Asset{}, errors.New("asset service unavailable")
	}

	id = strings.TrimSpace(id)
	if id == "" {
		return Asset{}, errors.New("asset ID is required")
	}

	name := strings.TrimSpace(in.Name)
	hostname := strings.ToLower(
		strings.TrimSuffix(strings.TrimSpace(in.Hostname), "."),
	)

	if len(name) > 128 {
		return Asset{}, errors.New("name is too long")
	}
	if hostname != "" && !hostRe.MatchString(hostname) {
		return Asset{}, errors.New("invalid hostname")
	}

	criticality := strings.ToLower(strings.TrimSpace(in.Criticality))
	switch criticality {
	case "", "low", "medium", "high", "critical":
	default:
		return Asset{}, errors.New("invalid criticality")
	}

	fields := map[string]string{
		"device type":      in.DeviceType,
		"device role":      in.DeviceRole,
		"manufacturer":     in.Manufacturer,
		"model":            in.Model,
		"operating system": in.OperatingSystem,
		"os version":       in.OSVersion,
	}

	for label, value := range fields {
		if len(strings.TrimSpace(value)) > 128 {
			return Asset{}, fmt.Errorf("%s is too long", label)
		}
	}

	var tags []string
	for _, tag := range in.Tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if len(tag) > 64 {
			return Asset{}, errors.New("tag is too long")
		}
		tags = addUnique(tags, tag, 16)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a := s.assets[id]
	if a == nil {
		return Asset{}, errors.New("asset not found")
	}

	if name == "" {
		name = a.Name
	}

	a.Name = name
	a.Hostname = hostname
	a.Criticality = criticality
	a.Tags = tags

	a.DeviceType = strings.TrimSpace(in.DeviceType)
	a.DeviceRole = strings.TrimSpace(in.DeviceRole)
	a.Manufacturer = strings.TrimSpace(in.Manufacturer)
	a.Model = strings.TrimSpace(in.Model)
	a.OperatingSystem = strings.TrimSpace(in.OperatingSystem)
	a.OSVersion = strings.TrimSpace(in.OSVersion)

	s.dirty[id] = struct{}{}

	return clone(*a), nil
}

func clone(a Asset) Asset {
	a.IPs = append([]string{}, a.IPs...)
	a.Sources = append([]string{}, a.Sources...)
	a.Tags = append([]string{}, a.Tags...)
	a.MACAddresses = append([]string{}, a.MACAddresses...)
	a.Protocols = append([]string{}, a.Protocols...)
	a.Services = append([]ServiceInfo{}, a.Services...)
	a.EnrichmentEvidence = append([]EnrichmentEvidence{}, a.EnrichmentEvidence...)
	return a
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func addUnique(list []string, v string, max int) []string {
	if contains(list, v) || len(list) >= max {
		return list
	}
	return append(list, v)
}

func addPort(ports []int, p, max int) []int {
	for _, x := range ports {
		if x == p {
			return ports
		}
	}
	if len(ports) >= max {
		return ports
	}
	ports = append(ports, p)
	sort.Ints(ports)
	return ports
}
