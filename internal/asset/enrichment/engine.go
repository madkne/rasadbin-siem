package enrichment

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"rasadbin/internal/asset"
)

type Inventory interface {
	Get(string) (asset.Asset, bool)
	Snapshot() []asset.Asset
	MarkEnriching(string) (asset.Asset, bool)
	CompleteEnrichment(string, asset.EnrichmentResult, string, string, int, time.Time) bool
}

type Config struct {
	Workers       int
	QueueSize     int
	RetryBase     time.Duration
	RetryMax      time.Duration
	ActiveAllowed ActivePolicy
}

type Engine struct {
	inventory Inventory
	providers []Provider
	cfg       Config
	queue     chan string
	mu        sync.Mutex
	queued    map[string]struct{}
}

func New(inventory Inventory, providers []Provider, cfg Config) (*Engine, error) {
	if inventory == nil {
		return nil, errors.New("enrichment inventory is required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.Workers > 16 {
		cfg.Workers = 16
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 512
	}
	if cfg.RetryBase <= 0 {
		cfg.RetryBase = 30 * time.Second
	}
	if cfg.RetryMax <= 0 {
		cfg.RetryMax = 30 * time.Minute
	}
	return &Engine{inventory: inventory, providers: append([]Provider{}, providers...), cfg: cfg,
		queue: make(chan string, cfg.QueueSize), queued: make(map[string]struct{})}, nil
}

// Enqueue is non-blocking and deduplicates work by stable asset ID. A full
// queue leaves the asset pending; the periodic scheduler will retry it.
func (e *Engine) Enqueue(id string) bool {
	if e == nil || id == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.queued[id]; ok {
		return true
	}
	select {
	case e.queue <- id:
		e.queued[id] = struct{}{}
		return true
	default:
		return false
	}
}

func (e *Engine) EnqueuePending() {
	if e == nil {
		return
	}
	now := time.Now()
	for _, a := range e.inventory.Snapshot() {
		if a.EnrichmentStatus == "" || a.EnrichmentStatus == "pending" || a.EnrichmentStatus == "enriching" ||
			((a.EnrichmentStatus == "partial" || a.EnrichmentStatus == "failed") &&
				(a.NextEnrichmentAt.IsZero() || !a.NextEnrichmentAt.After(now))) {
			e.Enqueue(a.ID)
		}
	}
}

// Run starts a bounded worker pool and a retry scheduler. Cancellation stops
// workers promptly; providers are required to honor context deadlines.
func (e *Engine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.worker(ctx) }()
	}
	e.EnqueuePending()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
			e.EnqueuePending()
		}
	}
}

func (e *Engine) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-e.queue:
			e.mu.Lock()
			delete(e.queued, id)
			e.mu.Unlock()
			e.process(ctx, id)
		}
	}
}

func (e *Engine) process(parent context.Context, id string) {
	a, ok := e.inventory.MarkEnriching(id)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	combined := asset.EnrichmentResult{}
	var failures []string
	for _, p := range e.providers {
		if p == nil {
			continue
		}
		if p.Active() && (e.cfg.ActiveAllowed == nil || !e.cfg.ActiveAllowed(a)) {
			continue
		}
		result, err := p.Enrich(ctx, a)
		if err != nil {
			failures = append(failures, p.Name()+": "+err.Error())
			continue
		}
		mergeResult(&combined, result)
	}
	attempts := a.EnrichmentAttempts + 1
	status := "enriched"
	message := ""
	var next time.Time
	if len(failures) > 0 {
		status = "partial"
		message = joinErrors(failures)
		next = time.Now().Add(e.retryDelay(attempts))
	}
	if ctx.Err() != nil && parent.Err() == nil {
		status = "failed"
		message = ctx.Err().Error()
		next = time.Now().Add(e.retryDelay(attempts))
	}
	if !e.inventory.CompleteEnrichment(id, combined, status, message, attempts, next) {
		slog.Debug("asset disappeared during enrichment", "asset_id", id)
	}
}

func (e *Engine) retryDelay(attempt int) time.Duration {
	d := e.cfg.RetryBase
	for i := 1; i < attempt && d < e.cfg.RetryMax; i++ {
		d *= 2
		if d > e.cfg.RetryMax {
			d = e.cfg.RetryMax
		}
	}
	return d
}
func mergeResult(dst *asset.EnrichmentResult, src asset.EnrichmentResult) {
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	dst.MACAddresses = append(dst.MACAddresses, src.MACAddresses...)
	dst.Services = append(dst.Services, src.Services...)
	dst.Protocols = append(dst.Protocols, src.Protocols...)
	dst.Evidence = append(dst.Evidence, src.Evidence...)
}
func joinErrors(items []string) string {
	out := ""
	for _, s := range items {
		if out != "" {
			out += "; "
		}
		out += s
		if len(out) > 1024 {
			return out[:1024]
		}
	}
	return out
}
