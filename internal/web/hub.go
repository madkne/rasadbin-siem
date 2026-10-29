package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const maxRecentEvents = 50

type message struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

type errorData struct {
	For     string `json:"for,omitempty"`
	Message string `json:"message"`
}

// EventQuerier is the read side of the persistence seam. internal/storage
// implements it alongside EventStore.
type EventQuerier interface {
	Query(ctx context.Context, q SearchQuery) (SearchResult, error)
}

func encode(typ string, data any) []byte {
	b, err := json.Marshal(message{Type: typ, Data: data})
	if err != nil {
		b, _ = json.Marshal(message{Type: "error", Data: errorData{Message: "encoding failure"}})
	}
	return b
}

// Event is one entry in the dashboard's live feed.
type Event struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Severity string    `json:"severity"` // info | low | medium | high | critical
	Message  string    `json:"message"`
}

// Stats is what the dashboard shows.
type Stats struct {
	Time          time.Time `json:"time"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	Version       string    `json:"version"`
	Commit        string    `json:"commit"`
	Goroutines    int       `json:"goroutines"`
	HeapMB        float64   `json:"heap_mb"`
	SysMB         float64   `json:"sys_mb"`
	GCCycles      uint32    `json:"gc_cycles"`
	Clients       int       `json:"clients"`
	EventsTotal   uint64    `json:"events_total"`
}

// Hub tracks connected clients and fans data out to them.
type Hub struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
	recent  []Event

	store      EventStore // nil = memory-only (tests, no DB)
	storeCh    chan Event
	writerDone chan struct{} // closes when storeWriter returns
	dropped atomic.Uint64

	started     time.Time
	version     string
	commit      string
	eventsTotal atomic.Uint64
}

// EventStore is the persistence seam. internal/storage implements it.
type EventStore interface {
	Append(ctx context.Context, e Event) error
}

func NewHub(version, commit string) *Hub {
	return &Hub{
		clients: make(map[*client]struct{}),
		started: time.Now(),
		version: version,
		commit:  commit,
	}
}

// SetStore attaches a persistent event store. Events published after this
// call are queued for storage by the storeWriter goroutine started in Run.
func (h *Hub) SetStore(store EventStore) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.store = store
	if store != nil && h.storeCh == nil {
		h.storeCh = make(chan Event, 1024)
		h.writerDone = make(chan struct{})
	}
}
func (h *Hub) add(c *client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *Hub) subscribers() []*client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []*client
	for c := range h.clients {
		if c.subscribed.Load() {
			out = append(out, c)
		}
	}
	return out
}

// Publish records an event and pushes it to dashboard subscribers.
func (h *Hub) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	h.eventsTotal.Add(1)

	h.mu.Lock()
	if len(h.recent) >= maxRecentEvents {
		copy(h.recent, h.recent[1:])
		h.recent[len(h.recent)-1] = e
	} else {
		h.recent = append(h.recent, e)
	}
	h.mu.Unlock()

	b := encode("event", e)
	for _, c := range h.subscribers() {
		c.enqueue(b)
	}
	h.mu.RLock()
	store := h.store
	ch := h.storeCh
	h.mu.RUnlock()
	if store != nil && ch != nil {
		select {
		case ch <- e:
		default:
			h.dropped.Add(1)
		}
	}
}

// drainStore waits for the writer goroutine to consume queued events.
func (h *Hub) drainStore(timeout time.Duration) {
	h.mu.RLock()
	ch, done := h.storeCh, h.writerDone
	h.mu.RUnlock()
	if ch == nil || done == nil {
		return
	}
	deadline := time.After(timeout)
	for {
		if len(ch) == 0 {
			// Give the writer a moment to persist the last one.
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
				return
			case <-deadline:
				return
			}
		}
		select {
		case <-deadline:
			slog.Warn("drainStore timed out", "remaining", len(ch))
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Recent returns the buffered events, oldest first.
func (h *Hub) Recent() []Event {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Event, len(h.recent))
	copy(out, h.recent)
	return out
}

func (h *Hub) Snapshot() Stats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	h.mu.RLock()
	authed := 0
	for c := range h.clients {
		if _, s := c.identity(); s != nil {
			authed++
		}
	}
	h.mu.RUnlock()

	const mb = 1 << 20
	return Stats{
		Time:          time.Now().UTC(),
		UptimeSeconds: int64(time.Since(h.started).Seconds()),
		Version:       h.version,
		Commit:        h.commit,
		Goroutines:    runtime.NumGoroutine(),
		HeapMB:        float64(m.HeapAlloc) / mb,
		SysMB:         float64(m.Sys) / mb,
		GCCycles:      m.NumGC,
		Clients:       authed,
		EventsTotal:   h.eventsTotal.Load(),
	}
}

// Run pushes stats to subscribers every refresh() until ctx is done.
func (h *Hub) Run(ctx context.Context, refresh func() time.Duration, auth *Auth) {
	timer := time.NewTimer(refresh())
	defer timer.Stop()
	if h.store != nil {
		go h.storeWriter(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			auth.Sweep()
			h.pushStats()
			timer.Reset(refresh())
		}
	}
}
func (h *Hub) storeWriter(ctx context.Context) {
	defer close(h.writerDone)
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-h.storeCh:
			wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := h.store.Append(wctx, e); err != nil {
				slog.Error("persist event failed", "error", err)
				h.dropped.Add(1)
			}
			cancel()
		}
	}
}
func (h *Hub) pushStats() {
	subs := h.subscribers()
	if len(subs) == 0 {
		return
	}
	b := encode("stats", h.Snapshot())
	for _, c := range subs {
		if c.current() != nil { // also expires stale sessions
			c.enqueue(b)
		}
	}
}
