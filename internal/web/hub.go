package web

import (
	"context"
	"encoding/json"
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

	started     time.Time
	version     string
	commit      string
	eventsTotal atomic.Uint64
}

func NewHub(version, commit string) *Hub {
	return &Hub{
		clients: make(map[*client]struct{}),
		started: time.Now(),
		version: version,
		commit:  commit,
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
