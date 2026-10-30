// Package servicelog is a minimal service-log collector for the
// "service-logs" integration. It tails configured application log files
// (nginx/Apache access and error logs, or any plain-text log), parses the
// formats it knows and emits normalized entries. It is independent of the
// web package.
package servicelog

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rasadbin/internal/collector/syslog"
)

const pollInterval = time.Second

// DefaultPaths are tailed when SERVICE_LOG_PATHS is not set.
var DefaultPaths = []string{
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
}

// Entry is one parsed service log line.
type Entry struct {
	Time     time.Time
	Path     string
	Service  string // nginx, apache2, myapp ...
	Kind     string // access | error | text
	Client   string // client IP when known
	Request  string // access logs: `GET /path HTTP/1.1`
	Status   int    // access logs: HTTP status
	Bytes    int64  // access logs: response size
	Message  string
	Severity string // info | low | medium | high | critical
}

// String keeps stable "key=value" markers so rules can match with match_any,
// e.g. "status=502" or "status=5".
func (e Entry) String() string {
	switch e.Kind {
	case "access":
		return fmt.Sprintf("%s access %s %q status=%d bytes=%d (file=%s)",
			e.Service, e.Client, e.Request, e.Status, e.Bytes, e.Path)
	case "error":
		return fmt.Sprintf("%s error: %s (file=%s)", e.Service, e.Message, e.Path)
	}
	return fmt.Sprintf("%s: %s (file=%s)", e.Service, e.Message, e.Path)
}

// Collector tails a set of files until the context is cancelled.
type Collector struct {
	paths []string
	emit  func(Entry)
	poll  time.Duration
}

// New validates the path list. Files that do not exist yet are fine: they are
// picked up when they appear.
func New(paths []string, emit func(Entry)) (*Collector, error) {
	if emit == nil {
		return nil, errors.New("service log collector requires an event callback")
	}
	seen := map[string]bool{}
	var clean []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			clean = append(clean, p)
		}
	}
	if len(clean) == 0 {
		return nil, errors.New("service log collector requires at least one file path")
	}
	return &Collector{paths: clean, emit: emit, poll: pollInterval}, nil
}

func (c *Collector) Paths() []string { return append([]string(nil), c.paths...) }

// Run blocks until ctx is cancelled.
//
// TODO(advanced): glob patterns and directory watching (e.g.
// /var/lib/docker/containers/*/*-json.log), Docker json-file and journald
// container sources, inotify instead of polling, persisted checkpoints
// (inode + offset), compressed rotated files, per-source parser selection in
// the UI, and backpressure/rate limiting for very busy access logs.
func (c *Collector) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, p := range c.paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			c.tail(ctx, path)
		}(p)
	}
	wg.Wait()
	return nil
}

func (c *Collector) tail(ctx context.Context, path string) {
	f := syslog.NewFollower(path) // existing content is skipped
	defer f.Close()
	service := ServiceName(path)
	tick := time.NewTicker(c.poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, line := range f.ReadNew() {
				if e, ok := ParseLine(line, service, time.Now()); ok {
					e.Path = path
					c.emit(e)
				}
			}
		}
	}
}

// ServiceName derives a service label from the path:
// /var/log/nginx/access.log -> nginx, /var/log/myapp.log -> myapp.
func ServiceName(path string) string {
	if dir := filepath.Base(filepath.Dir(path)); dir != "log" && dir != "." && dir != "/" && dir != "" {
		return dir
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}