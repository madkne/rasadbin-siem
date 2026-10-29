// Package syslog is a minimal syslog-file collector for the "syslog-files"
// integration. It tails text log files (auth.log, syslog, messages, secure),
// survives rotation/truncation, parses classic and RFC 3339 syslog lines and
// emits normalized entries. It is deliberately independent of the web package.
package syslog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pollInterval    = time.Second
	maxLineBytes    = 16 << 10 // longer lines are truncated
	maxBytesPerPoll = 4 << 20  // per file, per tick; the rest waits for next tick
)

// Entry is one parsed syslog line.
type Entry struct {
	Time     time.Time
	Path     string
	Host     string
	Program  string
	PID      string
	Message  string
	Severity string // info | low | medium | high
}

func (e Entry) String() string {
	var b strings.Builder
	if e.Host != "" {
		b.WriteString(e.Host + " ")
	}
	if e.Program != "" {
		b.WriteString(e.Program)
		if e.PID != "" {
			b.WriteString("[" + e.PID + "]")
		}
		b.WriteString(": ")
	}
	b.WriteString(e.Message)
	return fmt.Sprintf("%s (file=%s)", b.String(), e.Path)
}

// Collector tails a set of files until the context is cancelled.
type Collector struct {
	paths []string
	emit  func(Entry)
	poll  time.Duration
}

// New validates the path list. Files that do not exist yet are fine: they
// are picked up when they appear.
func New(paths []string, emit func(Entry)) (*Collector, error) {
	if emit == nil {
		return nil, errors.New("syslog collector requires an event callback")
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
		return nil, errors.New("syslog collector requires at least one file path")
	}
	return &Collector{paths: clean, emit: emit, poll: pollInterval}, nil
}

func (c *Collector) Paths() []string { return append([]string(nil), c.paths...) }

// Run blocks until ctx is cancelled.
//
// TODO(advanced): replace polling with inotify/fsnotify, persist per-file
// checkpoints (inode + offset) so restarts neither lose nor replay lines,
// support glob patterns and compressed rotated files (*.gz), and add
// backpressure/rate limiting for noisy files.
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
	t := newTailer(path) // existing content is skipped: only new lines are collected
	defer t.close()
	tick := time.NewTicker(c.poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, line := range t.readNew() {
				if e, ok := ParseLine(line, time.Now()); ok {
					e.Path = path
					c.emit(e)
				}
			}
		}
	}
}

// tailer follows one file, handling rotation (new inode), truncation and
// partial trailing lines.
type tailer struct {
	path    string
	f       *os.File
	info    os.FileInfo
	offset  int64
	partial []byte
	buf     []byte
	warned  bool
}

func newTailer(path string) *tailer {
	t := &tailer{path: path, buf: make([]byte, 32<<10)}
	t.open(true)
	return t
}

// open opens the file. skipExisting positions at EOF (used once at startup);
// files that appear or rotate later are read from the beginning.
func (t *tailer) open(skipExisting bool) bool {
	f, err := os.Open(t.path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) && !t.warned {
			t.warned = true
			slog.Warn("syslog file not readable (check group membership, e.g. adm)", "path", t.path, "error", err)
		}
		return false // missing or unreadable: retry on the next tick
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return false
	}
	t.f, t.info, t.offset, t.partial = f, fi, 0, t.partial[:0]
	if skipExisting {
		t.offset = fi.Size()
	}
	return true
}

func (t *tailer) close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f, t.info = nil, nil
	}
}

// readNew returns complete lines appended since the last call.
func (t *tailer) readNew() []string {
	if t.f == nil && !t.open(false) {
		return nil
	}
	var out []string
	if cur, err := os.Stat(t.path); err == nil && !os.SameFile(t.info, cur) {
		// Rotated: finish the old file, then start the new one from the top.
		out = append(out, t.drain()...)
		t.close()
		if !t.open(false) {
			return out
		}
	}
	return append(out, t.drain()...)
}

func (t *tailer) drain() []string {
	fi, err := t.f.Stat()
	if err != nil {
		return nil
	}
	if fi.Size() < t.offset { // truncated in place (copytruncate)
		t.offset = 0
		t.partial = t.partial[:0]
	}
	var lines []string
	read := 0
	for read < maxBytesPerPoll {
		n, err := t.f.ReadAt(t.buf, t.offset)
		if n > 0 {
			t.offset += int64(n)
			read += n
			lines = t.split(t.buf[:n], lines)
		}
		if err != nil { // io.EOF or a real error; either way wait for next tick
			if err != io.EOF {
				slog.Warn("syslog read failed", "path", t.path, "error", err)
			}
			break
		}
	}
	return lines
}

func (t *tailer) split(b []byte, lines []string) []string {
	t.partial = append(t.partial, b...)
	for {
		i := bytes.IndexByte(t.partial, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(t.partial[:i]), "\r")
		t.partial = t.partial[i+1:]
		if len(line) > maxLineBytes {
			line = line[:maxLineBytes]
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(t.partial) > maxLineBytes {
		// TODO(advanced): drop the remainder of an over-long line instead of
		// emitting it as a second fragment.
		lines = append(lines, string(t.partial[:maxLineBytes]))
		t.partial = t.partial[:0]
	}
	return lines
}
