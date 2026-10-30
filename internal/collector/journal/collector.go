// Package journal is a minimal systemd-journal collector for the
// "systemd-journal" integration. It follows `journalctl -o json`, parses each
// entry and emits normalized entries. It is deliberately independent of the
// web package.
package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	maxLineBytes   = 1 << 20  // journalctl JSON lines can be large; longer ones restart the stream
	maxMessageSize = 16 << 10 // message text is truncated to this
	minBackoff     = 2 * time.Second
	maxBackoff     = 30 * time.Second
	healthyRunTime = time.Minute // a run at least this long resets the backoff
)

// Entry is one parsed journal record.
type Entry struct {
	Time       time.Time
	Host       string
	Identifier string // SYSLOG_IDENTIFIER (e.g. sshd, sudo)
	Unit       string // _SYSTEMD_UNIT
	PID        string
	Priority   int // 0 (emerg) .. 7 (debug); -1 when unknown
	Message    string
	Severity   string // info | low | medium | high | critical
}

// String mirrors the syslog collector layout so existing rules
// (ssh_brute_force, auth_failures) match journal events too.
func (e Entry) String() string {
	var b strings.Builder
	if e.Host != "" {
		b.WriteString(e.Host + " ")
	}
	if e.Identifier != "" {
		b.WriteString(e.Identifier)
		if e.PID != "" {
			b.WriteString("[" + e.PID + "]")
		}
		b.WriteString(": ")
	}
	b.WriteString(e.Message)
	if e.Unit != "" {
		return fmt.Sprintf("%s (unit=%s)", b.String(), e.Unit)
	}
	return b.String()
}

// Collector follows the journal until the context is cancelled.
type Collector struct {
	bin  string
	emit func(Entry)
}

// New checks that journalctl is available.
func New(emit func(Entry)) (*Collector, error) {
	if emit == nil {
		return nil, errors.New("journal collector requires an event callback")
	}
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not found (systemd journal collector needs systemd): %w", err)
	}
	return &Collector{bin: bin, emit: emit}, nil
}

// Run blocks until ctx is cancelled, restarting journalctl with backoff if it exits.
//
// TODO(advanced): read the journal natively (sd_journal / go-systemd sdjournal)
// instead of spawning journalctl; persist the cursor (journalctl --cursor-file)
// so restarts neither lose nor replay entries; support unit/priority/identifier
// filters, namespaces, remote journals and per-boot (_BOOT_ID) tracking;
// add rate limiting for noisy units.
func (c *Collector) Run(ctx context.Context) error {
	backoff := minBackoff
	for {
		started := time.Now()
		err := c.follow(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= healthyRunTime {
			backoff = minBackoff
		}
		slog.Warn("journalctl stopped, restarting", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Collector) follow(ctx context.Context) error {
	// --lines=0 with --follow starts at the end: existing history is skipped,
	// matching the syslog collector. Only the fields we use are requested.
	cmd := exec.CommandContext(ctx, c.bin,
		"--follow", "--no-pager", "--output=json", "--lines=0",
		"--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,_PID,_HOSTNAME",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}

	// journalctl reports permission problems on stderr (user needs to be in
	// the systemd-journal or adm group).
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				slog.Warn("journalctl", "stderr", line)
			}
		}
	}()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), maxLineBytes)
	for sc.Scan() {
		if e, ok := ParseEntry(sc.Bytes()); ok {
			c.emit(e)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		return waitErr
	}
	return errors.New("journalctl exited")
}

// ParseEntry parses one `journalctl -o json` line. It returns false for
// invalid JSON or entries without a message.
//
// TODO(advanced): decode binary MESSAGE payloads, map more fields (_UID,
// _COMM, _EXE, _CMDLINE, _SYSTEMD_SLICE, CODE_FILE), and add service-specific
// enrichment (sshd user/IP extraction, sudo command, kernel OOM/segfault).
func ParseEntry(line []byte) (Entry, bool) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return Entry{}, false
	}
	msg := strings.TrimSpace(field(m, "MESSAGE"))
	if msg == "" {
		return Entry{}, false
	}
	if len(msg) > maxMessageSize {
		msg = msg[:maxMessageSize]
	}

	ts := time.Now().UTC()
	if us, err := strconv.ParseInt(field(m, "__REALTIME_TIMESTAMP"), 10, 64); err == nil && us > 0 {
		ts = time.UnixMicro(us).UTC()
	}
	prio := -1
	if p, err := strconv.Atoi(field(m, "PRIORITY")); err == nil && p >= 0 && p <= 7 {
		prio = p
	}
	return Entry{
		Time:       ts,
		Host:       field(m, "_HOSTNAME"),
		Identifier: field(m, "SYSLOG_IDENTIFIER"),
		Unit:       field(m, "_SYSTEMD_UNIT"),
		PID:        field(m, "_PID"),
		Priority:   prio,
		Message:    msg,
		Severity:   severity(prio, msg),
	}, true
}

// field returns a journal field as text. journalctl encodes non-UTF-8 values
// as byte arrays and repeated fields as arrays of strings.
func field(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case []any:
		if len(v) == 0 {
			return ""
		}
		if _, isNum := v[0].(float64); isNum {
			b := make([]byte, 0, len(v))
			for _, x := range v {
				if n, ok := x.(float64); ok {
					b = append(b, byte(n))
				}
			}
			return strings.ToValidUTF8(string(b), "�")
		}
		if s, ok := v[0].(string); ok {
			return s
		}
	}
	return ""
}

// severity maps syslog priority to Rasadbin severities. Unknown priority
// falls back to a keyword heuristic.
//
// TODO(advanced): drop the keyword fallback in favour of the detection engine.
func severity(prio int, msg string) string {
	switch prio {
	case 0, 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "low"
	case 5, 6, 7:
		return "info"
	}
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "panic"), strings.Contains(m, "oom-killer"):
		return "high"
	case strings.Contains(m, "failed"), strings.Contains(m, "error"):
		return "medium"
	}
	return "info"
}
