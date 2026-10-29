package syslog

import (
	"strings"
	"time"
)

// ParseLine parses one syslog line. Two layouts are understood:
//
//	Oct 29 11:59:01 web1 sshd[812]: Failed password for root ...   (RFC 3164 style)
//	2026-10-29T11:59:01.123456+01:00 web1 sshd[812]: ...           (rsyslog RFC 3339)
//
// Anything else is kept verbatim with the current time so no line is lost.
// It returns false only for blank input.
//
// TODO(advanced): parse <PRI> (facility/severity), RFC 5424 structured data,
// "message repeated N times" folding, journald-exported files, and
// service-specific formats (nginx, docker) via pluggable parsers.
func ParseLine(line string, now time.Time) (Entry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Entry{}, false
	}

	ts, rest, ok := parseTimestamp(line, now)
	if !ok {
		return Entry{Time: now.UTC(), Message: line, Severity: classify(line)}, true
	}
	host, rest, _ := strings.Cut(strings.TrimSpace(rest), " ")
	prog, pid, msg := splitTag(strings.TrimSpace(rest))
	return Entry{
		Time:     ts.UTC(),
		Host:     host,
		Program:  prog,
		PID:      pid,
		Message:  msg,
		Severity: classify(msg),
	}, true
}

func parseTimestamp(line string, now time.Time) (time.Time, string, bool) {
	// RFC 3339: first whitespace-delimited token.
	if tok, rest, found := strings.Cut(line, " "); found && len(tok) > 10 && tok[4] == '-' {
		if t, err := time.Parse(time.RFC3339Nano, tok); err == nil {
			return t, rest, true
		}
	}
	// Classic "Mmm _d HH:MM:SS" (15 bytes, no year).
	if len(line) > 16 {
		if t, err := time.ParseInLocation(time.Stamp, line[:15], time.Local); err == nil {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			if t.After(now.Add(24 * time.Hour)) { // Dec lines read in January
				t = t.AddDate(-1, 0, 0)
			}
			return t, line[15:], true
		}
	}
	return time.Time{}, "", false
}

// splitTag separates "sshd[812]: message" into program, pid and message.
func splitTag(s string) (prog, pid, msg string) {
	i := strings.Index(s, ": ")
	if i <= 0 || i > 64 || strings.ContainsAny(s[:i], " \t") {
		if strings.HasSuffix(s, ":") && !strings.ContainsAny(s[:len(s)-1], " \t") && len(s) > 1 {
			return splitTagName(s[:len(s)-1]), tagPID(s[:len(s)-1]), ""
		}
		return "", "", s
	}
	tag := s[:i]
	return splitTagName(tag), tagPID(tag), strings.TrimSpace(s[i+2:])
}

func splitTagName(tag string) string {
	if j := strings.IndexByte(tag, '['); j >= 0 {
		return tag[:j]
	}
	return tag
}

func tagPID(tag string) string {
	j := strings.IndexByte(tag, '[')
	k := strings.LastIndexByte(tag, ']')
	if j >= 0 && k > j {
		return tag[j+1 : k]
	}
	return ""
}

// classify is a keyword heuristic, not a detection engine.
//
// TODO(advanced): drop this in favour of the detection rules engine
// (SSH brute force, sudo failures, kernel error bursts, ...).
func classify(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case containsAny(m, "kernel panic", "segfault", "out of memory", "oom-killer", "call trace", "fatal"):
		return "high"
	case containsAny(m, "failed password", "authentication failure", "invalid user",
		"not in sudoers", "incorrect password", "permission denied", "refused", "denied"):
		return "medium"
	case containsAny(m, "error", "fail", "critical"):
		return "medium"
	case containsAny(m, "warn"):
		return "low"
	}
	return "info"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
