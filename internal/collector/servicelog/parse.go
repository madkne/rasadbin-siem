package servicelog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// nginx/Apache "combined" (and "common") access log.
	accessRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)`)
	// nginx error log: 2026/10/29 11:59:01 [error] 812#812: *1 message
	nginxErrRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (.*)$`)
	clientRe   = regexp.MustCompile(`client: ([0-9A-Fa-f:.]+)`)
)

// ParseLine parses one log line. Known layouts are nginx/Apache access and
// nginx error logs; anything else is kept verbatim with the current time so
// no line is lost. It returns false only for blank input.
//
// TODO(advanced): Apache error format, JSON logs, custom log_format and
// user-defined regex/grok parsers, Docker json-file envelopes, SSH/service
// specific adapters, X-Forwarded-For client extraction, and user-agent/
// upstream-latency fields.
func ParseLine(line, service string, now time.Time) (Entry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Entry{}, false
	}

	if m := accessRe.FindStringSubmatch(line); m != nil {
		status, _ := strconv.Atoi(m[4])
		size, _ := strconv.ParseInt(m[5], 10, 64) // "-" -> 0
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
		if err != nil {
			ts = now
		}
		return Entry{
			Time: ts.UTC(), Service: service, Kind: "access",
			Client: m[1], Request: m[3], Status: status, Bytes: size,
			Message: line, Severity: statusSeverity(status),
		}, true
	}

	if m := nginxErrRe.FindStringSubmatch(line); m != nil {
		ts, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
		if err != nil {
			ts = now
		}
		e := Entry{
			Time: ts.UTC(), Service: service, Kind: "error",
			Message: m[3], Severity: nginxLevelSeverity(m[2]),
		}
		if c := clientRe.FindStringSubmatch(m[3]); c != nil {
			e.Client = c[1]
		}
		return e, true
	}

	return Entry{
		Time: now.UTC(), Service: service, Kind: "text",
		Message: line, Severity: classify(line),
	}, true
}

func statusSeverity(status int) string {
	switch {
	case status >= 500:
		return "medium"
	case status >= 400:
		return "low"
	}
	return "info"
}

func nginxLevelSeverity(level string) string {
	switch strings.ToLower(level) {
	case "emerg", "alert":
		return "critical"
	case "crit":
		return "high"
	case "error":
		return "medium"
	case "warn":
		return "low"
	}
	return "info" // debug, info, notice
}

// classify is a keyword heuristic, not a detection engine.
//
// TODO(advanced): drop this in favour of the detection rules engine.
func classify(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "panic"), strings.Contains(m, "fatal"):
		return "high"
	case strings.Contains(m, "error"), strings.Contains(m, "fail"), strings.Contains(m, "exception"):
		return "medium"
	case strings.Contains(m, "warn"):
		return "low"
	}
	return "info"
}