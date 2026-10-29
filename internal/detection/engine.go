// Package detection evaluates time-windowed rules and emits deduplicated alerts.
package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Event struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
}

type Alert struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
	Source      string    `json:"source"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Evidence    []string  `json:"evidence,omitempty"`
	Status      string    `json:"status"`
}

type Rule struct {
	ID            string   `yaml:"id" json:"id"`
	Title         string   `yaml:"title" json:"title"`
	Description   string   `yaml:"description" json:"description"`
	Severity      string   `yaml:"severity" json:"severity"`
	Enabled       *bool    `yaml:"enabled" json:"enabled"`
	Sources       []string `yaml:"sources" json:"sources"`
	MatchAny      []string `yaml:"match_any" json:"match_any"`
	Threshold     int      `yaml:"threshold" json:"threshold"`
	WindowSeconds int      `yaml:"window_seconds" json:"window_seconds"`
	DedupSeconds  int      `yaml:"dedup_seconds" json:"dedup_seconds"`
	Kind          string   `yaml:"kind" json:"kind"`
}

type occurrence struct {
	at    time.Time
	event Event
	key   string
}

type Engine struct {
	mu        sync.Mutex
	rules     []Rule
	history   map[string][]occurrence
	alerts    map[string]Alert
	order     []string
	maxAlerts int
}

func New(rulesDir string) (*Engine, error) {
	e := &Engine{history: map[string][]occurrence{}, alerts: map[string]Alert{}, maxAlerts: 5000}
	if err := e.Reload(rulesDir); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Reload(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rules directory %q does not exist", dir)
		}
		return err
	}
	var rules []Rule
	ids := map[string]bool{}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(ent.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return err
		}
		var parsed []Rule
		if ext == ".json" {
			var one Rule
			if err := json.Unmarshal(b, &one); err == nil && one.ID != "" {
				parsed = []Rule{one}
			} else if err := json.Unmarshal(b, &parsed); err != nil {
				return fmt.Errorf("parse rule file %s: %w", ent.Name(), err)
			}
		} else {
			var one Rule
			if err := yaml.Unmarshal(b, &one); err == nil && one.ID != "" {
				parsed = []Rule{one}
			} else if err := yaml.Unmarshal(b, &parsed); err != nil {
				return fmt.Errorf("parse rule file %s: %w", ent.Name(), err)
			}
		}
		for _, r := range parsed {
			if strings.TrimSpace(r.ID) == "" {
				return fmt.Errorf("rule in %s has no id", ent.Name())
			}
			if ids[r.ID] {
				return fmt.Errorf("duplicate rule id %q", r.ID)
			}
			ids[r.ID] = true
			if r.Title == "" {
				r.Title = r.ID
			}
			if r.Severity == "" {
				r.Severity = "medium"
			}
			r.Severity = strings.ToLower(r.Severity)
			switch r.Severity {
			case "info", "low", "medium", "high", "critical":
			default:
				return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
			}
			if r.Enabled == nil {
				enabled := true
				r.Enabled = &enabled
			}
			if r.Threshold < 1 {
				r.Threshold = 1
			}
			if r.WindowSeconds < 1 {
				r.WindowSeconds = 60
			}
			if r.DedupSeconds < 1 {
				r.DedupSeconds = 300
			}
			r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
			if r.Kind == "" {
				r.Kind = "threshold"
			}
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	e.mu.Lock()
	e.rules = rules
	e.history = map[string][]occurrence{}
	e.mu.Unlock()
	return nil
}

// Process evaluates an event and returns newly-created or updated alerts.
// Events are never transformed into alerts unless a rule threshold is met.
func (e *Engine) Process(ev Event) []Alert {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Alert
	for _, r := range e.rules {
		if r.Enabled == nil || !*r.Enabled || !matches(r, ev) {
			continue
		}
		group := groupKey(r, ev)
		hkey := r.ID + "|" + group
		cutoff := ev.Time.Add(-time.Duration(r.WindowSeconds) * time.Second)
		old := e.history[hkey]
		kept := old[:0]
		for _, o := range old {
			if !o.at.Before(cutoff) {
				kept = append(kept, o)
			}
		}
		kept = append(kept, occurrence{at: ev.Time, event: ev, key: group})
		e.history[hkey] = kept
		thresholdCount := len(kept)
		if r.Kind == "port_scan" {
			ports := map[string]struct{}{}
			for _, item := range kept {
				if p := destinationPort(item.event.Message); p != "" {
					ports[p] = struct{}{}
				}
			}
			thresholdCount = len(ports)
		}
		if thresholdCount < r.Threshold {
			continue
		}
		sourceIP := extractSourceIP(ev.Message)
		digest := sha256.Sum256([]byte(r.ID + "|" + group))
		id := hex.EncodeToString(digest[:12])
		a, exists := e.alerts[id]
		if exists && ev.Time.Sub(a.LastSeen) <= time.Duration(r.DedupSeconds)*time.Second {
			a.LastSeen = ev.Time
			a.Count++
			a.Source = ev.Source
			if len(a.Evidence) < 5 {
				a.Evidence = append(a.Evidence, truncate(ev.Message, 300))
			}
			e.alerts[id] = a
			out = append(out, a)
			continue
		}
		a = Alert{ID: id, RuleID: r.ID, Title: r.Title, Description: r.Description,
			Severity: r.Severity, FirstSeen: kept[0].at, LastSeen: ev.Time, Count: len(kept),
			Source: ev.Source, SourceIP: sourceIP, Evidence: []string{truncate(ev.Message, 300)}, Status: "open"}
		e.alerts[id] = a
		e.order = append(e.order, id)
		if len(e.order) > e.maxAlerts {
			delete(e.alerts, e.order[0])
			e.order = e.order[1:]
		}
		out = append(out, a)
	}
	return out
}

func (e *Engine) Recent(limit int) []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.order) {
		limit = len(e.order)
	}
	out := make([]Alert, 0, limit)
	for i := len(e.order) - 1; i >= 0 && len(out) < limit; i-- {
		if a, ok := e.alerts[e.order[i]]; ok {
			out = append(out, a)
		}
	}
	return out
}

func matches(r Rule, ev Event) bool {
	if len(r.Sources) > 0 {
		ok := false
		for _, s := range r.Sources {
			if strings.EqualFold(strings.TrimSpace(s), ev.Source) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	msg := strings.ToLower(ev.Message)
	for _, term := range r.MatchAny {
		if strings.Contains(msg, strings.ToLower(term)) {
			return true
		}
	}
	switch r.Kind {
	case "ssh_brute_force":
		return strings.Contains(msg, "sshd") && (strings.Contains(msg, "failed password") || strings.Contains(msg, "authentication failure") || strings.Contains(msg, "invalid user"))
	case "port_scan":
		return strings.Contains(strings.ToLower(ev.Source), "network") && strings.Contains(msg, "tcp")
	case "auth_failures":
		return containsAny(msg, "failed password", "authentication failure", "authentication failed", "auth failure", "invalid user", "pam_unix", "failed login", "login failed")
	case "threshold":
		return len(r.MatchAny) == 0
	default:
		return false
	}
}
func groupKey(r Rule, ev Event) string {
	switch r.Kind {
	case "port_scan":
		if ip := extractSourceIP(ev.Message); ip != "" {
			return ip
		}
	case "ssh_brute_force", "auth_failures":
		if ip := extractSourceIP(ev.Message); ip != "" {
			return ip
		}
	}
	return ev.Source + "|" + extractSourceIP(ev.Message)
}
func extractSourceIP(s string) string {
	// Handles sshd "from 192.0.2.1", and packet strings "192.0.2.1:123 -> ...".
	fields := strings.Fields(s)
	for i, f := range fields {
		candidate := strings.Trim(f, "[](),;")
		if strings.EqualFold(candidate, "from") && i+1 < len(fields) {
			candidate = strings.Trim(fields[i+1], "[](),;")
		}
		if j := strings.LastIndex(candidate, ":"); j > 0 && strings.Count(candidate, ":") == 1 {
			candidate = candidate[:j]
		}
		if strings.Contains(candidate, ".") {
			parts := strings.Split(candidate, ".")
			if len(parts) == 4 {
				valid := true
				for _, p := range parts {
					if p == "" {
						valid = false
						break
					}
					for _, c := range p {
						if c < '0' || c > '9' {
							valid = false
							break
						}
					}
				}
				if valid {
					return candidate
				}
			}
		}
	}
	return ""
}
func containsAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func destinationPort(s string) string {
	i := strings.Index(s, " -> ")
	if i < 0 {
		return ""
	}
	right := strings.Fields(s[i+4:])
	if len(right) == 0 {
		return ""
	}
	hostport := strings.Trim(right[0], "[](),;")
	j := strings.LastIndex(hostport, ":")
	if j < 0 || j == len(hostport)-1 {
		return ""
	}
	port := hostport[j+1:]
	for _, c := range port {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return port
}
