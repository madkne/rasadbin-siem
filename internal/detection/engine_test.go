package detection

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRulesAndDedup(t *testing.T) {
	dir := t.TempDir()
	rule := `id: auth
title: Auth failures
severity: high
sources: [syslog-files]
match_any: ["Failed password"]
kind: auth_failures
threshold: 3
window_seconds: 60
dedup_seconds: 300
`
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		if got := e.Process(Event{Time: now.Add(time.Duration(i) * time.Second), Source: "syslog-files", Message: "sshd: Failed password for root from 192.0.2.9"}); len(got) != 0 {
			t.Fatalf("alert too early: %+v", got)
		}
	}
	got := e.Process(Event{Time: now.Add(2 * time.Second), Source: "syslog-files", Message: "sshd: Failed password for root from 192.0.2.9"})
	if len(got) != 1 || got[0].RuleID != "auth" || got[0].Count != 3 {
		t.Fatalf("unexpected alert: %+v", got)
	}
	got = e.Process(Event{Time: now.Add(3 * time.Second), Source: "syslog-files", Message: "sshd: Failed password for root from 192.0.2.9"})
	if len(got) != 1 || got[0].ID == "" || got[0].Count != 4 {
		t.Fatalf("expected deduplicated update: %+v", got)
	}
	if len(e.Recent(10)) != 1 {
		t.Fatal("dedup should keep one alert")
	}
}

func TestPortScanRuleMatchesNetworkEvents(t *testing.T) {
	e := &Engine{rules: []Rule{{ID: "scan", Kind: "port_scan", Severity: "medium", Threshold: 2, WindowSeconds: 60, DedupSeconds: 300, Enabled: boolPtr(true), Sources: []string{"network-packets"}}}, history: map[string][]occurrence{}, alerts: map[string]Alert{}, maxAlerts: 50}
	now := time.Now()
	e.Process(Event{Time: now, Source: "network-packets", Message: "packet TCP 192.0.2.9:40000 -> 198.51.100.2:22"})
	got := e.Process(Event{Time: now.Add(time.Second), Source: "network-packets", Message: "packet TCP 192.0.2.9:40000 -> 198.51.100.2:23"})
	if len(got) != 1 {
		t.Fatalf("expected scan threshold alert, got %+v", got)
	}
}
func boolPtr(v bool) *bool { return &v }

func TestNewAlertAfterDedupWindowGetsNewID(t *testing.T) {
	dir := t.TempDir()
	rule := `id: auth
title: Auth failures
severity: high
sources: [syslog-files]
match_any: ["Failed password"]
kind: auth_failures
threshold: 3
window_seconds: 60
dedup_seconds: 300
`
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	var firstID string
	for i := 0; i < 4; i++ {
		got := e.Process(Event{Time: start.Add(time.Duration(i) * time.Second), Source: "syslog-files", Message: "sshd: Failed password for root from 192.0.2.9"})
		if i == 2 {
			firstID = got[0].ID
		}
	}
	var secondID string
	for i := 0; i < 3; i++ {
		got := e.Process(Event{Time: start.Add(400*time.Second + time.Duration(i)*time.Second), Source: "syslog-files", Message: "sshd: Failed password for root from 192.0.2.9"})
		if i == 2 {
			secondID = got[0].ID
		}
	}
	if firstID == "" || secondID == "" || firstID == secondID {
		t.Fatalf("expected a new alert ID after the dedup window: first=%q second=%q", firstID, secondID)
	}
	if len(e.Recent(10)) != 2 {
		t.Fatalf("expected both alert records to remain, got %d", len(e.Recent(10)))
	}
}
