package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuleCRUD(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	rule := Rule{ID: "ui_test_rule", Title: "UI test rule", Severity: "high", Enabled: &enabled, MatchAny: []string{"failed password"}, Threshold: 2, WindowSeconds: 60, DedupSeconds: 300, Kind: "auth_failures"}
	if err := e.SaveRule(rule); err != nil {
		t.Fatalf("SaveRule(create): %v", err)
	}
	if got := e.Rules(); len(got) != 1 || got[0].ID != rule.ID {
		t.Fatalf("unexpected rules after create: %#v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, rule.ID+".json")); err != nil {
		t.Fatalf("rule file not persisted: %v", err)
	}
	rule.Title = "Updated test rule"
	if err := e.SaveRule(rule); err != nil {
		t.Fatalf("SaveRule(update): %v", err)
	}
	if got := e.Rules(); len(got) != 1 || got[0].Title != rule.Title {
		t.Fatalf("rule update not applied: %#v", got)
	}
	if err := e.DeleteRule(rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if got := e.Rules(); len(got) != 0 {
		t.Fatalf("expected no rules after delete, got %#v", got)
	}
}

func TestSaveRuleRejectsInvalidRuleWithoutChangingActiveRules(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	good := Rule{ID: "valid_rule", Title: "Valid", Severity: "low", Enabled: &enabled, Threshold: 1, WindowSeconds: 60, DedupSeconds: 60, Kind: "threshold"}
	if err := e.SaveRule(good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.ID = "bad_rule"
	bad.Severity = "unrecognized"
	if err := e.SaveRule(bad); err == nil {
		t.Fatal("expected invalid severity to be rejected")
	}
	if got := e.Rules(); len(got) != 1 || got[0].ID != good.ID {
		t.Fatalf("invalid update changed active rules: %#v", got)
	}
}
