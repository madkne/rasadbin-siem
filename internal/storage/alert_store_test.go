package storage

import (
	"context"
	"testing"
	"time"

	"rasadbin/internal/detection"
	"rasadbin/internal/web"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAlertTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&AlertRecord{}, &AlertNote{}, &AlertHistory{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return &Store{db: db}
}

func TestAlertPersistenceWorkflowAndNotes(t *testing.T) {
	store := newAlertTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	input := detection.Alert{ID: "alert-1", RuleID: "ssh.bruteforce", Title: "SSH brute force", Severity: "high", FirstSeen: now, LastSeen: now, Count: 8, Source: "syslog-files", SourceIP: "192.0.2.8", Evidence: []string{"failed password"}, Status: "new"}

	created, err := store.UpsertAlert(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != "new" {
		t.Fatalf("status = %q, want new", created.Status)
	}

	updated, err := store.UpdateAlert(ctx, input.ID, "investigating", "analyst", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "investigating" || updated.Assignee != "analyst" {
		t.Fatalf("unexpected workflow update: %+v", updated)
	}

	input.Count = 12
	input.LastSeen = now.Add(time.Minute)
	input.Evidence = []string{"failed password", "invalid user"}
	persisted, err := store.UpsertAlert(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != "investigating" || persisted.Assignee != "analyst" {
		t.Fatalf("detection update overwrote analyst state: %+v", persisted)
	}
	if persisted.Count != 12 || len(persisted.Evidence) != 2 {
		t.Fatalf("detection fields not refreshed: %+v", persisted)
	}

	note, err := store.AddAlertNote(ctx, input.ID, "operator", "Investigating source IP")
	if err != nil {
		t.Fatal(err)
	}
	if note.AlertID != input.ID || note.Author != "operator" {
		t.Fatalf("unexpected note: %+v", note)
	}
	notes, err := store.ListAlertNotes(ctx, input.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || notes[0].Body != "Investigating source IP" {
		t.Fatalf("unexpected notes: %+v", notes)
	}
	history, err := store.ListAlertHistory(ctx, input.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 3 {
		t.Fatalf("expected creation, workflow and note audit records, got %+v", history)
	}

	items, total, err := store.ListAlerts(ctx, web.AlertQuery{Severity: "high", Status: "investigating", Search: "ssh", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != input.ID {
		t.Fatalf("unexpected alert query: total=%d items=%+v", total, items)
	}
}

func TestUpdateAlertRejectsUnknownStatus(t *testing.T) {
	store := newAlertTestStore(t)
	if _, err := store.UpdateAlert(context.Background(), "missing", "closed-ish", "", "operator"); err == nil {
		t.Fatal("expected invalid status error")
	}
}
