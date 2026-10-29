package web

import (
	"testing"
)

func TestIntegrationStorePersistsToggle(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadIntegrationStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Update("systemd-journal", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Alerting {
		t.Fatalf("unexpected update: %+v", got)
	}
	reloaded, err := LoadIntegrationStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Get("systemd-journal")
	if !ok || !got.Enabled || got.Alerting {
		t.Fatalf("toggle was not persisted: %+v", got)
	}
	if _, err := reloaded.Update("../bad", true, true); err == nil {
		t.Fatal("expected unknown integration error")
	}
}

func TestProcessEventRespectsIntegrationToggle(t *testing.T) {
	st, err := LoadIntegrationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := Event{Source: "systemd-journal", Message: "sshd failed"}
	if _, ok := st.ProcessEvent(e); ok {
		t.Fatal("disabled integration should drop its events")
	}
	if _, err := st.Update("systemd-journal", true, true); err != nil {
		t.Fatal(err)
	}
	got, ok := st.ProcessEvent(e)
	if !ok || got.Source != "systemd-journal" {
		t.Fatalf("unexpected processed event: %+v, %v", got, ok)
	}
}
