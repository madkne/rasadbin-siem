package journal

import (
	"strings"
	"testing"
)

func TestParseEntry(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1761825541123456","_HOSTNAME":"web1","SYSLOG_IDENTIFIER":"sshd","_PID":"812","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"6","MESSAGE":"Failed password for root from 192.0.2.9 port 22 ssh2"}`
	e, ok := ParseEntry([]byte(line))
	if !ok {
		t.Fatal("expected entry to parse")
	}
	if e.Host != "web1" || e.Identifier != "sshd" || e.PID != "812" || e.Unit != "ssh.service" {
		t.Fatalf("unexpected fields: %+v", e)
	}
	if e.Time.UnixMicro() != 1761825541123456 {
		t.Fatalf("unexpected time: %v", e.Time)
	}
	if e.Severity != "info" || e.Priority != 6 {
		t.Fatalf("unexpected severity: %+v", e)
	}
	// Must stay matchable by the ssh_brute_force / auth_failures rules.
	s := strings.ToLower(e.String())
	if !strings.Contains(s, "sshd") || !strings.Contains(s, "failed password") {
		t.Fatalf("unexpected String(): %s", e.String())
	}
}

func TestParseEntryBinaryAndInvalid(t *testing.T) {
	e, ok := ParseEntry([]byte(`{"MESSAGE":[104,105],"PRIORITY":"3"}`))
	if !ok || e.Message != "hi" || e.Severity != "medium" {
		t.Fatalf("binary message not decoded: %+v ok=%v", e, ok)
	}
	if _, ok := ParseEntry([]byte(`not json`)); ok {
		t.Fatal("invalid JSON should be rejected")
	}
	if _, ok := ParseEntry([]byte(`{"PRIORITY":"6"}`)); ok {
		t.Fatal("entry without MESSAGE should be rejected")
	}
}