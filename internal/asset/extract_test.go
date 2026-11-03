package asset

import (
	"testing"
	"time"
)

func TestExtractPacketParsesTTLAndWindow(t *testing.T) {
	msg := "packet TCP 10.0.0.1:50000 -> 10.0.0.2:80 flags=0x12 (60 bytes, interface=eth0) ttl=64 tos=0x0 id=12345 win=65535 seq=deadbeef ack=cafebabe"
	obs := extractPacket(msg, false)
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	src := obs[0]
	if src.ip != "10.0.0.1" || src.ttl != 64 || src.window != 65535 {
		t.Fatalf("unexpected source observation: %+v", src)
	}
	if obs[1].ip != "10.0.0.2" || obs[1].ttl != 0 || obs[1].window != 0 {
		t.Fatalf("destination should not inherit sender ttl/window: %+v", obs[1])
	}
}

func TestObserveEventRecordsNetworkEvidence(t *testing.T) {
	s := NewService(Options{}, nil)
	at := time.Now()
	s.ObserveEvent(SourceNetwork, "packet TCP 10.0.0.1:50000 -> 10.0.0.2:80 flags=0x12 (60 bytes, interface=eth0) ttl=64 win=65535", at)
	a, ok := s.Get("ip:10.0.0.1")
	if !ok {
		t.Fatal("source asset not created")
	}
	if len(a.EnrichmentEvidence) != 2 {
		t.Fatalf("expected 2 evidence entries, got %d: %+v", len(a.EnrichmentEvidence), a.EnrichmentEvidence)
	}
	// Duplicate TTL should not add a new entry.
	s.ObserveEvent(SourceNetwork, "packet TCP 10.0.0.1:50001 -> 10.0.0.2:80 flags=0x10 (60 bytes, interface=eth0) ttl=64 win=65535", at.Add(time.Second))
	a, _ = s.Get("ip:10.0.0.1")
	if len(a.EnrichmentEvidence) != 2 {
		t.Fatalf("expected evidence to stay deduped at 2, got %d: %+v", len(a.EnrichmentEvidence), a.EnrichmentEvidence)
	}
}
