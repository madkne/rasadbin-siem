package asset

import (
	"testing"
	"time"
)

func TestObserveEventExtractsEthernetMACs(t *testing.T) {
	s := NewService(Options{}, nil)
	s.ObserveEvent(SourceNetwork, "packet TCP 10.10.10.10:50000 -> 10.10.10.20:502 flags=0x02 (60 bytes, interface=eth0) src_mac=00:11:22:33:44:55 dst_mac=00:aa:bb:cc:dd:ee", time.Now())
	got, ok := s.Get("ip:10.10.10.10")
	if !ok || len(got.MACAddresses) != 1 || got.MACAddresses[0] != "00:11:22:33:44:55" {
		t.Fatalf("source MAC not extracted: %+v", got)
	}
	peer, ok := s.Get("ip:10.10.10.20")
	if !ok || len(peer.MACAddresses) != 1 || peer.MACAddresses[0] != "00:aa:bb:cc:dd:ee" {
		t.Fatalf("destination MAC not extracted: %+v", peer)
	}
}

func TestEnrichmentDoesNotOverwriteAnalystFields(t *testing.T) {
	s := NewService(Options{}, nil)
	manual, err := s.AddManual(Asset{IPs: []string{"10.10.10.30"}, Name: "PLC Line 1", Tags: []string{"critical-zone"}, Criticality: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	s.CompleteEnrichment(manual.ID, EnrichmentResult{Hostname: "plc-1.example", MACAddresses: []string{"00:11:22:33:44:55"}}, "enriched", "", 1, time.Time{})
	got, _ := s.Get(manual.ID)
	if got.Name != "PLC Line 1" || got.Criticality != "critical" || len(got.Tags) != 1 {
		t.Fatalf("analyst fields overwritten: %+v", got)
	}
	if got.Hostname != "plc-1.example" || len(got.MACAddresses) != 1 {
		t.Fatalf("enrichment not merged: %+v", got)
	}
}

func TestOnlySYNACKCreatesServicePortEvidence(t *testing.T) {
	s := NewService(Options{}, nil)
	now := time.Now()
	s.ObserveEvent(SourceNetwork, "packet TCP 10.10.10.10:50000 -> 10.10.10.20:502 flags=0x02 (60 bytes, interface=eth0)", now)
	server, _ := s.Get("ip:10.10.10.20")
	if len(server.Ports) != 0 {
		t.Fatalf("bare SYN must not be treated as an open service: %#v", server.Ports)
	}
	s.ObserveEvent(SourceNetwork, "packet TCP 10.10.10.20:502 -> 10.10.10.10:50000 flags=0x12 (60 bytes, interface=eth0)", now.Add(time.Second))
	server, _ = s.Get("ip:10.10.10.20")
	if len(server.Ports) != 1 || server.Ports[0] != 502 {
		t.Fatalf("SYN-ACK should record the accepted service port: %#v", server.Ports)
	}
}
