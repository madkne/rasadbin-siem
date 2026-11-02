package web

import "testing"

func TestActiveEnrichmentRequiresExplicitCIDR(t *testing.T) {
	s := DefaultSettings()
	s.ActiveEnrichmentEnabled = true
	if err := s.Validate(); err == nil {
		t.Fatal("active enrichment must require an explicit target CIDR")
	}
	s.ActiveEnrichmentCIDRs = []string{"10.20.0.0/16"}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid explicit allowlist rejected: %v", err)
	}
	s.ActiveEnrichmentCIDRs = []string{"10.20.0.1"}
	if err := s.Validate(); err == nil {
		t.Fatal("an IP without a CIDR prefix must be rejected")
	}
}
