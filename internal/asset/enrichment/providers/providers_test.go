package providers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"rasadbin/internal/asset"
)

func TestLinuxNeighborTableEnrichesMAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp")
	data := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.0.2.10      0x1         0x2         00:11:22:33:44:55     *        eth0\n" +
		"192.0.2.11      0x1         0x0         00:11:22:33:44:66     *        eth0\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (LinuxNeighborTable{Path: path}).Enrich(context.Background(), asset.Asset{IPs: []string{"192.0.2.10", "192.0.2.11"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MACAddresses) != 1 || got.MACAddresses[0] != "00:11:22:33:44:55" {
		t.Fatalf("unexpected MACs: %#v", got.MACAddresses)
	}
}

func TestPassiveServicesUsesObservedPortsOnly(t *testing.T) {
	got, err := (PassiveServices{}).Enrich(context.Background(), asset.Asset{Ports: []int{22, 502, 12345}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 2 {
		t.Fatalf("expected ssh and modbus fingerprints, got %#v", got.Services)
	}
	if got.Services[1].Protocol != "MODBUS" {
		t.Fatalf("expected Modbus fingerprint: %#v", got.Services)
	}
}
