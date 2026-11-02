package enrichment

import (
	"context"
	"testing"
	"time"

	"rasadbin/internal/asset"
)

type fakeProvider struct{ active bool }

func (fakeProvider) Name() string   { return "test" }
func (p fakeProvider) Active() bool { return p.active }
func (p fakeProvider) Enrich(context.Context, asset.Asset) (asset.EnrichmentResult, error) {
	return asset.EnrichmentResult{Hostname: "resolved.example"}, nil
}

func TestEngineEnrichesDiscoveredAsset(t *testing.T) {
	inventory := asset.NewService(asset.Options{}, nil)
	inventory.ObserveEvent(asset.SourceNetwork, "packet TCP 10.10.10.10:50000 -> 10.10.10.20:22 flags=0x02 (60 bytes, interface=eth0)", time.Now())
	engine, err := New(inventory, []Provider{fakeProvider{}}, Config{Workers: 1, QueueSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { engine.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for {
		got, _ := inventory.Get("ip:10.10.10.20")
		if got.EnrichmentStatus == "enriched" {
			if got.Hostname != "resolved.example" {
				t.Fatalf("hostname not merged: %+v", got)
			}
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("enrichment timed out: %+v", got)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestActiveProviderRequiresExplicitPolicy(t *testing.T) {
	inventory := asset.NewService(asset.Options{}, nil)
	inventory.ObserveEvent(asset.SourceNetwork, "packet TCP 10.10.10.10:50000 -> 10.10.10.20:22 flags=0x02 (60 bytes, interface=eth0)", time.Now())
	engine, err := New(inventory, []Provider{fakeProvider{active: true}}, Config{Workers: 1, QueueSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	engine.process(context.Background(), "ip:10.10.10.20")
	got, _ := inventory.Get("ip:10.10.10.20")
	if got.Hostname != "" {
		t.Fatalf("active provider ran without explicit policy: %+v", got)
	}
}
