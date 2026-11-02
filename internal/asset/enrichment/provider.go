// Package enrichment performs bounded, asynchronous asset enrichment.
// Providers in this first version are passive: they never connect to discovered
// endpoints or send protocol probes to OT/IT devices.
package enrichment

import (
	"context"
	"rasadbin/internal/asset"
)

type Provider interface {
	Name() string
	// Active is reserved for providers that initiate traffic to an asset.
	// Every current provider returns false.
	Active() bool
	Enrich(context.Context, asset.Asset) (asset.EnrichmentResult, error)
}

type ActivePolicy func(asset.Asset) bool
