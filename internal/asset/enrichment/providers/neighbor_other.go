//go:build !linux

package providers

import (
	"context"
	"errors"
	"rasadbin/internal/asset"
)

type LinuxNeighborTable struct{ Path string }

func (LinuxNeighborTable) Name() string { return "linux-neighbor-table" }
func (LinuxNeighborTable) Active() bool { return false }
func (LinuxNeighborTable) Enrich(context.Context, asset.Asset) (asset.EnrichmentResult, error) {
	return asset.EnrichmentResult{}, errors.New("Linux neighbor table is only available on Linux")
}
