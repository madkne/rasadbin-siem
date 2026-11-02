//go:build linux

package providers

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"time"

	"rasadbin/internal/asset"
)

type LinuxNeighborTable struct{ Path string }

func (LinuxNeighborTable) Name() string { return "linux-neighbor-table" }
func (LinuxNeighborTable) Active() bool { return false }
func (p LinuxNeighborTable) Enrich(_ context.Context, a asset.Asset) (asset.EnrichmentResult, error) {
	path := p.Path
	if path == "" {
		path = "/proc/net/arp"
	}
	f, err := os.Open(path)
	if err != nil {
		return asset.EnrichmentResult{}, err
	}
	defer f.Close()
	wanted := make(map[string]bool, len(a.IPs))
	for _, ip := range a.IPs {
		wanted[ip] = true
	}
	out := asset.EnrichmentResult{}
	sc := bufio.NewScanner(f)
	if sc.Scan() { /* skip header */
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !wanted[fields[0]] {
			continue
		}
		// ARP flags 0x2 means a complete neighbor entry; incomplete entries
		// and zero/broadcast/multicast MACs are ignored.
		if flags, err := parseHex(fields[2]); err != nil || flags&2 == 0 {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || strings.EqualFold(mac.String(), "00:00:00:00:00:00") {
			continue
		}
		value := strings.ToLower(mac.String())
		out.MACAddresses = append(out.MACAddresses, value)
		out.Evidence = append(out.Evidence, asset.EnrichmentEvidence{Field: "mac_address", Value: value,
			Source: p.Name() + ":" + fields[5], Confidence: .95, ObservedAt: time.Now().UTC()})
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}
func parseHex(s string) (uint64, error) {
	var n uint64
	for _, c := range strings.TrimPrefix(s, "0x") {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint64(c - 'A' + 10)
		default:
			return 0, os.ErrInvalid
		}
	}
	return n, nil
}
