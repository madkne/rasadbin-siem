package providers

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"rasadbin/internal/asset"
)

type DNSReverse struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

func (p DNSReverse) Name() string { return "dns-reverse" }
func (p DNSReverse) Active() bool { return false }
func (p DNSReverse) Enrich(ctx context.Context, a asset.Asset) (asset.EnrichmentResult, error) {
	result := asset.EnrichmentResult{}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	for _, ip := range a.IPs {
		qctx, cancel := context.WithTimeout(ctx, timeout)
		names, err := resolver.LookupAddr(qctx, ip)
		cancel()
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue // NXDOMAIN/no PTR is normal, not a worker failure.
			}
			return result, err
		}
		for _, raw := range names {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
			if host == "" || strings.ContainsAny(host, " /\\") {
				continue
			}
			result.Hostname = host
			result.Evidence = append(result.Evidence, asset.EnrichmentEvidence{
				Field: "hostname", Value: host, Source: p.Name(), Confidence: 0.8, ObservedAt: time.Now().UTC(),
			})
			return result, nil
		}
	}
	return result, nil
}
