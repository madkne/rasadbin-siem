package providers

import (
	"context"
	"time"

	"rasadbin/internal/asset"
)

type PassiveServices struct{}

func (PassiveServices) Name() string { return "passive-service-fingerprint" }
func (PassiveServices) Active() bool { return false }

// Port fingerprints are hypotheses based on observed SYN-ACK source ports,
// not proof of a running service. OT fingerprints intentionally have modest
// confidence and must be corroborated by parsed protocol traffic.
var portFingerprints = map[int]struct {
	name, protocol string
	confidence     float64
}{
	21: {"ftp", "FTP", .35}, 22: {"ssh", "SSH", .45}, 23: {"telnet", "TELNET", .35},
	25: {"smtp", "SMTP", .35}, 53: {"dns", "DNS", .35}, 80: {"http", "HTTP", .4},
	102: {"s7comm-or-iso-on-tcp", "S7COMM", .4}, 443: {"https", "TLS", .4},
	502:   {"modbus-tcp", "MODBUS", .45},
	20000: {"dnp3", "DNP3", .45}, 2404: {"iec-60870-5-104", "IEC104", .45},
	3306: {"mysql", "MYSQL", .35}, 3389: {"rdp", "RDP", .35},
	4840: {"opc-ua", "OPCUA", .45}, 5432: {"postgresql", "POSTGRESQL", .35},
	44818: {"ethernet-ip", "CIP", .45},
}

func (PassiveServices) Enrich(_ context.Context, a asset.Asset) (asset.EnrichmentResult, error) {
	now := time.Now().UTC()
	out := asset.EnrichmentResult{}
	for _, port := range a.Ports {
		fp, ok := portFingerprints[port]
		if !ok {
			continue
		}
		svc := asset.ServiceInfo{Port: port, Transport: "tcp", Name: fp.name,
			Protocol: fp.protocol, Confidence: fp.confidence, Source: "observed-tcp-handshake", ObservedAt: now}
		out.Services = append(out.Services, svc)
		out.Protocols = append(out.Protocols, fp.protocol)
		out.Evidence = append(out.Evidence, asset.EnrichmentEvidence{
			Field: "service", Value: fp.name + "/tcp:" + itoa(port),
			Source: "passive-port-fingerprint", Confidence: fp.confidence, ObservedAt: now,
		})
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
