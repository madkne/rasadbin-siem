package asset

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// observation is one thing an event told us about a host.
type observation struct {
	hostname string
	ip       string
	port     int // >0: this host accepts TCP connections on port
}

var (
	// "packet TCP 192.0.2.10:12345 -> 198.51.100.20:443 flags=0x02 (60 bytes, interface=eth0)"
	packetRe = regexp.MustCompile(`^packet (\w+) ((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))? -> ((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?(?: flags=0x([0-9a-fA-F]{1,2}))?`)
	// "web1 sshd[812]: message (file=/var/log/auth.log)"
	syslogHeadRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.\-]{0,252}) [A-Za-z0-9_.\-/]+(?:\[\d+\])?: `)
	ipv4Re       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostRe       = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

	cgnat = netip.MustParsePrefix("100.64.0.0/10")
)

const maxIPsPerMessage = 8

func extract(source, msg string, includePublic bool) []observation {
	switch source {
	case SourceNetwork:
		return extractPacket(msg, includePublic)
	case SourceSyslog:
		return extractSyslog(msg, includePublic)
	}
	return nil
}

func extractPacket(msg string, includePublic bool) []observation {
	m := packetRe.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	src, dst := observation{}, observation{}
	if ip, ok := normalizeIP(m[2], includePublic); ok {
		src.ip = ip
	}
	if ip, ok := normalizeIP(m[4], includePublic); ok {
		dst.ip = ip
	}
	if strings.EqualFold(m[1], "TCP") && m[6] != "" {
		if f, err := strconv.ParseUint(m[6], 16, 8); err == nil {
			switch f {
			case 0x02: // SYN: the destination is being asked to accept
				dst.port = parsePort(m[5])
			case 0x12: // SYN-ACK: the source accepted
				src.port = parsePort(m[3])
			}
		}
	}
	var out []observation
	for _, o := range []observation{src, dst} {
		if o.ip != "" {
			out = append(out, o)
		}
	}
	return out
}

func extractSyslog(msg string, includePublic bool) []observation {
	var out []observation
	rest := msg
	if m := syslogHeadRe.FindStringSubmatch(msg); m != nil {
		rest = msg[len(m[0]):]
		host := strings.ToLower(strings.TrimSuffix(m[1], "."))
		if addr, err := netip.ParseAddr(host); err == nil {
			if ip, ok := normalizeIP(addr.String(), includePublic); ok {
				out = append(out, observation{ip: ip})
			}
		} else if hostRe.MatchString(host) && !allDigitsDots(host) &&
			host != "localhost" && host != "localhost.localdomain" {
			out = append(out, observation{hostname: host})
		}
	}
	if i := strings.LastIndex(rest, " (file="); i >= 0 {
		rest = rest[:i]
	}
	seen := map[string]bool{}
	for _, raw := range ipv4Re.FindAllString(rest, maxIPsPerMessage*2) {
		ip, ok := normalizeIP(raw, includePublic)
		if !ok || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, observation{ip: ip})
		if len(seen) >= maxIPsPerMessage {
			break
		}
	}
	return out
}

// normalizeIP returns the canonical form of s and whether it is worth tracking.
// Loopback, multicast, broadcast and unspecified addresses are never assets;
// public addresses are skipped unless includePublic is set (otherwise every
// scanner or CDN seen in a log would become an "asset").
func normalizeIP(s string, includePublic bool) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalMulticast() ||
		(a.Is4() && a.As4() == [4]byte{255, 255, 255, 255}) {
		return "", false
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() || (a.Is4() && cgnat.Contains(a)) || includePublic {
		return a.String(), true
	}
	return "", false
}

func parsePort(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

func allDigitsDots(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}
