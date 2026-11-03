package asset

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// observation is one thing an event told us about a host.
type observation struct {
	hostname string
	ip       string
	mac      string
	port     int // >0: this host accepted a TCP connection on port
	ttl      int
	window   int
	// sender-side passive fingerprint inputs
	syn       bool // SYN or SYN-ACK
	df        bool
	mss       int
	wscale    int // -1 = option absent
	opts      string
	transport string
	srcPort   int
	appProto  string
	appRole   string
	appInfo   string // untrusted free text; never parsed as key=value
}

var (
	packetRe = regexp.MustCompile(`^packet (\w+) ((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))? -> ((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?(?: flags=0x([0-9a-fA-F]{1,2}))?`)
	kvRe     = regexp.MustCompile(`(?:^|\s)([a-z_]+)=([^\s"]+)`)

	syslogHeadRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.\-]{0,252}) [A-Za-z0-9_.\-/]+(?:\[\d+\])?: `)
	ipv4Re       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostRe       = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)
	packetMACRe  = regexp.MustCompile(`src_mac=([0-9a-fA-F:.-]{17})\s+dst_mac=([0-9a-fA-F:.-]{17})`)

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

func normalizeMAC(raw string) string {
	m, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(m) != 6 {
		return ""
	}
	// Do not treat multicast or all-zero addresses as an endpoint identity.
	if m[0]&1 != 0 || strings.EqualFold(m.String(), "00:00:00:00:00:00") {
		return ""
	}
	return strings.ToLower(m.String())
}

func normalizeIP(s string, includePublic bool) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalMulticast() ||
		(a.Is4() && a.As4()[3] == 255) {
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

func addEvidence(a *Asset, field, value, source string, conf float64, at time.Time) {
	for _, old := range a.EnrichmentEvidence {
		if old.Field == field && old.Value == value && old.Source == source {
			return
		}
	}
	if len(a.EnrichmentEvidence) < 256 {
		a.EnrichmentEvidence = append(a.EnrichmentEvidence, EnrichmentEvidence{
			Field: field, Value: value, Source: source, Confidence: conf, ObservedAt: at})
	}
}

// addNetworkEvidence records a passive network fingerprint hint (e.g. TTL or
// advertised TCP window) on an asset, deduplicated by field/value/source and
// capped at the existing evidence limit.
func addNetworkEvidence(a *Asset, field, value string, at time.Time) {
	addEvidence(a, field, value, SourceNetwork, 0.5, at)
}

// splitInfo separates the trusted head from the untrusted info="..." tail.
func splitInfo(msg string) (head, info string) {
	if i := strings.Index(msg, ` info="`); i >= 0 {
		rest := msg[i+7:]
		if j := strings.LastIndexByte(rest, '"'); j >= 0 {
			rest = rest[:j]
		}
		return msg[:i], rest
	}
	return msg, ""
}

func parseKV(s string) map[string]string {
	out := map[string]string{}
	for _, m := range kvRe.FindAllStringSubmatch(s, 64) {
		if _, ok := out[m[1]]; !ok {
			out[m[1]] = m[2]
		}
	}
	return out
}

func atoiKV(kv map[string]string, key string) int {
	n, err := strconv.Atoi(kv[key])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func cleanHostname(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || !hostRe.MatchString(s) || allDigitsDots(s) {
		return ""
	}
	return s
}

func extractPacket(msg string, includePublic bool) []observation {
	m := packetRe.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	head, info := splitInfo(msg)
	kv := parseKV(head)

	src, dst := observation{wscale: -1}, observation{wscale: -1}
	if ip, ok := normalizeIP(m[2], includePublic); ok {
		src.ip = ip
	}
	if ip, ok := normalizeIP(m[4], includePublic); ok {
		dst.ip = ip
	}
	if macs := packetMACRe.FindStringSubmatch(head); macs != nil {
		src.mac, dst.mac = normalizeMAC(macs[1]), normalizeMAC(macs[2])
	}
	proto := strings.ToUpper(m[1])
	src.transport, src.srcPort = proto, parsePort(m[3])
	if proto == "TCP" && m[6] != "" {
		if f, err := strconv.ParseUint(m[6], 16, 8); err == nil {
			src.syn = f&0x02 != 0
			if f == 0x12 { // SYN-ACK: the source accepted a connection on this port
				src.port = parsePort(m[3])
			}
		}
	}
	src.ttl, src.window, src.mss = atoiKV(kv, "ttl"), atoiKV(kv, "win"), atoiKV(kv, "mss")
	if n, err := strconv.Atoi(kv["ws"]); err == nil && n >= 0 && n <= 14 {
		src.wscale = n
	}
	src.opts = kv["opts"]
	if v := strings.TrimPrefix(kv["frag"], "0x"); v != "" {
		if n, err := strconv.ParseUint(v, 16, 8); err == nil {
			src.df = n&2 != 0
		}
	}
	src.appProto, src.appRole, src.appInfo = kv["app"], kv["role"], info

	if src.appProto == "DHCP" && src.appRole == "req" && src.ip != "" {
		src.hostname = cleanHostname(infoToken(info, "host"))
	}

	var out []observation
	for _, o := range []observation{src, dst} {
		if o.ip != "" {
			out = append(out, o)
		}
	}
	// DHCP clients usually send from 0.0.0.0: attribute the request to the
	// address it asks for (option 50 / ciaddr), keyed by the Ethernet MAC.
	if src.ip == "" && src.appProto == "DHCP" && src.appRole == "req" {
		if ip, ok := normalizeIP(infoToken(info, "ip"), includePublic); ok {
			out = append(out, observation{ip: ip, mac: src.mac, wscale: -1, transport: "UDP",
				appProto: "DHCP", appRole: "req", appInfo: info,
				hostname: cleanHostname(infoToken(info, "host"))})
		}
	}
	return out
}
