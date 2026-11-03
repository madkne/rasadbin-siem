package asset

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	OSSourcePassive = "passive"
	OSSourceManual  = "manual"
	osMinConfidence = 0.3
)

type osHint struct {
	Family, Name, Version string
	Confidence            float64
	Kind, Detail          string // Kind+Detail dedupe repeated identical evidence
}

type osScore struct {
	family            string
	score             float64
	name, version     string
	nameConf, verConf float64
}

type osState struct {
	scores map[string]*osScore
	seen   map[string]struct{}
}

// setOSManual records an analyst-entered OS. Discovery never overrides it.
func (a *Asset) setOSManual(osName, ver string) {
	if osName == a.OperatingSystem && ver == a.OSVersion {
		return
	}
	a.OperatingSystem, a.OSVersion = osName, ver
	if osName == "" && ver == "" {
		a.OSSource, a.OSConfidence = "", 0
		return
	}
	a.OSSource, a.OSConfidence = OSSourceManual, 1
}

func osHints(o observation) []osHint {
	var out []osHint
	if h, ok := tcpOSHint(o); ok {
		out = append(out, h)
	} else if h, ok := ttlOSHint(o); ok {
		out = append(out, h)
	}
	return append(out, appOSHints(o)...)
}

func initialTTL(t int) int {
	switch {
	case t <= 32:
		return 32
	case t <= 64:
		return 64
	case t <= 128:
		return 128
	}
	return 255
}

// tcpOSHint is a small p0f-like matcher on the SYN/SYN-ACK option layout.
// The signatures are approximate; move them to a data file for production.
func tcpOSHint(o observation) (osHint, bool) {
	if o.transport != "TCP" || !o.syn || o.opts == "" || o.ttl <= 0 {
		return osHint{}, false
	}
	it := initialTTL(o.ttl)
	h := osHint{Kind: "tcp-syn", Detail: fmt.Sprintf("ittl=%d win=%d mss=%d ws=%d df=%t opts=%s",
		it, o.window, o.mss, o.wscale, o.df, o.opts)}
	switch {
	case it == 128 && o.opts == "mss,nop,ws,nop,nop,sackok":
		h.Family, h.Name, h.Confidence = "Windows", "Windows", 0.85
		switch {
		case o.window == 64240 && o.wscale == 8:
			h.Version = "10/11/Server 2016+"
		case o.window == 8192 && o.wscale == 8:
			h.Version = "Vista/7/8/Server 2008-2012"
		}
	case it == 128 && o.opts == "mss,nop,nop,sackok":
		h.Family, h.Name, h.Version, h.Confidence = "Windows", "Windows", "XP/2003", 0.8
	case it == 64 && o.opts == "mss,sackok,ts,nop,ws":
		h.Family, h.Name, h.Confidence = "Linux", "Linux", 0.85 // Android shares this stack
	case it == 64 && strings.HasPrefix(o.opts, "mss,nop,ws,nop,nop,ts,sackok"):
		h.Family, h.Name, h.Confidence = "Apple", "macOS/iOS", 0.75
	case it == 64 && strings.HasPrefix(o.opts, "mss,nop,ws,sackok,ts"):
		h.Family, h.Name, h.Confidence = "FreeBSD", "FreeBSD", 0.75
	case it == 64 && o.opts == "mss,nop,nop,sackok,nop,ws,nop,nop,ts":
		h.Family, h.Name, h.Confidence = "OpenBSD", "OpenBSD", 0.7
	default:
		return osHint{}, false
	}
	return h, true
}

// ttlOSHint is a weak family guess from the initial TTL only.
func ttlOSHint(o observation) (osHint, bool) {
	if o.ttl <= 0 {
		return osHint{}, false
	}
	it := initialTTL(o.ttl)
	h := osHint{Kind: "ttl", Detail: "ittl=" + strconv.Itoa(it), Confidence: 0.3}
	switch it {
	case 64:
		h.Family, h.Name = "Linux", "Linux/Unix-like"
	case 128:
		h.Family, h.Name = "Windows", "Windows"
	case 255:
		h.Family, h.Name = "Network", "Network device/Solaris"
	default:
		return osHint{}, false
	}
	return h, true
}

var textOSTable = []struct {
	needle, family, name string
	conf                 float64
}{
	{"ubuntu", "Linux", "Ubuntu", 0.9}, {"debian", "Linux", "Debian", 0.9},
	{"raspbian", "Linux", "Raspbian", 0.9}, {"centos", "Linux", "CentOS", 0.9},
	{"red hat", "Linux", "Red Hat Enterprise Linux", 0.9}, {"fedora", "Linux", "Fedora", 0.9},
	{"freebsd", "FreeBSD", "FreeBSD", 0.9}, {"netbsd", "NetBSD", "NetBSD", 0.9},
	{"openbsd", "OpenBSD", "OpenBSD", 0.9},
	{"openssh_for_windows", "Windows", "Windows", 0.9}, {"microsoft-iis", "Windows", "Windows Server", 0.9},
	{"microsoft-httpapi", "Windows", "Windows", 0.85}, {"microsoft-windows", "Windows", "Windows", 0.9},
	{"(win64)", "Windows", "Windows", 0.85}, {"(win32)", "Windows", "Windows", 0.85},
	{"cisco", "Network", "Cisco IOS/NX-OS", 0.7},
	{"dropbear", "Linux", "Linux (embedded)", 0.6}, {"linux", "Linux", "Linux", 0.7},
}

func textOSHint(s string) (osHint, bool) {
	l := strings.ToLower(s)
	for _, e := range textOSTable {
		if strings.Contains(l, e.needle) {
			return osHint{Family: e.family, Name: e.name, Confidence: e.conf}, true
		}
	}
	return osHint{}, false
}

var (
	uaWinRe     = regexp.MustCompile(`windows nt (\d+\.\d+)`)
	uaAndroidRe = regexp.MustCompile(`android (\d+(?:\.\d+)*)`)
	uaIOSRe     = regexp.MustCompile(`\bos (\d+(?:_\d+)*) like mac os x`)
	winNT       = map[string]string{"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.2": "XP x64/2003", "5.1": "XP"}
)

func uaOSHint(ua string) (osHint, bool) {
	l := strings.ToLower(ua)
	switch {
	case l == "":
	case strings.Contains(l, "android"):
		h := osHint{Family: "Android", Name: "Android", Confidence: 0.9}
		if m := uaAndroidRe.FindStringSubmatch(l); m != nil {
			h.Version = m[1]
		}
		return h, true
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"):
		h := osHint{Family: "Apple", Name: "iOS", Confidence: 0.9}
		if strings.Contains(l, "ipad") {
			h.Name = "iPadOS"
		}
		if m := uaIOSRe.FindStringSubmatch(l); m != nil {
			h.Version = strings.ReplaceAll(m[1], "_", ".")
		}
		return h, true
	case strings.Contains(l, "windows nt"):
		h := osHint{Family: "Windows", Name: "Windows", Confidence: 0.85}
		if m := uaWinRe.FindStringSubmatch(l); m != nil {
			if v, ok := winNT[m[1]]; ok {
				h.Version = v
			} else {
				h.Version = "NT " + m[1]
			}
		}
		return h, true
	case strings.Contains(l, "; cros "):
		return osHint{Family: "ChromeOS", Name: "ChromeOS", Confidence: 0.9}, true
	case strings.Contains(l, "mac os x"), strings.Contains(l, "macintosh"):
		return osHint{Family: "Apple", Name: "macOS", Confidence: 0.85}, true // UA version is frozen by browsers
	case strings.Contains(l, "linux"), strings.Contains(l, "x11"):
		h := osHint{Family: "Linux", Name: "Linux", Confidence: 0.8}
		if strings.Contains(l, "ubuntu") {
			h.Name = "Ubuntu"
		}
		return h, true
	}
	return osHint{}, false
}

func leadingVersion(s string) string {
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return strings.Trim(s[:i], ".")
}

func dhcpVendorHint(v string) (osHint, bool) {
	l := strings.ToLower(v)
	switch {
	case l == "":
		return osHint{}, false
	case strings.HasPrefix(l, "msft "):
		return osHint{Family: "Windows", Name: "Windows", Confidence: 0.9}, true
	case strings.HasPrefix(l, "android-dhcp-"):
		return osHint{Family: "Android", Name: "Android", Confidence: 0.95,
			Version: leadingVersion(strings.TrimPrefix(l, "android-dhcp-"))}, true
	case strings.HasPrefix(l, "udhcp"):
		return osHint{Family: "Linux", Name: "Linux (BusyBox)", Confidence: 0.7}, true
	}
	return textOSHint(v)
}

// Parameter-request-list order is OS specific; examples only, extend as needed.
var prlSigs = []struct {
	prefix, family, name string
	conf                 float64
}{
	{"1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows", "Windows", 0.8},
	{"1,121,3,6,15,119,252", "Apple", "macOS/iOS", 0.75},
	{"1,28,2,3,15,6,119,12,44,47,26,121,42", "Linux", "Linux", 0.7},
}

func between(s, key string, stops ...string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	s = s[i+len(key):]
	end := len(s)
	for _, st := range stops {
		if j := strings.Index(s, st); j >= 0 && j < end {
			end = j
		}
	}
	return strings.TrimSpace(s[:end])
}

// infoToken returns the FIRST space-delimited key=value token (the collector
// writes trusted tokens before any free text such as vendor=).
func infoToken(info, key string) string {
	for _, f := range strings.Fields(info) {
		if strings.HasPrefix(f, key+"=") {
			return f[len(key)+1:]
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func appOSHints(o observation) []osHint {
	if o.appProto == "" || o.appInfo == "" {
		return nil
	}
	var out []osHint
	add := func(h osHint, src string) {
		h.Kind, h.Detail = "app-"+strings.ToLower(o.appProto), clip(src, 96)
		out = append(out, h)
	}
	switch o.appProto {
	case "SSH":
		if h, ok := textOSHint(o.appInfo); ok {
			add(h, o.appInfo)
		}
	case "HTTP":
		if o.appRole == "resp" {
			s := between(o.appInfo, " server=", " host=", " ua=")
			if h, ok := textOSHint(s); ok {
				add(h, s)
			}
		} else if o.appRole == "req" {
			ua := between(o.appInfo, " ua=")
			if h, ok := uaOSHint(ua); ok {
				add(h, ua)
			}
		}
	case "SSDP":
		s := between(o.appInfo, " server=")
		if h, ok := textOSHint(s); ok {
			add(h, s)
		}
	case "DHCP":
		if o.appRole != "req" {
			break
		}
		if i := strings.Index(o.appInfo, "vendor="); i >= 0 {
			v := o.appInfo[i+7:]
			if h, ok := dhcpVendorHint(v); ok {
				add(h, v)
			}
		}
		prl := infoToken(o.appInfo, "prl")
		for _, sg := range prlSigs {
			if prl != "" && strings.HasPrefix(prl, sg.prefix) {
				add(osHint{Family: sg.family, Name: sg.name, Confidence: sg.conf}, "prl="+clip(prl, 60))
				break
			}
		}
	case "ICMP":
		if strings.Contains(o.appInfo, "ping=windows") {
			add(osHint{Family: "Windows", Name: "Windows", Confidence: 0.7}, o.appInfo)
		}
	}
	return out
}

// applyOSHints combines distinct pieces of evidence with a noisy-OR per OS
// family. Identical evidence is counted once, so a chatty host cannot inflate
// its own confidence. Must be called with s.mu held.
func (s *Service) applyOSHints(a *Asset, o observation, at time.Time) {
	if a.OSSource == OSSourceManual {
		return
	}
	hints := osHints(o)
	if len(hints) == 0 {
		return
	}
	st := s.osStates[a.ID]
	if st == nil {
		st = &osState{scores: map[string]*osScore{}, seen: map[string]struct{}{}}
		s.osStates[a.ID] = st
	}
	changed := false
	for _, h := range hints {
		key := h.Kind + "|" + h.Detail
		if _, dup := st.seen[key]; dup || len(st.seen) >= 64 {
			continue
		}
		st.seen[key] = struct{}{}
		sc := st.scores[h.Family]
		if sc == nil {
			sc = &osScore{family: h.Family}
			st.scores[h.Family] = sc
		}
		sc.score = min(0.99, 1-(1-sc.score)*(1-h.Confidence))
		if h.Name != "" && (sc.name == "" || h.Confidence > sc.nameConf) {
			if h.Name != sc.name {
				sc.version, sc.verConf = "", 0
			}
			sc.name, sc.nameConf = h.Name, h.Confidence
		}
		if h.Version != "" && h.Confidence > sc.verConf {
			sc.version, sc.verConf = h.Version, h.Confidence
		}
		addEvidence(a, "operating_system", strings.TrimSpace(h.Name+" "+h.Version),
			"passive-os:"+h.Kind, h.Confidence, at)
		changed = true
	}
	if !changed {
		return
	}
	var best *osScore
	for _, sc := range st.scores {
		if best == nil || sc.score > best.score || (sc.score == best.score && sc.family < best.family) {
			best = sc
		}
	}
	if best != nil && best.score >= osMinConfidence && best.score > a.OSConfidence {
		a.OperatingSystem, a.OSVersion = best.name, best.version
		a.OSConfidence, a.OSSource = best.score, OSSourcePassive
	}
}

func bannerOf(o observation) string {
	switch {
	case o.appProto == "SSH":
		return o.appInfo
	case o.appProto == "HTTP" && o.appRole == "resp":
		return between(o.appInfo, " server=", " host=", " ua=")
	}
	return ""
}

// mergeService keys on port+transport+protocol (or name), so a payload-proven
// service (0.9) replaces the port-only guess (0.35–0.45) instead of duplicating it.
func mergeService(a *Asset, svc ServiceInfo) {
	for i := range a.Services {
		x := &a.Services[i]
		if x.Port == svc.Port && x.Transport == svc.Transport &&
			((svc.Protocol != "" && x.Protocol == svc.Protocol) || x.Name == svc.Name) {
			if svc.Confidence > x.Confidence {
				*x = svc
			}
			return
		}
	}
	if len(a.Services) < 128 {
		a.Services = append(a.Services, svc)
	}
}

// applyAppEvidence turns parsed payloads into protocol/service/banner evidence.
func (s *Service) applyAppEvidence(a *Asset, o observation, at time.Time) {
	if o.appProto == "" {
		return
	}
	a.Protocols = addUnique(a.Protocols, o.appProto, 32)
	if o.appRole == "resp" && o.srcPort > 0 && (o.transport == "TCP" || o.transport == "UDP") {
		mergeService(a, ServiceInfo{Port: o.srcPort, Transport: strings.ToLower(o.transport),
			Name: strings.ToLower(o.appProto), Protocol: o.appProto, Confidence: 0.9,
			Source: "passive-payload", ObservedAt: at})
	}
	if b := bannerOf(o); b != "" {
		addEvidence(a, "banner", clip(b, 128), "passive-payload:"+strings.ToLower(o.appProto), 0.9, at)
	}
}
