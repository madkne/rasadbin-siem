package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	maxInspectBytes = 512 // only the first bytes of a payload are examined, never retained
	maxDetailLen    = 200
)

var inspectEnabled atomic.Bool

func init() { inspectEnabled.Store(true) }

// SetPayloadInspection toggles application-layer payload analysis.
func SetPayloadInspection(on bool) { inspectEnabled.Store(on) }

// AppInfo is derived metadata. Detail is untrusted free text (sanitized);
// Func is a trusted identifier produced only from fixed tables.
type AppInfo struct{ Proto, Role, Detail, Func string }

// TCPOptions is a p0f-style summary of the TCP option block.
type TCPOptions struct {
	MSS    uint16
	WScale int // -1 when absent
	Layout string
}

func parseTCPOptions(b []byte) TCPOptions {
	o := TCPOptions{WScale: -1}
	var layout []string
loop:
	for i := 0; i < len(b); {
		switch b[i] {
		case 0:
			layout = append(layout, "eol")
			break loop
		case 1:
			layout = append(layout, "nop")
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if l < 2 || i+l > len(b) {
			break
		}
		switch b[i] {
		case 2:
			layout = append(layout, "mss")
			if l == 4 {
				o.MSS = binary.BigEndian.Uint16(b[i+2:])
			}
		case 3:
			layout = append(layout, "ws")
			if l == 3 {
				o.WScale = int(b[i+2])
			}
		case 4:
			layout = append(layout, "sackok")
		case 5:
			layout = append(layout, "sack")
		case 8:
			layout = append(layout, "ts")
		default:
			layout = append(layout, "opt"+strconv.Itoa(int(b[i])))
		}
		i += l
	}
	if len(layout) > 16 {
		layout = layout[:16]
	}
	o.Layout = strings.Join(layout, ",")
	return o
}

func shannon(p []byte) float64 {
	if len(p) > maxInspectBytes {
		p = p[:maxInspectBytes]
	}
	var c [256]int
	for _, b := range p {
		c[b]++
	}
	n, h := float64(len(p)), 0.0
	for _, v := range c {
		if v > 0 {
			f := float64(v) / n
			h -= f * math.Log2(f)
		}
	}
	return h
}

// sanitize keeps printable ASCII only and removes double quotes, so the value
// can be embedded safely in `info="..."` and in log lines.
func sanitize(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		switch c := s[i]; {
		case c == '"':
			b.WriteByte('\'')
		case c < 0x20 || c == 0x7f:
		case c >= 0x80:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

func inspectPayload(transport string, sport, dport uint16, p []byte) AppInfo {
	if len(p) == 0 {
		return AppInfo{}
	}
	if len(p) > maxInspectBytes {
		p = p[:maxInspectBytes]
	}
	var a AppInfo
	if transport == "UDP" {
		a = inspectUDP(sport, dport, p)
	} else {
		a = inspectTCP(sport, dport, p)
	}
	a.Detail = sanitize(a.Detail, maxDetailLen)
	return a
}

func inspectTCP(sport, dport uint16, p []byte) AppInfo {
	if a, ok := inspectTLS(p); ok {
		return a
	}
	if bytes.HasPrefix(p, []byte("SSH-")) {
		end := bytes.IndexAny(p, "\r\n")
		if end < 0 || end > 80 {
			end = min(len(p), 80)
		}
		return AppInfo{Proto: "SSH", Detail: string(p[:end])}
	}
	if a, ok := inspectHTTP(p); ok {
		return a
	}
	if a, ok := inspectSMB(sport, dport, p); ok {
		return a
	}
	if a, ok := inspectOT(sport, dport, p); ok {
		return a
	}
	return AppInfo{}
}

func inspectUDP(sport, dport uint16, p []byte) AppInfo {
	has := func(ports ...uint16) bool {
		for _, x := range ports {
			if sport == x || dport == x {
				return true
			}
		}
		return false
	}
	switch {
	case has(53, 5353, 5355):
		if a, ok := inspectDNS(sport, dport, p); ok {
			return a
		}
	case has(67, 68):
		if a, ok := inspectDHCP(p); ok {
			return a
		}
	case has(123):
		if len(p) >= 48 {
			vn, mode := (p[0]>>3)&7, p[0]&7
			if vn >= 1 && vn <= 4 && mode >= 1 && mode <= 5 {
				role := ""
				switch mode {
				case 3:
					role = "req"
				case 4:
					role = "resp"
				}
				return AppInfo{Proto: "NTP", Role: role, Detail: fmt.Sprintf("v%d mode=%d stratum=%d", vn, mode, p[1])}
			}
		}
	case has(1900):
		if a, ok := inspectSSDP(p); ok {
			return a
		}
	}
	return AppInfo{}
}

// ---- TLS -------------------------------------------------------------

func inspectTLS(p []byte) (AppInfo, bool) {
	if len(p) < 6 || p[1] != 3 || p[2] > 4 {
		return AppInfo{}, false
	}
	switch p[0] {
	case 0x16:
		switch p[5] {
		case 1:
			d := "ClientHello"
			if sni := clientHelloSNI(p); sni != "" {
				d += " sni=" + sni
			}
			return AppInfo{Proto: "TLS", Role: "req", Detail: d}, true
		case 2:
			return AppInfo{Proto: "TLS", Role: "resp", Detail: "ServerHello"}, true
		}
		return AppInfo{Proto: "TLS", Detail: "handshake"}, true
	case 0x17:
		return AppInfo{Proto: "TLS", Detail: "application_data"}, true
	}
	return AppInfo{}, false
}

// clientHelloSNI walks record -> handshake -> extensions with strict bounds checks.
func clientHelloSNI(p []byte) string {
	if len(p) < 43 || p[5] != 1 {
		return ""
	}
	b := p[9:][34:] // skip record(5)+handshake header(4), then version(2)+random(32)
	if len(b) < 1 {
		return ""
	}
	n := int(b[0])
	if len(b) < 1+n {
		return ""
	}
	b = b[1+n:] // session id
	if len(b) < 2 {
		return ""
	}
	n = int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return ""
	}
	b = b[2+n:] // cipher suites
	if len(b) < 1 {
		return ""
	}
	n = int(b[0])
	if len(b) < 1+n {
		return ""
	}
	b = b[1+n:] // compression
	if len(b) < 2 {
		return ""
	}
	n = int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n < len(b) {
		b = b[:n]
	}
	for len(b) >= 4 {
		typ, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if l > len(b) {
			return ""
		}
		if typ == 0 && l >= 5 {
			d := b[:l]
			nl := int(binary.BigEndian.Uint16(d[3:]))
			if d[2] == 0 && 5+nl <= len(d) {
				return sanitize(string(d[5:5+nl]), 128)
			}
			return ""
		}
		b = b[l:]
	}
	return ""
}

// ---- HTTP ------------------------------------------------------------

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}

func inspectHTTP(p []byte) (AppInfo, bool) {
	isResp := bytes.HasPrefix(p, []byte("HTTP/1."))
	isReq := false
	if !isResp {
		for _, m := range httpMethods {
			if bytes.HasPrefix(p, []byte(m)) {
				isReq = true
				break
			}
		}
	}
	if !isReq && !isResp {
		return AppInfo{}, false
	}
	head := p
	if i := bytes.Index(p, []byte("\r\n\r\n")); i >= 0 {
		head = p[:i]
	}
	lines := strings.Split(string(head), "\r\n")
	first := lines[0]
	if isReq {
		if f := strings.Fields(first); len(f) >= 2 {
			path := f[1]
			if q := strings.IndexByte(path, '?'); q >= 0 {
				path = path[:q] // never keep query strings (tokens, PII)
			}
			first = f[0] + " " + path
		}
	}
	var host, ua, server string
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "host":
			host = v
		case "user-agent":
			ua = v
		case "server":
			server = v
		}
	}
	// Order matters: ua is last, so truncation can only cut its tail.
	d := first
	if server != "" {
		d += " server=" + server
	}
	if host != "" {
		d += " host=" + host
	}
	if ua != "" {
		d += " ua=" + ua
	}
	role := "req"
	if isResp {
		role = "resp"
	}
	return AppInfo{Proto: "HTTP", Role: role, Detail: d}, true
}

// ---- SMB / OT --------------------------------------------------------

func inspectSMB(sport, dport uint16, p []byte) (AppInfo, bool) {
	if !(sport == 445 || dport == 445 || sport == 139 || dport == 139) || len(p) < 8 || p[0] != 0 {
		return AppInfo{}, false
	}
	role := "resp"
	if dport == 445 || dport == 139 {
		role = "req"
	}
	switch {
	case bytes.Equal(p[4:8], []byte{0xff, 'S', 'M', 'B'}):
		return AppInfo{Proto: "SMB", Role: role, Detail: "SMB1"}, true
	case bytes.Equal(p[4:8], []byte{0xfe, 'S', 'M', 'B'}):
		return AppInfo{Proto: "SMB", Role: role, Detail: "SMB2/3"}, true
	}
	return AppInfo{}, false
}

var modbusFC = map[byte]string{
	1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_registers", 4: "read_input_registers",
	5: "write_single_coil", 6: "write_single_register", 15: "write_multiple_coils",
	16: "write_multiple_registers", 22: "mask_write_register", 23: "read_write_registers",
	43: "encapsulated_interface",
}

// inspectOT is strictly passive: it only labels traffic that already exists.
func inspectOT(sport, dport uint16, p []byte) (AppInfo, bool) {
	role := func(port uint16) string {
		switch {
		case dport == port:
			return "req"
		case sport == port:
			return "resp"
		}
		return ""
	}
	on := func(port uint16) bool { return sport == port || dport == port }
	switch {
	case on(502):
		if len(p) >= 8 && binary.BigEndian.Uint16(p[2:4]) == 0 {
			if l := int(binary.BigEndian.Uint16(p[4:6])); l >= 2 && l <= 254 {
				base := p[7] & 0x7f
				name := modbusFC[base]
				if name == "" {
					name = "fc_" + strconv.Itoa(int(base))
				}
				d := fmt.Sprintf("fc=%d %s unit=%d", base, name, p[6])
				if p[7]&0x80 != 0 {
					d += " exception"
					if len(p) >= 9 {
						d += fmt.Sprintf(" code=%d", p[8])
					}
				}
				return AppInfo{Proto: "MODBUS", Role: role(502), Detail: d, Func: name}, true
			}
		}
	case on(102):
		if len(p) >= 8 && p[0] == 3 && p[1] == 0 {
			off := 5 + int(p[4])
			if len(p) > off+1 && p[off] == 0x32 {
				fn := map[byte]string{1: "job", 2: "ack", 3: "ack_data", 7: "userdata"}[p[off+1]]
				if fn == "" {
					fn = "rosctr_" + strconv.Itoa(int(p[off+1]))
				}
				return AppInfo{Proto: "S7COMM", Role: role(102), Detail: "rosctr=" + fn, Func: fn}, true
			}
			return AppInfo{Proto: "ISOTSAP", Role: role(102), Detail: "tpkt/cotp"}, true
		}
	case on(20000):
		if len(p) >= 10 && p[0] == 0x05 && p[1] == 0x64 {
			return AppInfo{Proto: "DNP3", Role: role(20000),
				Detail: fmt.Sprintf("link dst=%d src=%d", binary.LittleEndian.Uint16(p[4:6]), binary.LittleEndian.Uint16(p[6:8]))}, true
		}
	case on(2404):
		if len(p) >= 6 && p[0] == 0x68 && p[1] >= 4 {
			f := "u_format"
			switch {
			case p[2]&1 == 0:
				f = "i_format"
			case p[2]&3 == 1:
				f = "s_format"
			}
			d := f
			if f == "i_format" && len(p) >= 7 {
				d += fmt.Sprintf(" typeid=%d", p[6])
			}
			return AppInfo{Proto: "IEC104", Role: role(2404), Detail: d, Func: f}, true
		}
	case on(3389):
		if len(p) >= 4 && p[0] == 3 && p[1] == 0 {
			return AppInfo{Proto: "RDP", Role: role(3389), Detail: "x224"}, true
		}
	}
	return AppInfo{}, false
}

// ---- DNS / DHCP / SSDP / ICMP ---------------------------------------

var dnsTypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

func inspectDNS(sport, dport uint16, p []byte) (AppInfo, bool) {
	if len(p) < 17 {
		return AppInfo{}, false
	}
	flags, qd := binary.BigEndian.Uint16(p[2:4]), binary.BigEndian.Uint16(p[4:6])
	if (flags>>11)&0xf > 5 || qd == 0 || qd > 16 {
		return AppInfo{}, false
	}
	i, labels := 12, []string(nil)
	for {
		if i >= len(p) || len(labels) > 16 {
			return AppInfo{}, false
		}
		l := int(p[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || i+l > len(p) {
			return AppInfo{}, false
		}
		labels = append(labels, string(p[i:i+l]))
		i += l
	}
	if i+4 > len(p) {
		return AppInfo{}, false
	}
	qt := binary.BigEndian.Uint16(p[i:])
	tn := dnsTypes[qt]
	if tn == "" {
		tn = "type" + strconv.Itoa(int(qt))
	}
	proto := "DNS"
	switch {
	case sport == 5353 || dport == 5353:
		proto = "MDNS"
	case sport == 5355 || dport == 5355:
		proto = "LLMNR"
	}
	kind, role := "query", "req"
	if flags&0x8000 != 0 {
		kind, role = "response", "resp"
	}
	return AppInfo{Proto: proto, Role: role, Detail: kind + " " + strings.Join(labels, ".") + " " + tn}, true
}

var dhcpTypes = map[byte]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}

func ipv4(b []byte) string { return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]) }

// inspectDHCP: vendor class (opt 60), hostname (opt 12) and the parameter
// request list (opt 55) are among the best passive OS signals on a LAN.
// vendor= must stay last: its value may contain spaces.
func inspectDHCP(p []byte) (AppInfo, bool) {
	if len(p) < 241 || binary.BigEndian.Uint32(p[236:240]) != 0x63825363 {
		return AppInfo{}, false
	}
	var mt byte
	var host, vendor, reqIP string
	var prl []string
	for i := 240; i+1 < len(p); {
		code := p[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		l := int(p[i+1])
		if i+2+l > len(p) {
			break
		}
		v := p[i+2 : i+2+l]
		switch code {
		case 53:
			if l == 1 {
				mt = v[0]
			}
		case 50:
			if l == 4 {
				reqIP = ipv4(v)
			}
		case 12:
			host = strings.ReplaceAll(strings.TrimSpace(string(v)), " ", "_")
		case 55:
			for _, b := range v {
				if len(prl) < 40 {
					prl = append(prl, strconv.Itoa(int(b)))
				}
			}
		case 60:
			vendor = string(v)
		}
		i += 2 + l
	}
	if reqIP == "" && !bytes.Equal(p[12:16], []byte{0, 0, 0, 0}) {
		reqIP = ipv4(p[12:16]) // ciaddr
	}
	name := dhcpTypes[mt]
	if name == "" {
		name = "msg" + strconv.Itoa(int(mt))
	}
	d := name
	if reqIP != "" {
		d += " ip=" + reqIP
	}
	if host != "" {
		d += " host=" + host
	}
	if len(prl) > 0 {
		d += " prl=" + strings.Join(prl, ",")
	}
	if vendor != "" {
		d += " vendor=" + vendor
	}
	role := "resp"
	if p[0] == 1 {
		role = "req"
	}
	return AppInfo{Proto: "DHCP", Role: role, Detail: d}, true
}

func inspectSSDP(p []byte) (AppInfo, bool) {
	s := string(p)
	var kind, role string
	switch {
	case strings.HasPrefix(s, "M-SEARCH "):
		kind, role = "M-SEARCH", "req"
	case strings.HasPrefix(s, "NOTIFY "):
		kind = "NOTIFY"
	case strings.HasPrefix(s, "HTTP/1.1 200"):
		kind, role = "RESPONSE", "resp"
	default:
		return AppInfo{}, false
	}
	d := kind
	for _, l := range strings.Split(s, "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			if k = strings.ToLower(strings.TrimSpace(k)); k == "server" || k == "user-agent" {
				d += " server=" + strings.TrimSpace(v)
				break
			}
		}
	}
	return AppInfo{Proto: "SSDP", Role: role, Detail: d}, true
}

// Windows `ping` fills echo requests with this fixed 32-byte pattern.
func inspectICMPEcho(p []byte) AppInfo {
	if bytes.HasPrefix(p, []byte("abcdefghijklmnopqrstuvwabcdefghi")) {
		return AppInfo{Proto: "ICMP", Role: "req", Detail: "echo ping=windows"}
	}
	return AppInfo{}
}
