package network

import (
	"strings"
	"testing"
)

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func buildClientHello(sni string) []byte {
	name := []byte(sni)
	list := append([]byte{0}, u16(len(name))...)
	list = append(list, name...)
	data := append(u16(len(list)), list...)
	ext := append([]byte{0, 0}, u16(len(data))...)
	ext = append(ext, data...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, u16(len(ext))...)
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 3, 1}, u16(len(hs))...), hs...)
}

func TestParseTCPOptionsLinuxSYN(t *testing.T) {
	o := parseTCPOptions([]byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7})
	if o.Layout != "mss,sackok,ts,nop,ws" || o.MSS != 1460 || o.WScale != 7 {
		t.Fatalf("unexpected: %+v", o)
	}
}

func TestInspectTLSClientHelloSNI(t *testing.T) {
	a := inspectPayload("TCP", 50000, 443, buildClientHello("example.com"))
	if a.Proto != "TLS" || !strings.Contains(a.Detail, "sni=example.com") {
		t.Fatalf("unexpected: %+v", a)
	}
	// truncated hello must not panic
	for i := 0; i < 60; i++ {
		_ = inspectPayload("TCP", 50000, 443, buildClientHello("example.com")[:i])
	}
}

func TestInspectHTTPStripsQueryAndKeepsUA(t *testing.T) {
	req := "GET /a?token=secret HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)\r\n\r\n"
	a := inspectPayload("TCP", 50000, 80, []byte(req))
	if a.Proto != "HTTP" || a.Role != "req" || strings.Contains(a.Detail, "secret") ||
		!strings.Contains(a.Detail, "Windows NT 10.0") || strings.Contains(a.Detail, `"`) {
		t.Fatalf("unexpected: %+v", a)
	}
}

func TestInspectModbus(t *testing.T) {
	a := inspectPayload("TCP", 50000, 502, []byte{0, 1, 0, 0, 0, 6, 1, 6, 0, 1, 0, 3})
	if a.Proto != "MODBUS" || a.Role != "req" || a.Func != "write_single_register" {
		t.Fatalf("unexpected: %+v", a)
	}
}
