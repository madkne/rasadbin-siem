//go:build linux

package network

import (
	"encoding/binary"
	"testing"
)

func TestDecodeEthernetIPv4TCP(t *testing.T) {
	frame := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 51, 100, 20})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50
	tcp[13] = 0x02
	got, ok := decodeEthernet(frame, "eth0")
	if !ok {
		t.Fatal("expected IPv4 frame to be decoded")
	}
	if got.SourceIP != "192.0.2.10" || got.DestinationIP != "198.51.100.20" {
		t.Fatalf("unexpected IPs: %+v", got)
	}
	if got.SourcePort != 12345 || got.DestinationPort != 443 || got.Protocol != "TCP" {
		t.Fatalf("unexpected L4 fields: %+v", got)
	}
	if got.TCPFlags != 0x02 {
		t.Fatalf("TCP flags = %#x, want SYN", got.TCPFlags)
	}
}

func TestDecodeRejectsTruncatedEthernet(t *testing.T) {
	if _, ok := decodeEthernet([]byte{1, 2, 3}, "eth0"); ok {
		t.Fatal("expected truncated frame to be rejected")
	}
}
