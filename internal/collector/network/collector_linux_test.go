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

func TestDecodeEthernetIPv4TCPDetailed(t *testing.T) {
	frame := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	ip[1] = 0xb8
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[6] = 0x40 // DF
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], 0xdeadbeef)
	binary.BigEndian.PutUint32(tcp[8:12], 0xcafebabe)
	tcp[12] = 0x50 // data offset 5
	tcp[13] = 0x12 // SYN-ACK
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[18:20], 1234) // urgent
	got, ok := decodeEthernet(frame, "eth0")
	if !ok {
		t.Fatal("expected IPv4/TCP frame to be decoded")
	}
	if got.IPTTL != 64 || got.IPTOS != 0xb8 {
		t.Fatalf("unexpected IP TTL/TOS: ttl=%d tos=0x%02x", got.IPTTL, got.IPTOS)
	}
	if got.IPIdent != 0x1234 || got.IPFlags != 2 {
		t.Fatalf("unexpected IP id=0x%x flags=%d (want DF=2)", got.IPIdent, got.IPFlags)
	}
	if got.TCPSeq != 0xdeadbeef || got.TCPAck != 0xcafebabe {
		t.Fatalf("unexpected TCP seq=0x%x ack=0x%x", got.TCPSeq, got.TCPAck)
	}
	if got.TCPOff != 5 || got.TCPWindow != 65535 || got.TCPUrgent != 1234 {
		t.Fatalf("unexpected TCP off=%d win=%d urp=%d", got.TCPOff, got.TCPWindow, got.TCPUrgent)
	}
	if got.TCPFlags != 0x12 {
		t.Fatalf("TCP flags = %#x, want SYN-ACK", got.TCPFlags)
	}
}

func TestDecodeEthernetIPv4ICMP(t *testing.T) {
	frame := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 1 // ICMP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	icmp := ip[20:]
	icmp[0] = 8 // echo request
	icmp[1] = 0
	got, ok := decodeEthernet(frame, "eth0")
	if !ok {
		t.Fatal("expected IPv4/ICMP frame to be decoded")
	}
	if got.Protocol != "ICMP" || got.ICMPType != 8 || got.ICMPCode != 0 {
		t.Fatalf("unexpected ICMP: proto=%s type=%d code=%d", got.Protocol, got.ICMPType, got.ICMPCode)
	}
}

func TestDecodeEthernetIPv4UDP(t *testing.T) {
	frame := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 17 // UDP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], 12345)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	binary.BigEndian.PutUint16(udp[6:8], 0xabcd)
	got, ok := decodeEthernet(frame, "eth0")
	if !ok {
		t.Fatal("expected IPv4/UDP frame to be decoded")
	}
	if got.Protocol != "UDP" || got.SourcePort != 53 || got.DestinationPort != 12345 {
		t.Fatalf("unexpected UDP ports: %d -> %d", got.SourcePort, got.DestinationPort)
	}
	if got.UDPLen != 8 || got.UDPChecksum != 0xabcd {
		t.Fatalf("unexpected UDP len=%d cksum=0x%x", got.UDPLen, got.UDPChecksum)
	}
}

func TestDecodeEthernetWithVLAN(t *testing.T) {
	// 802.1Q tag: ethertype 0x8100, TCI=0x100a (vlan 10), then inner ethertype 0x0800.
	frame := make([]byte, 14+4+20+20)
	binary.BigEndian.PutUint16(frame[12:14], 0x8100)
	binary.BigEndian.PutUint16(frame[14:16], 0x100a) // vlan id 10
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	ip := frame[18:]
	ip[0] = 0x45
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	got, ok := decodeEthernet(frame, "eth0")
	if !ok {
		t.Fatal("expected VLAN-tagged IPv4 frame to be decoded")
	}
	if got.VLANID != 10 {
		t.Fatalf("unexpected VLAN ID %d, want 10", got.VLANID)
	}
}
