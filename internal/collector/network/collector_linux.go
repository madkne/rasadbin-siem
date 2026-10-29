//go:build linux

// Package network provides a minimal Linux AF_PACKET collector.
// It emits normalized L3/L4 metadata only; packet payloads are never retained.
package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

const ethPAll = 0x0003

type PacketEvent struct {
	Time            time.Time
	Interface       string
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string
	Length          int
	TCPFlags        byte
}

func (e PacketEvent) String() string {
	flags := ""
	if e.Protocol == "TCP" && e.TCPFlags != 0 {
		flags = fmt.Sprintf(" flags=0x%02x", e.TCPFlags)
	}
	if e.SourcePort != 0 || e.DestinationPort != 0 {
		return fmt.Sprintf("packet %s %s:%d -> %s:%d%s (%d bytes, interface=%s)",
			e.Protocol, e.SourceIP, e.SourcePort, e.DestinationIP, e.DestinationPort, flags, e.Length, e.Interface)
	}
	return fmt.Sprintf("packet %s %s -> %s%s (%d bytes, interface=%s)",
		e.Protocol, e.SourceIP, e.DestinationIP, flags, e.Length, e.Interface)
}

type Collector struct {
	iface string
	emit  func(PacketEvent)
}

func New(iface string, emit func(PacketEvent)) (*Collector, error) {
	if emit == nil {
		return nil, errors.New("network collector requires an event callback")
	}
	if strings.TrimSpace(iface) == "" {
		iface = "any"
	}
	if iface != "any" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return nil, fmt.Errorf("network interface %q: %w", iface, err)
		}
	}
	return &Collector{iface: iface, emit: emit}, nil
}

func (c *Collector) Interface() string { return c.iface }

// Run reads Ethernet frames from AF_PACKET until ctx is cancelled.
// TODO: support cooked capture on "any" (Linux cooked SLL/SLL2), VLAN stacks,
// IPv6 extension headers, fragment reassembly, capture filters and configurable
// snaplen/buffer sizes. "any" currently binds to all interfaces only by opening
// a packet socket without a bind; Ethernet parsing still applies per frame.
func (c *Collector) Run(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("open AF_PACKET socket (requires CAP_NET_RAW): %w", err)
	}
	defer syscall.Close(fd)

	if c.iface != "any" {
		iface, err := net.InterfaceByName(c.iface)
		if err != nil {
			return err
		}
		if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: iface.Index}); err != nil {
			return fmt.Errorf("bind capture socket to %s: %w", c.iface, err)
		}
	}
	// A short receive timeout lets the loop observe cancellation without a
	// goroutine blocked forever in Recvfrom.
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set capture receive timeout: %w", err)
	}
	buf := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("read packet: %w", err)
		}
		if n <= 0 {
			continue
		}
		ev, ok := decodeEthernet(buf[:n], c.iface)
		if ok {
			c.emit(ev)
		}
	}
}

func decodeEthernet(frame []byte, iface string) (PacketEvent, bool) {
	if len(frame) < 14 {
		return PacketEvent{}, false
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	// Basic 802.1Q / 802.1ad support.
	for ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < offset+4 {
			return PacketEvent{}, false
		}
		ethType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if ethType != 0x0800 || len(frame) < offset+20 {
		return PacketEvent{}, false
	}
	ip := frame[offset:]
	if ip[0]>>4 != 4 {
		return PacketEvent{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return PacketEvent{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl {
		return PacketEvent{}, false
	}
	if totalLen > len(ip) {
		totalLen = len(ip)
	}
	proto := "IP"
	ev := PacketEvent{Time: time.Now().UTC(), Interface: iface,
		SourceIP: net.IP(ip[12:16]).String(), DestinationIP: net.IP(ip[16:20]).String(),
		Protocol: proto, Length: offset + totalLen}
	l4 := ip[ihl:totalLen]
	switch ip[9] {
	case syscall.IPPROTO_TCP:
		ev.Protocol = "TCP"
		if len(l4) < 20 {
			return ev, true
		}
		ev.SourcePort = binary.BigEndian.Uint16(l4[0:2])
		ev.DestinationPort = binary.BigEndian.Uint16(l4[2:4])
		ev.TCPFlags = l4[13]
	case syscall.IPPROTO_UDP:
		ev.Protocol = "UDP"
		if len(l4) < 8 {
			return ev, true
		}
		ev.SourcePort = binary.BigEndian.Uint16(l4[0:2])
		ev.DestinationPort = binary.BigEndian.Uint16(l4[2:4])
	case syscall.IPPROTO_ICMP:
		ev.Protocol = "ICMP"
	}
	return ev, true
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }
