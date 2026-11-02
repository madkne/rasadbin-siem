package asset

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Link is an observed communication between two assets. It is undirected for
// identity (one Link per pair) but oriented client -> server whenever a TCP
// handshake was seen. Links are kept in memory only: they describe live
// traffic, not inventory, and expire after Options.LinkTTL without traffic.
type Link struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"` // asset ID of the client side
	Target    string    `json:"target"` // asset ID of the server side
	Protocols []string  `json:"protocols"`
	Ports     []int     `json:"ports"` // service ports seen in TCP handshakes
	Packets   int64     `json:"packets"`
	Bytes     int64     `json:"bytes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Topology is the graph snapshot sent to the UI.
type Topology struct {
	Assets []Asset `json:"assets"`
	Links  []Link  `json:"links"`
}

type flow struct {
	src, dst string // normalized IPs
	proto    string
	port     int   // service port when a handshake packet told us
	orient   int   // +1: src is the client, -1: dst is the client, 0: unknown
	bytes    int64 // packet length as reported by the collector
}

var packetBytesRe = regexp.MustCompile(`\((\d+) bytes`)

// extractFlow parses a network-packets event. Both endpoints must be trackable
// addresses, otherwise there is no asset-to-asset link to draw.
func extractFlow(msg string, includePublic bool) (flow, bool) {
	m := packetRe.FindStringSubmatch(msg)
	if m == nil {
		return flow{}, false
	}
	src, ok1 := normalizeIP(m[2], includePublic)
	dst, ok2 := normalizeIP(m[4], includePublic)
	if !ok1 || !ok2 || src == dst {
		return flow{}, false
	}
	f := flow{src: src, dst: dst, proto: strings.ToUpper(m[1])}
	if f.proto == "TCP" && m[6] != "" {
		if v, err := strconv.ParseUint(m[6], 16, 8); err == nil {
			switch v {
			case 0x02: // SYN
				f.orient, f.port = 1, parsePort(m[5])
			case 0x12: // SYN-ACK
				f.orient, f.port = -1, parsePort(m[3])
			}
		}
	}
	if b := packetBytesRe.FindStringSubmatch(msg); b != nil {
		if n, err := strconv.ParseInt(b[1], 10, 64); err == nil {
			f.bytes = n
		}
	}
	return f, true
}

func linkID(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// recordLink must be called with s.mu held, after the endpoint assets were applied.
func (s *Service) recordLink(f flow, at time.Time) {
	a, b := "ip:"+f.src, "ip:"+f.dst
	if s.assets[a] == nil || s.assets[b] == nil {
		return // an endpoint was dropped by the inventory cap
	}
	client, server := a, b
	if f.orient < 0 {
		client, server = b, a
	}
	id := linkID(a, b)
	l := s.links[id]
	if l == nil {
		if len(s.links) >= s.opts.MaxLinks {
			s.droppedLinks++
			return
		}
		l = &Link{ID: id, Source: client, Target: server, FirstSeen: at, LastSeen: at}
		s.links[id] = l
	} else if f.orient != 0 {
		l.Source, l.Target = client, server
	}
	if at.After(l.LastSeen) {
		l.LastSeen = at
	}
	l.Packets++
	l.Bytes += f.bytes
	l.Protocols = addUnique(l.Protocols, f.proto, 8)
	if f.port > 0 {
		l.Ports = addPort(l.Ports, f.port, 16)
	}
	s.dirtyLinks[id] = struct{}{}
	delete(s.removedLinks, id)
}

// SetLinkHandler registers the receiver of FlushLinks batches.
func (s *Service) SetLinkHandler(fn func(changed []Link, removed []string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.onLinks = fn
	s.mu.Unlock()
}

// FlushLinks expires idle links and reports changed/removed links to the handler.
func (s *Service) FlushLinks() {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	if now.Sub(s.lastPrune) >= 30*time.Second {
		s.lastPrune = now
		cutoff := now.Add(-s.opts.LinkTTL)
		for id, l := range s.links {
			if l.LastSeen.Before(cutoff) {
				delete(s.links, id)
				delete(s.dirtyLinks, id)
				s.removedLinks[id] = struct{}{}
			}
		}
	}
	if len(s.dirtyLinks) == 0 && len(s.removedLinks) == 0 {
		s.mu.Unlock()
		return
	}
	changed := make([]Link, 0, len(s.dirtyLinks))
	for id := range s.dirtyLinks {
		if l := s.links[id]; l != nil {
			changed = append(changed, cloneLink(*l))
		}
	}
	removed := make([]string, 0, len(s.removedLinks))
	for id := range s.removedLinks {
		removed = append(removed, id)
	}
	s.dirtyLinks = map[string]struct{}{}
	s.removedLinks = map[string]struct{}{}
	fn := s.onLinks
	s.mu.Unlock()
	if fn != nil {
		fn(changed, removed)
	}
}

// Topology returns the most recently seen assets and the links among them.
func (s *Service) Topology(maxAssets, maxLinks int) Topology {
	t := Topology{Assets: []Asset{}, Links: []Link{}}
	if s == nil {
		return t
	}
	if maxLinks <= 0 {
		maxLinks = 5000
	}
	t.Assets, _ = s.List(Filter{Limit: maxAssets})
	ids := make(map[string]struct{}, len(t.Assets))
	for _, a := range t.Assets {
		ids[a.ID] = struct{}{}
	}
	s.mu.RLock()
	for _, l := range s.links {
		_, okS := ids[l.Source]
		_, okT := ids[l.Target]
		if okS && okT {
			t.Links = append(t.Links, cloneLink(*l))
		}
	}
	s.mu.RUnlock()
	sort.Slice(t.Links, func(i, j int) bool {
		if !t.Links[i].LastSeen.Equal(t.Links[j].LastSeen) {
			return t.Links[i].LastSeen.After(t.Links[j].LastSeen)
		}
		return t.Links[i].ID < t.Links[j].ID
	})
	if len(t.Links) > maxLinks {
		t.Links = t.Links[:maxLinks]
	}
	return t
}

func cloneLink(l Link) Link {
	l.Protocols = append([]string{}, l.Protocols...)
	l.Ports = append([]int{}, l.Ports...)
	return l
}
