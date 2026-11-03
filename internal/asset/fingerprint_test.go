package asset

import (
	"testing"
	"time"
)

func TestWindowsSYNFingerprint(t *testing.T) {
	s := NewService(Options{}, nil)
	s.ObserveEvent(SourceNetwork, "packet TCP 10.0.0.5:50000 -> 10.0.0.9:443 flags=0x02 (66 bytes, interface=eth0) ttl=128 id=1 frag=0x2 win=64240 doff=8 opts=mss,nop,ws,nop,nop,sackok mss=1460 ws=8", time.Now())
	a, _ := s.Get("ip:10.0.0.5")
	if a.OperatingSystem != "Windows" || a.OSVersion != "10/11/Server 2016+" || a.OSConfidence < 0.8 || a.OSSource != OSSourcePassive {
		t.Fatalf("unexpected OS: %+v", a)
	}
}

func TestUserAgentRefinesVersion(t *testing.T) {
	s := NewService(Options{}, nil)
	s.ObserveEvent(SourceNetwork, `packet TCP 10.0.0.5:50000 -> 10.0.0.9:80 flags=0x18 (200 bytes, interface=eth0) ttl=128 app=HTTP role=req info="GET /x host=a ua=Mozilla/5.0 (Windows NT 6.1; WOW64)"`, time.Now())
	a, _ := s.Get("ip:10.0.0.5")
	if a.OperatingSystem != "Windows" || a.OSVersion != "7" {
		t.Fatalf("unexpected OS: %+v", a)
	}
}

func TestInfoCannotSpoofTrustedFields(t *testing.T) {
	s := NewService(Options{}, nil)
	s.ObserveEvent(SourceNetwork, `packet TCP 10.0.0.5:50000 -> 10.0.0.9:80 flags=0x18 (200 bytes, interface=eth0) app=HTTP role=req info="GET / ua=x ttl=128 win=64240"`, time.Now())
	a, _ := s.Get("ip:10.0.0.5")
	if a.OperatingSystem != "" {
		t.Fatalf("free text must not act as fingerprint input: %+v", a)
	}
}

func TestManualOSIsNotOverwritten(t *testing.T) {
	s := NewService(Options{}, nil)
	m, err := s.AddManual(Asset{IPs: []string{"10.0.0.7"}, OperatingSystem: "Custom OS"})
	if err != nil {
		t.Fatal(err)
	}
	s.ObserveEvent(SourceNetwork, "packet TCP 10.0.0.7:50000 -> 10.0.0.9:443 flags=0x02 (66 bytes, interface=eth0) ttl=128 win=64240 opts=mss,nop,ws,nop,nop,sackok ws=8", time.Now())
	a, _ := s.Get(m.ID)
	if a.OperatingSystem != "Custom OS" || a.OSSource != OSSourceManual {
		t.Fatalf("manual OS overwritten: %+v", a)
	}
}

func TestDHCPAttributesHostnameAndOSByRequestedIP(t *testing.T) {
	s := NewService(Options{}, nil)
	s.ObserveEvent(SourceNetwork, `packet UDP 0.0.0.0:68 -> 255.255.255.255:67 (342 bytes, interface=eth0) src_mac=00:11:22:33:44:55 dst_mac=ff:ff:ff:ff:ff:ff app=DHCP role=req info="Request ip=10.0.0.20 host=laptop-1 prl=1,3,6,15,31,33,43,44,46,47,119,121,249,252 vendor=MSFT 5.0"`, time.Now())
	a, ok := s.Get("ip:10.0.0.20")
	if !ok || a.Hostname != "laptop-1" || a.OperatingSystem != "Windows" || len(a.MACAddresses) != 1 {
		t.Fatalf("unexpected: %+v ok=%v", a, ok)
	}
}
