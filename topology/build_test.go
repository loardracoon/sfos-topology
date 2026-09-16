package topology

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/tales/sfos-topology/sfos"
)

type envelope[T any] struct {
	Items []T `json:"items"`
}

func load[T any](t *testing.T, path string) []T {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e envelope[T]
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e.Items
}

// fw01 is the real lab appliance.
func fw01(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host:       "192.168.101.99:4444",
		Label:      "FW-LAB-01",
		Hostname:   "fw-lab-01",
		Zones:      load[sfos.Zone](t, "testdata/zones.json"),
		Interfaces: load[sfos.Interface](t, "testdata/interfaces.json"),
		Routes: []sfos.Route{
			{Name: "to-core", DestinationAddressIPv4: "10.50.0.0", CIDR: 16,
				GatewayIPv4: ptr("192.168.101.254")},
		},
	}
}

// fw02 is a synthetic peer: same upstream on Internet-01, and the far end of
// the xfrm1 transit net.
func fw02(t *testing.T) *sfos.Snapshot {
	ifs := []sfos.Interface{}
	raw := `[
	 {"name":"PortB","type":"physical","enabled":true,"hardwareName":"PortB","zone":{"name":"WAN"},
	  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.101.102","gatewayName":"Internet-01","gatewayIpAddress":"10.199.101.1","secondaryAddresses":[]}},
	 {"name":"PortA","type":"physical","enabled":true,"hardwareName":"PortA","zone":{"name":"LAN"},
	  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.98","gatewayName":"","gatewayIpAddress":"","secondaryAddresses":[]}},
	 {"name":"xfrm1","type":"xfrm","enabled":true,"hardwareName":"xfrm1","zone":{"name":"VPN"},
	  "ipv4":{"assignmentType":"static","cidr":30,"ipv4Address":"10.252.0.1"}}
	]`
	if err := json.Unmarshal([]byte(raw), &ifs); err != nil {
		t.Fatal(err)
	}
	return &sfos.Snapshot{
		Host:       "192.168.101.98:4444",
		Label:      "FW-LAB-02",
		Zones:      load[sfos.Zone](t, "testdata/zones.json"),
		Interfaces: ifs,
	}
}

func ptr(s string) *string { return &s }

func TestDecodeRealPayload(t *testing.T) {
	s := fw01(t)
	if len(s.Zones) != 5 {
		t.Fatalf("zones = %d, want 5", len(s.Zones))
	}
	// The WiFi zone reports type "lan": orientation must come from Type,
	// never from Name.
	var wifi sfos.Zone
	for _, z := range s.Zones {
		if z.Name == "WiFi" {
			wifi = z
		}
	}
	if wifi.Type != sfos.ZoneLAN {
		t.Fatalf("WiFi zone type = %q, want lan", wifi.Type)
	}

	byName := map[string]sfos.Interface{}
	for _, i := range s.Interfaces {
		byName[i.Name] = i
	}

	// Empty-string gateway must normalize to nil.
	if g := byName["PortA"].IPv4.GatewayIPAddress; g != nil {
		t.Fatalf("PortA gateway = %q, want nil", *g)
	}
	// Populated gateway must survive.
	if g := byName["PortB"].IPv4.GatewayName; g == nil || *g != "Internet-01" {
		t.Fatalf("PortB gatewayName not decoded: %v", g)
	}
	// xfrm omits memberOf/macAddress entirely.
	if byName["xfrm1"].MemberOf != nil {
		t.Fatal("xfrm1 memberOf should be nil")
	}
	// macAddress is the override field and is empty on every interface here.
	if m := byName["PortA"].MACAddress; m != nil {
		t.Fatalf("PortA macAddress = %q, expected empty/nil", *m)
	}
}

func TestOrientation(t *testing.T) {
	cases := []struct {
		it   sfos.InterfaceType
		zt   sfos.ZoneType
		want Orientation
	}{
		{sfos.IfPhysical, sfos.ZoneWAN, North},
		{sfos.IfPhysical, sfos.ZoneLAN, South},
		{sfos.IfPhysical, sfos.ZoneDMZ, South},
		{sfos.IfPhysical, sfos.ZoneDiscover, Passive},
		{sfos.IfXFRM, sfos.ZoneVPN, Overlay},
		// An xfrm parked in a LAN-typed zone is still overlay.
		{sfos.IfXFRM, sfos.ZoneLAN, Overlay},
	}
	for _, c := range cases {
		if got := OrientationFor(c.it, c.zt); got != c.want {
			t.Errorf("OrientationFor(%s,%s) = %s, want %s", c.it, c.zt, got, c.want)
		}
	}
}

func TestPointToPointPeer(t *testing.T) {
	cases := map[string]string{
		"10.252.0.2":  "10.252.0.1",
		"10.252.0.17": "10.252.0.18",
		"10.252.0.29": "10.252.0.30",
		"10.252.0.14": "10.252.0.13",
	}
	for in, want := range cases {
		got, ok := peerOfPointToPoint(in, 30)
		if !ok || got != want {
			t.Errorf("peer(%s/30) = %q ok=%v, want %s", in, got, ok, want)
		}
	}
	if _, ok := peerOfPointToPoint("192.168.1.1", 24); ok {
		t.Error("a /24 has no deterministic peer")
	}
}

func TestBuildSingleDevice(t *testing.T) {
	g := Build([]*sfos.Snapshot{fw01(t)})

	clouds := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == KindCloud {
			clouds[n.Label] = true
		}
	}
	// Two WAN gateways with different next hops are two upstreams, not one
	// "INTERNET" node.
	if len(clouds) != 2 || !clouds["Internet-01"] || !clouds["Internet-02"] {
		t.Fatalf("clouds = %v, want Internet-01 and Internet-02", clouds)
	}

	// The static route next hop is not an appliance: a ghost router appears.
	var ghost bool
	for _, n := range g.Nodes {
		if n.Kind == KindGateway && n.Label == "192.168.101.254" {
			ghost = true
		}
	}
	if !ghost {
		t.Fatal("expected an inferred ghost router for 192.168.101.254")
	}

	// Segments exclude overlay and count the three addressed south/north nets.
	segs := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == KindSegment {
			segs[n.CIDR] = true
		}
	}
	for _, want := range []string{"10.255.255.0/24", "192.168.101.0/24", "10.199.101.0/24", "10.199.201.0/24"} {
		if !segs[want] {
			t.Errorf("missing segment %s (got %v)", want, segs)
		}
	}
	if segs["10.252.0.0/30"] {
		t.Error("xfrm transit nets must not become segments")
	}

	// No appliance serial: identity must fall back and warn.
	for _, n := range g.Nodes {
		if n.Kind == KindDevice && len(n.Warnings) == 0 {
			t.Error("expected a warning about missing serial number")
		}
	}
}

func TestBuildTwoDevicesMergesAndPairs(t *testing.T) {
	g := Build([]*sfos.Snapshot{fw01(t), fw02(t)})

	// E3: both appliances sit in 10.199.101.0/24 on distinct addresses and
	// point at the same next hop, so the WAN segment is ONE node.
	if n := countSegments(g, "10.199.101.0/24"); n != 1 {
		t.Fatalf("10.199.101.0/24 produced %d segment nodes, want 1 (E3 merge)", n)
	}

	// E1: the two LAN interfaces share 192.168.101.0/24 on different addresses
	// (.99 and .98). Distinct addresses are consistent with one wire, so they
	// merge even without a shared gateway.
	if n := countSegments(g, "192.168.101.0/24"); n != 1 {
		t.Fatalf("192.168.101.0/24 produced %d segment nodes, want 1 (E1 merge)", n)
	}
	for _, n := range g.Nodes {
		if n.CIDR == "192.168.101.0/24" && n.OverlappingCIDR {
			t.Error("distinct addresses must not be flagged as overlapping")
		}
	}

	// Every upstream converges on one root.
	var world, worldEdges int
	for _, n := range g.Nodes {
		if n.Kind == KindWorld {
			world++
			if n.ID != WorldID {
				t.Errorf("root node id = %q, want %q", n.ID, WorldID)
			}
		}
	}
	for _, e := range g.Edges {
		if e.To == WorldID {
			worldEdges++
		}
	}
	if world != 1 {
		t.Fatalf("root nodes = %d, want exactly 1", world)
	}
	if worldEdges != 2 {
		t.Fatalf("edges into the root = %d, want 2 (one per upstream)", worldEdges)
	}

	// E8: xfrm1 on both ends of 10.252.0.0/30 is a confirmed overlay edge.
	var tunnel int
	for _, e := range g.Edges {
		if e.Orientation == Overlay && e.Confidence == Confirmed {
			tunnel++
			if len(e.Evidence) == 0 || e.Evidence[0].Rule != "E8" {
				t.Errorf("overlay edge missing E8 evidence: %+v", e)
			}
		}
	}
	if tunnel != 1 {
		t.Fatalf("overlay edges = %d, want 1", tunnel)
	}
}

// fw03 reuses FW-LAB-01's exact LAN address, which is what a second site
// running the same template looks like.
func fw03(t *testing.T) *sfos.Snapshot {
	ifs := []sfos.Interface{}
	raw := `[
	 {"name":"PortA","type":"physical","enabled":true,"hardwareName":"PortA","zone":{"name":"LAN"},
	  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.99","gatewayName":"","gatewayIpAddress":"","secondaryAddresses":[]}}
	]`
	if err := json.Unmarshal([]byte(raw), &ifs); err != nil {
		t.Fatal(err)
	}
	return &sfos.Snapshot{
		Host:       "192.168.103.99:4444",
		Label:      "FW-LAB-03",
		Zones:      load[sfos.Zone](t, "testdata/zones.json"),
		Interfaces: ifs,
	}
}

func TestSameAddressSplitsTheSegment(t *testing.T) {
	g := Build([]*sfos.Snapshot{fw01(t), fw03(t)})

	// E9: two appliances cannot hold 192.168.101.99 on the same wire, so this
	// is two networks reusing one range.
	if n := countSegments(g, "192.168.101.0/24"); n != 2 {
		t.Fatalf("192.168.101.0/24 produced %d segment nodes, want 2 (E9 split)", n)
	}
	var flagged int
	for _, n := range g.Nodes {
		if n.CIDR == "192.168.101.0/24" {
			if n.OverlappingCIDR {
				flagged++
			}
			if len(n.Warnings) == 0 {
				t.Error("a split segment must carry a warning")
			}
		}
	}
	if flagged != 2 {
		t.Fatalf("flagged segments = %d, want 2", flagged)
	}
}

func iptr(i int) *int { return &i }

func TestCloudNodeCarriesGatewayIP(t *testing.T) {
	g := Build([]*sfos.Snapshot{fw01(t)})

	var found bool
	for _, n := range g.Nodes {
		if n.Kind == KindCloud && n.Label == "Internet-01" {
			found = true
			if n.GatewayIP != "10.199.101.1" {
				t.Errorf("gatewayIp = %q, want 10.199.101.1", n.GatewayIP)
			}
		}
	}
	if !found {
		t.Fatal("Internet-01 cloud node not found")
	}
}

func TestAddressObjectsAttachToSegments(t *testing.T) {
	s1 := fw01(t)
	s1.IPAddresses = []sfos.IPHost{
		{Name: "LAN-Servers", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
		{Name: "DC-01", HostType: sfos.HostTypeIP, IPv4Address: ptr("192.168.101.10")},
		{Name: "Elsewhere", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("10.0.0.0"), CIDR: iptr(8)},
	}
	s2 := fw02(t)
	s2.IPAddresses = []sfos.IPHost{
		{Name: "LAN-Servers", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
	}

	g := Build([]*sfos.Snapshot{s1, s2})

	var seg *Node
	for i, n := range g.Nodes {
		if n.Kind == KindSegment && n.CIDR == "192.168.101.0/24" {
			seg = &g.Nodes[i]
		}
	}
	if seg == nil {
		t.Fatal("192.168.101.0/24 segment not found")
	}

	byName := map[string][]AddressObject{}
	for _, o := range seg.AddressObjects {
		byName[o.Name] = append(byName[o.Name], o)
	}

	if len(byName["DC-01"]) != 1 {
		t.Fatalf("DC-01 = %v, want exactly one entry", byName["DC-01"])
	}
	if byName["DC-01"][0].MultipleFirewalls {
		t.Error("DC-01 is defined by one appliance; must not carry multiple-firewalls")
	}
	if byName["DC-01"][0].Value != "192.168.101.10" {
		t.Errorf("DC-01 value = %q", byName["DC-01"][0].Value)
	}

	if len(byName["LAN-Servers"]) != 2 {
		t.Fatalf("LAN-Servers = %v, want one entry per appliance", byName["LAN-Servers"])
	}
	for _, o := range byName["LAN-Servers"] {
		if !o.MultipleFirewalls {
			t.Errorf("LAN-Servers entry from %s must carry multiple-firewalls", o.DeviceLabel)
		}
	}

	if len(byName["Elsewhere"]) != 0 {
		t.Error("a /8 object rooted at 10.0.0.0 must not attach to an unrelated 192.168.101.0/24 segment")
	}
}

func TestAddressObjectsDoNotBleedAcrossASplitSegment(t *testing.T) {
	s1 := fw01(t)
	s1.IPAddresses = []sfos.IPHost{
		{Name: "LAN-Servers", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
	}
	g := Build([]*sfos.Snapshot{s1, fw03(t)})

	if n := countSegments(g, "192.168.101.0/24"); n != 2 {
		t.Fatalf("192.168.101.0/24 produced %d segment nodes, want 2 (E9 split)", n)
	}

	var withObject, without int
	for _, n := range g.Nodes {
		if n.CIDR != "192.168.101.0/24" {
			continue
		}
		if len(n.AddressObjects) > 0 {
			withObject++
			if n.AddressObjects[0].DeviceLabel != "FW-LAB-01" {
				t.Errorf("object attached to the wrong segment's device: %+v", n.AddressObjects[0])
			}
		} else {
			without++
		}
	}
	if withObject != 1 || without != 1 {
		t.Fatalf("withObject=%d without=%d, want exactly one of each: FW-01's object must not "+
			"bleed onto FW-03's segment just because they share a CIDR string", withObject, without)
	}
}

func countSegments(g *Graph, cidr string) int {
	n := 0
	for _, node := range g.Nodes {
		if node.Kind == KindSegment && node.CIDR == cidr {
			n++
		}
	}
	return n
}
