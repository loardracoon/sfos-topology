package ipam

import (
	"encoding/json"
	"testing"

	"github.com/tales/sfos-topology/sfos"
	"github.com/tales/sfos-topology/topology"
)

func zones(t *testing.T) []sfos.Zone {
	t.Helper()
	return []sfos.Zone{
		{Name: "LAN", Type: sfos.ZoneLAN},
		{Name: "WAN", Type: sfos.ZoneWAN},
	}
}

func ifaces(t *testing.T, raw string) []sfos.Interface {
	t.Helper()
	var ifs []sfos.Interface
	if err := json.Unmarshal([]byte(raw), &ifs); err != nil {
		t.Fatal(err)
	}
	return ifs
}

func ptr(s string) *string { return &s }
func iptr(i int) *int      { return &i }

// fw01 and fw02 mirror the topology package's lab fixtures: two appliances on
// one merged WAN segment, each with its own LAN.
func fw01(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host: "192.168.101.99:4444", Label: "FW-LAB-01", Hostname: "fw-lab-01",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.99"}},
		 {"name":"PortB","type":"physical","enabled":true,"zone":{"name":"WAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.101.101","gatewayName":"Internet-01","gatewayIpAddress":"10.199.101.1"}}
		]`),
		IPAddresses: []sfos.IPHost{
			{Name: "LAN-Servers", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
			{Name: "DC-01", HostType: sfos.HostTypeIP, IPv4Address: ptr("192.168.101.10")},
			{Name: "Printer-Pool", HostType: sfos.HostTypeRange, RangeStart: ptr("192.168.101.200"), RangeEnd: ptr("192.168.101.210")},
		},
	}
}

func fw02(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host: "192.168.101.98:4444", Label: "FW-LAB-02",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.20.1"}},
		 {"name":"PortB","type":"physical","enabled":true,"zone":{"name":"WAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.101.102","gatewayName":"Internet-01","gatewayIpAddress":"10.199.101.1"}}
		]`),
	}
}

func build(t *testing.T, snaps ...*sfos.Snapshot) *Index {
	t.Helper()
	g := topology.Build(snaps)
	return Build(snaps, g)
}

func TestLookupExactInterfaceAddress(t *testing.T) {
	idx := build(t, fw01(t), fw02(t))

	res, status := idx.Lookup("192.168.101.99")
	if status != Found {
		t.Fatalf("status = %v, want Found", status)
	}
	if res.Ambiguous || len(res.Networks) != 1 {
		t.Fatalf("networks = %+v, want exactly 1, not ambiguous", res.Networks)
	}
	net := res.Networks[0]
	if net.Network.CIDR != "192.168.101.0/24" {
		t.Fatalf("cidr = %q", net.Network.CIDR)
	}
	if len(net.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(net.Members))
	}
	m := net.Members[0]
	if m.Device.Label != "FW-LAB-01" || m.Interface.Name != "PortA" {
		t.Fatalf("member = %+v", m)
	}
	if !m.Interface.IsQueriedAddress {
		t.Error("expected IsQueriedAddress on the exact match")
	}
}

func TestLookupNamesFromAddressObjects(t *testing.T) {
	idx := build(t, fw01(t), fw02(t))

	// A neighbour on the LAN, not an interface address: the Network object
	// should name it even though no interface holds this exact IP.
	res, status := idx.Lookup("192.168.101.50")
	if status != Found {
		t.Fatalf("status = %v", status)
	}
	net := res.Networks[0]
	if net.Network.Name != "LAN-Servers" || net.Network.NameSource != "address-object" {
		t.Fatalf("network = %+v", net.Network)
	}
	if net.Members[0].Interface.IsQueriedAddress {
		t.Error("192.168.101.50 is not PortA's own address")
	}

	// An exact IP host object beats the containing Network object.
	res, _ = idx.Lookup("192.168.101.10")
	if res.Networks[0].Network.Name != "DC-01" {
		t.Fatalf("name = %q, want DC-01 (host beats network)", res.Networks[0].Network.Name)
	}

	// A range object names an address the Network object also contains.
	res, _ = idx.Lookup("192.168.101.205")
	if res.Networks[0].Network.Name != "Printer-Pool" {
		t.Fatalf("name = %q, want Printer-Pool (range beats network)", res.Networks[0].Network.Name)
	}
}

func TestLookupFallsBackToInterfaceWhenNoObjectMatches(t *testing.T) {
	idx := build(t, fw01(t), fw02(t))

	res, status := idx.Lookup("192.168.20.5")
	if status != Found {
		t.Fatalf("status = %v", status)
	}
	net := res.Networks[0]
	if net.Network.Name != "" {
		t.Fatalf("name = %q, want empty (no address object on this network)", net.Network.Name)
	}
	if net.Network.CIDR != "192.168.20.0/24" {
		t.Fatalf("cidr = %q", net.Network.CIDR)
	}
	if len(net.Members) != 1 || net.Members[0].Interface.Name != "PortA" {
		t.Fatalf("members = %+v", net.Members)
	}
}

func TestLookupMergedWANSegmentListsBothDevices(t *testing.T) {
	idx := build(t, fw01(t), fw02(t))

	res, status := idx.Lookup("10.199.101.101")
	if status != Found {
		t.Fatalf("status = %v", status)
	}
	if res.Ambiguous || len(res.Networks) != 1 {
		t.Fatalf("networks = %+v, want exactly 1 merged network, not ambiguous", res.Networks)
	}
	if len(res.Networks[0].Members) != 2 {
		t.Fatalf("members = %d, want 2 (E3 merged both appliances onto one segment)", len(res.Networks[0].Members))
	}
}

// fw03 reuses FW-01's exact LAN address, which is what a second site running
// the same template looks like -- and is what forces topology.Build to split
// 192.168.101.0/24 into two separate segment nodes under rule E9.
func fw03(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host: "192.168.103.99:4444", Label: "FW-LAB-03",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.99"}}
		]`),
	}
}

func TestLookupWarnsOnASplitSegmentInsteadOfGuessing(t *testing.T) {
	idx := build(t, fw01(t), fw03(t))

	// Both segments genuinely claim the full 192.168.101.0/24 -- that is
	// what the E9 split means -- so there is no honest way to say a generic
	// address in it belongs to one appliance's network and not the other's.
	// Showing both, as two distinct candidates with a warning, is correct;
	// silently merging or picking one would misrepresent the topology.
	res, status := idx.Lookup("192.168.101.50")
	if status != Found {
		t.Fatalf("status = %v", status)
	}
	if !res.Ambiguous {
		t.Error("expected Ambiguous = true for a split-segment collision")
	}
	if len(res.Networks) != 2 {
		t.Fatalf("networks = %d, want 2 distinct candidates", len(res.Networks))
	}
	for _, n := range res.Networks {
		if len(n.Members) != 1 {
			t.Errorf("candidate %+v: members = %d, want 1 (one device per split segment)", n.Network, len(n.Members))
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a split-network warning")
	}
}

func TestLookupIgnoresObjectsFromDevicesNotOnTheNetwork(t *testing.T) {
	s2 := fw02(t)
	s2.IPAddresses = []sfos.IPHost{
		// FW-02 sits on 192.168.20.0/24, not 192.168.101.0/24. This object's
		// range numerically covers 192.168.101.50 too, but FW-02 has no
		// interface on that network, so it must not be considered for it --
		// only a device actually on the matched network gets to name it.
		{Name: "Should-Not-Apply", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.0.0"), CIDR: iptr(16)},
	}
	idx := build(t, fw01(t), s2)

	res, status := idx.Lookup("192.168.101.50")
	if status != Found {
		t.Fatalf("status = %v", status)
	}
	if res.Networks[0].Network.Name != "LAN-Servers" {
		t.Fatalf("name = %q, want LAN-Servers (FW-02's object is unrelated to this network)", res.Networks[0].Network.Name)
	}
}

func TestLookupPrefersTheMostSpecificNetworkObject(t *testing.T) {
	s1 := fw01(t)
	s1.IPAddresses = append(s1.IPAddresses,
		sfos.IPHost{Name: "Corp-Net", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.0.0"), CIDR: iptr(16)})
	idx := build(t, s1, fw02(t))

	// 192.168.0.0/16 (Corp-Net) contains 192.168.101.0/24 (LAN-Servers)
	// contains 192.168.101.10 (DC-01): the narrowest match must win at every
	// address that more than one object covers.
	res, _ := idx.Lookup("192.168.101.10")
	if res.Networks[0].Network.Name != "DC-01" {
		t.Errorf("name = %q, want DC-01 (host beats /24 and /16)", res.Networks[0].Network.Name)
	}
	res, _ = idx.Lookup("192.168.101.50")
	if res.Networks[0].Network.Name != "LAN-Servers" {
		t.Errorf("name = %q, want LAN-Servers (/24 beats /16)", res.Networks[0].Network.Name)
	}
}

func TestLookupNotFoundAndInvalid(t *testing.T) {
	idx := build(t, fw01(t), fw02(t))

	if _, status := idx.Lookup("8.8.8.8"); status != NotFound {
		t.Errorf("status = %v, want NotFound", status)
	}
	if _, status := idx.Lookup("not-an-ip"); status != Invalid {
		t.Errorf("status = %v, want Invalid", status)
	}
	if _, status := idx.Lookup("2001:db8::1"); status != Invalid {
		t.Errorf("status = %v, want Invalid (IPv6 unsupported)", status)
	}
}
