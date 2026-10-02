package policy

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

// fw01 has two LANs (via a bridge/vlan-like split represented as two
// interfaces) plus a WAN, so ApplicableDevices has something to intersect.
func fw01(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host: "192.168.101.99:4444", Label: "FW-01",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.99"}},
		 {"name":"PortD","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.102.99"}},
		 {"name":"PortB","type":"physical","enabled":true,"zone":{"name":"WAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.101.101","gatewayName":"Internet-01","gatewayIpAddress":"10.199.101.1"}}
		]`),
		IPAddresses: []sfos.IPHost{
			{Name: "LAN-101", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
		},
	}
}

// fw02 only has the second LAN, not the first, so a policy between LAN-101
// and LAN-102 must not apply to it.
func fw02(t *testing.T) *sfos.Snapshot {
	return &sfos.Snapshot{
		Host: "192.168.102.98:4444", Label: "FW-02",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.102.1"}},
		 {"name":"PortB","type":"physical","enabled":true,"zone":{"name":"WAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.102.101","gatewayName":"Internet-02","gatewayIpAddress":"10.199.102.1"}}
		]`),
	}
}

func build(t *testing.T, snaps ...*sfos.Snapshot) *topology.Graph {
	t.Helper()
	return topology.Build(snaps)
}

func idFor(nets []Network, cidr string) string {
	for _, n := range nets {
		if n.CIDR == cidr {
			return n.ID
		}
	}
	return ""
}

func TestNetworksExcludesWANAndAddsAny(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)

	var sawWAN, sawAny bool
	for _, n := range nets {
		if n.CIDR == "10.199.101.0/24" || n.CIDR == "10.199.102.0/24" {
			sawWAN = true
		}
		if n.IsAny {
			sawAny = true
			if n.ID != AnyID {
				t.Errorf("Any entry id = %q, want %q", n.ID, AnyID)
			}
		}
	}
	if sawWAN {
		t.Error("a WAN-oriented segment leaked into the matrix axis")
	}
	if !sawAny {
		t.Error("expected a single Any entry standing in for WAN")
	}
	if nets[len(nets)-1].ID != AnyID {
		t.Error("Any must sort last")
	}
}

func TestNetworksCarryDeviceAndZoneForDisplay(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan101 := idFor(nets, "192.168.101.0/24")

	var n Network
	for _, x := range nets {
		if x.ID == lan101 {
			n = x
		}
	}
	if len(n.Members) != 1 {
		t.Fatalf("members = %+v, want exactly 1 (only FW-01 has this LAN)", n.Members)
	}
	m := n.Members[0]
	if m.DeviceLabel != "FW-01" {
		t.Errorf("deviceLabel = %q, want FW-01", m.DeviceLabel)
	}
	if m.ZoneName != "LAN" || m.ZoneType != "lan" {
		t.Errorf("zone = %+v, want name=LAN type=lan", m)
	}

	any := nets[len(nets)-1]
	if len(any.Members) != 0 {
		t.Errorf("Any must carry no members, got %+v", any.Members)
	}
}

func TestApplicableDevicesIntersectsBothSpecificSides(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan101 := idFor(nets, "192.168.101.0/24")
	lan102 := idFor(nets, "192.168.102.0/24")
	if lan101 == "" || lan102 == "" {
		t.Fatalf("expected both LANs on the axis, got %+v", nets)
	}

	// LAN-101 exists only on FW-01; LAN-102 exists on both. The rule can
	// only make sense on an appliance that has BOTH networks -- FW-01.
	devs := ApplicableDevices(g, lan101, lan102)
	if len(devs) != 1 || devs[0].Label != "FW-01" {
		t.Fatalf("devices = %+v, want exactly FW-01", devs)
	}
}

func TestApplicableDevicesWithAnyUsesTheSpecificSide(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan102 := idFor(nets, "192.168.102.0/24")

	// LAN-102 -> Any must land on every device that has LAN-102: both.
	devs := ApplicableDevices(g, lan102, AnyID)
	if len(devs) != 2 {
		t.Fatalf("devices = %+v, want FW-01 and FW-02", devs)
	}
}

func TestApplicableDevicesAnyToAnyIsEmpty(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	if devs := ApplicableDevices(g, AnyID, AnyID); len(devs) != 0 {
		t.Errorf("Any -> Any devices = %+v, want none (nothing to anchor the rule to)", devs)
	}
}

func TestIntentsReportsAddressObjectExistence(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan101 := idFor(nets, "192.168.101.0/24")

	c := Cell{Source: lan101, Destination: AnyID, Action: Allow, RequireHeartbeat: true}
	intents := Intents(g, c)
	if len(intents) != 1 {
		t.Fatalf("intents = %+v, want exactly 1 (only FW-01 has LAN-101)", intents)
	}
	in := intents[0]
	if in.Device.Label != "FW-01" {
		t.Errorf("device = %q, want FW-01", in.Device.Label)
	}
	if !in.SourceObjectExists {
		t.Error("FW-01 already has an address object for 192.168.101.0/24; expected SourceObjectExists")
	}
	if !in.DestObjectExists {
		t.Error("Any must always report as existing")
	}
	if in.Service != "Any" {
		t.Errorf("service = %q, want Any (macro matrix is service-agnostic)", in.Service)
	}
	if !in.RequireHeartbeat || in.RequireAuth {
		t.Errorf("heartbeat/auth flags not carried through: %+v", in)
	}
	if in.RuleName != c.RuleName() {
		t.Errorf("ruleName = %q, want %q", in.RuleName, c.RuleName())
	}
}

func TestIntentsMissingAddressObject(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan102 := idFor(nets, "192.168.102.0/24")

	// FW-02 has 192.168.102.0/24 wired but never defined a named object for
	// it (fw02 has no IPAddresses at all).
	c := Cell{Source: lan102, Destination: AnyID, Action: Deny}
	var forFW02 *RuleIntent
	for _, in := range Intents(g, c) {
		in := in
		if in.Device.Label == "FW-02" {
			forFW02 = &in
		}
	}
	if forFW02 == nil {
		t.Fatal("expected an intent for FW-02")
	}
	if forFW02.SourceObjectExists {
		t.Error("FW-02 has no address object for 192.168.102.0/24; expected SourceObjectExists = false")
	}
}

func TestRuleNameIsStableAndDistinctPerDirection(t *testing.T) {
	a := Cell{Source: "seg:10.0.0.0/24", Destination: AnyID}
	b := Cell{Source: AnyID, Destination: "seg:10.0.0.0/24"}
	if a.RuleName() == b.RuleName() {
		t.Error("opposite directions must not collide on the same rule name")
	}
	if a.RuleName() != (Cell{Source: "seg:10.0.0.0/24", Destination: AnyID}).RuleName() {
		t.Error("RuleName must be deterministic for the same pair")
	}
	// A rule name must only ever contain characters Sophos accepts in one --
	// a split segment's "seg:...#1" / "seg:...#2" id is exactly the kind of
	// punctuation that must not leak through, and the two must not collide.
	c1 := Cell{Source: "seg:192.168.101.0/24#1", Destination: AnyID}
	c2 := Cell{Source: "seg:192.168.101.0/24#2", Destination: AnyID}
	if c1.RuleName() == c2.RuleName() {
		t.Errorf("split-segment rule names collided: both %q", c1.RuleName())
	}
	for _, name := range []string{c1.RuleName(), c2.RuleName(), a.RuleName()} {
		for _, r := range name {
			safe := (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
			if !safe {
				t.Errorf("RuleName %q contains a character Sophos would likely reject: %q", name, r)
			}
		}
	}
}
