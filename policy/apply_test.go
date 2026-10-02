package policy

import (
	"testing"

	"github.com/tales/sfos-topology/sfos"
	"github.com/tales/sfos-topology/topology"
)

func deviceIDFor(t *testing.T, g *topology.Graph, label string) string {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Kind == topology.KindDevice && n.Label == label {
			return n.ID
		}
	}
	t.Fatalf("no device labeled %q in graph", label)
	return ""
}

func TestResolveSideReusesExistingObject(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan101 := idFor(nets, "192.168.101.0/24")
	fw01ID := deviceIDFor(t, g, "FW-01")

	side := ResolveSide(g, lan101, fw01ID, "FW-01")
	if !side.ObjectExists || side.ObjectName != "LAN-101" {
		t.Errorf("side = %+v, want the existing LAN-101 object", side)
	}
	if len(side.ZoneNames) != 1 || side.ZoneNames[0] != "LAN" {
		t.Errorf("zoneNames = %v, want [LAN]", side.ZoneNames)
	}
	if side.NetAny {
		t.Error("a specific network must not resolve to NetAny")
	}
}

func TestResolveSideCreatesObjectWhenMissing(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	nets := Networks(g)
	lan102 := idFor(nets, "192.168.102.0/24")
	fw02ID := deviceIDFor(t, g, "FW-02")

	// fw02 has no named address objects at all (see the fixture), so Apply
	// would need to create one before it can write a rule.
	side := ResolveSide(g, lan102, fw02ID, "FW-02")
	if side.ObjectExists {
		t.Fatalf("side = %+v, want ObjectExists = false", side)
	}
	if side.NetworkAddress != "192.168.102.0" || side.CIDR != 24 {
		t.Errorf("side network/cidr = %s/%d, want 192.168.102.0/24", side.NetworkAddress, side.CIDR)
	}
	if side.ObjectName == "" {
		t.Error("a to-be-created side must still carry a deterministic name")
	}
	// Idempotent: resolving the same pair again proposes the same name, so a
	// re-apply after a partial failure does not create a second object.
	again := ResolveSide(g, lan102, fw02ID, "FW-02")
	if again.ObjectName != side.ObjectName {
		t.Errorf("AutoObjectName is not stable: %q vs %q", side.ObjectName, again.ObjectName)
	}
}

// TestResolveSideIgnoresInternalHostObjectPreferringNetworkObject reproduces
// a real bug caught against a live appliance: FW-101 names its LAN with a
// proper network object ("Firewall-101_LAN_SNET") but the API also lists an
// internal single-host object for the interface's own address ("#PortA"),
// which also falls inside the segment. '#' sorts before letters, so picking
// "the first address object for this device" (the old behavior) silently
// chose the host object -- a rule built from it would only ever match the
// firewall's own address, not the LAN it was designed against.
func TestResolveSideIgnoresInternalHostObjectPreferringNetworkObject(t *testing.T) {
	snap := &sfos.Snapshot{
		Host: "192.168.101.99:4444", Label: "FW-01",
		Zones: zones(t),
		Interfaces: ifaces(t, `[
		 {"name":"PortA","type":"physical","enabled":true,"zone":{"name":"LAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"192.168.101.99"}},
		 {"name":"PortB","type":"physical","enabled":true,"zone":{"name":"WAN"},
		  "ipv4":{"assignmentType":"static","cidr":24,"ipv4Address":"10.199.101.101","gatewayName":"Internet-01","gatewayIpAddress":"10.199.101.1"}}
		]`),
		IPAddresses: []sfos.IPHost{
			{Name: "#PortA", HostType: sfos.HostTypeIP, IPv4Address: ptr("192.168.101.99")},
			{Name: "Firewall-101_LAN_SNET", HostType: sfos.HostTypeNetwork, NetworkAddress: ptr("192.168.101.0"), CIDR: iptr(24)},
		},
	}

	g := build(t, snap)
	nets := Networks(g)
	lan101 := idFor(nets, "192.168.101.0/24")
	fwID := deviceIDFor(t, g, "FW-01")

	side := ResolveSide(g, lan101, fwID, "FW-01")
	if !side.ObjectExists {
		t.Fatalf("side = %+v, want an existing network object found", side)
	}
	if side.ObjectName != "Firewall-101_LAN_SNET" {
		t.Errorf("objectName = %q, want the named network object, not the interface's own host object", side.ObjectName)
	}
}

func TestResolveSideAnyUsesDeviceWANZoneNotAnyZone(t *testing.T) {
	g := build(t, fw01(t), fw02(t))
	fw01ID := deviceIDFor(t, g, "FW-01")

	side := ResolveSide(g, AnyID, fw01ID, "FW-01")
	if !side.NetAny {
		t.Error("Any must always resolve to NetAny = true (the module's own requirement)")
	}
	if !side.ObjectExists {
		t.Error("Any must always report as existing -- nothing to create")
	}
	if len(side.ZoneNames) != 1 || side.ZoneNames[0] != "WAN" {
		t.Errorf("zoneNames = %v, want [WAN] -- Any must not widen to any ZONE too", side.ZoneNames)
	}
}

func TestBuildRuleAllowSetsHeartbeatAndAuthOnlyWhenRequested(t *testing.T) {
	src := ResolvedSide{ZoneNames: []string{"LAN"}, ObjectName: "LAN-101", ObjectExists: true}
	dst := ResolvedSide{NetAny: true, ZoneNames: []string{"WAN"}, ObjectExists: true}

	plain := BuildRule(Cell{Action: Allow}, src, dst)
	if plain.Action != sfos.RuleAccept {
		t.Errorf("action = %q, want accept", plain.Action)
	}
	if plain.SynchronizedSecurityHeartbeat != nil || plain.UserAuthentication != nil {
		t.Error("heartbeat/auth must stay nil when not requested")
	}

	full := BuildRule(Cell{Action: Allow, RequireHeartbeat: true, RequireAuth: true}, src, dst)
	if full.SynchronizedSecurityHeartbeat == nil {
		t.Fatal("heartbeat must be set when requested")
	}
	if !full.SynchronizedSecurityHeartbeat.Source.BlockClientsWithNoHeartbeat {
		t.Error("source side must block clients with no heartbeat")
	}
	if full.UserAuthentication == nil {
		t.Fatal("userAuthentication must be set when requested")
	}
	if len(full.UserAuthentication.UsersOrGroups.UserGroups) != 1 ||
		full.UserAuthentication.UsersOrGroups.UserGroups[0].Name != "Open Group" {
		t.Errorf("userAuthentication groups = %+v, want [Open Group]", full.UserAuthentication.UsersOrGroups)
	}
}

func TestBuildRuleDenyNeverSetsHeartbeatOrAuth(t *testing.T) {
	src := ResolvedSide{ZoneNames: []string{"LAN"}, ObjectName: "LAN-101", ObjectExists: true}
	dst := ResolvedSide{NetAny: true, ZoneNames: []string{"WAN"}, ObjectExists: true}

	// The UI should never send RequireHeartbeat/RequireAuth alongside Deny,
	// but BuildRule defends against it anyway: a drop rule has no session to
	// gate on either field.
	r := BuildRule(Cell{Action: Deny, RequireHeartbeat: true, RequireAuth: true}, src, dst)
	if r.Action != sfos.RuleDrop {
		t.Errorf("action = %q, want drop", r.Action)
	}
	if r.SynchronizedSecurityHeartbeat != nil || r.UserAuthentication != nil {
		t.Error("a deny rule must never carry heartbeat or user-authentication restrictions")
	}
}

func TestBuildRuleNetworkSelectorsMatchSideKind(t *testing.T) {
	specific := ResolvedSide{ZoneNames: []string{"LAN"}, ObjectName: "LAN-101", ObjectExists: true}
	any := ResolvedSide{NetAny: true, ZoneNames: []string{"WAN"}, ObjectExists: true}

	r := BuildRule(Cell{Action: Allow}, specific, any)
	if r.SourceNetworks.Any || len(r.SourceNetworks.IPv4Addresses) != 1 || r.SourceNetworks.IPv4Addresses[0].Name != "LAN-101" {
		t.Errorf("sourceNetworks = %+v, want a named LAN-101 object, not Any", r.SourceNetworks)
	}
	if !r.DestinationNetworks.Any || len(r.DestinationNetworks.IPv4Addresses) != 0 {
		t.Errorf("destinationNetworks = %+v, want Any", r.DestinationNetworks)
	}
	if r.DestinationZones.Any || len(r.DestinationZones.Zones) != 1 || r.DestinationZones.Zones[0].Name != "WAN" {
		t.Errorf("destinationZones = %+v, want the specific WAN zone, not Any", r.DestinationZones)
	}
}
