package policy

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/tales/sfos-topology/sfos"
	"github.com/tales/sfos-topology/topology"
)

// This file turns one RuleIntent into the concrete Sophos selectors an Apply
// step sends over the wire. It is pure: no network call happens here, so it
// stays as testable as the rest of the package. The caller (cmd/sfos-topology)
// owns the actual HTTP round-trips, since only it holds per-device
// credentials.

// ResolvedSide is one side of a rule, resolved to what a specific appliance
// needs to write: which zone(s), and which network object.
type ResolvedSide struct {
	ZoneNames []string
	NetAny    bool
	// ObjectName is set when NetAny is false: the address object's name,
	// existing or (see ObjectExists) about to be created.
	ObjectName   string
	ObjectExists bool
	// NetworkAddress/CIDR are only meaningful when !ObjectExists: what
	// CreateAddressObject should create.
	NetworkAddress string
	CIDR           int
}

// ResolveSide resolves one axis id (a segment id, or AnyID) against one
// specific device. deviceLabel names the object Apply would create when none
// exists yet -- see AutoObjectName.
//
// For AnyID this follows the module's own requirement literally: "for WAN,
// don't consider the network, use Any" -- so the network side is always Any,
// but the zone is still the device's own WAN zone(s), not Any, matching every
// WAN-facing rule seen on a live capture (e.g. "Employees-to-Internet" has
// destinationZones: {zones:[WAN]}, destinationNetworks: {any:true}, never
// destinationZones: {any:true}). Any -> Any zones would be a much broader
// rule than "this network can reach the internet."
func ResolveSide(g *topology.Graph, netID, deviceID, deviceLabel string) ResolvedSide {
	if netID == AnyID {
		return ResolvedSide{ZoneNames: wanZoneNames(g, deviceID), NetAny: true, ObjectExists: true}
	}

	seg, ok := segmentsByID(g)[netID]
	if !ok {
		return ResolvedSide{NetAny: true, ObjectExists: true}
	}
	zoneName := deviceZoneForSegment(g, netID, deviceID)
	var zones []string
	if zoneName != "" {
		zones = []string{zoneName}
	}

	if o, ok := networkObjectFor(seg, deviceID); ok {
		return ResolvedSide{ZoneNames: zones, ObjectName: o.Name, ObjectExists: true}
	}

	addr, cidr := splitCIDR(seg.CIDR)
	return ResolvedSide{
		ZoneNames:      zones,
		ObjectName:     AutoObjectName(deviceLabel, zoneName, seg.CIDR),
		ObjectExists:   false,
		NetworkAddress: addr,
		CIDR:           cidr,
	}
}

// AutoObjectName is the deterministic name Apply gives a newly created
// address object for a network that has no named object yet on this
// appliance, e.g. "MATRIX_FW_02_LAN_192_168_102_0_24". It bakes in the CIDR,
// not just the zone name, so the one case this project already treats
// specially -- two segments sharing a CIDR string because they are split by
// E9 evidence -- can never collide on one device (a single appliance cannot
// itself have two interfaces on the identical CIDR, so this is always safe).
func AutoObjectName(deviceLabel, zoneName, cidr string) string {
	return "MATRIX_" + slug(deviceLabel) + "_" + slug(zoneName) + "_" + slug(cidr)
}

// networkObjectFor returns the one address object on seg, if any, that
// correctly stands in for the WHOLE segment in a rule's network selector:
// HostType must be a network, and its own prefix must equal seg's CIDR
// exactly -- not merely overlap it.
//
// seg.AddressObjects also carries objects matchSegment includes for good
// reason elsewhere (the inspector's "every named object touching this
// network" view): an interface's own single-host object, e.g. the
// appliance-managed "#PortA", falls inside the segment prefix too and would
// otherwise sort ahead of an admin-named network object alphabetically
// ('#' < letters). Reusing it here would scope a rule to one host address
// instead of the whole network -- syntactically valid, silently wrong. Exact
// prefix equality is the only test cheap enough to state and safe enough not
// to guess: a broader supernet or a narrower subset object might also
// "cover" the segment but would over- or under-scope the rule the admin
// designed against the network as a whole.
func networkObjectFor(seg topology.Node, deviceID string) (topology.AddressObject, bool) {
	for _, o := range seg.AddressObjects {
		if o.DeviceID == deviceID && strings.EqualFold(o.HostType, string(sfos.HostTypeNetwork)) && o.Value == seg.CIDR {
			return o, true
		}
	}
	return topology.AddressObject{}, false
}

func splitCIDR(cidr string) (address string, bits int) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", 0
	}
	return p.Addr().String(), p.Bits()
}

// deviceZoneForSegment finds which zone deviceID's own wire onto segID sits
// in, by walking the device -> segment edge Pass 2 of topology.Build drew
// (the same source of truth networkMembers uses) rather than matching on
// CIDR, which a split segment can share with an unrelated one.
func deviceZoneForSegment(g *topology.Graph, segID, deviceID string) string {
	var ifaces []topology.Iface
	for _, n := range g.Nodes {
		if n.Kind == topology.KindDevice && n.ID == deviceID {
			ifaces = n.Interfaces
			break
		}
	}
	ifaceByName := map[string]topology.Iface{}
	for _, f := range ifaces {
		ifaceByName[f.Name] = f
	}
	for _, e := range g.Edges {
		if e.From == deviceID && e.To == segID {
			if f, ok := ifaceByName[e.Label]; ok {
				return f.ZoneName
			}
		}
	}
	return ""
}

// wanZoneNames returns deviceID's own north-oriented zone name(s), sorted
// and de-duplicated. Almost always exactly one ("WAN"); more than one only on
// a dual-WAN appliance whose two links sit in differently named zones.
func wanZoneNames(g *topology.Graph, deviceID string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range g.Nodes {
		if n.Kind != topology.KindDevice || n.ID != deviceID {
			continue
		}
		for _, f := range n.Interfaces {
			if f.Orientation == topology.North && f.ZoneName != "" && !seen[f.ZoneName] {
				seen[f.ZoneName] = true
				out = append(out, f.ZoneName)
			}
		}
	}
	sort.Strings(out)
	return out
}

// BuildRule turns one Cell plus both sides' resolved selectors into the
// sfos.FirewallRule Apply sends. Heartbeat and user-authentication are only
// populated for Allow: a Deny rule with either set is meaningless (there is
// no session to authenticate or heartbeat-gate once the traffic is already
// dropped), and this project's one live sample showing both fields
// non-default was itself an accept rule -- see sfos.FirewallRule's doc for
// why a drop rule is not assumed to persist them at all.
func BuildRule(c Cell, source, destination ResolvedSide) sfos.FirewallRule {
	r := sfos.FirewallRule{
		Name:                c.RuleName(),
		Description:         "Managed by sfos-topology's access policy matrix. Edit the matrix, not this rule directly.",
		Enabled:             true,
		SourceZones:         zoneSelector(source),
		SourceNetworks:      networkSelector(source),
		DestinationZones:    zoneSelector(destination),
		DestinationNetworks: networkSelector(destination),
		ServicesOrGroups:    sfos.RuleServiceSelector{Any: true},
	}
	if c.Action == Allow {
		r.Action = sfos.RuleAccept
		if c.RequireHeartbeat {
			r.SynchronizedSecurityHeartbeat = &sfos.SecurityHeartbeat{
				Source:      sfos.HeartbeatSide{BlockClientsWithNoHeartbeat: true, MinimumLevel: sfos.HeartbeatGreen},
				Destination: sfos.HeartbeatSide{BlockClientsWithNoHeartbeat: false, MinimumLevel: sfos.HeartbeatNoRestriction},
			}
		}
		if c.RequireAuth {
			r.UserAuthentication = &sfos.UserAuthentication{
				UsersOrGroups:                    sfos.UsersOrGroups{UserGroups: []sfos.UserOrGroupRef{{Name: "Open Group"}}},
				WebAuthenticationForUnknownUsers: true,
			}
		}
	} else {
		r.Action = sfos.RuleDrop
	}
	return r
}

func zoneSelector(s ResolvedSide) sfos.RuleZoneSelector {
	if len(s.ZoneNames) == 0 {
		return sfos.RuleZoneSelector{Any: true}
	}
	zones := make([]sfos.ZoneRef, len(s.ZoneNames))
	for i, z := range s.ZoneNames {
		zones[i] = sfos.ZoneRef{Name: z}
	}
	return sfos.RuleZoneSelector{Zones: zones}
}

func networkSelector(s ResolvedSide) sfos.RuleNetworkSelector {
	if s.NetAny {
		return sfos.RuleNetworkSelector{Any: true}
	}
	return sfos.RuleNetworkSelector{IPv4Addresses: []sfos.AddressRef{{Name: s.ObjectName}}}
}

