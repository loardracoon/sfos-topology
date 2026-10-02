// Package policy turns a simple network-by-network matrix into the concrete
// firewall rules it implies, one appliance at a time.
//
// The matrix's axes are the networks topology.Build already discovered:
// every LAN/DMZ/management segment, plus a single synthetic "Any" entry
// standing in for everything WAN-facing -- an administrator writes a policy
// against "the internet," never against one specific ISP hand-off.
//
// Phase 1 (this package): a cell says "Allow" or "Deny" between two
// networks, optionally requiring Security Heartbeat and/or an authenticated
// user, and optionally bidirectional (expanded into two independent cells
// upstream, in the store that owns persistence). Applicability is
// deliberately narrow: a cell only produces a rule intent on an appliance
// where at least one side is a network directly wired to it (the other side
// may be the universal "Any"). A network reachable only through an SD-WAN
// policy route on some other appliance is NOT detected yet -- that needs a
// second Sophos resource (SD-WAN policy routes) this package does not read,
// because its schema has not been confirmed against a live capture the way
// every other type in this project has been. Extend Applicable once that
// capture exists; do not guess at it.
//
// This package only computes what a cell WOULD do. It never calls the
// Sophos API -- that is deliberate until the firewall-rule request/response
// schema is confirmed against a real capture, the same discipline that
// caught sfos.IPHost's wrong field names before they shipped silently
// broken. Guessing the schema for a write endpoint that plants live
// security policy is a materially worse mistake to make quietly.
package policy

import (
	"sort"
	"strings"

	"github.com/tales/sfos-topology/topology"
)

// AnyID is the synthetic axis entry for every WAN-facing network.
const AnyID = "any"

// Network is one matrix axis entry.
type Network struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	CIDR  string `json:"cidr,omitempty"`
	IsAny bool   `json:"isAny,omitempty"`
	// Members is who actually calls this network something: the
	// appliance(s) with a wire on it and the zone name/type that wire sits
	// in, e.g. {DeviceLabel: "Firewall1", ZoneName: "Employees", ZoneType:
	// "lan"} -- a network's own CIDR is not a name an administrator
	// recognizes, but "Firewall1 / Employees" is. Almost always one entry;
	// more than one only for a network genuinely shared by several
	// appliances (a merged LAN is rare -- merged WANs are the common case,
	// and WAN networks never reach this axis at all).
	Members []NetworkMember `json:"members,omitempty"`
}

// NetworkMember names one appliance's own view of a Network: which zone,
// on which device, it calls this wire.
type NetworkMember struct {
	DeviceLabel string `json:"deviceLabel"`
	ZoneName    string `json:"zoneName"`
	ZoneType    string `json:"zoneType"`
}

// Device is enough of a topology device node to name it in a rule intent.
type Device struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Action is the effect of a policy cell.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Cell is one user-defined policy: Action applied to all traffic from
// Source to Destination, any service -- this is a macro switch, not a
// per-service rule builder, by design. A bidirectional policy is two Cells
// (one per direction, each with its own identity); expanding "bidi" into
// both is the caller's job (see the policy store), not this type's.
type Cell struct {
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	Action           Action `json:"action"`
	RequireHeartbeat bool   `json:"requireHeartbeat"`
	RequireAuth      bool   `json:"requireAuth"`
}

// Key identifies a cell by its axis pair, independent of its policy —
// used to find-or-replace a cell rather than accumulate duplicates when the
// same pair is edited again.
func (c Cell) Key() string { return c.Source + ">" + c.Destination }

// RuleName is the deterministic name a live-apply step (not yet built)
// would use to find this cell's own rule again on a given appliance, so
// reapplying the matrix updates it instead of piling up duplicates.
func (c Cell) RuleName() string {
	return "MATRIX_" + slug(c.Source) + "_TO_" + slug(c.Destination)
}

// slug turns a network id into the alphanumeric-plus-underscore form a
// Sophos rule name needs. It replaces anything else (a split segment's
// "#2" suffix included) rather than assuming a fixed set of punctuation to
// swap, so an id shaped differently than the ones seen so far still comes
// out safe instead of leaking a stray character into a rule name.
func slug(id string) string {
	if id == AnyID {
		return "ANY"
	}
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToUpper(id) {
		safe := (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		switch {
		case safe:
			b.WriteRune(r)
			prevUnderscore = false
		case !prevUnderscore:
			b.WriteByte('_')
			prevUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// Networks returns every matrix axis entry, sorted by label with "Any"
// pinned last so the matrix does not reshuffle between loads.
func Networks(g *topology.Graph) []Network {
	members := networkMembers(g)

	var nets []Network
	for _, n := range g.Nodes {
		if n.Kind != topology.KindSegment || n.Orientation == topology.North {
			continue // WAN-oriented segments collapse into the Any entry
		}
		nets = append(nets, Network{ID: n.ID, Label: n.Label, CIDR: n.CIDR, Members: members[n.ID]})
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].Label < nets[j].Label })
	return append(nets, Network{ID: AnyID, Label: "Any (WAN / Internet)", IsAny: true})
}

// networkMembers maps each segment id to the appliance(s) and zone(s) that
// actually sit on it, straight from the device -> segment edges Pass 2 of
// topology.Build drew (Edge.Label is that edge's interface name).
func networkMembers(g *topology.Graph) map[string][]NetworkMember {
	devLabel := map[string]string{}
	ifaceByKey := map[string]topology.Iface{}
	for _, n := range g.Nodes {
		if n.Kind != topology.KindDevice {
			continue
		}
		devLabel[n.ID] = n.Label
		for _, f := range n.Interfaces {
			ifaceByKey[f.DeviceID+"\x00"+f.Name] = f
		}
	}

	segIDs := segmentsByID(g)
	out := map[string][]NetworkMember{}
	seen := map[string]bool{} // segID + deviceID, so a device is not listed twice
	for _, e := range g.Edges {
		label, ok := devLabel[e.From]
		if !ok {
			continue
		}
		if _, ok := segIDs[e.To]; !ok {
			continue
		}
		f, ok := ifaceByKey[e.From+"\x00"+e.Label]
		if !ok {
			continue
		}
		key := e.To + "\x00" + e.From
		if seen[key] {
			continue
		}
		seen[key] = true
		out[e.To] = append(out[e.To], NetworkMember{
			DeviceLabel: label, ZoneName: f.ZoneName, ZoneType: f.ZoneType,
		})
	}
	for _, ms := range out {
		sort.Slice(ms, func(i, j int) bool { return ms[i].DeviceLabel < ms[j].DeviceLabel })
	}
	return out
}

// segmentsByID and connectedDevices are the two lookups every other
// function in this package builds on: which node is which segment, and
// which devices have a wire directly on it.
func segmentsByID(g *topology.Graph) map[string]topology.Node {
	m := map[string]topology.Node{}
	for _, n := range g.Nodes {
		if n.Kind == topology.KindSegment {
			m[n.ID] = n
		}
	}
	return m
}

func connectedDevices(g *topology.Graph) map[string]map[string]bool {
	devIDs := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == topology.KindDevice {
			devIDs[n.ID] = true
		}
	}
	segIDs := segmentsByID(g)

	members := map[string]map[string]bool{}
	for _, e := range g.Edges {
		if !devIDs[e.From] {
			continue
		}
		if _, ok := segIDs[e.To]; !ok {
			continue
		}
		if members[e.To] == nil {
			members[e.To] = map[string]bool{}
		}
		members[e.To][e.From] = true
	}
	return members
}

// ApplicableDevices returns the devices Phase 1 would touch for a
// source -> destination pair: the intersection of both sides' directly
// connected devices, or every device touching the one specific side when
// the other is Any -- Any is universal and never narrows the set on its
// own.
func ApplicableDevices(g *topology.Graph, sourceID, destinationID string) []Device {
	members := connectedDevices(g)
	devByID := map[string]Device{}
	for _, n := range g.Nodes {
		if n.Kind == topology.KindDevice {
			devByID[n.ID] = Device{ID: n.ID, Label: n.Label}
		}
	}

	srcAny, dstAny := sourceID == AnyID, destinationID == AnyID
	ids := map[string]bool{}
	switch {
	case srcAny && dstAny:
		// Any -> Any names no specific network on either side: nothing to
		// anchor the rule to one appliance, so it produces no intent.
	case srcAny:
		ids = members[destinationID]
	case dstAny:
		ids = members[sourceID]
	default:
		for id := range members[sourceID] {
			if members[destinationID][id] {
				ids[id] = true
			}
		}
	}

	out := make([]Device, 0, len(ids))
	for id := range ids {
		if d, ok := devByID[id]; ok {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// RuleIntent is the concrete rule Phase 1 would create or update on one
// specific appliance for one Cell. It is a preview: nothing in this package
// sends it anywhere.
type RuleIntent struct {
	Device      Device `json:"device"`
	RuleName    string `json:"ruleName"`
	SourceLabel string `json:"sourceLabel"`
	DestLabel   string `json:"destLabel"`
	Action      Action `json:"action"`
	// Service is always "Any": this matrix trades per-service precision for
	// a macro switch, by design.
	Service          string `json:"service"`
	RequireHeartbeat bool   `json:"requireHeartbeat"`
	RequireAuth      bool   `json:"requireAuth"`
	// SourceObjectExists/DestObjectExists report whether the appliance
	// already has a named address object for that side (Any always counts
	// as existing -- it is built in). False means a live-apply step would
	// need to create one first, per the module's own "if the network object
	// doesn't exist, create it" requirement.
	SourceObjectExists bool `json:"sourceObjectExists"`
	DestObjectExists   bool `json:"destObjectExists"`
}

// Intents expands one Cell into the rule(s) it implies, one per applicable
// device.
func Intents(g *topology.Graph, c Cell) []RuleIntent {
	segs := segmentsByID(g)
	nets := map[string]Network{}
	for _, n := range Networks(g) {
		nets[n.ID] = n
	}

	devices := ApplicableDevices(g, c.Source, c.Destination)
	out := make([]RuleIntent, 0, len(devices))
	for _, d := range devices {
		out = append(out, RuleIntent{
			Device:             d,
			RuleName:           c.RuleName(),
			SourceLabel:        axisLabel(nets, c.Source),
			DestLabel:          axisLabel(nets, c.Destination),
			Action:             c.Action,
			Service:            "Any",
			RequireHeartbeat:   c.RequireHeartbeat,
			RequireAuth:        c.RequireAuth,
			SourceObjectExists: hasObject(segs, c.Source, d.ID),
			DestObjectExists:   hasObject(segs, c.Destination, d.ID),
		})
	}
	return out
}

func axisLabel(nets map[string]Network, id string) string {
	if n, ok := nets[id]; ok {
		return n.Label
	}
	return id
}

// hasObject reports whether the appliance already has an address object that
// correctly stands in for the WHOLE segment -- see networkObjectFor (apply.go)
// for why "any object that happens to touch this network" is not the same
// question and would misreport an interface's own single-host object as if
// it were a usable stand-in for the network.
func hasObject(segs map[string]topology.Node, netID, deviceID string) bool {
	if netID == AnyID {
		return true // built into every appliance
	}
	seg, ok := segs[netID]
	if !ok {
		return false
	}
	_, ok = networkObjectFor(seg, deviceID)
	return ok
}
