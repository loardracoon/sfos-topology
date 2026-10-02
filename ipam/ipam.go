// Package ipam answers "what is this address" for one IP: which network
// contains it, through which device and interface, and — when the fleet
// defines a named address object for it — what an administrator calls that
// network instead of its bare CIDR.
//
// It is an in-memory index rebuilt from scratch on every collection pass,
// the same lifecycle the topology graph already has. This project ships as a
// single dependency-free binary meant to build with a bare Go toolchain on a
// jump host with no module proxy (see cmd/sfos-topology); a persistent
// database would break that, and nothing here needs data to survive a
// restart — the fleet itself is the source of truth on the next pass.
package ipam

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/tales/sfos-topology/sfos"
	"github.com/tales/sfos-topology/topology"
)

// Status distinguishes "no network contains this address" from "this is not
// even a valid address," because those deserve different HTTP statuses at
// the API boundary.
type Status int

const (
	Found Status = iota
	NotFound
	Invalid
)

type Device struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Hostname string `json:"hostname,omitempty"`
	Serial   string `json:"serial,omitempty"`
}

type Interface struct {
	Name     string `json:"name"`
	ZoneName string `json:"zoneName"`
	ZoneType string `json:"zoneType"`
	Addr     string `json:"addr"`
	// IsQueriedAddress marks the interface that holds the exact address
	// looked up, as opposed to a neighbour on the same network.
	IsQueriedAddress bool `json:"isQueriedAddress,omitempty"`
}

// Membership is one device's interface on the matched network. A network
// shared by more than one appliance (a merged WAN segment, an HA pair) lists
// one entry per interface, not one entry for the network.
type Membership struct {
	Device    Device    `json:"device"`
	Interface Interface `json:"interface"`
}

type Network struct {
	CIDR string `json:"cidr"`
	// Name is the friendliest label found for this network: the name of a
	// matching Sophos address object when one exists. Empty means no object
	// matched — the caller still has the CIDR and each member's interface
	// name, which is the "just the network interface" fallback.
	Name       string `json:"name,omitempty"`
	NameSource string `json:"nameSource,omitempty"` // "address-object" when Name is set
}

// NetworkGroup is one candidate network a lookup resolved to: its identity
// plus the memberships that belong to it. Ordinarily a Result has exactly
// one; an E9 split segment produces two, each a distinct network that
// genuinely claims the address, not one merged guess.
type NetworkGroup struct {
	Network Network      `json:"network"`
	Members []Membership `json:"members"`
}

type Result struct {
	IP string `json:"ip"`
	// Networks is never empty on a Found result. Ambiguous is true exactly
	// when it holds more than one entry, so a caller does not have to infer
	// "collision" from the slice length.
	Networks  []NetworkGroup `json:"networks"`
	Ambiguous bool           `json:"ambiguous,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

type membership struct {
	prefix netip.Prefix
	segID  string
	dev    Device
	iface  Interface
}

// Index is the table this package builds fresh from every collection pass:
// one row per (network, device, interface) membership, plus every named
// address object the fleet defines, filed by the device that defines it.
type Index struct {
	members         []membership
	objectsByDevice map[string][]sfos.IPHost
}

// Build assembles the index from the same snapshots and graph the topology
// viewer already produced, so a network's membership here always agrees with
// what the diagram shows — including a network that rule E9 split into two
// separate nodes because two appliances collide on the same address inside
// it.
//
// Every address object the fleet defines is kept (objectsByDevice), but
// Lookup only ever consults the ones filed under a device that is actually a
// member of the network being resolved — an object is "related to a network
// on the topology" precisely because the device that defines it sits on that
// network, not because its own range happens to overlap the right numbers.
// That distinction is what keeps two E9-split networks sharing one CIDR
// string from borrowing each other's names.
func Build(snaps []*sfos.Snapshot, g *topology.Graph) *Index {
	idx := &Index{objectsByDevice: map[string][]sfos.IPHost{}}

	devByID := map[string]Device{}
	ifaceByKey := map[string]topology.Iface{}
	for _, n := range g.Nodes {
		if n.Kind != topology.KindDevice {
			continue
		}
		devByID[n.ID] = Device{ID: n.ID, Label: n.Label, Hostname: n.Hostname, Serial: n.Serial}
		for _, f := range n.Interfaces {
			ifaceByKey[f.DeviceID+"\x00"+f.Name] = f
		}
	}

	segByID := map[string]topology.Node{}
	for _, n := range g.Nodes {
		if n.Kind == topology.KindSegment {
			segByID[n.ID] = n
		}
	}

	// Device -> segment edges are the only edges Pass 2 of topology.Build
	// emits with an interface name as the label, so this walk recovers
	// exactly the memberships the drawing shows without re-deriving
	// containment or the E1/E3/E9 merge rules a second time.
	for _, e := range g.Edges {
		seg, ok := segByID[e.To]
		if !ok {
			continue
		}
		dev, ok := devByID[e.From]
		if !ok {
			continue
		}
		f, ok := ifaceByKey[e.From+"\x00"+e.Label]
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(seg.CIDR)
		if err != nil {
			continue
		}
		idx.members = append(idx.members, membership{
			prefix: p.Masked(),
			segID:  seg.ID,
			dev:    dev,
			iface: Interface{
				Name: f.Name, ZoneName: f.ZoneName, ZoneType: f.ZoneType, Addr: f.Addr,
			},
		})
	}

	for _, s := range snaps {
		if len(s.IPAddresses) == 0 {
			continue
		}
		devID, _ := topology.DeviceID(s)
		idx.objectsByDevice[devID] = s.IPAddresses
	}

	return idx
}

// Lookup resolves one address against the index Build produced.
func (idx *Index) Lookup(raw string) (*Result, Status) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return nil, Invalid
	}

	bestBits := -1
	for _, m := range idx.members {
		if m.prefix.Contains(addr) && m.prefix.Bits() > bestBits {
			bestBits = m.prefix.Bits()
		}
	}
	if bestBits < 0 {
		return nil, NotFound
	}

	// Group by segment rather than merging into one list: two segments can
	// share the identical CIDR string after an E9 split precisely because
	// they are NOT the same network, and a caller needs to be able to tell
	// them apart, not just see a longer member list.
	bySeg := map[string][]membership{}
	var segOrder []string
	for _, m := range idx.members {
		if !m.prefix.Contains(addr) || m.prefix.Bits() != bestBits {
			continue
		}
		if _, ok := bySeg[m.segID]; !ok {
			segOrder = append(segOrder, m.segID)
		}
		bySeg[m.segID] = append(bySeg[m.segID], m)
	}
	sort.Strings(segOrder)

	groups := make([]NetworkGroup, 0, len(segOrder))
	for _, segID := range segOrder {
		ms := bySeg[segID]
		deviceIDs := map[string]bool{}
		var members []Membership
		var cidr string
		for _, m := range ms {
			deviceIDs[m.dev.ID] = true
			cidr = m.prefix.String()
			iface := m.iface
			if host, _, ok := strings.Cut(iface.Addr, "/"); ok {
				if a, err := netip.ParseAddr(host); err == nil && a == addr {
					iface.IsQueriedAddress = true
				}
			}
			members = append(members, Membership{Device: m.dev, Interface: iface})
		}
		sort.Slice(members, func(i, j int) bool {
			if members[i].Device.ID != members[j].Device.ID {
				return members[i].Device.ID < members[j].Device.ID
			}
			return members[i].Interface.Name < members[j].Interface.Name
		})

		net := Network{CIDR: cidr}
		// Scoped to THIS segment's own devices, not the union across every
		// matched segment -- an ambiguous lookup must never let an object
		// from one candidate's device name the other candidate too.
		if name, ok := idx.bestName(addr, deviceIDs); ok {
			net.Name = name
			net.NameSource = "address-object"
		}
		groups = append(groups, NetworkGroup{Network: net, Members: members})
	}

	res := &Result{IP: addr.String(), Networks: groups}
	if len(groups) > 1 {
		res.Ambiguous = true
		res.Warnings = append(res.Warnings,
			"this address matches more than one distinct network in the topology (duplicate/overlapping addressing across appliances) -- both candidates are shown below, neither was picked for you")
	}
	return res, Found
}

// bestName picks the most specific named address object covering addr, among
// only the objects defined by a device in deviceIDs — a device that is
// actually a member of the network being resolved. An exact host (or list
// membership) beats a range, which beats a network, and among networks the
// narrower prefix wins: a /24 naming exactly this network outranks a /16
// naming the wider block it sits in, which in turn outranks nothing at all.
func (idx *Index) bestName(addr netip.Addr, deviceIDs map[string]bool) (string, bool) {
	const (
		none = iota
		asNetwork
		asRange
		asHost
	)
	rank, specificity, name := none, -1, ""
	consider := func(r, spec int, n string) {
		if r > rank || (r == rank && spec > specificity) {
			rank, specificity, name = r, spec, n
		}
	}

	for devID := range deviceIDs {
		for _, h := range idx.objectsByDevice[devID] {
			switch {
			case h.HostType.Is(sfos.HostTypeNetwork):
				if p, ok := h.Prefix(); ok && p.Contains(addr) {
					consider(asNetwork, p.Bits(), h.Name)
				}
			case h.HostType.Is(sfos.HostTypeRange):
				if h.InRange(addr) {
					consider(asRange, 0, h.Name)
				}
			case h.HostType.Is(sfos.HostTypeList):
				for _, s := range h.Addresses {
					if a, err := netip.ParseAddr(s); err == nil && a == addr {
						consider(asHost, 32, h.Name)
						break
					}
				}
			default: // HostTypeIP, or an unrecognised/empty type: a bare host address
				if h.IPv4Address == nil {
					continue
				}
				if a, err := netip.ParseAddr(*h.IPv4Address); err == nil && a == addr {
					consider(asHost, 32, h.Name)
				}
			}
		}
	}
	return name, rank != none
}
