// Package topology turns a set of per-appliance snapshots into a single
// annotated graph.
//
// The graph is derived entirely from configuration. No ARP table, no live DHCP
// lease and no LLDP is available from the Sophos Firewall Configuration API,
// so adjacency is inferred from shared gateways, /30 tunnel arithmetic and
// static routes. Every inferred edge carries the evidence that produced it, so
// the UI can explain itself and a wrong edge can be traced to a rule instead of
// to a hunch.
package topology

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/tales/sfos-topology/sfos"
)

type Orientation string

const (
	North      Orientation = "north"      // WAN, toward the internet
	South      Orientation = "south"      // LAN and DMZ, internal
	Overlay    Orientation = "overlay"    // VPN, no layout rank
	Management Orientation = "management" // hidden by default
	Passive    Orientation = "passive"    // Discover/TAP ports: no traffic edge
)

type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Inferred  Confidence = "inferred"
	Assumed   Confidence = "assumed"
)

type NodeKind string

const (
	KindDevice  NodeKind = "device"
	KindSegment NodeKind = "segment"
	KindGateway NodeKind = "gateway" // next hop that is not a known device
	KindCloud   NodeKind = "cloud"   // upstream beyond a WAN gateway
	KindWorld   NodeKind = "world"   // the single root every uplink ends at
)

// WorldID is the root node. Every upstream converges on it, so a reader can
// see at a glance which appliances reach the outside and by how many paths.
const WorldID = "world"

type Node struct {
	ID    string   `json:"id"`
	Kind  NodeKind `json:"kind"`
	Label string   `json:"label"`

	// Device fields
	Serial     string   `json:"serial,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	HAPeers    []string `json:"haPeers,omitempty"`
	Interfaces []Iface  `json:"interfaces,omitempty"`

	// Segment fields
	CIDR            string          `json:"cidr,omitempty"`
	OverlappingCIDR bool            `json:"overlappingCidr,omitempty"`
	AddressObjects  []AddressObject `json:"addressObjects,omitempty"`

	// Cloud fields
	GatewayIP string `json:"gatewayIp,omitempty"`
	// GatewayCIDR is GatewayIP with the prefix length of the local WAN
	// interface it was read from (the gateway itself carries no prefix of
	// its own -- it shares the interface's subnet). Display-only.
	GatewayCIDR string `json:"gatewayCidr,omitempty"`

	Orientation Orientation `json:"orientation,omitempty"`
	Warnings    []string    `json:"warnings,omitempty"`
}

// AddressObject is a Sophos-named address object attached to a segment
// because it names all or part of that network. The same physical network is
// often described independently by every appliance that sits on it, so this
// keeps the device that defined it rather than collapsing to one pick --
// disagreement between appliances is a fact about the fleet worth showing,
// not something to hide behind a single "best" name.
type AddressObject struct {
	Name     string `json:"name"`
	HostType string `json:"hostType"`
	// Value is what the object actually covers, in a form worth reading:
	// the object's own prefix for a Network, the bare address for an IP,
	// "start - end" for a range, the matching addresses for a list.
	Value       string `json:"value"`
	DeviceID    string `json:"deviceId"`
	DeviceLabel string `json:"deviceLabel"`
	// MultipleFirewalls marks an object whose name is defined, for this same
	// network, by more than one appliance in the fleet -- usually two
	// configs that drifted apart rather than two appliances agreeing on
	// purpose, and worth a second look either way.
	MultipleFirewalls bool `json:"multipleFirewalls,omitempty"`
}

type Iface struct {
	DeviceID    string      `json:"deviceId"`
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	ZoneName    string      `json:"zoneName"`
	ZoneType    string      `json:"zoneType"`
	Orientation Orientation `json:"orientation"`
	Addr        string      `json:"addr,omitempty"` // a.b.c.d/len
	GatewayName string      `json:"gatewayName,omitempty"`
	GatewayIP   string      `json:"gatewayIp,omitempty"`
	MemberOf    string      `json:"memberOf,omitempty"`
	Enabled     bool        `json:"enabled"`
	// IsAPIPath marks the interface whose address matches the host the
	// collector connected to.
	IsAPIPath bool `json:"isApiPath,omitempty"`
}

func (i Iface) id() string { return i.DeviceID + ":" + i.Name }

type Evidence struct {
	Rule   string `json:"rule"` // E1, E3, E5, E6, E8...
	Detail string `json:"detail"`
}

type Edge struct {
	From        string      `json:"from"`
	To          string      `json:"to"`
	Orientation Orientation `json:"orientation"`
	Confidence  Confidence  `json:"confidence"`
	Label       string      `json:"label,omitempty"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// OrientationFor maps an interface to a layout orientation.
//
// Zone type is the primary key, but it is coarser than the zone list: a "WiFi"
// zone reports type "lan", and admin-created zones reuse the same types. An
// xfrm interface is always overlay regardless of the zone it sits in.
func OrientationFor(ifaceType sfos.InterfaceType, zoneType sfos.ZoneType) Orientation {
	if ifaceType == sfos.IfXFRM {
		return Overlay
	}
	switch zoneType {
	case sfos.ZoneWAN:
		return North
	case sfos.ZoneLAN, sfos.ZoneDMZ:
		return South
	case sfos.ZoneVPN:
		return Overlay
	case sfos.ZoneLocal:
		return Management
	case sfos.ZoneDiscover:
		return Passive
	}
	return South
}

// DeviceID prefers the Central serial number. Falling back to the management
// host is deliberate but lossy: the ID changes if the appliance is re-addressed,
// which breaks snapshot-to-snapshot diffing.
//
// Exported so other packages (ipam) that need to correlate a *sfos.Snapshot
// back to the device node Build produced for it use the exact same identity
// rule instead of re-deriving it and risking drift.
func DeviceID(s *sfos.Snapshot) (string, []string) {
	var warn []string
	if s.Central.Registration.Registered && s.Central.Registration.SerialNumber != "" {
		return "serial:" + s.Central.Registration.SerialNumber, warn
	}
	warn = append(warn, "no serial number (appliance not registered with Sophos Central); node identity falls back to management address and will not survive re-addressing")
	return "host:" + s.Host, warn
}

// network returns the containing prefix for an address, e.g.
// 10.199.101.101/24 -> 10.199.101.0/24.
func network(addr string, bits int) (netip.Prefix, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// peerOfPointToPoint returns the other host address of a /30 or /31.
// Route-based VPN interfaces (xfrm) are numbered from /30 transit nets, so the
// peer address is arithmetic — no IPsec object lookup needed to pair two
// tunnel endpoints across the inventory.
func peerOfPointToPoint(addr string, bits int) (string, bool) {
	if bits != 30 && bits != 31 {
		return "", false
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return "", false
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	first := p.Masked().Addr()
	if bits == 31 {
		if a == first {
			return first.Next().String(), true
		}
		return first.String(), true
	}
	h1 := first.Next() // .1 of the /30
	h2 := h1.Next()    // .2 of the /30
	if a == h1 {
		return h2.String(), true
	}
	if a == h2 {
		return h1.String(), true
	}
	return "", false
}

// Build assembles the graph from one or more appliance snapshots.
func Build(snaps []*sfos.Snapshot) *Graph {
	g := &Graph{}

	zoneTypeByDevice := map[string]map[string]sfos.ZoneType{}
	ifacesByDevice := map[string][]Iface{}
	deviceOrder := []string{}
	deviceLabelByID := map[string]string{}

	// ---- Pass 1: devices and interfaces -------------------------------
	for _, s := range snaps {
		id, warn := DeviceID(s)
		deviceOrder = append(deviceOrder, id)

		zt := map[string]sfos.ZoneType{}
		for _, z := range s.Zones {
			zt[z.Name] = z.Type
		}
		zoneTypeByDevice[id] = zt

		apiHost := s.Host
		if h, _, ok := strings.Cut(s.Host, ":"); ok {
			apiHost = h
		}

		var ifs []Iface
		for _, in := range s.Interfaces {
			zoneType := zt[in.Zone.Name]
			f := Iface{
				DeviceID:    id,
				Name:        in.Name,
				Type:        string(in.Type),
				ZoneName:    in.Zone.Name,
				ZoneType:    string(zoneType),
				Orientation: OrientationFor(in.Type, zoneType),
				Enabled:     in.Enabled,
			}
			if in.MemberOf != nil {
				f.MemberOf = *in.MemberOf
			}
			if in.IPv4 != nil && in.IPv4.IPv4Address != nil {
				f.Addr = fmt.Sprintf("%s/%d", *in.IPv4.IPv4Address, in.IPv4.CIDR)
				f.IsAPIPath = *in.IPv4.IPv4Address == apiHost
				if in.IPv4.GatewayName != nil {
					f.GatewayName = *in.IPv4.GatewayName
				}
				if in.IPv4.GatewayIPAddress != nil {
					f.GatewayIP = *in.IPv4.GatewayIPAddress
				}
			}
			ifs = append(ifs, f)
		}
		ifacesByDevice[id] = ifs

		label := s.Label
		if label == "" {
			label = s.Hostname
		}
		if label == "" {
			label = s.Host
		}
		deviceLabelByID[id] = label
		n := Node{
			ID: id, Kind: KindDevice, Label: label,
			Serial:     s.Central.Registration.SerialNumber,
			Hostname:   s.Hostname,
			Interfaces: ifs,
			Warnings:   warn,
		}
		for _, p := range s.Central.PeerNodes {
			if p.SerialNumber != "" {
				n.HAPeers = append(n.HAPeers, p.SerialNumber)
			}
		}
		if len(n.HAPeers) > 0 {
			n.Warnings = append(n.Warnings,
				"appliance is a node of an HA pair; render the pair as one logical device or the correlator will merge duplicate segments")
		}
		g.Nodes = append(g.Nodes, n)
	}

	// ---- Pass 2: segments ---------------------------------------------
	// Candidate grouping is by prefix (rule E1). Two interfaces sharing a
	// prefix are only merged into one segment when corroborating evidence
	// exists; otherwise the segment is split per device and flagged, because
	// 192.168.1.0/24 at two different sites is not one broadcast domain.
	type segKey struct {
		prefix      string
		orientation Orientation
	}
	members := map[segKey][]Iface{}
	for _, id := range deviceOrder {
		for _, f := range ifacesByDevice[id] {
			if f.Addr == "" || f.Orientation == Overlay || f.Orientation == Passive {
				continue
			}
			ip, bitsStr, _ := strings.Cut(f.Addr, "/")
			var bits int
			fmt.Sscanf(bitsStr, "%d", &bits)
			p, ok := network(ip, bits)
			if !ok {
				continue
			}
			k := segKey{p.String(), f.Orientation}
			members[k] = append(members[k], f)
		}
	}

	keys := make([]segKey, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].prefix < keys[j].prefix })

	segIDOf := map[string]string{}             // iface id -> segment node id
	segMembers := map[string]map[string]bool{} // segment node id -> device IDs actually on it
	for _, k := range keys {
		ms := members[k]
		groups := mergeGroups(ms)
		for gi, grp := range groups {
			segID := "seg:" + k.prefix
			if len(groups) > 1 {
				segID = fmt.Sprintf("seg:%s#%d", k.prefix, gi+1)
			}
			node := Node{
				ID: segID, Kind: KindSegment, Label: k.prefix,
				CIDR: k.prefix, Orientation: k.orientation,
				OverlappingCIDR: grp.split,
			}
			if grp.split {
				node.Warnings = append(node.Warnings,
					"another appliance holds the same address inside this prefix, so these are separate networks reusing the same range")
			}
			g.Nodes = append(g.Nodes, node)

			for _, f := range grp.ifaces {
				segIDOf[f.id()] = segID
				if segMembers[segID] == nil {
					segMembers[segID] = map[string]bool{}
				}
				segMembers[segID][f.DeviceID] = true
				e := Edge{
					From: f.DeviceID, To: segID,
					Orientation: f.Orientation,
					Confidence:  grp.conf,
					Label:       f.Name,
					Evidence: []Evidence{{
						Rule:   "E0",
						Detail: fmt.Sprintf("%s holds %s in zone %s", f.Name, f.Addr, f.ZoneName),
					}},
				}
				// Why this segment has the membership it has belongs on the
				// link, not on the node: a successful merge is an explanation,
				// not a caveat, and warnings are what raise a flag in the UI.
				if grp.evidence != nil {
					e.Evidence = append(e.Evidence, *grp.evidence)
				}
				g.Edges = append(g.Edges, e)
			}
		}
	}

	// ---- Pass 2b: named address objects on each segment ---------------
	// A segment already has a CIDR from wire evidence (E0/E1/E3). An address
	// object with the same or overlapping network is what an administrator
	// actually calls it. Every object that applies is attached, not just one
	// "best" pick, so a name only some of the fleet's appliances agree on is
	// visible as a fact rather than hidden behind a single choice.
	type objKey struct{ segID, name string }
	objDevices := map[objKey]map[string]bool{}
	for i := range g.Nodes {
		seg := &g.Nodes[i]
		if seg.Kind != KindSegment {
			continue
		}
		segPrefix, err := netip.ParsePrefix(seg.CIDR)
		if err != nil {
			continue
		}
		for _, s := range snaps {
			devID, _ := DeviceID(s)
			// Only a device actually on this wire gets to name it. Two
			// segments can share a CIDR string after an E9 split precisely
			// because they are NOT the same network, and an object from the
			// device on the other one must not bleed across.
			if !segMembers[seg.ID][devID] {
				continue
			}
			for _, h := range s.IPAddresses {
				value, ok := matchSegment(h, segPrefix)
				if !ok {
					continue
				}
				seg.AddressObjects = append(seg.AddressObjects, AddressObject{
					Name: h.Name, HostType: string(h.HostType), Value: value,
					DeviceID: devID, DeviceLabel: deviceLabelByID[devID],
				})
				k := objKey{seg.ID, h.Name}
				if objDevices[k] == nil {
					objDevices[k] = map[string]bool{}
				}
				objDevices[k][devID] = true
			}
		}
		sort.Slice(seg.AddressObjects, func(a, b int) bool {
			oa, ob := seg.AddressObjects[a], seg.AddressObjects[b]
			if oa.Name != ob.Name {
				return oa.Name < ob.Name
			}
			return oa.DeviceID < ob.DeviceID
		})
	}
	for i := range g.Nodes {
		seg := &g.Nodes[i]
		if seg.Kind != KindSegment {
			continue
		}
		for j := range seg.AddressObjects {
			k := objKey{seg.ID, seg.AddressObjects[j].Name}
			if len(objDevices[k]) > 1 {
				seg.AddressObjects[j].MultipleFirewalls = true
			}
		}
	}

	// ---- Pass 3: upstream clouds (E5) ---------------------------------
	// One cloud per distinct WAN gateway address. Two appliances pointing at
	// the same next hop share an upstream; different next hops are different
	// links and must not collapse into a single "INTERNET" node.
	cloudSeen := map[string]bool{}
	cloudEdge := map[string]int{}
	for _, id := range deviceOrder {
		for _, f := range ifacesByDevice[id] {
			if f.Orientation != North || f.GatewayIP == "" {
				continue
			}
			cloudID := "cloud:" + f.GatewayIP
			if !cloudSeen[cloudID] {
				cloudSeen[cloudID] = true
				label := f.GatewayName
				if label == "" {
					label = f.GatewayIP
				}
				gatewayCIDR := f.GatewayIP
				if _, bitsStr, ok := strings.Cut(f.Addr, "/"); ok {
					gatewayCIDR = f.GatewayIP + "/" + bitsStr
				}
				g.Nodes = append(g.Nodes, Node{
					ID: cloudID, Kind: KindCloud, Label: label,
					Orientation: North, GatewayIP: f.GatewayIP, GatewayCIDR: gatewayCIDR,
				})
			}
			from := segIDOf[f.id()]
			if from == "" {
				from = f.DeviceID
			}
			ev := Evidence{
				Rule:   "E5",
				Detail: fmt.Sprintf("%s: gateway %s (%s) on %s", id, f.GatewayName, f.GatewayIP, f.Name),
			}
			// When E3 merged the WAN segment, every appliance on it points at
			// the same next hop and would emit the same edge. Keep one edge and
			// accumulate the evidence instead of drawing parallel lines.
			if k, dup := cloudEdge[from+"->"+cloudID]; dup {
				g.Edges[k].Evidence = append(g.Edges[k].Evidence, ev)
				continue
			}
			cloudEdge[from+"->"+cloudID] = len(g.Edges)
			g.Edges = append(g.Edges, Edge{
				From: from, To: cloudID, Orientation: North, Confidence: Confirmed,
				Label:    f.Name,
				Evidence: []Evidence{ev},
			})
		}
	}

	// Every upstream converges on one root. Without it a multi-link fleet
	// reads as several disconnected drawings stacked side by side.
	if len(cloudSeen) > 0 {
		g.Nodes = append(g.Nodes, Node{
			ID: WorldID, Kind: KindWorld, Label: "Outer world", Orientation: North,
		})
		ids := make([]string, 0, len(cloudSeen))
		for id := range cloudSeen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, cloudID := range ids {
			g.Edges = append(g.Edges, Edge{
				From: cloudID, To: WorldID, Orientation: North, Confidence: Confirmed,
			})
		}
	}

	// ---- Pass 4: tunnel pairing (E8) ----------------------------------
	// xfrm interfaces are numbered from /30 transit nets, so the peer address
	// is arithmetic. If the peer address belongs to another appliance in the
	// inventory, the tunnel is a confirmed overlay edge between the two.
	owner := map[string]Iface{} // bare address -> interface
	for _, id := range deviceOrder {
		for _, f := range ifacesByDevice[id] {
			if ip, _, ok := strings.Cut(f.Addr, "/"); ok {
				owner[ip] = f
			}
		}
	}
	tunnelSeen := map[string]bool{}
	for _, id := range deviceOrder {
		for _, f := range ifacesByDevice[id] {
			if f.Type != string(sfos.IfXFRM) || f.Addr == "" {
				continue
			}
			ip, bitsStr, _ := strings.Cut(f.Addr, "/")
			var bits int
			fmt.Sscanf(bitsStr, "%d", &bits)
			peerIP, ok := peerOfPointToPoint(ip, bits)
			if !ok {
				continue
			}
			peer, known := owner[peerIP]
			if !known || peer.DeviceID == f.DeviceID {
				continue
			}
			key := pairKey(f.DeviceID+"/"+f.Name, peer.DeviceID+"/"+peer.Name)
			if tunnelSeen[key] {
				continue
			}
			tunnelSeen[key] = true
			g.Edges = append(g.Edges, Edge{
				From: f.DeviceID, To: peer.DeviceID,
				Orientation: Overlay, Confidence: Confirmed,
				Label: f.Name + " ↔ " + peer.Name,
				Evidence: []Evidence{{
					Rule:   "E8",
					Detail: fmt.Sprintf("%s (%s) and %s (%s) are the two hosts of the same /%d transit net", f.Name, f.Addr, peer.Name, peer.Addr, bits),
				}},
			})
		}
	}

	// ---- Pass 5: downstream ghost routers (E6) ------------------------
	// A static route whose next hop is not an address of any known appliance
	// implies an L3 device on that segment. Rendered as an inferred node, the
	// way Meraki renders an unknown device.
	ghostSeen := map[string]bool{}
	for si, s := range snaps {
		_ = si
		id, _ := DeviceID(s)
		for _, r := range s.Routes {
			if r.GatewayIPv4 == nil || *r.GatewayIPv4 == "" {
				continue
			}
			gw := *r.GatewayIPv4
			if _, isKnown := owner[gw]; isKnown {
				continue // next hop is another appliance: already edged
			}
			ghostID := "gw:" + gw
			if !ghostSeen[ghostID] {
				ghostSeen[ghostID] = true
				g.Nodes = append(g.Nodes, Node{
					ID: ghostID, Kind: KindGateway, Label: gw,
					Orientation: South,
				})
			}
			// Attach the ghost to the segment that contains its address.
			attach := id
			viaIface := ""
			for _, f := range ifacesByDevice[id] {
				if f.Addr == "" {
					continue
				}
				ip, bitsStr, _ := strings.Cut(f.Addr, "/")
				var bits int
				fmt.Sscanf(bitsStr, "%d", &bits)
				p, ok := network(ip, bits)
				if !ok {
					continue
				}
				a, err := netip.ParseAddr(gw)
				if err == nil && p.Contains(a) {
					if sid := segIDOf[f.id()]; sid != "" {
						attach = sid
					}
					viaIface = f.Name
					break
				}
			}
			// Prefer the physical interface the route goes out of; fall back
			// to the destination prefix when no local interface matched (the
			// route's next hop is reachable through more than one hop).
			label := fmt.Sprintf("%s/%d", r.DestinationAddressIPv4, r.CIDR)
			if viaIface != "" {
				label = viaIface
			}
			g.Edges = append(g.Edges, Edge{
				From: attach, To: ghostID, Orientation: South, Confidence: Inferred,
				Label: label,
				Evidence: []Evidence{{
					Rule:   "E6",
					Detail: fmt.Sprintf("static route %s/%d via %s on %s", r.DestinationAddressIPv4, r.CIDR, gw, id),
				}},
			})
		}
	}

	return g
}

type group struct {
	ifaces   []Iface
	evidence *Evidence
	conf     Confidence
	split    bool
}

// mergeGroups decides whether interfaces sharing a prefix are one segment.
//
// The discriminator is the host address. Two appliances holding different
// addresses inside the same prefix are consistent with a single broadcast
// domain and are merged (rule E1). Two appliances holding the SAME address in
// that prefix cannot coexist on one wire — it would be a duplicate address —
// so they are separate networks that happen to reuse the same range, and they
// stay apart and flagged (rule E9). That is the ordinary case of
// 192.168.1.0/24 at two different sites.
//
// A shared next hop inside the prefix (rule E3) is corroboration, not a
// precondition: it upgrades a merged segment from inferred to confirmed.
func mergeGroups(ifaces []Iface) []group {
	byDevice := map[string][]Iface{}
	order := []string{}
	for _, f := range ifaces {
		if _, seen := byDevice[f.DeviceID]; !seen {
			order = append(order, f.DeviceID)
		}
		byDevice[f.DeviceID] = append(byDevice[f.DeviceID], f)
	}
	if len(order) <= 1 {
		return []group{{ifaces: ifaces, conf: Confirmed}}
	}
	sort.Strings(order)

	// Greedily place each appliance in the first group whose addresses it does
	// not collide with. A collision opens a new group.
	type bucket struct {
		devices []string
		addrs   map[string]string // host address -> device that holds it
		ifaces  []Iface
	}
	var buckets []*bucket
	collided := false

	for _, dev := range order {
		fs := byDevice[dev]
		placed := false
		for _, b := range buckets {
			clash := false
			for _, f := range fs {
				if ip, _, ok := strings.Cut(f.Addr, "/"); ok {
					if _, taken := b.addrs[ip]; taken {
						clash = true
						break
					}
				}
			}
			if clash {
				continue
			}
			for _, f := range fs {
				if ip, _, ok := strings.Cut(f.Addr, "/"); ok {
					b.addrs[ip] = dev
				}
			}
			b.devices = append(b.devices, dev)
			b.ifaces = append(b.ifaces, fs...)
			placed = true
			break
		}
		if !placed {
			b := &bucket{addrs: map[string]string{}}
			for _, f := range fs {
				if ip, _, ok := strings.Cut(f.Addr, "/"); ok {
					b.addrs[ip] = dev
				}
			}
			b.devices = []string{dev}
			b.ifaces = append(b.ifaces, fs...)
			buckets = append(buckets, b)
			if len(buckets) > 1 {
				collided = true
			}
		}
	}

	out := make([]group, 0, len(buckets))
	for _, b := range buckets {
		g := group{ifaces: b.ifaces, conf: Confirmed, split: collided}
		if len(b.devices) > 1 {
			// Do the members agree on a next hop inside this prefix?
			gw := ""
			agree := true
			for _, f := range b.ifaces {
				if f.GatewayIP == "" {
					continue
				}
				if gw == "" {
					gw = f.GatewayIP
				} else if gw != f.GatewayIP {
					agree = false
				}
			}
			if gw != "" && agree {
				g.conf = Confirmed
				g.evidence = &Evidence{
					Rule:   "E3",
					Detail: fmt.Sprintf("merged: %s hold distinct addresses here and share next hop %s", strings.Join(b.devices, ", "), gw),
				}
			} else {
				g.conf = Inferred
				g.evidence = &Evidence{
					Rule:   "E1",
					Detail: fmt.Sprintf("merged: %s hold distinct addresses inside this prefix", strings.Join(b.devices, ", ")),
				}
			}
		}
		if collided {
			g.evidence = &Evidence{
				Rule:   "E9",
				Detail: "kept apart: another appliance holds the same address in this prefix, which cannot happen on one wire",
			}
			g.conf = Inferred
		}
		out = append(out, g)
	}
	return out
}

func pairKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

// matchSegment reports whether an address object applies to seg and, if so,
// a human-readable rendering of what the object actually covers.
func matchSegment(h sfos.IPHost, seg netip.Prefix) (string, bool) {
	switch {
	case h.HostType.Is(sfos.HostTypeNetwork):
		p, ok := h.Prefix()
		if !ok || !p.Overlaps(seg) {
			return "", false
		}
		return p.String(), true

	case h.HostType.Is(sfos.HostTypeRange):
		if h.RangeStart == nil || h.RangeEnd == nil {
			return "", false
		}
		start, err1 := netip.ParseAddr(*h.RangeStart)
		end, err2 := netip.ParseAddr(*h.RangeEnd)
		if err1 != nil || err2 != nil || (!seg.Contains(start) && !seg.Contains(end)) {
			return "", false
		}
		return fmt.Sprintf("%s - %s", start, end), true

	case h.HostType.Is(sfos.HostTypeList):
		var hit []string
		for _, s := range h.Addresses {
			if a, err := netip.ParseAddr(s); err == nil && seg.Contains(a) {
				hit = append(hit, s)
			}
		}
		if len(hit) == 0 {
			return "", false
		}
		return strings.Join(hit, ", "), true

	default: // HostTypeIP, or an unrecognised/empty type: a bare host address
		if h.IPv4Address == nil {
			return "", false
		}
		a, err := netip.ParseAddr(*h.IPv4Address)
		if err != nil || !seg.Contains(a) {
			return "", false
		}
		return *h.IPv4Address, true
	}
}
