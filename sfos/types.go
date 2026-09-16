// Package sfos provides a read-only client for the Sophos Firewall
// Configuration API (base path /api/firewall-config/v1).
//
// The types here are modeled against real appliance responses, not only
// against the OpenAPI schema. Three quirks drove the design:
//
//  1. "Absent", "null" and "" all occur in the same response and mean the
//     same thing. LAN interfaces carry gatewayIpAddress:"" while xfrm
//     interfaces omit the key entirely, and ipv6 arrives as null.
//     Every optional scalar is therefore a pointer, and Clean() folds the
//     empty string into nil so downstream code has exactly one nil check.
//
//  2. The interface item is a oneOf discriminated on "type". A superset
//     struct decodes every variant correctly because the variants only add
//     fields; Raw keeps the original bytes for variant-specific decoding.
//
//  3. Pagination never reports the total unless pageTotal=true is passed,
//     so the page loop cannot rely on pages.total being present.
//
//  4. IPHost's "type" discriminator picks a DIFFERENT field name per variant
//     (ipv4Address, ipv4NetworkAddress+cidr, ipv4AddressStart/End,
//     ipv4Addresses) rather than reusing one field across types. An earlier
//     version of this type guessed at XML-derived names instead and silently
//     decoded every object to its zero value; the names here are confirmed
//     against a live capture.
package sfos

import (
	"encoding/json"
	"net/netip"
	"strings"
)

// Pages is the pagination envelope. Total and Items are only populated when
// the request passes pageTotal=true, so never branch on them being non-nil.
type Pages struct {
	Current int  `json:"current"`
	Size    int  `json:"size"`
	MaxSize int  `json:"maxSize"`
	Total   *int `json:"total"`
	Items   *int `json:"items"`
}

type page[T any] struct {
	Items []T   `json:"items"`
	Pages Pages `json:"pages"`
}

// ZoneType is the closed enum returned by GET /network/zones. Note that it is
// coarser than the zone list: a built-in "WiFi" zone reports type "lan", and
// admin-created zones reuse these same types. Orientation must be derived from
// Type; the human-facing label must come from Name.
type ZoneType string

const (
	ZoneLAN      ZoneType = "lan"
	ZoneWAN      ZoneType = "wan"
	ZoneDMZ      ZoneType = "dmz"
	ZoneLocal    ZoneType = "local"
	ZoneVPN      ZoneType = "vpn"
	ZoneDiscover ZoneType = "discover"
)

type Zone struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Type ZoneType `json:"type"`
	// IsInternal marks built-in zones. It is returned by the appliance but is
	// absent from the published schema, so treat it as advisory.
	IsInternal  bool   `json:"isInternal"`
	Description string `json:"description"`
}

// InterfaceType is the oneOf discriminator.
type InterfaceType string

const (
	IfPhysical    InterfaceType = "physical"
	IfRED         InterfaceType = "red"
	IfVLAN        InterfaceType = "vlan"
	IfBridge      InterfaceType = "bridge"
	IfLAG         InterfaceType = "lag"
	IfXFRM        InterfaceType = "xfrm"
	IfCellularWAN InterfaceType = "cellularWan"
)

type ZoneRef struct {
	Name string `json:"name"`
}

type SecondaryAddress struct {
	IPv4Address string `json:"ipv4Address"`
	CIDR        int    `json:"cidr"`
}

// IPv4Config is present on most interface variants. GatewayName and
// GatewayIPAddress are only meaningful on WAN-zone interfaces; elsewhere the
// appliance returns empty strings or omits them.
type IPv4Config struct {
	AssignmentType     string             `json:"assignmentType"`
	IPv4Address        *string            `json:"ipv4Address"`
	CIDR               int                `json:"cidr"`
	GatewayName        *string            `json:"gatewayName"`
	GatewayIPAddress   *string            `json:"gatewayIpAddress"`
	SecondaryAddresses []SecondaryAddress `json:"secondaryAddresses"`
}

// Interface is a superset of every oneOf variant. Fields that only exist on
// some variants are pointers so that "absent" is distinguishable from "zero".
type Interface struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Type         InterfaceType `json:"type"`
	Enabled      bool          `json:"enabled"`
	HardwareName string        `json:"hardwareName"`
	Zone         ZoneRef       `json:"zone"`
	IPv4         *IPv4Config   `json:"ipv4"`

	// MemberOf names the parent bridge or LAG. Empty for standalone
	// interfaces and absent on xfrm.
	MemberOf *string `json:"memberOf"`

	// MACAddress is the administratively overridden MAC, NOT the burned-in
	// hardware address. It is populated only when OverrideMAC is true; the
	// appliance returns "" otherwise. Do not treat this as an interface
	// identity key.
	MACAddress  *string `json:"macAddress"`
	OverrideMAC *bool   `json:"overrideMac"`

	MTU *int `json:"mtu"`
	MSS *int `json:"mss"`

	// Raw retains the original object for variant-specific decoding
	// (PPPoE credentials, RED settings, cellular profiles).
	Raw json.RawMessage `json:"-"`
}

func (i *Interface) UnmarshalJSON(b []byte) error {
	type alias Interface
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*i = Interface(a)
	i.Raw = append(json.RawMessage(nil), b...)
	i.clean()
	return nil
}

// clean folds the appliance's three encodings of "no value" into nil.
func (i *Interface) clean() {
	i.MemberOf = nilIfEmpty(i.MemberOf)
	i.MACAddress = nilIfEmpty(i.MACAddress)
	if i.IPv4 != nil {
		i.IPv4.GatewayName = nilIfEmpty(i.IPv4.GatewayName)
		i.IPv4.GatewayIPAddress = nilIfEmpty(i.IPv4.GatewayIPAddress)
		i.IPv4.IPv4Address = nilIfEmpty(i.IPv4.IPv4Address)
	}
}

func nilIfEmpty(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

// Gateway is returned by GET /routing/gateways/ipv4.
type Gateway struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	IPv4Address string  `json:"ipv4Address"`
	Interface   ZoneRef `json:"interface"`
}

// WANGateway adds failover semantics: Weight drives load distribution across
// active links and BackupGatewaySettings marks standby links.
type WANGateway struct {
	Gateway
	Weight                int             `json:"weight"`
	BackupGatewaySettings json.RawMessage `json:"backupGatewaySettings"`
	HealthCheck           json.RawMessage `json:"healthCheck"`
}

// Route is a static unicast IPv4 route. Interface may name "Blackhole".
type Route struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	DestinationAddressIPv4 string   `json:"destinationAddressIpv4"`
	CIDR                   int      `json:"cidr"`
	GatewayIPv4            *string  `json:"gatewayIpv4"`
	Interface              *ZoneRef `json:"interface"`
	Metric                 int      `json:"metric"`
	AdministrativeDistance int      `json:"administrativeDistance"`
}

// SystemSettings is GET /administration/system-settings.
type SystemSettings struct {
	Hostname string `json:"hostname"`
}

// CentralStatus is GET /sophos-central/status. It is the only source of the
// appliance serial number, and PeerNodes is present only on HA pairs.
type CentralStatus struct {
	Registration struct {
		Registered   bool   `json:"registered"`
		SerialNumber string `json:"serialNumber"`
		CompanyName  string `json:"companyName"`
	} `json:"registration"`
	HeartbeatAvailable bool `json:"heartbeatAvailable"`
	PeerNodes          []struct {
		Registered   bool   `json:"registered"`
		SerialNumber string `json:"serialNumber"`
	} `json:"peerNodes"`
}

// IPsecConnection is a site-to-site tunnel. RemoteGateway is the correlation
// key that links two appliances in the inventory.
type IPsecConnection struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	GatewayType   string `json:"gatewayType"`
	RemoteGateway struct {
		IPv4Address *string `json:"ipv4Address"`
		FQDN        *string `json:"fqdn"`
		Any         *bool   `json:"any"`
	} `json:"remoteGateway"`
	LocalGateway struct {
		IPv4Address *string `json:"ipv4Address"`
		FQDN        *string `json:"fqdn"`
	} `json:"localGateway"`
}

// DHCPServer carries the scope plus static client reservations. The API does
// NOT expose active leases — reservations are configuration, not state.
type DHCPServer struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Enabled      bool    `json:"enabled"`
	Interface    ZoneRef `json:"interface"`
	CIDR         int     `json:"cidr"`
	GatewayIPv4  string  `json:"gatewayIpv4"`
	AddressPools []struct {
		StartAddressIPv4 string `json:"startAddressIpv4"`
		EndAddressIPv4   string `json:"endAddressIpv4"`
	} `json:"addressPools"`
	ClientReservations []struct {
		Hostname    string `json:"hostname"`
		MACAddress  string `json:"macAddress"`
		IPv4Address string `json:"ipv4Address"`
	} `json:"clientReservations"`
}

// Snapshot is one complete read of one appliance.
type Snapshot struct {
	Host        string
	Label       string
	Hostname    string
	Central     CentralStatus
	Zones       []Zone
	Interfaces  []Interface
	Gateways    []Gateway
	WANGateways []WANGateway
	Routes      []Route
	DHCPServers []DHCPServer
	IPsec       []IPsecConnection
	IPAddresses []IPHost
	// Partial records endpoints that failed. Collection degrades, never aborts.
	Partial map[string]string
}

// HostType is the IPHost discriminator: what kind of address (or addresses)
// one named object stands for. Values are the appliance's own "type" enum,
// confirmed against a live capture.
type HostType string

const (
	HostTypeIP      HostType = "ipv4Address"
	HostTypeNetwork HostType = "ipv4Network"
	HostTypeRange   HostType = "ipv4Range"
	HostTypeList    HostType = "ipv4List"
)

// Is compares case-insensitively. The values above are exactly what a
// capture showed, but nothing else in this file assumes REST API enums are
// case-stable, and there is no cost to being lenient here too.
func (h HostType) Is(want HostType) bool { return strings.EqualFold(string(h), string(want)) }

// IPHost is a named IPv4 address object (GET /network/addresses/ipv4): what
// an administrator calls "DC-LAN" where the wire only carries 10.0.5.0/24.
//
// Confirmed against a live capture. Each HostType uses a distinct field for
// its value rather than sharing one: an ipv4Network's base address lives in
// NetworkAddress, not IPv4Address, because the appliance also emits internal
// ipv4Address objects named "#PortA" etc. for every interface's own address,
// and the two are not the same field reused.
type IPHost struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// IsInternal marks an appliance-managed object such as "#PortA" (an
	// interface's own address) or "##ALL_RW" (an empty built-in list).
	// Kept, not filtered, so a name that happens to be the most specific
	// match is still shown rather than silently skipped.
	IsInternal bool     `json:"isInternal,omitempty"`
	HostType   HostType `json:"type"`

	IPv4Address *string `json:"ipv4Address,omitempty"` // HostTypeIP

	NetworkAddress *string `json:"ipv4NetworkAddress,omitempty"` // HostTypeNetwork
	CIDR           *int    `json:"cidr,omitempty"`               // HostTypeNetwork

	RangeStart *string `json:"ipv4AddressStart,omitempty"` // HostTypeRange
	RangeEnd   *string `json:"ipv4AddressEnd,omitempty"`   // HostTypeRange

	Addresses []string `json:"ipv4Addresses,omitempty"` // HostTypeList
}

// Prefix returns the network a HostType Network object represents.
func (h IPHost) Prefix() (netip.Prefix, bool) {
	if h.NetworkAddress == nil || h.CIDR == nil {
		return netip.Prefix{}, false
	}
	a, err := netip.ParseAddr(*h.NetworkAddress)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	p, err := a.Prefix(*h.CIDR)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// InRange reports whether addr falls within a HostType Range object.
func (h IPHost) InRange(addr netip.Addr) bool {
	if h.RangeStart == nil || h.RangeEnd == nil {
		return false
	}
	start, err1 := netip.ParseAddr(*h.RangeStart)
	end, err2 := netip.ParseAddr(*h.RangeEnd)
	if err1 != nil || err2 != nil {
		return false
	}
	return !addr.Less(start) && !end.Less(addr)
}
