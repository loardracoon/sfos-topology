package sfos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// This file models the subset of /firewall/rules/ipv4 and
// /network/addresses/ipv4's write paths the policy matrix needs. Every field
// and every quirk below is confirmed against a live capture, not the OpenAPI
// doc alone -- see testdata/firewall-rules/ for the raw responses and the
// project's IPHost comment for why that discipline exists.
//
// Two requirements only showed up as 400s on write, never on a GET:
//   - ruleType must be "firewall" on create.
//   - position must be set on create ("bottom" is the only value this
//     project has exercised; the matrix always appends, never reorders).
//
// synchronizedSecurityHeartbeat and userAuthentication were only ever
// observed non-default on an action:"accept" rule created through WebAdmin;
// an action:"drop" rule this project created with the same fields set them
// but the appliance did not surface them back on a follow-up GET. Treat that
// as this project's working assumption, not an exhaustively proven appliance
// rule -- only set them here when Action is RuleAccept.

// RuleAction is the confirmed action enum. It is NOT the same vocabulary as
// policy.Action ("allow"/"deny"); the caller translates between the two.
type RuleAction string

const (
	RuleAccept RuleAction = "accept"
	RuleDrop   RuleAction = "drop"
)

// RulePositionBottom is the only create-time position value this project
// exercises: the matrix always appends, never reorders existing rules.
const RulePositionBottom = "bottom"

// AddressRef names one existing address object inside a rule's network
// selector.
type AddressRef struct {
	Name string `json:"name"`
}

// RuleZoneSelector picks zero or more zones, or "any". The two are mutually
// exclusive on the wire in every capture seen.
type RuleZoneSelector struct {
	Any   bool      `json:"any,omitempty"`
	Zones []ZoneRef `json:"zones,omitempty"`
}

// RuleNetworkSelector picks zero or more named address objects, or "any".
// The real schema also carries ipv4Groups, fqdnAddresses, countries, etc.
// (see testdata/firewall-rules/sample-list.json); this project's matrix
// never writes them, so they are intentionally not modeled here.
type RuleNetworkSelector struct {
	Any           bool         `json:"any,omitempty"`
	IPv4Addresses []AddressRef `json:"ipv4Addresses,omitempty"`
}

// RuleServiceSelector picks services, or "any". The matrix is
// service-agnostic by design (policy.RuleIntent.Service is always "Any"), so
// this project only ever writes Any: true.
type RuleServiceSelector struct {
	Any bool `json:"any,omitempty"`
}

// Confirmed synchronizedSecurityHeartbeat.minimumLevel values. Only these two
// have been observed on a live capture; do not add more without one.
const (
	HeartbeatNoRestriction = "noRestriction"
	HeartbeatGreen         = "green"
)

type HeartbeatSide struct {
	BlockClientsWithNoHeartbeat bool   `json:"blockClientsWithNoHeartbeat"`
	MinimumLevel                string `json:"minimumLevel"`
}

type SecurityHeartbeat struct {
	Source      HeartbeatSide `json:"source"`
	Destination HeartbeatSide `json:"destination"`
}

type UserOrGroupRef struct {
	Name string `json:"name"`
}

type UsersOrGroups struct {
	UserGroups []UserOrGroupRef `json:"userGroups"`
	Users      []UserOrGroupRef `json:"users"`
}

// UserAuthentication is only ever sent non-nil. "Open Group" is the built-in
// stand-in for "any known user," confirmed against a live WebAdmin-created
// capture (testdata/firewall-rules/sample-with-heartbeat-and-user-auth.json).
type UserAuthentication struct {
	UsersOrGroups                    UsersOrGroups `json:"usersOrGroups"`
	WebAuthenticationForUnknownUsers bool          `json:"webAuthenticationForUnknownUsers"`
	ExcludeUsersFromAccounting       bool          `json:"excludeUsersFromAccounting"`
}

// FirewallRule is GET/POST/PATCH /firewall/rules/ipv4, addressed by Name (the
// appliance accepts the rule name in place of id/ruleId on every write path
// this project uses).
//
// This models only the subset of the real schema the policy matrix reads or
// writes. A live rule carries substantially more (qos, schedule,
// securityFeatures, exclusions, emailScanning...) -- see
// testdata/firewall-rules/sample-list.json for the full shape. Unmodeled
// fields are simply ignored on decode and left absent (appliance-defaulted)
// on encode.
type FirewallRule struct {
	ID     string `json:"id,omitempty"`
	RuleID int    `json:"ruleId,omitempty"`
	Name   string `json:"name"`

	// RuleType and Position are write-only requirements the GET response
	// never includes. Position only matters on create; Update leaves it
	// unset rather than assuming PATCH accepts (or ignores) it too.
	RuleType string `json:"ruleType,omitempty"`
	Position string `json:"position,omitempty"`

	Description string     `json:"description,omitempty"`
	Action      RuleAction `json:"action"`
	Enabled     bool       `json:"enabled"`
	LogTraffic  bool       `json:"logTraffic"`

	SourceZones         RuleZoneSelector    `json:"sourceZones"`
	SourceNetworks      RuleNetworkSelector `json:"sourceNetworks"`
	DestinationZones    RuleZoneSelector    `json:"destinationZones"`
	DestinationNetworks RuleNetworkSelector `json:"destinationNetworks"`
	ServicesOrGroups    RuleServiceSelector `json:"servicesOrGroups"`

	SynchronizedSecurityHeartbeat *SecurityHeartbeat  `json:"synchronizedSecurityHeartbeat,omitempty"`
	UserAuthentication            *UserAuthentication `json:"userAuthentication,omitempty"`
}

// write performs a non-GET request. Unlike do, it accepts any 2xx as success
// (POST answers 201, DELETE has answered 200 in every capture seen) and
// returns the response body verbatim in the error on failure, since these
// appliances put the useful detail ("Invalid ruleType.") in the JSON body,
// not the status line.
func (c *Client) write(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.creds.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, string(bytes.TrimSpace(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) FirewallRules(ctx context.Context) ([]FirewallRule, error) {
	return getAll[FirewallRule](ctx, c, "/firewall/rules/ipv4")
}

func (c *Client) FirewallRule(ctx context.Context, name string) (FirewallRule, error) {
	var r FirewallRule
	err := c.do(ctx, "/firewall/rules/ipv4/"+url.PathEscape(name), nil, &r)
	return r, err
}

// CreateFirewallRule appends r to the end of the rule list. RuleType and
// Position are set here rather than left to the caller, since both are
// mandatory-but-invisible-on-GET quirks this package owns, not policy
// decisions the caller should have to know about.
func (c *Client) CreateFirewallRule(ctx context.Context, r FirewallRule) (FirewallRule, error) {
	r.RuleType = "firewall"
	if r.Position == "" {
		r.Position = RulePositionBottom
	}
	var out FirewallRule
	err := c.write(ctx, http.MethodPost, "/firewall/rules/ipv4", r, &out)
	return out, err
}

// UpdateFirewallRule replaces the fields this package writes on the existing
// rule named name. RuleType and Position are cleared: PATCH has not been
// exercised with either set, so this project does not assume it needs
// (or tolerates) them.
func (c *Client) UpdateFirewallRule(ctx context.Context, name string, r FirewallRule) (FirewallRule, error) {
	r.RuleType = ""
	r.Position = ""
	var out FirewallRule
	err := c.write(ctx, http.MethodPatch, "/firewall/rules/ipv4/"+url.PathEscape(name), r, &out)
	return out, err
}

func (c *Client) DeleteFirewallRule(ctx context.Context, name string) error {
	return c.write(ctx, http.MethodDelete, "/firewall/rules/ipv4/"+url.PathEscape(name), nil, nil)
}

// CreateAddressObject defines a named ipv4Network object, e.g. the object a
// rule's network selector needs when a segment has none yet. Confirmed
// against a live create/delete cycle: no hidden required field, unlike the
// firewall rule endpoint.
func (c *Client) CreateAddressObject(ctx context.Context, name, networkAddress string, cidr int) (IPHost, error) {
	body := IPHost{
		Name:           name,
		HostType:       HostTypeNetwork,
		NetworkAddress: &networkAddress,
		CIDR:           &cidr,
	}
	var out IPHost
	err := c.write(ctx, http.MethodPost, "/network/addresses/ipv4", body, &out)
	return out, err
}

func (c *Client) DeleteAddressObject(ctx context.Context, name string) error {
	return c.write(ctx, http.MethodDelete, "/network/addresses/ipv4/"+url.PathEscape(name), nil, nil)
}
