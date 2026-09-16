package sfos

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// maxPageSize is the appliance ceiling reported in pages.maxSize.
const maxPageSize = 100

type Credentials struct {
	// Host is "address:port", e.g. "192.168.101.99:4444".
	Host string
	// Label is the operator-supplied display name.
	Label string
	// Token is the bearer API key.
	Token string
	// PinnedSHA256 is the hex SHA-256 of the appliance leaf certificate.
	// Firewalls ship self-signed certs, so pinning replaces CA validation.
	// Empty means trust-on-first-use: Fingerprint is filled in after the
	// first successful call for the operator to confirm.
	PinnedSHA256 string
}

type Client struct {
	creds Credentials
	http  *http.Client
	// Fingerprint is the leaf certificate digest observed on the last call.
	Fingerprint string
}

func New(c Credentials) *Client {
	cl := &Client{creds: c}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Appliance certificates are self-signed by design. Verification
			// is done by pin below, not by the system trust store.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("no peer certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				fp := hex.EncodeToString(sum[:])
				cl.Fingerprint = fp
				if c.PinnedSHA256 != "" && c.PinnedSHA256 != fp {
					return fmt.Errorf("certificate pin mismatch for %s", c.Host)
				}
				return nil
			},
		},
	}
	cl.http = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return cl
}

func (c *Client) base() string {
	// Note the /api prefix. The "Getting started" page omits it; the OpenAPI
	// servers block is authoritative.
	return "https://" + c.creds.Host + "/api/firewall-config/v1"
}

func (c *Client) do(ctx context.Context, path string, q url.Values, out any) error {
	u := c.base() + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.creds.Token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// getAll walks every page of a collection endpoint.
//
// pages.total is only computed when pageTotal=true is requested, and even then
// it is optional. The reliable termination condition is a short page: fewer
// items than the page size the appliance says it served.
func getAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	for p := 1; ; p++ {
		q := url.Values{}
		q.Set("page", strconv.Itoa(p))
		q.Set("pageSize", strconv.Itoa(maxPageSize))

		var pg page[T]
		if err := c.do(ctx, path, q, &pg); err != nil {
			return all, err
		}
		all = append(all, pg.Items...)

		size := pg.Pages.Size
		if size <= 0 {
			size = maxPageSize
		}
		if len(pg.Items) < size {
			return all, nil
		}
		if p > 200 { // runaway guard
			return all, fmt.Errorf("pagination did not terminate for %s", path)
		}
	}
}

func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	return getAll[Zone](ctx, c, "/network/zones")
}

func (c *Client) Interfaces(ctx context.Context) ([]Interface, error) {
	return getAll[Interface](ctx, c, "/network/interfaces/network-interfaces")
}

func (c *Client) Gateways(ctx context.Context) ([]Gateway, error) {
	return getAll[Gateway](ctx, c, "/routing/gateways/ipv4")
}

func (c *Client) WANGateways(ctx context.Context) ([]WANGateway, error) {
	return getAll[WANGateway](ctx, c, "/routing/gateways/wan/ipv4")
}

func (c *Client) Routes(ctx context.Context) ([]Route, error) {
	return getAll[Route](ctx, c, "/routing/static-unicast-routes/ipv4")
}

func (c *Client) DHCPServers(ctx context.Context) ([]DHCPServer, error) {
	return getAll[DHCPServer](ctx, c, "/network/dhcp/servers/ipv4")
}

func (c *Client) IPsecConnections(ctx context.Context) ([]IPsecConnection, error) {
	return getAll[IPsecConnection](ctx, c, "/ipsec-vpn/site-to-site/connections/ipv4")
}

// IPAddresses returns every named IPv4 address object (IP/Network/IPRange/
// IPList) configured on the appliance, used to give a network a name better
// than its CIDR.
func (c *Client) IPAddresses(ctx context.Context) ([]IPHost, error) {
	return getAll[IPHost](ctx, c, "/network/addresses/ipv4")
}

func (c *Client) SystemSettings(ctx context.Context) (SystemSettings, error) {
	var s SystemSettings
	err := c.do(ctx, "/administration/system-settings", nil, &s)
	return s, err
}

func (c *Client) CentralStatus(ctx context.Context) (CentralStatus, error) {
	var s CentralStatus
	err := c.do(ctx, "/sophos-central/status", nil, &s)
	return s, err
}

// Collect performs the full read of one appliance.
//
// Every endpoint is optional: a failure is recorded in Snapshot.Partial and
// collection continues. A firewall not registered with Sophos Central has no
// serial number, and an API key scoped to a restricted profile may be denied
// individual endpoints. Neither should produce an empty topology.
func (c *Client) Collect(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{
		Host:    c.creds.Host,
		Label:   c.creds.Label,
		Partial: map[string]string{},
	}
	record := func(name string, err error) {
		if err != nil {
			s.Partial[name] = err.Error()
		}
	}

	var err error
	if s.Zones, err = c.Zones(ctx); err != nil {
		// Zones drive orientation for everything else; without them the
		// snapshot is not worth normalizing.
		return nil, fmt.Errorf("zones: %w", err)
	}
	if s.Interfaces, err = c.Interfaces(ctx); err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}

	sys, err := c.SystemSettings(ctx)
	record("system-settings", err)
	s.Hostname = sys.Hostname

	cs, err := c.CentralStatus(ctx)
	record("central-status", err)
	s.Central = cs

	s.Gateways, err = c.Gateways(ctx)
	record("gateways", err)
	s.WANGateways, err = c.WANGateways(ctx)
	record("wan-gateways", err)
	s.Routes, err = c.Routes(ctx)
	record("routes", err)
	s.DHCPServers, err = c.DHCPServers(ctx)
	record("dhcp-servers", err)
	s.IPsec, err = c.IPsecConnections(ctx)
	record("ipsec", err)
	s.IPAddresses, err = c.IPAddresses(ctx)
	record("ip-addresses", err)

	return s, nil
}
