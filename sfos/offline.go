package sfos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// OfflineFiles maps a snapshot field to the file name expected inside a
// capture directory. The names match the endpoint, so an operator can produce
// a directory with plain curl and no tooling:
//
//	curl -sk -H "Authorization: Bearer $TOKEN" \
//	  "https://$FW/api/firewall-config/v1/network/zones?pageSize=100" > zones.json
//
// Replaying a capture is the supported way to work on the normalizer without
// handing a live token to the build, and the only way to reproduce a customer
// bug from a support bundle.
var OfflineFiles = []string{
	"zones.json",
	"interfaces.json",
	"gateways.json",
	"wan-gateways.json",
	"routes.json",
	"dhcp-servers.json",
	"ipsec.json",
	"ip-addresses.json",
	"system-settings.json",
	"central-status.json",
}

// LoadDir builds a Snapshot from a capture directory. Missing files are
// recorded in Partial rather than treated as errors, mirroring how the live
// collector degrades. Only zones.json and interfaces.json are mandatory.
func LoadDir(label, host, dir string) (*Snapshot, error) {
	s := &Snapshot{Host: host, Label: label, Partial: map[string]string{}}

	readItems := func(name string, dst any) bool {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			s.Partial[name] = err.Error()
			return false
		}
		// Accept both the API envelope {"items":[...]} and a bare array, so a
		// hand-trimmed capture still loads.
		var env struct {
			Items json.RawMessage `json:"items"`
		}
		payload := b
		if err := json.Unmarshal(b, &env); err == nil && len(env.Items) > 0 {
			payload = env.Items
		}
		if err := json.Unmarshal(payload, dst); err != nil {
			s.Partial[name] = err.Error()
			return false
		}
		return true
	}

	readObject := func(name string, dst any) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			s.Partial[name] = err.Error()
			return
		}
		if err := json.Unmarshal(b, dst); err != nil {
			s.Partial[name] = err.Error()
		}
	}

	if !readItems("zones.json", &s.Zones) {
		return nil, fmt.Errorf("%s: zones.json is required: %s", dir, s.Partial["zones.json"])
	}
	if !readItems("interfaces.json", &s.Interfaces) {
		return nil, fmt.Errorf("%s: interfaces.json is required: %s", dir, s.Partial["interfaces.json"])
	}

	readItems("gateways.json", &s.Gateways)
	readItems("wan-gateways.json", &s.WANGateways)
	readItems("routes.json", &s.Routes)
	readItems("dhcp-servers.json", &s.DHCPServers)
	readItems("ipsec.json", &s.IPsec)
	readItems("ip-addresses.json", &s.IPAddresses)

	var sys SystemSettings
	readObject("system-settings.json", &sys)
	s.Hostname = sys.Hostname

	readObject("central-status.json", &s.Central)

	return s, nil
}
