// Command sfos-topology reads one or more Sophos Firewalls and emits a single
// topology graph as JSON.
//
// It has no external dependencies: the config is JSON rather than YAML so the
// binary builds with a bare Go toolchain, with no module proxy, which matters
// when the collector runs on a jump host inside a customer network.
//
// Usage:
//
//	sfos-topology -config devices.json -out graph.json
//	sfos-topology -config devices.json -serve 127.0.0.1:8080 -refresh 15m
//	sfos-topology -config devices.json -probe      # print cert fingerprints, collect nothing
//
// A device entry is either live (host + token) or a replay of a capture
// directory (offlineDir). Mixing both in one run is supported and is how you
// diff a customer capture against your own lab.
//
// With -serve, setting SFOS_ADMIN_TOKEN enables a settings API (see web
// package) that can add, edit and remove devices at runtime. It is a
// bare-binary / local-use feature: it persists by writing devices.json and a
// sibling secrets file, and the documented Docker deployment mounts
// devices.json read-only and runs the container's root filesystem read-only
// specifically so the process can never rewrite its own config. Settings
// writes there will fail with a clear error rather than silently doing
// nothing; edit devices.json from the host and restart instead.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tales/sfos-topology/ipam"
	"github.com/tales/sfos-topology/sfos"
	"github.com/tales/sfos-topology/topology"
	"github.com/tales/sfos-topology/web"
)

type deviceConfig struct {
	Label string `json:"label"`
	// Live collection
	Host  string `json:"host,omitempty"`  // address:port, e.g. 192.168.101.99:4444
	Token string `json:"token,omitempty"` // bearer API key, inline
	// TokenEnv names an environment variable holding the key. Prefer it over
	// Token: the config file is the thing that gets committed, pasted into a
	// ticket and shared with a colleague, and an API key inherits every
	// permission of the account that created it.
	TokenEnv  string `json:"tokenEnv,omitempty"`
	PinSHA256 string `json:"pinSha256,omitempty"` // leaf cert digest; empty = trust on first use
	// Replay
	OfflineDir string `json:"offlineDir,omitempty"`
}

type config struct {
	Devices []deviceConfig `json:"devices"`
	// Concurrency caps simultaneous appliance reads. Each read is ten GETs;
	// a web admin console is not a load balancer, so keep this modest.
	Concurrency int `json:"concurrency,omitempty"`
	// TimeoutSeconds bounds one appliance, not the whole run.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

type result struct {
	label       string
	source      string // "live" or "replay"
	snap        *sfos.Snapshot
	fingerprint string
	err         error
}

type output struct {
	GeneratedAt  time.Time         `json:"generatedAt"`
	Graph        *topology.Graph   `json:"graph"`
	Devices      []deviceReport    `json:"devices"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

type deviceReport struct {
	Label   string            `json:"label"`
	Host    string            `json:"host,omitempty"`
	Source  string            `json:"source"` // "live" or "replay"
	Error   string            `json:"error,omitempty"`
	Partial map[string]string `json:"partial,omitempty"`
}

func main() {
	var (
		cfgPath     = flag.String("config", "devices.json", "path to the device config")
		secretsPath = flag.String("secrets", "", "path to the settings-managed secrets file (default: devices.secrets.json next to -config)")
		outPath     = flag.String("out", "-", "output file for the graph JSON, or - for stdout")
		probe       = flag.Bool("probe", false, "connect and print TLS fingerprints, then exit")
		serve       = flag.String("serve", "", "serve the viewer and the graph on this address, e.g. 127.0.0.1:8080")
		refresh     = flag.Duration("refresh", 0, "with -serve, re-read the fleet on this interval, e.g. 15m")
		health      = flag.String("healthcheck", "", "probe this URL and exit; used by the container healthcheck")
	)
	flag.Parse()

	if *health != "" {
		// A scratch image has no shell and no curl, so the binary probes
		// itself.
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(*health)
		if err != nil {
			fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fatal(fmt.Errorf("%s: %s", *health, resp.Status))
		}
		return
	}

	if *secretsPath == "" {
		*secretsPath = filepath.Join(filepath.Dir(*cfgPath), "devices.secrets.json")
	}
	store := newFleetStore(*cfgPath, *secretsPath)
	if err := store.Load(); err != nil {
		fatal(err)
	}
	cfg, secrets := store.Snapshot()
	if len(cfg.Devices) == 0 {
		fatal(fmt.Errorf("%s lists no devices", *cfgPath))
	}

	if *probe {
		for _, r := range collect(cfg, true, secrets) {
			switch {
			case r.err != nil:
				fmt.Fprintf(os.Stderr, "%-20s ERROR %v\n", r.label, r.err)
			case r.fingerprint != "":
				fmt.Printf("%-20s %s\n", r.label, r.fingerprint)
			default:
				fmt.Printf("%-20s (replay, no TLS)\n", r.label)
			}
		}
		return
	}

	b, _, idx, failed, err := buildOnce(cfg, secrets)
	if err != nil {
		fatal(err)
	}

	if *serve == "" {
		if *outPath == "-" {
			os.Stdout.Write(append(b, '\n'))
		} else if err := os.WriteFile(*outPath, append(b, '\n'), 0o600); err != nil {
			fatal(err)
		}
		if failed > 0 {
			os.Exit(1)
		}
		return
	}

	if *outPath != "-" {
		if err := os.WriteFile(*outPath, append(b, '\n'), 0o600); err != nil {
			fatal(err)
		}
	}

	var current atomic.Pointer[[]byte]
	current.Store(&b)
	var currentIPAM atomic.Pointer[ipam.Index]
	currentIPAM.Store(idx)

	if *refresh > 0 {
		go func() {
			t := time.NewTicker(*refresh)
			defer t.Stop()
			for range t.C {
				// A failed pass keeps the previous graph on screen. A blank
				// page is worse than a stale one, and the timestamp in the
				// header shows the reader how old it is.
				cfg, secrets := store.Snapshot()
				next, _, nextIdx, _, err := buildOnce(cfg, secrets)
				if err != nil {
					fmt.Fprintf(os.Stderr, "refresh failed, keeping the previous graph: %v\n", err)
					continue
				}
				current.Store(&next)
				currentIPAM.Store(nextIdx)
			}
		}()
	}

	adminToken := os.Getenv("SFOS_ADMIN_TOKEN")
	if adminToken == "" {
		fmt.Fprintln(os.Stderr, "settings API disabled: set SFOS_ADMIN_TOKEN to enable adding/editing/removing firewalls from the viewer")
	}

	srv := &http.Server{
		Addr: *serve,
		Handler: web.Handler(
			func() []byte { return *current.Load() },
			ipamLookup(&currentIPAM),
			devicesAPI(store, &current, &currentIPAM),
			adminToken,
		),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "viewer on http://%s\n", *serve)
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// ipamLookup adapts the ipam package to web.IPAMLookup, translating a lookup
// result into the JSON body and HTTP status the handler writes verbatim.
func ipamLookup(current *atomic.Pointer[ipam.Index]) web.IPAMLookup {
	return func(ip string) ([]byte, int) {
		idx := current.Load()
		if idx == nil {
			return mustJSON(map[string]string{"error": "no graph collected yet"}), http.StatusServiceUnavailable
		}
		res, status := idx.Lookup(ip)
		switch status {
		case ipam.Invalid:
			return mustJSON(map[string]string{"ip": ip, "error": "not a valid IPv4 address"}), http.StatusBadRequest
		case ipam.NotFound:
			return mustJSON(map[string]string{"ip": ip, "error": "no known network contains this address"}), http.StatusNotFound
		default:
			b, err := json.Marshal(res)
			if err != nil {
				return mustJSON(map[string]string{"error": "internal error"}), http.StatusInternalServerError
			}
			return b, http.StatusOK
		}
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"internal error"}`)
	}
	return b
}

// buildOnce reads every appliance and marshals the document, plus the IPAM
// index built from the same snapshots and graph. It returns the number of
// appliances that failed so a one-shot run can exit non-zero while a served
// run carries on with a partial picture, and the per-device reports so a
// settings edit can report back on specifically the device it just touched
// without waiting for the next refresh tick.
func buildOnce(cfg config, secrets map[string]string) ([]byte, []deviceReport, *ipam.Index, int, error) {
	results := collect(cfg, false, secrets)

	var snaps []*sfos.Snapshot
	out := output{
		GeneratedAt:  time.Now().UTC(),
		Fingerprints: map[string]string{},
	}
	var failed int
	for _, r := range results {
		rep := deviceReport{Label: r.label, Source: r.source}
		if r.snap != nil {
			rep.Host = r.snap.Host
			rep.Partial = r.snap.Partial
			snaps = append(snaps, r.snap)
		}
		if r.fingerprint != "" {
			out.Fingerprints[r.label] = r.fingerprint
		}
		if r.err != nil {
			failed++
			rep.Error = r.err.Error()
			fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r.label, r.err)
		}
		out.Devices = append(out.Devices, rep)
	}

	if len(snaps) == 0 {
		return nil, out.Devices, nil, failed, fmt.Errorf("no appliance could be read; nothing to draw")
	}

	out.Graph = topology.Build(snaps)
	idx := ipam.Build(snaps, out.Graph)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, out.Devices, nil, failed, err
	}

	fmt.Fprintf(os.Stderr, "%d/%d appliances read, %d nodes, %d edges\n",
		len(snaps), len(cfg.Devices), len(out.Graph.Nodes), len(out.Graph.Edges))
	return b, out.Devices, idx, failed, nil
}

func collect(cfg config, probeOnly bool, secrets map[string]string) []result {
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	results := make([]result, len(cfg.Devices))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, d := range cfg.Devices {
		wg.Add(1)
		go func(i int, d deviceConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			label := d.Label
			if label == "" {
				label = d.Host
			}
			r := result{label: label, source: "live"}

			if d.OfflineDir != "" {
				r.source = "replay"
				if probeOnly {
					results[i] = r
					return
				}
				host := d.Host
				if host == "" {
					host = "replay:" + d.OfflineDir
				}
				r.snap, r.err = sfos.LoadDir(label, host, d.OfflineDir)
				results[i] = r
				return
			}

			token := d.Token
			switch {
			case token != "":
				// inline, as configured
			case d.TokenEnv != "":
				token = os.Getenv(d.TokenEnv)
				if token == "" {
					r.err = fmt.Errorf("%s is not set in the environment", d.TokenEnv)
					results[i] = r
					return
				}
			default:
				// Neither set: a device the settings API created or edited
				// keeps its key out of devices.json entirely, in the
				// sibling secrets file instead.
				token = secrets[label]
			}
			if d.Host == "" || token == "" {
				r.err = fmt.Errorf("needs host and a token (token, tokenEnv, or one set via settings), or offlineDir")
				results[i] = r
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			c := sfos.New(sfos.Credentials{
				Host: d.Host, Label: label, Token: token, PinnedSHA256: d.PinSHA256,
			})
			if probeOnly {
				_, r.err = c.SystemSettings(ctx)
				r.fingerprint = c.Fingerprint
				results[i] = r
				return
			}
			r.snap, r.err = c.Collect(ctx)
			r.fingerprint = c.Fingerprint
			results[i] = r
		}(i, d)
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool { return results[a].label < results[b].label })
	return results
}

func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ---- settings: fleetStore and its HTTP surface -----------------------

// fleetStore is the mutable, on-disk-backed fleet definition the settings
// API edits. devices.json and a sibling secrets file (gitignored, never a
// live token) are the two files it owns; one mutex guards both so a
// concurrent read (a refresh tick, a settings GET) and a write (an edit)
// never interleave a torn read.
//
// This is deliberately a bare-binary / local-use feature. The documented
// Docker deployment mounts devices.json read-only and runs the container's
// root filesystem read-only specifically so the process can never rewrite
// its own config; a write here will simply fail there, loudly, rather than
// silently doing nothing.
type fleetStore struct {
	mu          sync.RWMutex
	cfgPath     string
	secretsPath string
	cfg         config
	secrets     map[string]string // device label -> API token
}

func newFleetStore(cfgPath, secretsPath string) *fleetStore {
	return &fleetStore{cfgPath: cfgPath, secretsPath: secretsPath, secrets: map[string]string{}}
}

func (s *fleetStore) Load() error {
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	secrets, err := loadSecrets(s.secretsPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg, s.secrets = cfg, secrets
	s.mu.Unlock()
	return nil
}

// Snapshot returns copies safe for a collection pass to use without holding
// the store's lock for the whole pass.
func (s *fleetStore) Snapshot() (config, map[string]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.Devices = append([]deviceConfig(nil), s.cfg.Devices...)
	secrets := make(map[string]string, len(s.secrets))
	for k, v := range s.secrets {
		secrets[k] = v
	}
	return cfg, secrets
}

// deviceSummary is what GET /api/devices answers with: everything about a
// device except the token's value, since a settings viewer that can read
// back a live API key is not meaningfully different from one that stores
// them in plaintext where anyone can browse to them.
type deviceSummary struct {
	Label      string `json:"label"`
	Host       string `json:"host,omitempty"`
	TokenEnv   string `json:"tokenEnv,omitempty"`
	HasToken   bool   `json:"hasToken"`
	PinSHA256  string `json:"pinSha256,omitempty"`
	OfflineDir string `json:"offlineDir,omitempty"`
}

func (s *fleetStore) List() []deviceSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]deviceSummary, 0, len(s.cfg.Devices))
	for _, d := range s.cfg.Devices {
		_, hasSecret := s.secrets[d.Label]
		out = append(out, deviceSummary{
			Label: d.Label, Host: d.Host, TokenEnv: d.TokenEnv,
			HasToken:   d.Token != "" || d.TokenEnv != "" || hasSecret,
			PinSHA256:  d.PinSHA256,
			OfflineDir: d.OfflineDir,
		})
	}
	return out
}

// deviceInput is the shape settings sends for a create or update. Token is
// plaintext in the request body (as it has to be, coming from a form) but is
// stored in the secrets file, never in devices.json; an empty Token on an
// update leaves the existing one untouched.
type deviceInput struct {
	Label      string `json:"label"`
	Host       string `json:"host"`
	Token      string `json:"token"`
	PinSHA256  string `json:"pinSha256"`
	OfflineDir string `json:"offlineDir"`
}

func (in deviceInput) validate() error {
	if strings.TrimSpace(in.Label) == "" {
		return fmt.Errorf("label is required")
	}
	if in.OfflineDir == "" && in.Host == "" {
		return fmt.Errorf("host is required (or offlineDir for a replay device)")
	}
	return nil
}

// persistError marks a failure to write the underlying files, as opposed to
// a validation error -- the two deserve different HTTP statuses.
type persistError struct{ err error }

func (e *persistError) Error() string { return e.err.Error() }
func (e *persistError) Unwrap() error { return e.err }

func (s *fleetStore) Add(in deviceInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.cfg.Devices {
		if d.Label == in.Label {
			return fmt.Errorf("a device labeled %q already exists", in.Label)
		}
	}
	s.cfg.Devices = append(s.cfg.Devices, deviceConfig{
		Label: in.Label, Host: in.Host, PinSHA256: in.PinSHA256, OfflineDir: in.OfflineDir,
	})
	if in.Token != "" {
		s.secrets[in.Label] = in.Token
	}
	if err := s.persistLocked(); err != nil {
		return &persistError{err}
	}
	return nil
}

func (s *fleetStore) Update(label string, in deviceInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, d := range s.cfg.Devices {
		if d.Label == label {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("no device labeled %q", label)
	}
	if in.Label != label {
		for _, d := range s.cfg.Devices {
			if d.Label == in.Label {
				return fmt.Errorf("a device labeled %q already exists", in.Label)
			}
		}
	}
	existing := s.cfg.Devices[idx]
	s.cfg.Devices[idx] = deviceConfig{
		Label: in.Label, Host: in.Host, PinSHA256: in.PinSHA256, OfflineDir: in.OfflineDir,
		// A manually-authored entry using tokenEnv keeps working; settings
		// never fills this field in, only Token via the secrets file.
		TokenEnv: existing.TokenEnv, Token: existing.Token,
	}
	if label != in.Label {
		if v, ok := s.secrets[label]; ok {
			delete(s.secrets, label)
			s.secrets[in.Label] = v
		}
	}
	if in.Token != "" {
		s.secrets[in.Label] = in.Token
		// A UI-managed secret retires any inline token, so the field is not
		// silently ignored from now on.
		s.cfg.Devices[idx].Token = ""
	}
	if err := s.persistLocked(); err != nil {
		return &persistError{err}
	}
	return nil
}

func (s *fleetStore) Remove(label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.cfg.Devices[:0]
	found := false
	for _, d := range s.cfg.Devices {
		if d.Label == label {
			found = true
			continue
		}
		kept = append(kept, d)
	}
	if !found {
		return fmt.Errorf("no device labeled %q", label)
	}
	s.cfg.Devices = kept
	delete(s.secrets, label)
	if err := s.persistLocked(); err != nil {
		return &persistError{err}
	}
	return nil
}

// persistLocked writes both files. Called with mu held.
func (s *fleetStore) persistLocked() error {
	cfgBytes, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.cfgPath, append(cfgBytes, '\n'), 0o644); err != nil {
		return fmt.Errorf("saving %s: %w (a read-only config mount, as the documented Docker "+
			"deployment uses, refuses this by design -- edit it from the host and restart instead)", s.cfgPath, err)
	}
	secBytes, err := json.MarshalIndent(s.secrets, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.secretsPath, append(secBytes, '\n'), 0o600); err != nil {
		return fmt.Errorf("saving %s: %w", s.secretsPath, err)
	}
	return nil
}

func loadSecrets(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// devicesAPI wires the store into web.DeviceAPI. Every mutation re-collects
// the whole fleet immediately (like the background refresh, but on demand)
// so the graph reflects the edit without waiting for the next tick, and
// reports back specifically how the device just touched fared -- a save
// that can't reach its new firewall should say so immediately, not leave the
// admin guessing until the next refresh.
func devicesAPI(store *fleetStore, current *atomic.Pointer[[]byte], currentIPAM *atomic.Pointer[ipam.Index]) web.DeviceAPI {
	applyAndReport := func(label string) []byte {
		cfg, secrets := store.Snapshot()
		b, reports, idx, _, err := buildOnce(cfg, secrets)
		if err == nil {
			current.Store(&b)
			currentIPAM.Store(idx)
		}
		resp := map[string]any{"devices": store.List()}
		for _, r := range reports {
			if r.Label == label {
				resp["device"] = r
			}
		}
		return mustJSON(resp)
	}

	classify := func(err error) int {
		var pe *persistError
		if errors.As(err, &pe) {
			return http.StatusInternalServerError
		}
		return http.StatusBadRequest
	}

	return web.DeviceAPI{
		List: func() ([]byte, int) {
			return mustJSON(store.List()), http.StatusOK
		},
		Create: func(body []byte) ([]byte, int) {
			var in deviceInput
			if err := json.Unmarshal(body, &in); err != nil {
				return mustJSON(map[string]string{"error": "invalid JSON: " + err.Error()}), http.StatusBadRequest
			}
			if err := store.Add(in); err != nil {
				return mustJSON(map[string]string{"error": err.Error()}), classify(err)
			}
			return applyAndReport(in.Label), http.StatusOK
		},
		Update: func(label string, body []byte) ([]byte, int) {
			var in deviceInput
			if err := json.Unmarshal(body, &in); err != nil {
				return mustJSON(map[string]string{"error": "invalid JSON: " + err.Error()}), http.StatusBadRequest
			}
			if err := store.Update(label, in); err != nil {
				return mustJSON(map[string]string{"error": err.Error()}), classify(err)
			}
			return applyAndReport(in.Label), http.StatusOK
		},
		Delete: func(label string) ([]byte, int) {
			if err := store.Remove(label); err != nil {
				return mustJSON(map[string]string{"error": err.Error()}), classify(err)
			}
			return applyAndReport(""), http.StatusOK
		},
	}
}
