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
//	sfos-topology -config devices.json -serve 127.0.0.1:8089 -refresh 15m
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
	"github.com/tales/sfos-topology/policy"
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
	// stale is true when snap was not read live this pass but reused from
	// snapshotCache after err made a fresh read impossible -- the device
	// still draws in the topology, just visibly out of date.
	stale bool
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
	// Stale marks a device currently unreachable whose node still appears
	// in the graph, drawn from its last successful collection rather than
	// omitted -- Error explains why a fresh read failed, Stale is what the
	// UI keys off to render that device (and only that device) as offline.
	Stale bool `json:"stale,omitempty"`
}

// snapshotCache remembers the most recent successful snapshot per device
// label. A device that goes unreachable for one or more passes keeps
// drawing from here instead of disappearing from the topology entirely --
// the topology is a fact about the fleet's configuration, and a firewall
// being briefly offline does not erase where it sits in the network. The
// device report still carries the failure, so the UI can tell "this is
// current" from "this is the last thing we knew" apart.
type snapshotCache struct {
	mu      sync.Mutex
	byLabel map[string]*sfos.Snapshot
}

func newSnapshotCache() *snapshotCache { return &snapshotCache{byLabel: map[string]*sfos.Snapshot{}} }

func (c *snapshotCache) get(label string) *sfos.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byLabel[label]
}

func (c *snapshotCache) put(label string, s *sfos.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byLabel[label] = s
}

func main() {
	var (
		cfgPath     = flag.String("config", "devices.json", "path to the device config")
		secretsPath = flag.String("secrets", "", "path to the settings-managed secrets file (default: devices.secrets.json next to -config)")
		outPath     = flag.String("out", "-", "output file for the graph JSON, or - for stdout")
		probe       = flag.Bool("probe", false, "connect and print TLS fingerprints, then exit")
		serve       = flag.String("serve", "", "serve the viewer and the graph on this address, e.g. 127.0.0.1:8089")
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

	policyPath := filepath.Join(filepath.Dir(*cfgPath), "policy-matrix.json")
	polStore := newPolicyStore(policyPath)
	if err := polStore.Load(); err != nil {
		fatal(err)
	}

	// cache remembers the last snapshot each device gave us, so a device
	// that goes unreachable keeps drawing from its last known
	// configuration -- visibly marked stale -- instead of vanishing from
	// the graph. Shared across every collection pass for the life of the
	// process; probe mode never touches it, since it never builds a graph.
	cache := newSnapshotCache()

	if *probe {
		for _, r := range collect(cfg, true, secrets, nil) {
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

	b, graph, _, idx, failed, err := buildOnce(cfg, secrets, cache)
	if err != nil {
		if *serve == "" {
			fatal(err)
		}
		// -serve must not crash-loop the container over a transient or
		// total outage at the moment it happens to start: a boot-time
		// collection failure is not different in kind from a later pass
		// where every appliance drops off, and that case already keeps the
		// process serving (see the refresh loop below). Start empty and let
		// -refresh retry; the web layer already renders "no graph yet"
		// (503) rather than crashing on a nil graph/index.
		fmt.Fprintf(os.Stderr, "warn: initial collection failed, starting anyway: %v\n", err)
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

	if b != nil && *outPath != "-" {
		if err := os.WriteFile(*outPath, append(b, '\n'), 0o600); err != nil {
			fatal(err)
		}
	}

	var current atomic.Pointer[[]byte]
	current.Store(&b)
	var currentIPAM atomic.Pointer[ipam.Index]
	currentIPAM.Store(idx)
	var currentGraph atomic.Pointer[topology.Graph]
	currentGraph.Store(graph)

	if *refresh > 0 {
		go func() {
			t := time.NewTicker(*refresh)
			defer t.Stop()
			for range t.C {
				// A failed pass keeps the previous graph on screen. A blank
				// page is worse than a stale one, and the timestamp in the
				// header shows the reader how old it is.
				cfg, secrets := store.Snapshot()
				next, nextGraph, _, nextIdx, _, err := buildOnce(cfg, secrets, cache)
				if err != nil {
					fmt.Fprintf(os.Stderr, "refresh failed, keeping the previous graph: %v\n", err)
					continue
				}
				current.Store(&next)
				currentIPAM.Store(nextIdx)
				currentGraph.Store(nextGraph)
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
			devicesAPI(store, &current, &currentIPAM, &currentGraph, cache),
			policyAPI(polStore, &currentGraph, store),
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
func buildOnce(cfg config, secrets map[string]string, cache *snapshotCache) ([]byte, *topology.Graph, []deviceReport, *ipam.Index, int, error) {
	results := collect(cfg, false, secrets, cache)

	var snaps []*sfos.Snapshot
	out := output{
		GeneratedAt:  time.Now().UTC(),
		Fingerprints: map[string]string{},
	}
	var failed int
	for _, r := range results {
		rep := deviceReport{Label: r.label, Source: r.source, Stale: r.stale}
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
		return nil, nil, out.Devices, nil, failed, fmt.Errorf("no appliance could be read; nothing to draw")
	}

	out.Graph = topology.Build(snaps)
	idx := ipam.Build(snaps, out.Graph)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, nil, out.Devices, nil, failed, err
	}

	fmt.Fprintf(os.Stderr, "%d/%d appliances read, %d nodes, %d edges\n",
		len(snaps), len(cfg.Devices), len(out.Graph.Nodes), len(out.Graph.Edges))
	return b, out.Graph, out.Devices, idx, failed, nil
}

// resolveToken picks a device's API token from its three possible sources
// (inline, an environment variable, or the settings-managed secrets file)
// and validates that both it and Host are present. Shared by collect (bulk
// fleet reads) and fleetStore.ClientFor (one on-demand client for a policy
// Apply step) so the two never drift on precedence.
func resolveToken(d deviceConfig, secrets map[string]string) (string, error) {
	token := d.Token
	switch {
	case token != "":
		// inline, as configured
	case d.TokenEnv != "":
		token = os.Getenv(d.TokenEnv)
		if token == "" {
			return "", fmt.Errorf("%s is not set in the environment", d.TokenEnv)
		}
	default:
		// Neither set: a device the settings API created or edited keeps its
		// key out of devices.json entirely, in the sibling secrets file
		// instead.
		label := d.Label
		if label == "" {
			label = d.Host
		}
		token = secrets[label]
	}
	if d.Host == "" || token == "" {
		return "", fmt.Errorf("needs host and a token (token, tokenEnv, or one set via settings), or offlineDir")
	}
	return token, nil
}

func collect(cfg config, probeOnly bool, secrets map[string]string, cache *snapshotCache) []result {
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	// finish reconciles one device's outcome against the cache: a failure
	// falls back to the last snapshot that device ever gave us (if any),
	// marked stale, so it keeps its place in the topology instead of
	// disappearing; a success refreshes the cache for the next failure to
	// fall back to. probe mode passes a nil cache, which no-ops both paths.
	finish := func(r result) result {
		if cache == nil {
			return r
		}
		if r.err != nil {
			if cached := cache.get(r.label); cached != nil {
				r.snap, r.stale = cached, true
			}
			return r
		}
		if r.snap != nil {
			cache.put(r.label, r.snap)
		}
		return r
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
				results[i] = finish(r)
				return
			}

			token, err := resolveToken(d, secrets)
			if err != nil {
				r.err = err
				results[i] = finish(r)
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
			results[i] = finish(r)
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

// ClientFor builds a live sfos.Client for one device by label, using
// whichever token source (inline, env, or settings-managed secret) it's
// configured with. It is how a policy Apply step reaches the one appliance a
// rule intent names, without duplicating collect's token precedence.
func (s *fleetStore) ClientFor(label string) (*sfos.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.cfg.Devices {
		if d.Label != label {
			continue
		}
		if d.OfflineDir != "" {
			return nil, fmt.Errorf("%s is a replay device (offlineDir); Apply needs a live appliance", label)
		}
		token, err := resolveToken(d, s.secrets)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		return sfos.New(sfos.Credentials{Host: d.Host, Label: label, Token: token, PinnedSHA256: d.PinSHA256}), nil
	}
	return nil, fmt.Errorf("no device labeled %q", label)
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
func devicesAPI(store *fleetStore, current *atomic.Pointer[[]byte], currentIPAM *atomic.Pointer[ipam.Index], currentGraph *atomic.Pointer[topology.Graph], cache *snapshotCache) web.DeviceAPI {
	applyAndReport := func(label string) []byte {
		cfg, secrets := store.Snapshot()
		b, graph, reports, idx, _, err := buildOnce(cfg, secrets, cache)
		if err == nil {
			current.Store(&b)
			currentIPAM.Store(idx)
			currentGraph.Store(graph)
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
		Refresh: func() ([]byte, int) {
			return applyAndReport(""), http.StatusOK
		},
	}
}

// ---- policy matrix: store and its HTTP surface -------------------------

// policyStore is the persisted, user-authored policy matrix: a network x
// network grid of macro allow/deny switches, independent of any one
// collection pass and kept until explicitly changed through the UI.
//
// It only ever computes and stores intent (see package policy's doc for
// why): nothing here calls the Sophos API. Persisting to policy-matrix.json
// is the same file-based, no-database approach devices.json and
// devices.secrets.json already use.
type policyStore struct {
	mu    sync.RWMutex
	path  string
	cells map[string]policy.Cell // keyed by Cell.Key()
}

func newPolicyStore(path string) *policyStore {
	return &policyStore{path: path, cells: map[string]policy.Cell{}}
}

func (s *policyStore) Load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var doc struct {
		Cells []policy.Cell `json:"cells"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cells = make(map[string]policy.Cell, len(doc.Cells))
	for _, c := range doc.Cells {
		s.cells[c.Key()] = c
	}
	return nil
}

// List returns every cell, sorted for a stable API response.
func (s *policyStore) List() []policy.Cell {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policy.Cell, 0, len(s.cells))
	for _, c := range s.cells {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// cellInput is the shape the matrix UI sends for one edit. Bidi expands into
// two independently-keyed Cells at write time, so toggling one direction
// later never touches the other.
type cellInput struct {
	Source           string        `json:"source"`
	Destination      string        `json:"destination"`
	Action           policy.Action `json:"action"`
	RequireHeartbeat bool          `json:"requireHeartbeat"`
	RequireAuth      bool          `json:"requireAuth"`
	Bidi             bool          `json:"bidi"`
}

func (in cellInput) validate() error {
	if in.Source == "" || in.Destination == "" {
		return fmt.Errorf("source and destination are required")
	}
	if in.Source == in.Destination {
		return fmt.Errorf("source and destination must differ")
	}
	if in.Action != policy.Allow && in.Action != policy.Deny {
		return fmt.Errorf("action must be %q or %q", policy.Allow, policy.Deny)
	}
	return nil
}

func (s *policyStore) SetCell(in cellInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	cells := []policy.Cell{{
		Source: in.Source, Destination: in.Destination, Action: in.Action,
		RequireHeartbeat: in.RequireHeartbeat, RequireAuth: in.RequireAuth,
	}}
	if in.Bidi {
		cells = append(cells, policy.Cell{
			Source: in.Destination, Destination: in.Source, Action: in.Action,
			RequireHeartbeat: in.RequireHeartbeat, RequireAuth: in.RequireAuth,
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cells {
		s.cells[c.Key()] = c
	}
	if err := s.persistLocked(); err != nil {
		return &persistError{err}
	}
	return nil
}

func (s *policyStore) DeleteCell(source, destination string, bidi bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := (policy.Cell{Source: source, Destination: destination}).Key()
	if _, ok := s.cells[key]; !ok {
		return fmt.Errorf("no policy from %q to %q", source, destination)
	}
	delete(s.cells, key)
	if bidi {
		delete(s.cells, (policy.Cell{Source: destination, Destination: source}).Key())
	}
	if err := s.persistLocked(); err != nil {
		return &persistError{err}
	}
	return nil
}

// Get returns the one saved cell for a source/destination pair, if any --
// Apply only ever acts on a cell the matrix has already saved, never on an
// in-progress edit still sitting in the UI.
func (s *policyStore) Get(source, destination string) (policy.Cell, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cells[(policy.Cell{Source: source, Destination: destination}).Key()]
	return c, ok
}

func (s *policyStore) persistLocked() error {
	cells := make([]policy.Cell, 0, len(s.cells))
	for _, c := range s.cells {
		cells = append(cells, c)
	}
	sort.Slice(cells, func(i, j int) bool { return cells[i].Key() < cells[j].Key() })
	b, err := json.MarshalIndent(struct {
		Cells []policy.Cell `json:"cells"`
	}{cells}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("saving %s: %w (a read-only config mount, as the documented Docker "+
			"deployment uses, refuses this by design -- edit it from the host and restart instead)", s.path, err)
	}
	return nil
}

// cellView is one cell plus the rule intents it currently implies against
// the live graph -- the preview the matrix UI renders per cell, since
// nothing here can actually apply a rule yet (see package policy's doc).
type cellView struct {
	policy.Cell
	Intents []policy.RuleIntent `json:"intents"`
}

// applyResult is one device's outcome from an Apply step, keyed by device
// label so the UI can show it next to the right row in the rule preview it
// already renders.
type applyResult struct {
	Device   string `json:"device"`
	RuleName string `json:"ruleName"`
	Status   string `json:"status"` // "created", "updated", or "error"
	Error    string `json:"error,omitempty"`
}

// applyCell is the real "Apply": it expands c into RuleIntents exactly like
// the preview does, then for each applicable device creates any missing
// address object, resolves both sides' zone/network selectors, and either
// creates or updates that device's rule. One device's failure does not stop
// the others -- a fleet-wide apply degrades per device, the same way
// collection already does.
func applyCell(fleet *fleetStore, g *topology.Graph, c policy.Cell) []applyResult {
	intents := policy.Intents(g, c)
	results := make([]applyResult, 0, len(intents))

	for _, in := range intents {
		res := applyResult{Device: in.Device.Label, RuleName: in.RuleName}

		client, err := fleet.ClientFor(in.Device.Label)
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}

		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			src := policy.ResolveSide(g, c.Source, in.Device.ID, in.Device.Label)
			dst := policy.ResolveSide(g, c.Destination, in.Device.ID, in.Device.Label)

			if !src.ObjectExists {
				if _, err := client.CreateAddressObject(ctx, src.ObjectName, src.NetworkAddress, src.CIDR); err != nil {
					res.Status, res.Error = "error", fmt.Sprintf("creating source object %s: %v", src.ObjectName, err)
					results = append(results, res)
					return
				}
			}
			if !dst.ObjectExists {
				if _, err := client.CreateAddressObject(ctx, dst.ObjectName, dst.NetworkAddress, dst.CIDR); err != nil {
					res.Status, res.Error = "error", fmt.Sprintf("creating destination object %s: %v", dst.ObjectName, err)
					results = append(results, res)
					return
				}
			}

			rule := policy.BuildRule(c, src, dst)
			_, getErr := client.FirewallRule(ctx, rule.Name)
			switch {
			case getErr == nil:
				res.Status = "updated"
				if _, err := client.UpdateFirewallRule(ctx, rule.Name, rule); err != nil {
					res.Status, res.Error = "error", err.Error()
				}
			case strings.Contains(getErr.Error(), "404"):
				res.Status = "created"
				if _, err := client.CreateFirewallRule(ctx, rule); err != nil {
					res.Status, res.Error = "error", err.Error()
				}
			default:
				res.Status, res.Error = "error", fmt.Sprintf("checking for an existing rule: %v", getErr)
			}
			results = append(results, res)
		}()
	}
	return results
}

// cellApplyResult is one saved cell's outcome from an "apply all" step --
// the same per-device results applyCell already produces, labeled with the
// cell they belong to so the UI can show one summary covering every policy
// instead of requiring a click per cell.
type cellApplyResult struct {
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Action      policy.Action `json:"action"`
	Results     []applyResult `json:"results"`
}

// applyAllCells runs applyCell for every saved cell, one after another. It
// does not stop at the first failure -- one cell's error (or one device's,
// within that cell) must not hide whether every other cell succeeded.
func applyAllCells(fleet *fleetStore, g *topology.Graph, cells []policy.Cell) []cellApplyResult {
	out := make([]cellApplyResult, 0, len(cells))
	for _, c := range cells {
		out = append(out, cellApplyResult{
			Source: c.Source, Destination: c.Destination, Action: c.Action,
			Results: applyCell(fleet, g, c),
		})
	}
	return out
}

// policyAPI wires the store into web.PolicyAPI, recomputing rule-intent
// previews against whatever graph is current on every read -- a topology
// change (a firewall added or removed, an interface reconfigured) changes
// which devices a cell applies to without needing the matrix itself
// touched.
func policyAPI(store *policyStore, currentGraph *atomic.Pointer[topology.Graph], fleet *fleetStore) web.PolicyAPI {
	view := func() ([]byte, int) {
		g := currentGraph.Load()
		if g == nil {
			return mustJSON(map[string]string{"error": "no graph collected yet"}), http.StatusServiceUnavailable
		}
		cells := store.List()
		views := make([]cellView, 0, len(cells))
		for _, c := range cells {
			views = append(views, cellView{Cell: c, Intents: policy.Intents(g, c)})
		}
		resp := map[string]any{
			"networks": policy.Networks(g),
			"cells":    views,
		}
		return mustJSON(resp), http.StatusOK
	}

	classify := func(err error) int {
		var pe *persistError
		if errors.As(err, &pe) {
			return http.StatusInternalServerError
		}
		return http.StatusBadRequest
	}

	return web.PolicyAPI{
		Get: view,
		SetCell: func(body []byte) ([]byte, int) {
			var in cellInput
			if err := json.Unmarshal(body, &in); err != nil {
				return mustJSON(map[string]string{"error": "invalid JSON: " + err.Error()}), http.StatusBadRequest
			}
			if err := store.SetCell(in); err != nil {
				return mustJSON(map[string]string{"error": err.Error()}), classify(err)
			}
			return view()
		},
		DeleteCell: func(source, destination string, bidi bool) ([]byte, int) {
			if err := store.DeleteCell(source, destination, bidi); err != nil {
				return mustJSON(map[string]string{"error": err.Error()}), classify(err)
			}
			return view()
		},
		ApplyCell: func(source, destination string) ([]byte, int) {
			g := currentGraph.Load()
			if g == nil {
				return mustJSON(map[string]string{"error": "no graph collected yet"}), http.StatusServiceUnavailable
			}
			c, ok := store.Get(source, destination)
			if !ok {
				return mustJSON(map[string]string{"error": fmt.Sprintf("no saved policy from %q to %q -- save it first", source, destination)}), http.StatusBadRequest
			}
			results := applyCell(fleet, g, c)
			return mustJSON(map[string]any{"results": results}), http.StatusOK
		},
		ApplyAll: func() ([]byte, int) {
			g := currentGraph.Load()
			if g == nil {
				return mustJSON(map[string]string{"error": "no graph collected yet"}), http.StatusServiceUnavailable
			}
			cells := store.List()
			if len(cells) == 0 {
				return mustJSON(map[string]string{"error": "no saved policies to apply"}), http.StatusBadRequest
			}
			results := applyAllCells(fleet, g, cells)
			return mustJSON(map[string]any{"results": results}), http.StatusOK
		},
	}
}
