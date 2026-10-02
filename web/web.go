// Package web embeds the topology viewer and the IPAM API so the collector
// can serve both.
//
// Serving beats handing someone an HTML file and a JSON file: browsers block
// fetch() from file://, so a standalone page has to be fed through a file
// picker. Over HTTP the page loads the graph on its own and one command
// produces a working screen.
package web

import (
	"bytes"
	"crypto/subtle"
	_ "embed"
	"io"
	"net/http"
	"time"
)

// v2 is the current interface, served at / and /policy.
//
//go:embed index.html
var indexHTML []byte

//go:embed policy.html
var policyHTML []byte

//go:embed app.css
var appCSS []byte

//go:embed graph.js
var graphJS []byte

//go:embed policy.js
var policyJS []byte

//go:embed fleet.js
var fleetJS []byte

// v1 is the previous interface, kept reachable at /v1 and /v1/policy for
// anyone mid-workflow with it open, or who simply prefers it. It is frozen
// as-is: no new features land there, only the two internal nav links were
// repointed when it moved under /v1 (see web/v1's own history).
//
//go:embed v1/index.html
var v1IndexHTML []byte

//go:embed v1/policy.html
var v1PolicyHTML []byte

// Provider returns the current graph document. It is a function rather than a
// value because a long-running collector re-reads the fleet on a timer and the
// handler must serve whatever the latest pass produced.
type Provider func() []byte

// IPAMLookup resolves one address to the network, interface and device that
// carry it, already marshaled to the JSON body to write plus the HTTP status
// to send with it. Handing back a finished response, rather than a Go value,
// keeps this package ignorant of the ipam and topology types the way it is
// already ignorant of topology.Graph — it only ever moves bytes.
type IPAMLookup func(ip string) (body []byte, status int)

// DeviceAPI is the settings CRUD surface: list every device, create one,
// update one by label, delete one by label. Each returns the JSON body to
// write and the HTTP status, the same "finished response" shape as
// IPAMLookup, so this package stays ignorant of the config and secrets types
// on the other side of it.
type DeviceAPI struct {
	List   func() (body []byte, status int)
	Create func(body []byte) (respBody []byte, status int)
	Update func(label string, body []byte) (respBody []byte, status int)
	Delete func(label string) (respBody []byte, status int)
}

// PolicyAPI is the access-control matrix surface: the current design (every
// discovered network plus each defined cell and the rule-intent preview it
// implies), set one cell, delete one cell, apply one saved cell for real.
// Same "finished response" shape as DeviceAPI and IPAMLookup, for the same
// reason.
type PolicyAPI struct {
	Get        func() (body []byte, status int)
	SetCell    func(body []byte) (respBody []byte, status int)
	DeleteCell func(source, destination string, bidi bool) (respBody []byte, status int)
	// ApplyCell creates or updates the real Sophos rule(s) a saved cell
	// implies, on every applicable appliance, and reports per-device
	// results. It only ever acts on a cell already saved via SetCell.
	ApplyCell func(source, destination string) (respBody []byte, status int)
	// ApplyAll runs ApplyCell for every saved cell in one action, so a
	// user does not have to open and apply each cell individually.
	ApplyAll func() (respBody []byte, status int)
}

// Handler serves the current viewer at / and the policy matrix at /policy,
// the previous interface at /v1 and /v1/policy, the current graph at
// /graph.json, IP lookups at /api/ipam/{ip}, the settings API at
// /api/devices and the policy API at /api/policy (both only when
// adminToken is non-empty), and a liveness probe at /healthz.
//
// adminToken gates every /api/devices and /api/policy request via the
// X-Admin-Token header. An empty adminToken disables both surfaces entirely
// (404, not just unauthenticated) rather than defaulting them open: this
// viewer has no other authentication of its own, and write endpoints that
// can plant firewall API keys or change access-control policy are a
// materially bigger blast radius than the read-only graph.
func Handler(graph Provider, ipamLookup IPAMLookup, devices DeviceAPI, policyAPI PolicyAPI, adminToken string) http.Handler {
	mux := http.NewServeMux()
	started := time.Now()

	writeJSON := func(w http.ResponseWriter, body []byte, status int) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		w.Write(body)
	}

	mux.HandleFunc("/graph.json", func(w http.ResponseWriter, r *http.Request) {
		b := graph()
		if len(b) == 0 {
			http.Error(w, `{"error":"no graph collected yet"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, "graph.json", time.Now(), bytes.NewReader(b))
	})

	mux.HandleFunc("GET /api/ipam/{ip}", func(w http.ResponseWriter, r *http.Request) {
		body, status := ipamLookup(r.PathValue("ip"))
		writeJSON(w, body, status)
	})

	// settingsGate enforces the admin token before a DeviceAPI call runs.
	// Comparing with subtle.ConstantTimeCompare avoids leaking the token's
	// value one byte at a time through response-timing differences.
	settingsGate := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if adminToken == "" {
				writeJSON(w, []byte(`{"error":"settings are disabled: set SFOS_ADMIN_TOKEN to enable"}`), http.StatusNotFound)
				return
			}
			got := r.Header.Get("X-Admin-Token")
			if len(got) != len(adminToken) || subtle.ConstantTimeCompare([]byte(got), []byte(adminToken)) != 1 {
				writeJSON(w, []byte(`{"error":"missing or incorrect admin token"}`), http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("GET /api/devices", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		body, status := devices.List()
		writeJSON(w, body, status)
	}))
	mux.HandleFunc("POST /api/devices", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, []byte(`{"error":"could not read request body"}`), http.StatusBadRequest)
			return
		}
		respBody, status := devices.Create(body)
		writeJSON(w, respBody, status)
	}))
	mux.HandleFunc("PUT /api/devices/{label}", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, []byte(`{"error":"could not read request body"}`), http.StatusBadRequest)
			return
		}
		respBody, status := devices.Update(r.PathValue("label"), body)
		writeJSON(w, respBody, status)
	}))
	mux.HandleFunc("DELETE /api/devices/{label}", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		respBody, status := devices.Delete(r.PathValue("label"))
		writeJSON(w, respBody, status)
	}))

	mux.HandleFunc("GET /api/policy", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		body, status := policyAPI.Get()
		writeJSON(w, body, status)
	}))
	mux.HandleFunc("PUT /api/policy/cell", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, []byte(`{"error":"could not read request body"}`), http.StatusBadRequest)
			return
		}
		respBody, status := policyAPI.SetCell(body)
		writeJSON(w, respBody, status)
	}))
	// source/destination arrive as query parameters, not path segments: a
	// network id is a segment node id like "seg:192.168.101.0/24", which
	// contains "/" and would be misread as extra path segments.
	mux.HandleFunc("DELETE /api/policy/cell", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		respBody, status := policyAPI.DeleteCell(q.Get("source"), q.Get("destination"), q.Get("bidi") == "true")
		writeJSON(w, respBody, status)
	}))
	mux.HandleFunc("POST /api/policy/apply", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		respBody, status := policyAPI.ApplyCell(q.Get("source"), q.Get("destination"))
		writeJSON(w, respBody, status)
	}))
	mux.HandleFunc("POST /api/policy/apply-all", settingsGate(func(w http.ResponseWriter, r *http.Request) {
		respBody, status := policyAPI.ApplyAll()
		writeJSON(w, respBody, status)
	}))

	// healthz reports that the process is serving, not that every appliance
	// answered. A fleet where one firewall is unreachable still produces a
	// useful graph, and restarting the container would not fix the firewall.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "policy.html", started, bytes.NewReader(policyHTML))
	})
	mux.HandleFunc("GET /app.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeContent(w, r, "app.css", started, bytes.NewReader(appCSS))
	})
	mux.HandleFunc("GET /graph.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		http.ServeContent(w, r, "graph.js", started, bytes.NewReader(graphJS))
	})
	mux.HandleFunc("GET /policy.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		http.ServeContent(w, r, "policy.js", started, bytes.NewReader(policyJS))
	})
	mux.HandleFunc("GET /fleet.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		http.ServeContent(w, r, "fleet.js", started, bytes.NewReader(fleetJS))
	})

	// v1: the previous interface, kept reachable for anyone mid-workflow
	// with it open. Not linked from v2's chrome except a small "legacy" nod;
	// v1 itself links forward to v2 so either can be reached from the other.
	mux.HandleFunc("GET /v1", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "v1", started, bytes.NewReader(v1IndexHTML))
	})
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "v1-policy", started, bytes.NewReader(v1PolicyHTML))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", started, bytes.NewReader(indexHTML))
	})

	return mux
}
