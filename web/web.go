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

//go:embed index.html
var indexHTML []byte

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

// Handler serves the viewer at /, the current graph at /graph.json, IP
// lookups at /api/ipam/{ip}, the settings API at /api/devices (when
// adminToken is non-empty), and a liveness probe at /healthz.
//
// adminToken gates every /api/devices request via the X-Admin-Token header.
// An empty adminToken disables the settings surface entirely (404, not just
// unauthenticated) rather than defaulting it open: this viewer has no other
// authentication of its own, and a write endpoint that can plant firewall
// API keys is a materially bigger blast radius than the read-only graph.
func Handler(graph Provider, ipamLookup IPAMLookup, devices DeviceAPI, adminToken string) http.Handler {
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

	// healthz reports that the process is serving, not that every appliance
	// answered. A fleet where one firewall is unreachable still produces a
	// useful graph, and restarting the container would not fix the firewall.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
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
