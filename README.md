# sfos-topology

Builds a network topology graph from one or more Sophos Firewalls using the
Firewall Configuration REST API (`/api/firewall-config/v1`).

The graph is derived **entirely from configuration**. The API exposes no ARP
table, no active DHCP lease and no LLDP, so adjacency between appliances is
inferred from shared gateways, point-to-point tunnel arithmetic and static
routes. Every inferred edge carries the rule and the evidence that produced it,
so a wrong edge can be traced to a rule rather than to a guess.

No external dependencies. `go build ./...` works with a bare toolchain and no
module proxy, which matters when the collector runs on a jump host inside a
customer network.

## Interface versions

`/` and `/policy` serve the current interface (a deterministic, layered graph
layout with an evidence-first inspector, plus a redesigned policy matrix — see
`web/index.html`, `web/policy.html`, `web/app.css`, `web/graph.js`,
`web/policy.js`, `web/fleet.js`). The previous interface remains reachable at
`/v1` and `/v1/policy` (`web/v1/`), frozen as-is, for anyone mid-workflow with
it open or who prefers it; each version links to the other. Both talk to the
same collector process and the same `/api/*` surface — nothing about the
backend or the Sophos-facing behavior differs between them.

## Quick start

The lab fleet is already described in `devices.json`, with the API keys kept
out of it in `lab.env`.

```bash
make up       # build the image and serve the viewer on 127.0.0.1:8089
make rebuild  # same, but without the build cache
make logs     # follow the collector
make down     # stop it
```

Without containers:

```bash
make probe    # connect to each firewall, print its TLS fingerprint
make serve    # collect everything and serve on 127.0.0.1:8089
make run      # collect and write graph.json instead of serving
make capture  # snapshot the raw API responses into captures/ for offline work
```

Those targets source `lab.env` for you. To run the binary by hand:

```bash
set -a; . ./lab.env; set +a
go run ./cmd/sfos-topology -config devices.json -serve 127.0.0.1:8089 -refresh 15m
```

## Containers

`docker compose build --no-cache && docker compose up -d` is the whole
deployment. Use `--no-cache` the first time after any change to the Dockerfile
or `.dockerignore`, since a cached `COPY` layer will otherwise be reused. The image is a
multi-stage build ending in `scratch`: the binary is static, there is no shell,
no package manager and no CA bundle, and it runs as uid 65532 with a read-only
root filesystem and every capability dropped. `podman-compose` works the same
way.

Two things are mounted or injected rather than baked in:

- `lab.env` arrives through `env_file`, so no key is ever written to an image
  layer. It is also in `.dockerignore`, which keeps it out of the build context
  entirely.
- `devices.json` is mounted read-only, so adding a firewall is an edit and a
  restart rather than a rebuild.
- `policy-matrix.json` is mounted **writable** — unlike `devices.json`, it
  holds no credentials, only the access-policy design, and the matrix UI's
  whole point is editing it live from the container. Create it once before
  the first `docker compose up` (`echo '{"cells":[]}' > policy-matrix.json`):
  Docker turns a missing bind-mount source file into a directory instead of
  failing, which would otherwise break every later Save.

`-refresh 15m` makes the container re-read the fleet on a timer. A failed pass
keeps the previous graph on screen rather than blanking the page; the timestamp
in the header shows how old the drawing is.

The healthcheck runs the binary against its own `/healthz`, because a `scratch`
image has no `curl` to call. It reports that the process is serving, not that
every firewall answered — a fleet with one unreachable appliance still produces
a useful graph, and restarting the container would not fix the firewall.

The port is published on `127.0.0.1` on purpose. The viewer shows a customer's
internal addressing and has no authentication of its own; put something that
does in front of it before exposing it further.

If the container cannot reach the appliances, the firewalls are probably
reachable only through a host route or a VPN interface. Either add
`network_mode: host` to the service, or route the bridge network accordingly.

### Credentials

`devices.json` names an environment variable per appliance rather than holding
the key, because the config file is the artefact that gets committed, pasted
into a ticket and shared with a colleague. `lab.env` holds the actual keys, is
mode 600, and is in `.gitignore`.

A Sophos API key inherits every permission of the account that created it, so
generate one from a dedicated read-only administrator profile. The collector
only issues GETs and never needs more.

After `make probe`, paste each fingerprint into `pinSha256` in `devices.json`.
From then on the collector refuses to talk to a different certificate, which is
the only meaningful validation available against self-signed appliance certs.

### Adding a firewall

```json
{ "label": "FW-104", "host": "192.168.104.99:4444", "tokenEnv": "SFOS_TOKEN_FW104" }
```

Add the matching `export` to `lab.env`. A device entry can also be a replay of
a capture directory (`"offlineDir": "captures/fw101"`), and live and replayed
appliances can be mixed in one run — which is how you diff a customer capture
against your own lab.

### Settings UI

`make serve` also adds a **⚙ Settings** button to the viewer for adding,
editing and removing firewalls without hand-editing `devices.json` — useful
for a quick lab change, less so for anything you want tracked in git.

It's disabled by default. Set `SFOS_ADMIN_TOKEN` in the collector's
environment to turn it on; the UI prompts for that token once per browser
tab (kept in `sessionStorage`, gone when the tab closes) and sends it as
`X-Admin-Token` on every settings request. Leaving it unset is a deliberate
default, not an oversight: this viewer has no other authentication of its
own, and a write endpoint that can plant firewall API keys is a bigger blast
radius than the read-only graph it otherwise only ever serves.

Keys entered through Settings never touch `devices.json` — they go to a
sibling `devices.secrets.json` (gitignored, `0600`, mirroring `lab.env`'s
role) keyed by device label. `devices.json` stays the thing you'd feel safe
pasting into a ticket, the same guarantee `tokenEnv` gives manually-authored
entries.

This is a bare-binary / local-use feature. The documented Docker deployment
mounts `devices.json` read-only and runs the container's root filesystem
read-only specifically so the process can never rewrite its own config;
Settings writes there fail with a clear error rather than silently doing
nothing. Edit `devices.json` from the host and restart the container instead.

Saving triggers an immediate re-collection (not a wait for the next
`-refresh` tick) and reports back specifically how the device you just
added or edited fared, so a typo in the host or a stale key shows up right
away instead of on the next scheduled pass.

### Access policy matrix

A second page, at **`/policy`** (linked from the viewer's top bar), designs
firewall access-control policy as a network-by-network grid instead of a
rule-by-rule form: click the cell where a source network's row meets a
destination network's column, pick Allow or Deny (always "any service" —
this is a macro switch, not a per-service rule builder), and optionally
require Security Heartbeat and/or an authenticated user. A "bidirectional"
checkbox creates the reverse cell too, as its own independent policy.

The matrix's axes are every LAN/DMZ/management network the topology
discovered, plus a single **Any** entry standing in for everything
WAN-facing — an administrator writes a policy against "the internet," not
against one specific ISP hand-off. Each axis label reads as the appliance
and zone that actually calls it something (e.g. `[Firewall1] Employees` /
`LAN:192.168.101.0/24`), not the bare CIDR — a network's number is not a
name anyone recognizes.

A cell's icon always summarizes *both* directions between that row and
column, not just the one cell stored there, so the mirrored position on the
other side of the diagonal reads consistently: a check mark is allow both
ways, an X is deny both ways, `›`/`‹` is a one-way allow (pointing the way
traffic actually flows), and `!` flags a genuine conflict — one direction
allows, the other denies.

**Fleet-wide, but only where a network is directly wired to a device.**
The fleet can have many appliances; a policy only produces a rule preview
on the appliances where at least one side is a network with an actual wire
on it (the other side may be the universal Any). Two specific networks that
live on different, unrelated appliances produce no rule anywhere — Phase 1
does not yet infer reachability through an SD-WAN policy route on a third
appliance; extending it needs that resource's schema confirmed against a
live capture first, the same discipline documented below for
`/network/addresses/ipv4`.

**Save vs. Apply.** Clicking a cell and choosing Save only stores the design
in `policy-matrix.json` and computes a preview: exactly which appliances it
would touch, the rule name it would create or update on each (deterministic,
so editing a cell later updates that rule instead of piling up duplicates),
and whether a named address object already exists on that appliance for each
side. **Apply** is a second, explicit step that actually calls the Sophos
API: it creates any missing address object first, then creates or updates
the real `/firewall/rules/ipv4` rule on every applicable appliance, and
reports success or failure per device. It only ever acts on a cell that has
already been saved. Both the rule and address-object write schemas were
confirmed against a live create/inspect/delete cycle before this was built —
the vendor's OpenAPI page for `/firewall/rules/ipv4` renders client-side and
yields nothing on fetch, so this project captured the real request/response
shape by hand (see `testdata/firewall-rules/`) rather than guess at a write
endpoint that plants live security policy, a materially worse mistake to
make quietly than guessing at a read endpoint's naming.

A rule's `action` is only ever `accept` or `drop` (not "allow"/"deny" — that
vocabulary is this project's own); Security Heartbeat and user-authentication
restrictions are only ever set on an Allow rule's *source* side, since
neither means anything once traffic is already dropped, and "Any" always
resolves to a specific WAN zone with an Any *network* inside it, never an Any
*zone* — matching every WAN-facing rule seen on a live capture and avoiding a
far broader rule than "this network can reach the internet."

Gated by the same `SFOS_ADMIN_TOKEN` as Settings (empty disables it,
404-not-just-401, same reasoning), and persisted the same file-based way — a
flat `policy-matrix.json` next to `devices.json`. Unlike Settings, though,
this file holds no credentials, so the documented Docker deployment mounts
it **writable** rather than treating it as host-managed like `devices.json`
— see [Containers](#containers).

## Project layout

```
cmd/sfos-topology   CLI: collect, serve, probe, healthcheck
sfos/               API client, types, offline replay
topology/           graph model, orientation, correlation rules
ipam/               address -> network/interface/device index and lookup
policy/             network x network access-policy matrix and rule-intent preview
web/                embedded HTTP handler (web.go) + IPAM/settings/policy APIs
web/index.html, policy.html, app.css, graph.js, policy.js, fleet.js   current UI (/, /policy)
web/v1/             previous UI, frozen (/v1, /v1/policy)
capture.sh          raw endpoint snapshot for one appliance
devices.json        the lab fleet
devices.secrets.json  Settings-managed API keys (gitignored, mode 600; created on first use)
policy-matrix.json  the access-policy matrix design (created on first use, no secrets)
lab.env             API keys (gitignored, dockerignored, mode 600)
Dockerfile          multi-stage build ending in scratch
docker-compose.yml  the deployment
```

## Viewer

`make serve` collects the fleet and serves the viewer with the graph already
loaded. The page is a single file with no dependencies and no external network
access; it is embedded in the binary, so there is nothing to deploy.

Opening `web/index.html` straight from disk also works — browsers block
`fetch()` from `file://`, so in that mode the page falls back to an embedded
sample and you drop a `graph.json` onto it.

Reading the drawing:

- Uplinks sit above the appliance, internal segments below, VPN tunnels as an
  arc between appliances. That ranking is the whole point of classifying zones
  in the collector.
- A dashed line is inferred rather than read directly, and a dotted line is a
  candidate with no corroboration.
- A segment marked `split` shares a prefix with another segment that the
  collector refused to merge.
- Clicking a node or a link fills the inspector with the rule and the evidence
  behind it, so the drawing can justify itself in front of a customer.
- Clicking a network segment also lists every appliance interface actually on
  that wire, and any Sophos address object that names all or part of it. An
  object defined identically by more than one appliance is tagged
  `multiple-firewalls` — usually two configs that drifted apart rather than
  intentional agreement, and worth a second look.
- Clicking an upstream (cloud) node shows the gateway IP address itself, not
  just the friendly name it was given.

`Save SVG` exports the current drawing with the stylesheet inlined, which drops
straight into a proposal or a report.

## Endpoints read

Eleven GETs per appliance, all read-only. Run the collector with an API key
generated from a restricted, read-only administrator profile.

| Endpoint | Feeds |
|---|---|
| `/network/zones` | orientation (north/south/overlay) |
| `/network/interfaces/network-interfaces` | the whole interface inventory |
| `/routing/gateways/ipv4` | gateway objects |
| `/routing/gateways/wan/ipv4` | link weight, backup, health checks |
| `/routing/static-unicast-routes/ipv4` | downstream ghost routers |
| `/network/dhcp/servers/ipv4` | scopes and static reservations |
| `/ipsec-vpn/site-to-site/connections/ipv4` | tunnel endpoints |
| `/network/addresses/ipv4` | named address objects, for IPAM lookups |
| `/administration/system-settings` | hostname |
| `/sophos-central/status` | serial number, HA peers |

`/network/addresses/ipv4` returns a `type` discriminator (`ipv4Address`,
`ipv4Network`, `ipv4Range`, `ipv4List`) that puts each variant's value in a
*different* field name — `ipv4Address`, `ipv4NetworkAddress`+`cidr`,
`ipv4AddressStart`/`ipv4AddressEnd`, `ipv4Addresses` — rather than reusing one
field across types. Confirmed against a live capture.

## IPAM endpoint

`make serve` also exposes `GET /api/ipam/{ip}`, which answers "what is this
address": the network it belongs to, every device and interface on that
network, and — when a matching named address object exists on some appliance
in the fleet — the name an administrator gave that network instead of its
bare CIDR.

```bash
curl http://127.0.0.1:8089/api/ipam/192.168.101.50
```

```json
{
  "ip": "192.168.101.50",
  "network": { "cidr": "192.168.101.0/24", "name": "LAN-Servers", "nameSource": "address-object" },
  "members": [
    { "device": { "id": "serial:...", "label": "FW-LAB-01", "hostname": "fw-lab-01" },
      "interface": { "name": "PortA", "zoneName": "LAN", "zoneType": "lan", "addr": "192.168.101.99/24" } }
  ]
}
```

`network.name` is only present when a Sophos address object (`IP`, `Network`,
`IPRange` or `IPList`) matches — an exact host beats a range, which beats a
network, and among networks the narrower one wins (a `/24` naming exactly
this network outranks a `/16` naming the wider block it sits in). Only
objects defined by a device that is actually a member of the matched network
are considered, even if some other appliance's object numerically covers the
address too — an object is "related to a network on the topology" because
the device that defines it sits on that network, not because its range
happens to overlap the right numbers. IP Host Groups are not resolved yet.
Without a match, `network.cidr` and each member's `interface.name` are the
fallback identification. A `404` means no known network contains the
address; a `400` means the path segment is not a valid IPv4 address.

The index behind this endpoint (package `ipam`) is rebuilt from scratch on
every collection pass, the same lifecycle the topology graph already has —
not a persistent database. That keeps the zero-dependency, single-binary
build intact; nothing here needs to survive a restart, since the fleet itself
is the source of truth on the next pass.

## Correlation rules

| Rule | Evidence | Confidence |
|---|---|---|
| E0 | an interface holds an address in a zone | confirmed |
| E1 | two interfaces share a prefix — candidate only | assumed |
| E3 | two appliances share a prefix **and** the same next hop | confirmed |
| E5 | one upstream cloud per distinct WAN gateway address | confirmed |
| E6 | static route whose next hop belongs to no known appliance | inferred |
| E8 | both host addresses of a `/30` or `/31` transit net are known | confirmed |

E1 alone never merges segments. `192.168.1.0/24` at two different sites is not
one broadcast domain, so without corroboration the segments stay separate and
are flagged `overlappingCidr`.

## Known limits of the API

- **No interface MAC.** The `macAddress` field on an interface is the
  administrative override, populated only when `overrideMac` is true. The
  burned-in hardware address is not exposed, so MAC cannot be used as an
  interface identity key and ARP-based adjacency is unavailable.
- **No active DHCP leases.** `clientReservations` are static reservations,
  which is configuration rather than state.
- **Serial number only via Sophos Central.** An appliance that is not
  registered has no serial, and node identity falls back to the management
  address — which changes if the appliance is re-addressed, breaking
  snapshot-to-snapshot diffing. The fallback emits a warning on the node.
- **Zone type is coarser than the zone list.** The built-in `WiFi` zone reports
  type `lan`. Orientation must come from `type`; the label must come from
  `name`.
- **Management interfaces are indistinguishable.** An out-of-band management
  port sits in a `lan`-typed zone like any other. Nothing in the API marks it,
  so let the operator tag those segments in the UI and persist the tag
  alongside the credential.
- **Pagination never reports totals** unless `pageTotal=true` is requested, and
  even then `total` is optional. The reliable termination condition is a short
  page. `pageSize` maxes out at 100.
- **Three encodings of "no value"** appear in one response: `""`,
  `null`, and an absent key. `sfos.Interface.UnmarshalJSON` folds them into
  `nil`.

## HA pairs

`/sophos-central/status` returns `peerNodes` only when the appliance is a node
of an HA pair. Two cluster members have identical interface configuration, so
without handling them the correlator sees duplicate segments. The device node
carries `haPeers` and a warning; render the pair as one logical device.

## Drawing ranks

Orientation maps to vertical rank:

| zone type | orientation | rank |
|---|---|---|
| `wan` | north | above the device |
| `lan`, `dmz` | south | below the device |
| `vpn`, any `xfrm` interface | overlay | no rank; drawn device-to-device |
| `local` | management | hidden by default |
| `discover` | passive | TAP/mirror port, **no traffic edge** |

An `xfrm` interface is overlay regardless of the zone it sits in.
