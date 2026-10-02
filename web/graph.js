// graph.js — the fleet graph view (GET /).
//
// Everything here is derived from configuration alone (see PROJECT_OVERVIEW.md):
// no live traffic, no health, no throughput. The layout is a deterministic,
// layered rank assignment -- never force-directed -- so the same fleet always
// draws the same picture. Coordinates are computed here; the server sends
// only nodes and edges (see buildModel below for the exact adapter from the
// real /graph.json shape to this view's render model).
import { probeFleetAvailable, openFleetPanel } from "./fleet.js";

// A script error during setup must not leave a silently blank stage -- the
// project's own rule for a failed collection pass ("never blank the view")
// applies just as much to the view's own code failing to run. This listener
// is registered before anything below that touches the DOM, so any
// synchronous throw during module setup gets a visible, readable banner
// instead of a page that looks like it is loading forever.
window.addEventListener("error", (ev) => {
  const box = document.getElementById("stale");
  if (!box) return; // page markup itself is broken; nothing left to render into
  box.hidden = false;
  box.innerHTML = `<div class="banner bad"><div>${
    `<svg class="icon" viewBox="0 0 24 24"><path d="M12 4 2 20h20L12 4Z"/><path d="M12 10v4M12 17h.01"/></svg>`
  }</div><div><b>The graph view failed to start.</b> ${escapeHtmlSafe(ev.message)}${ev.filename ? ` (${escapeHtmlSafe(ev.filename)}:${ev.lineno})` : ""}</div></div>`;
});
function escapeHtmlSafe(s) { return String(s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

const STAGE_W = 1440;
const GUTTER = 16;
// Overlay mode drops every rank but devices down to a single row of tunnel
// endpoints -- the tight underlay gutter then reads as crowded, so devices
// get extra breathing room specifically in that mode.
const GUTTER_OVERLAY_DEVICE = 96;

// Underlay rank Y positions, top to bottom, per the spec.
const RANK_Y_UNDERLAY = { world: 56, cloud: 172, segNorth: 288, device: 414, segSouth: 552, gateway: 676 };
// Overlay hides world/cloud/segNorth and lifts the rest by 172px. These are
// a floor, not a fixed value -- applyProjectionY pushes the whole overlay
// stack further down when the tunnel mesh above the device rank needs more
// headroom than this leaves (see TUNNEL_DIP_BASE/STEP below).
const RANK_Y_OVERLAY = { device: 242, segSouth: 380, gateway: 504 };
// How far the device rank bows into a concave arc in overlay mode -- ends
// pulled up by this many pixels relative to the (unmoved) center, so the
// row reads as a shallow bowl instead of a flat line, and the VPN mesh
// arcing above it has a natural "inside the bowl" home.
const ARC_DEPTH_OVERLAY = 64;
// Must match the dip step used in renderEdges' tunnelDips assignment --
// kept as named constants here so applyProjectionY can reserve enough
// headroom above the device rank for however many tunnels will stack.
const TUNNEL_DIP_BASE = 70, TUNNEL_DIP_STEP = 46;

// Cloud nodes are drawn as a plain circle (icon only, no label) -- same
// value used for both width and height so the node is round.
const CLOUD_DIAMETER = 44;
const NODE_H = { world: 48, device: 56, cloud: CLOUD_DIAMETER, default: 52 };

// Plain-language explanation per correlation rule, and the confidence each
// one actually produces in this codebase (topology/build.go is the source of
// truth -- these are not guesses).
const RULE_EXPLAIN = {
  E0: "A direct fact read from this appliance's own interface configuration.",
  E1: "Merge candidate: two appliances hold distinct addresses inside the same prefix, but their next-hop gateways do not agree (or are missing), so the merge is not fully confirmed.",
  E3: "Merge confirmed: the appliances hold distinct addresses inside the same prefix and agree on the same next-hop gateway -- which only makes sense if they share one wire.",
  E5: "An upstream reached through this interface's own configured gateway address.",
  E6: "A static route names a next hop that is not any known appliance -- inferred as a downstream device the collector never read directly.",
  E8: "Both interfaces are the two ends of the same point-to-point transit network -- the arithmetic that identifies a tunnel's two sides.",
  E9: "Kept apart: another appliance holds the identical address inside this exact prefix, which cannot happen on one real wire -- these are two different networks reusing the same range.",
};

const ICONS = {
  device: `<path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/><path d="M8 19h8M12 15v4"/><circle cx="6.5" cy="10" r=".6" fill="currentColor" stroke="none"/>`,
  segment: `<rect x="3" y="8" width="18" height="8" rx="2"/><path d="M7 8V6M17 8V6M7 18v-2M17 18v-2"/>`,
  cloud: `<path d="M7 18a4 4 0 1 1 .7-7.94A5 5 0 0 1 17 12h.5a3.5 3.5 0 0 1 0 7H7Z"/>`,
  gateway: `<circle cx="12" cy="12" r="8"/><path d="M12 4v16M4 12h16" stroke-dasharray="2 2"/>`,
  world: `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 4 6 4 9s-1.5 6.4-4 9c-2.5-2.6-4-6-4-9s1.5-6.4 4-9Z"/>`,
};
function iconFor(kind) { return ICONS[kind] || ICONS.segment; }

const $ = (sel, root) => (root || document).querySelector(sel);
const el = (tag, cls, html) => { const n = document.createElement(tag); if (cls) n.className = cls; if (html !== undefined) n.innerHTML = html; return n; };

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------
let doc = null;           // raw /graph.json payload
let model = null;         // { nodes: Map, edges: [] } -- adapted render model
let layout = null;        // Map(nodeId -> {x,y,w,h})
let projection = "underlay";
let confFilter = "all";
let showManagement = false;
let pinnedId = null;
let hoveredId = null;
let panned = false;

// ---------------------------------------------------------------------
// Data adapter: real topology.Graph -> this view's render model.
//
// The backend has no per-node confidence or structured evidence/warnings --
// those live on edges (topology.Edge.Confidence/.Evidence) and as plain
// strings (topology.Node.Warnings). This adapter derives everything the
// design needs from what the graph actually carries, rather than the
// idealized contract in the implementation prompt; nothing here invents a
// fact the backend didn't provide.
// ---------------------------------------------------------------------
function buildModel(raw) {
  const nodesById = new Map();
  const edgesOf = new Map(); // nodeId -> edge[]

  for (const n of raw.graph.nodes || []) nodesById.set(n.id, n);
  for (const e of raw.graph.edges || []) {
    (edgesOf.get(e.from) || edgesOf.set(e.from, []).get(e.from)).push(e);
    (edgesOf.get(e.to) || edgesOf.set(e.to, []).get(e.to)).push(e);
  }

  // stale (not merely .error): a device can fail with nothing cached yet
  // (its very first pass), in which case it has no node to mark at all --
  // stale is specifically "drawing from a last-known-good snapshot while
  // currently unreachable," which is the case the graph can actually show.
  const staleLabels = new Set((raw.devices || []).filter(d => d.stale).map(d => d.label));
  const staleDeviceIds = new Set();
  for (const n of raw.graph.nodes || []) {
    if (n.kind === "device" && staleLabels.has(n.label)) staleDeviceIds.add(n.id);
  }

  function neighborEdges(id) { return edgesOf.get(id) || []; }

  function nodeConfidence(n) {
    if (n.kind === "device" || n.kind === "world") return "confirmed";
    if (n.kind === "cloud" || n.kind === "gateway") return "inferred";
    // segment: best (highest) confidence among the edges that attached it.
    const rank = { confirmed: 3, inferred: 2, assumed: 1 };
    let best = null;
    for (const e of neighborEdges(n.id)) {
      if (!best || rank[e.confidence] > rank[best]) best = e.confidence;
    }
    return best || "assumed";
  }

  function segmentMeta(n) {
    const devIds = new Set();
    for (const e of neighborEdges(n.id)) {
      if (nodesById.get(e.from)?.kind === "device") devIds.add(e.from);
      if (nodesById.get(e.to)?.kind === "device") devIds.add(e.to);
    }
    const parts = [];
    if (n.orientation) parts.push(n.orientation.toUpperCase());
    const names = [...new Set((n.addressObjects || []).map(o => o.name))];
    if (names.length) parts.push(names.slice(0, 2).join(", "));
    parts.push(`${devIds.size} device${devIds.size === 1 ? "" : "s"}`);
    return parts.join(" · ");
  }

  function deviceMeta(n) {
    const parts = [];
    if (n.hostname && n.hostname !== n.label) parts.push(n.hostname);
    if (n.haPeers && n.haPeers.length) parts.push("HA pair");
    parts.push(`${(n.interfaces || []).length} interface${(n.interfaces || []).length === 1 ? "" : "s"}`);
    return parts.join(" · ");
  }

  function cloudMeta(n) {
    const devIds = new Set();
    for (const e of neighborEdges(n.id)) {
      if (nodesById.get(e.from)?.kind !== "cloud") devIds.add(e.from);
      if (nodesById.get(e.to)?.kind !== "cloud") devIds.add(e.to);
    }
    const gw = n.gatewayCidr || n.gatewayIp;
    return `${gw ? gw + " · " : ""}Upstream · ${devIds.size} device${devIds.size === 1 ? "" : "s"}`;
  }

  function evidenceFor(id) {
    const out = [];
    for (const e of neighborEdges(id)) {
      const otherId = e.from === id ? e.to : e.from;
      const other = nodesById.get(otherId);
      for (const ev of e.evidence || []) {
        out.push({
          rule: ev.rule,
          confidence: e.confidence,
          what: RULE_EXPLAIN[ev.rule] || "A correlation rule fired for this connection.",
          quote: ev.detail,
          via: other ? other.label : otherId,
        });
      }
    }
    // The "interesting" rule (a merge/split verdict) reads better before the
    // routine E0 fact repeated once per interface; stable-sort so E0 last.
    return out.sort((a, b) => (a.rule === "E0" ? 1 : 0) - (b.rule === "E0" ? 1 : 0));
  }

  function warningsFor(n) {
    return (n.warnings || []).map(w => ({ title: "Warning", body: w }));
  }

  function membersFor(n) {
    if (n.kind === "device") {
      return (n.interfaces || []).map(f => ({
        device: n.label, iface: `${f.name}${f.addr ? " · " + f.addr : ""}`, zone: f.zoneName,
      }));
    }
    if (n.kind === "segment") {
      const out = [];
      for (const e of neighborEdges(n.id)) {
        const devId = e.from === n.id ? e.to : e.from;
        const dev = nodesById.get(devId);
        if (!dev || dev.kind !== "device") continue;
        const iface = (dev.interfaces || []).find(f => f.name === e.label);
        out.push({ device: dev.label, iface: `${e.label}${iface && iface.addr ? " · " + iface.addr : ""}`, zone: iface ? iface.zoneName : "" });
      }
      return out;
    }
    return [];
  }

  const nodes = [];
  for (const n of raw.graph.nodes || []) {
    const rec = {
      id: n.id, kind: n.kind, label: n.label,
      cidr: n.kind === "cloud" ? (n.gatewayCidr || n.gatewayIp || "") : (n.cidr || ""),
      orientation: n.orientation || "",
      confidence: nodeConfidence(n),
      stale: n.kind === "device" && staleDeviceIds.has(n.id),
      warnings: warningsFor(n),
      evidence: evidenceFor(n.id),
      members: membersFor(n),
      raw: n,
    };
    if (n.kind === "device") rec.meta = deviceMeta(n);
    else if (n.kind === "segment") rec.meta = segmentMeta(n);
    else if (n.kind === "cloud") rec.meta = cloudMeta(n);
    else if (n.kind === "gateway") rec.meta = "Inferred next hop · not collected";
    else rec.meta = "";
    nodes.push(rec);
  }

  const edges = (raw.graph.edges || []).map((e, i) => ({
    id: "e" + i, a: e.from, b: e.to,
    overlay: e.orientation === "overlay",
    confidence: e.confidence,
    label: e.label || "",
    rule: (e.evidence && e.evidence.length) ? e.evidence[e.evidence.length - 1].rule : "?",
    evidence: (e.evidence || []).map(ev => ({
      rule: ev.rule, confidence: e.confidence,
      what: RULE_EXPLAIN[ev.rule] || "A correlation rule fired for this connection.",
      quote: ev.detail,
    })),
  }));

  return { nodesById: new Map(nodes.map(n => [n.id, n])), nodes, edges, staleLabels: [...staleLabels] };
}

// ---------------------------------------------------------------------
// Layout: deterministic, layered, no physics.
// ---------------------------------------------------------------------
function estimateWidth(label, kind) {
  if (kind === "cloud") return CLOUD_DIAMETER;
  const w = 84 + label.length * 6.6;
  return Math.max(150, Math.min(216, Math.round(w)));
}

function rankOf(n) {
  if (n.kind === "world") return 0;
  if (n.kind === "cloud") return 1;
  if (n.kind === "segment" && n.orientation === "north") return 2;
  if (n.kind === "device") return 3;
  if (n.kind === "segment") return 4; // south, management, passive, overlay-tagged segments
  if (n.kind === "gateway") return 5;
  return 4;
}

function computeLayout(m) {
  const ranks = [[], [], [], [], [], []];
  for (const n of m.nodes) {
    if (n.orientation === "management" && !showManagement) continue;
    ranks[rankOf(n)].push(n);
  }

  const pos = new Map();
  const neighborsOf = (id) => m.edges.filter(e => e.a === id || e.b === id).map(e => (e.a === id ? e.b : e.a));

  for (let r = 0; r < ranks.length; r++) {
    const list = ranks[r];
    // Order by the average x of any already-positioned neighbor (an earlier
    // rank); stable-falls back to label order for orphans (world, or a
    // passive node with no traffic edge at all).
    const withKey = list.map(n => {
      const xs = neighborsOf(n.id).map(id => pos.get(id)).filter(Boolean).map(p => p.x);
      const key = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
      return { n, key };
    });
    withKey.sort((a, b) => {
      if (a.key === null && b.key === null) return a.n.label.localeCompare(b.n.label);
      if (a.key === null) return 1;
      if (b.key === null) return -1;
      return a.key - b.key;
    });

    const widths = withKey.map(w => estimateWidth(w.n.label, w.n.kind));
    const gutter = (projection === "overlay" && r === 3) ? GUTTER_OVERLAY_DEVICE : GUTTER;
    const totalW = widths.reduce((a, b) => a + b, 0) + gutter * Math.max(0, widths.length - 1);
    let x = (STAGE_W - totalW) / 2;
    withKey.forEach((w, i) => {
      const width = widths[i];
      const h = NODE_H[w.n.kind] || NODE_H.default;
      pos.set(w.n.id, { x: x + width / 2, y: 0, w: width, h, rank: r });
      x += width + gutter;
    });
  }
  return pos;
}

function applyProjectionY(pos, m) {
  // Overlay-only prep: where the device rank actually spans (to bow it into
  // an arc around its own center) and how many VPN tunnels will stack above
  // it (to push the whole rank down far enough that the highest arc still
  // clears y=0 instead of clipping against the stage top).
  let centerX = STAGE_W / 2, halfSpan = 0, deviceBaseY = RANK_Y_OVERLAY.device;
  if (projection === "overlay") {
    let minX = Infinity, maxX = -Infinity;
    for (const n of m.nodes) {
      if (rankOf(n) !== 3) continue;
      const p = pos.get(n.id);
      if (!p) continue;
      minX = Math.min(minX, p.x);
      maxX = Math.max(maxX, p.x);
    }
    if (minX <= maxX) { centerX = (minX + maxX) / 2; halfSpan = (maxX - minX) / 2; }

    const tunnelCount = new Set(m.edges.filter(e => e.overlay).map(e => e.id)).size;
    const maxDip = tunnelCount > 0 ? TUNNEL_DIP_BASE + TUNNEL_DIP_STEP * (tunnelCount - 1) : 0;
    deviceBaseY = Math.max(RANK_Y_OVERLAY.device, maxDip + ARC_DEPTH_OVERLAY + 40);
  }
  const overlayShift = deviceBaseY - RANK_Y_OVERLAY.device;

  for (const n of m.nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    if (projection === "underlay") {
      p.y = [RANK_Y_UNDERLAY.world, RANK_Y_UNDERLAY.cloud, RANK_Y_UNDERLAY.segNorth,
             RANK_Y_UNDERLAY.device, RANK_Y_UNDERLAY.segSouth, RANK_Y_UNDERLAY.gateway][p.rank];
      p.hidden = false;
    } else {
      if (p.rank <= 2) { p.hidden = true; continue; }
      p.hidden = false;
      if (p.rank === 3) {
        // Concave arc: the center of the row stays at the base Y: the ends
        // get pulled up toward the VPN mesh above, rather than drawing a
        // flat line of firewalls.
        const dx = halfSpan ? (p.x - centerX) / halfSpan : 0;
        p.y = deviceBaseY - ARC_DEPTH_OVERLAY * dx * dx;
      } else {
        p.y = (p.rank === 4 ? RANK_Y_OVERLAY.segSouth : RANK_Y_OVERLAY.gateway) + overlayShift;
      }
    }
  }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------
const stageInner = $("#stageInner");
const svgLayer = document.createElementNS("http://www.w3.org/2000/svg", "svg");
svgLayer.setAttribute("class", "edge-layer");
svgLayer.setAttribute("aria-hidden", "true");
let pathConfirmed, pathInferred, pathAssumed, pathTunnel, pathLit, pathStale;

function edgePath(a, b) {
  const x1 = a.x, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y - b.h / 2;
  if (Math.abs(x1 - x2) < 0.5) return `M ${x1} ${y1} L ${x2} ${y2}`;
  const my = y1 + (y2 - y1) * 0.55, r = 14, d = x2 > x1 ? 1 : -1;
  return `M ${x1} ${y1} L ${x1} ${my - r} Q ${x1} ${my} ${x1 + d * r} ${my}` +
         ` L ${x2 - d * r} ${my} Q ${x2} ${my} ${x2} ${my + r} L ${x2} ${y2}`;
}
// VPN tunnels only ever render in overlay mode (edgeMatchesProjection keeps
// them out of underlay), where they sit above the device rank -- so the arc
// always bows upward, mirroring where WAN uplinks used to sit.
function tunnelPath(a, b, dip) {
  const x1 = a.x, y1 = a.y, x2 = b.x, y2 = b.y;
  const midY = Math.min(y1, y2) - dip;
  return `M ${x1} ${y1} Q ${(x1 + x2) / 2} ${midY} ${x2} ${y2}`;
}

function litSet() {
  const focus = pinnedId || hoveredId;
  if (!focus) return new Set();
  const s = new Set([focus]);
  for (const e of model.edges) {
    if (e.a === focus) s.add(e.b);
    if (e.b === focus) s.add(e.a);
  }
  return s;
}

function passiveIds() {
  const s = new Set();
  for (const n of model.nodes) if (n.orientation === "passive") s.add(n.id);
  return s;
}

// Underlay is the physical fabric -- VPN tunnels are overlay detail and stay
// hidden there. Overlay inverts that: WAN/cloud/north-segment ranks are
// already dropped by applyProjectionY, and here the structural edges follow
// them off, leaving only the VPN mesh between devices.
function edgeMatchesProjection(e) {
  if (projection === "underlay") return !e.overlay;
  return e.overlay;
}

function renderEdges() {
  const groups = { confirmed: [], inferred: [], assumed: [], tunnel: [], lit: [], stale: [] };
  const lit = litSet();
  const passive = passiveIds();
  const staleIds = new Set(model.nodes.filter(n => n.stale).map(n => n.id));
  const tunnelDips = new Map();
  let dipSeq = 0;

  for (const e of model.edges) {
    const pa = layout.get(e.a), pb = layout.get(e.b);
    if (!pa || !pb || pa.hidden || pb.hidden) continue;
    if (passive.has(e.a) || passive.has(e.b)) continue; // passive: node only, never an edge
    if (!edgeMatchesProjection(e)) continue;

    const isLitEdge = lit.size > 0 && lit.has(e.a) && lit.has(e.b);
    // An edge touching an offline device fades with it, unless actively
    // highlighted -- a hover/pin should still read clearly even there.
    const isStaleEdge = !isLitEdge && (staleIds.has(e.a) || staleIds.has(e.b));
    if (e.overlay) {
      let dip = tunnelDips.get(e.id);
      if (dip === undefined) { dip = TUNNEL_DIP_BASE + TUNNEL_DIP_STEP * (dipSeq++); tunnelDips.set(e.id, dip); }
      const d = tunnelPath(pa, pb, dip);
      groups[isLitEdge ? "lit" : isStaleEdge ? "stale" : "tunnel"].push(d);
    } else {
      const d = edgePath(pa.y <= pb.y ? pa : pb, pa.y <= pb.y ? pb : pa);
      groups[isLitEdge ? "lit" : isStaleEdge ? "stale" : e.confidence].push(d);
    }
  }

  pathConfirmed.setAttribute("d", groups.confirmed.join(" "));
  pathInferred.setAttribute("d", groups.inferred.join(" "));
  pathAssumed.setAttribute("d", groups.assumed.join(" "));
  pathTunnel.setAttribute("d", groups.tunnel.join(" "));
  pathLit.setAttribute("d", groups.lit.join(" "));
  pathStale.setAttribute("d", groups.stale.join(" "));

  // rule tags: one real <button> per edge midpoint (kept out of the SVG,
  // absolutely positioned in the same stage-inner coordinate space).
  document.querySelectorAll(".rule-tag").forEach(n => n.remove());
  for (const e of model.edges) {
    const pa = layout.get(e.a), pb = layout.get(e.b);
    if (!pa || !pb || pa.hidden || pb.hidden) continue;
    if (passive.has(e.a) || passive.has(e.b)) continue;
    if (!edgeMatchesProjection(e)) continue;
    // The tag shows the physical interface the edge was read from (e.g.
    // "PortB", or "PortB ↔ PortA" for a tunnel pair) rather than the rule
    // code -- an analyst reads a port name, not a correlator internal. An
    // edge with no interface to name (e.g. the cloud -> world convergence
    // edge) gets no tag at all instead of a bare "?".
    if (!e.label) continue;
    const mx = (pa.x + pb.x) / 2;
    const my = e.overlay
      ? Math.min(pa.y, pb.y) - (tunnelDips.get(e.id) || TUNNEL_DIP_BASE) * 0.55
      : (pa.y <= pb.y ? pa.y + pa.h / 2 : pb.y + pb.h / 2) + Math.abs(pa.y - pb.y) * 0.5 * 0.55;
    const btn = el("button", "rule-tag" + (lit.size && lit.has(e.a) && lit.has(e.b) ? " lit" : ""), escapeHtml(e.label));
    btn.type = "button";
    btn.style.left = mx + "px";
    btn.style.top = my + "px";
    btn.setAttribute("aria-label", `${e.label}, rule ${e.rule}, ${e.confidence} edge`);
    btn.addEventListener("mouseenter", () => showEdgeTooltip(btn, e));
    btn.addEventListener("focus", () => showEdgeTooltip(btn, e));
    btn.addEventListener("mouseleave", hideTooltip);
    btn.addEventListener("blur", hideTooltip);
    btn.addEventListener("dblclick", () => openEdgeInspector(e));
    btn.addEventListener("keydown", (ev) => { if (ev.key === "Enter") openEdgeInspector(e); });
    stageInner.appendChild(btn);
  }
}

function renderNodes() {
  document.querySelectorAll(".node").forEach(n => n.remove());
  const lit = litSet();
  for (const n of model.nodes) {
    const p = layout.get(n.id);
    if (!p) continue;
    const btn = el("button", `node k-${n.kind} conf-${n.confidence}` +
      (p.hidden ? " dim" : "") +
      (n.stale ? " stale" : "") +
      (lit.has(n.id) ? " lit" : "") +
      (pinnedId === n.id ? " pinned" : ""));
    btn.type = "button";
    btn.dataset.nodeId = n.id;
    btn.style.left = p.x + "px";
    btn.style.top = p.y + "px";
    btn.style.width = p.w + "px";
    if (p.hidden) btn.tabIndex = -1;
    btn.setAttribute("aria-label", `${n.label}, ${n.kind}, ${n.confidence}${n.stale ? ", offline" : ""}`);

    const tile = el("div", "tile", `<svg class="icon" viewBox="0 0 24 24">${iconFor(n.kind)}</svg>`);
    if (n.kind === "cloud") {
      // Upstream markers carry no label of their own in the graph -- the
      // gateway name, IP/CIDR and device count show up in the tooltip on
      // hover/focus (showNodeTooltip, wired below) instead of as permanent
      // text, so the drawing's visual weight stays on devices and segments.
      btn.appendChild(tile);
    } else {
      const text = el("div", "text");
      text.appendChild(el("div", "label", escapeHtml(n.label)));
      text.appendChild(el("div", "meta", escapeHtml(n.stale ? "Offline · showing last known configuration" : (n.meta || ""))));
      btn.append(tile, text);
      if (n.stale) btn.appendChild(el("div", "offline-pill", "OFFLINE"));
      else if (n.warnings.length) btn.appendChild(el("div", "warn-flag", warnSvg()));
      btn.appendChild(el("div", `conf-dot ${n.confidence}`));
    }

    btn.addEventListener("mouseenter", () => { hoveredId = n.id; renderEdges(); renderNodes.dirty = true; showNodeTooltip(btn, n); });
    btn.addEventListener("focus", () => { hoveredId = n.id; renderEdges(); showNodeTooltip(btn, n); });
    btn.addEventListener("mouseleave", () => { hoveredId = null; renderEdges(); hideTooltip(); });
    btn.addEventListener("blur", () => { hoveredId = null; renderEdges(); hideTooltip(); });
    btn.addEventListener("click", () => { pinnedId = pinnedId === n.id ? null : n.id; renderNodes(); renderEdges(); });
    btn.addEventListener("dblclick", () => openNodeInspector(n));
    btn.addEventListener("keydown", (ev) => { if (ev.key === "Enter") openNodeInspector(n); });

    stageInner.appendChild(btn);
  }
}

// applyConfidenceFilter only ever touches nodes the projection itself left
// visible (p.hidden === false). A projection-hidden node (e.g. world/cloud/
// north-segment in overlay mode) already carries its own "dim" from
// renderNodes() for a completely different reason -- clearing "dim"
// unconditionally here used to strip that too, leaving those nodes fully
// opaque, clickable and stacked at their stale y:0 placeholder instead of
// actually hidden. Skipping p.hidden nodes entirely keeps the two concerns
// (projection visibility vs. confidence filtering) from stepping on each
// other.
function applyConfidenceFilter() {
  for (const n of model.nodes) {
    const p = layout.get(n.id);
    if (!p || p.hidden) continue;
    const btn = document.querySelector(`.node[data-node-id="${CSS.escape(n.id)}"]`);
    if (!btn) continue;
    btn.classList.toggle("dim", confFilter !== "all" && n.confidence !== confFilter);
  }
}

function warnSvg() { return `<svg class="icon" viewBox="0 0 24 24" width="13" height="13"><path d="M12 4 2 20h20L12 4Z"/><path d="M12 10v4M12 17h.01"/></svg>`; }
function escapeHtml(s) { return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

function renderCounts() {
  const visible = model.nodes.filter(n => layout.get(n.id) && !layout.get(n.id).hidden);
  const warnCount = visible.reduce((a, n) => a + n.warnings.length, 0);
  $("#counts").textContent = `${visible.length} nodes · ${model.edges.filter(e => {
    const pa = layout.get(e.a), pb = layout.get(e.b);
    return pa && pb && !pa.hidden && !pb.hidden && edgeMatchesProjection(e);
  }).length} edges · ${warnCount} warnings`;
}

function render() {
  layout = computeLayout(model);
  applyProjectionY(layout, model);
  let maxY = 0;
  for (const p of layout.values()) if (!p.hidden) maxY = Math.max(maxY, p.y + p.h);
  stageInner.style.height = (maxY + 80) + "px";
  svgLayer.setAttribute("width", STAGE_W);
  svgLayer.setAttribute("height", maxY + 80);
  renderNodes();
  renderEdges();
  applyConfidenceFilter();
  renderCounts();
}

// ---------------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------------
const tooltip = $("#tooltip");
function positionTooltip(target) {
  const stageRect = $("#stageWrap").getBoundingClientRect();
  const r = target.getBoundingClientRect();
  let x = r.left - stageRect.left + r.width / 2;
  let y = r.top - stageRect.top;
  const flip = r.top - stageRect.top < 240;
  tooltip.style.left = Math.max(158, Math.min(1282, x)) + "px";
  tooltip.style.top = (flip ? y + r.height + 12 : y - 12) + "px";
  tooltip.style.transform = `translate(-50%, ${flip ? "0" : "-100%"})`;
}
function confPillHtml(conf) {
  const cls = conf === "assumed" ? "ghost" : conf === "inferred" ? "blue" : "mint";
  return `<span class="pill ${cls}">${conf}</span>`;
}
function showNodeTooltip(target, n) {
  positionTooltip(target);
  tooltip.innerHTML = `
    <div class="row1"><span class="label">${escapeHtml(n.label)}</span>${confPillHtml(n.confidence)}</div>
    <div class="kind">${n.kind}${n.stale ? " · stale" : ""}</div>
    <div class="kv"><span class="k">CIDR</span><span class="v">${escapeHtml(n.cidr || "—")}</span></div>
    <div class="kv"><span class="k">Meta</span><span class="v">${escapeHtml(n.meta || "—")}</span></div>
    <div class="kv"><span class="k">Warnings</span><span class="v">${n.warnings.length || "none"}</span></div>
    <div class="hint">Double-click to open the inspector</div>`;
  tooltip.classList.add("shown");
}
function showEdgeTooltip(target, e) {
  positionTooltip(target);
  const first = e.evidence[e.evidence.length - 1] || {};
  tooltip.innerHTML = `
    <div class="row1"><span class="label">Rule ${e.rule}</span>${confPillHtml(e.confidence)}</div>
    <div class="kind">Edge${e.overlay ? " · vpn overlay" : ""}</div>
    <div class="kv"><span class="k">Rule</span><span class="v">${e.rule}</span></div>
    <div class="kv"><span class="k">Confidence</span><span class="v">${e.confidence}</span></div>
    <div class="kv"><span class="k">Evidence</span><span class="v">${escapeHtml((first.quote || "").split("\n")[0] || "")}</span></div>
    <div class="hint">Double-click to read the configuration behind it</div>`;
  tooltip.classList.add("shown");
}
function hideTooltip() { tooltip.classList.remove("shown"); }

// ---------------------------------------------------------------------
// Inspector drawer
// ---------------------------------------------------------------------
const drawer = $("#drawer");
const drawerBody = $("#drawerBody");
const drawerTabs = $("#drawerTabs");
const stage = $("#stage");
let activeTab = "overview";

function setPanned(v) { panned = v; stage.classList.toggle("panned", v); }

function openDrawer() { drawer.classList.add("open"); setPanned(true); }
function closeDrawer() { drawer.classList.remove("open"); setPanned(false); }

const TAB_IDS = ["overview", "evidence", "warnings"];
drawerTabs.querySelectorAll("button").forEach((b, i) => {
  b.addEventListener("click", () => { activeTab = TAB_IDS[i]; renderDrawerBody(); syncTabs(); });
});
function syncTabs() { drawerTabs.querySelectorAll("button").forEach((b, i) => b.setAttribute("aria-selected", String(TAB_IDS[i] === activeTab))); }

let currentSubject = null; // { kind: 'node'|'edge'|'lookup', data }

function openNodeInspector(n) {
  currentSubject = { kind: "node", data: n };
  activeTab = "overview";
  drawerTabs.style.display = "";
  renderDrawerHead();
  renderDrawerBody();
  syncTabs();
  openDrawer();
}
function openEdgeInspector(e) {
  currentSubject = { kind: "edge", data: e };
  activeTab = "evidence";
  drawerTabs.style.display = "none";
  renderDrawerHead();
  renderDrawerBody();
  openDrawer();
}

function renderDrawerHead() {
  const head = $("#drawerHead");
  if (currentSubject.kind === "node") {
    const n = currentSubject.data;
    head.innerHTML = "";
    const top = el("div", "top");
    top.innerHTML = `<div class="tile"><svg class="icon" viewBox="0 0 24 24">${iconFor(n.kind)}</svg></div>
      <div class="titles"><div class="title">${escapeHtml(n.label)}</div><div class="subtitle">${escapeHtml(n.kind)}${n.cidr ? " · " + escapeHtml(n.cidr) : ""}</div></div>`;
    head.appendChild(top);
    const prov = el("div", "prov",
      `${confPillHtml(n.confidence)} &nbsp; ${n.members.length} member${n.members.length === 1 ? "" : "s"} · ${n.evidence.length} rule${n.evidence.length === 1 ? "" : "s"}${n.orientation ? " · " + escapeHtml(n.orientation) : ""}`);
    head.appendChild(prov);
  } else {
    const e = currentSubject.data;
    head.innerHTML = `<div class="top"><div class="tile"><svg class="icon" viewBox="0 0 24 24"><path d="M4 12h16M14 6l6 6-6 6"/></svg></div>
      <div class="titles"><div class="title">Rule ${e.rule}</div><div class="subtitle">Edge${e.overlay ? " · VPN overlay" : ""}</div></div></div>
      <div class="prov">${confPillHtml(e.confidence)}</div>`;
  }
}

function renderDrawerBody() {
  drawerBody.innerHTML = "";
  if (currentSubject.kind === "edge") { drawerBody.appendChild(evidenceView(currentSubject.data.evidence)); return; }
  const n = currentSubject.data;
  if (activeTab === "overview") drawerBody.appendChild(overviewView(n));
  else if (activeTab === "evidence") drawerBody.appendChild(evidenceView(n.evidence));
  else drawerBody.appendChild(warningsView(n));
}

function kvRows(pairs) {
  const wrap = el("div", "kv-rows");
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    const row = el("div", "kv-row");
    row.innerHTML = `<span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(String(v))}</span>`;
    wrap.appendChild(row);
  }
  return wrap;
}

function overviewView(n) {
  const wrap = document.createDocumentFragment ? el("div") : el("div");
  if (n.kind === "segment") {
    wrap.appendChild(kvRows([
      ["Kind", "Segment"], ["CIDR", n.cidr], ["Orientation", n.orientation],
      ["Named objects", [...new Set((n.raw.addressObjects || []).map(o => o.name))].join(", ") || "none"],
    ]));
  } else if (n.kind === "device") {
    wrap.appendChild(kvRows([
      ["Hostname", n.raw.hostname], ["Serial", n.raw.serial],
      ["HA peer", (n.raw.haPeers || []).join(", ")], ["Interfaces", (n.raw.interfaces || []).length],
    ]));
  } else if (n.kind === "cloud") {
    wrap.appendChild(kvRows([
      ["Kind", "Upstream"], ["Gateway name", n.label],
      ["Gateway IP", n.raw.gatewayCidr || n.raw.gatewayIp],
    ]));
  } else {
    wrap.appendChild(kvRows([["Kind", n.kind], ["Label", n.label]]));
  }
  const h = el("div", "eyebrow", "Members"); h.style.margin = "1rem 0 .6rem";
  wrap.appendChild(h);
  if (!n.members.length) {
    wrap.appendChild(el("p", "empty-note", "No member interfaces on this node."));
  } else {
    for (const m of n.members) {
      const row = el("div", "member-row");
      row.innerHTML = `<span class="dev">${escapeHtml(m.device)} · ${escapeHtml(m.iface)}</span>${m.zone ? `<span class="pill ghost" style="background:var(--n100);color:var(--n600)">${escapeHtml(m.zone)}</span>` : ""}`;
      wrap.appendChild(row);
    }
  }
  return wrap;
}

function evidenceView(evidence) {
  const wrap = el("div");
  if (!evidence.length) {
    wrap.appendChild(el("p", "empty-note", "No evidence recorded for this connection."));
    return wrap;
  }
  for (const ev of evidence) {
    const card = el("div", "evidence-card");
    card.innerHTML = `<div class="top"><span class="rule-chip">${ev.rule}</span>${confPillHtml(ev.confidence)}${ev.via ? `<span class="pill ghost" style="background:var(--n100);color:var(--n600)">via ${escapeHtml(ev.via)}</span>` : ""}</div>
      <div class="sentence">${escapeHtml(ev.what)}</div>
      <pre>${escapeHtml(ev.quote || "")}</pre>`;
    wrap.appendChild(card);
  }
  wrap.appendChild(el("p", "evidence-note",
    "Evidence is the literal configuration the correlator read. If an edge is wrong, this is the field to go and check on the appliance."));
  return wrap;
}

function warningsView(n) {
  const wrap = el("div");
  if (n.stale) {
    const card = el("div", "warning-card");
    card.innerHTML = `<div class="title">Stale snapshot</div><div class="body">The last collection pass for this device failed. It is shown from the previous good pass.</div>`;
    wrap.appendChild(card);
  }
  if (!n.warnings.length && !n.stale) {
    wrap.appendChild(el("p", "empty-note",
      "Nothing flagged. Every fact behind this node was corroborated by a second piece of configuration."));
    return wrap;
  }
  for (const w of n.warnings) {
    const card = el("div", "warning-card");
    card.innerHTML = `<div class="title">${escapeHtml(w.title)}</div><div class="body">${escapeHtml(w.body)}</div>`;
    wrap.appendChild(card);
  }
  return wrap;
}

$("#drawerClose").addEventListener("click", closeDrawer);
drawer.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeDrawer(); });
$("#stageWrap").addEventListener("click", (ev) => {
  if (ev.target === $("#stageWrap") || ev.target === stage || ev.target === stageInner) {
    closeDrawer(); pinnedId = null; renderNodes(); renderEdges();
  }
});

$("#copyJson").addEventListener("click", () => {
  if (!currentSubject) return;
  const text = JSON.stringify(currentSubject.data.raw || currentSubject.data, null, 2);
  navigator.clipboard?.writeText(text).catch(() => {});
});

// ---------------------------------------------------------------------
// IP lookup
// ---------------------------------------------------------------------
$("#lookupForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const ip = $("#lookupInput").value.trim();
  if (!ip) return;
  const res = await fetch(`/api/ipam/${encodeURIComponent(ip)}`);
  const body = await res.json().catch(() => null);
  renderLookupResult(ip, res.status, body);
});

function renderLookupResult(ip, status, body) {
  currentSubject = { kind: "lookup", data: { raw: body } };
  drawerTabs.style.display = "none";
  $("#drawerHead").innerHTML = `<div class="top"><div class="tile"><svg class="icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg></div>
    <div class="titles"><div class="title">${escapeHtml(ip)}</div><div class="subtitle">IP lookup</div></div></div>`;
  drawerBody.innerHTML = "";

  if (status === 400 || !body) {
    const card = el("div", "lookup-card critical");
    card.innerHTML = `<div class="headline">Not a valid IPv4 address</div>
      <div>Nothing was looked up. This is a malformed address, not an address outside the fleet.</div>`;
    drawerBody.appendChild(card);
  } else if (status === 404) {
    const card = el("div", "lookup-card");
    card.innerHTML = `<div class="headline">No known network</div>
      <div>A valid address, but no segment in this fleet contains it.</div>`;
    drawerBody.appendChild(card);
  } else if (body.ambiguous) {
    const banner = el("div", "banner warn");
    banner.innerHTML = `<div>${warnSvg()}</div><div><b>Ambiguous — rule E9 collision.</b> ${escapeHtml((body.warnings || [])[0] || "")}</div>`;
    drawerBody.appendChild(banner);
    for (const grp of body.networks) drawerBody.appendChild(networkGroupCard(grp, true));
  } else {
    const grp = body.networks[0];
    const hero = el("div", "lookup-hero");
    hero.innerHTML = `<div class="ip">${escapeHtml(grp.network.name || grp.network.cidr)}</div>
      <div class="sub">${grp.network.name ? escapeHtml(grp.network.cidr) : "no address object names this network"}</div>`;
    drawerBody.appendChild(hero);
    for (const m of grp.members) {
      const row = el("div", "member-row");
      row.innerHTML = `<span class="dev">${escapeHtml(m.device.label)} · ${escapeHtml(m.interface.name)}</span>
        <span class="pill ${m.interface.isQueriedAddress ? "blue" : "ghost"}" style="${m.interface.isQueriedAddress ? "" : "background:var(--n100);color:var(--n600)"}">${escapeHtml(m.interface.zoneType || "")}</span>`;
      drawerBody.appendChild(row);
    }
    if (grp.network.nameSource) {
      const p = el("p", "kv-rows"); p.style.marginTop = ".6rem";
      drawerBody.appendChild(kvRows([["Named by", "address object"]]));
    }
    drawerBody.appendChild(el("p", "lookup-footnote",
      "Only address objects defined by a device that is actually a member of the matched network are considered — a numerically overlapping object on an unrelated appliance is never used."));
  }
  openDrawer();
}

function networkGroupCard(grp, warn) {
  const card = el("div", `lookup-card${warn ? " warn" : ""}`);
  const title = el("div", "headline", grp.network.name || grp.network.cidr);
  card.appendChild(title);
  card.appendChild(el("div", null, grp.network.cidr));
  for (const m of grp.members) {
    const row = el("div", "member-row");
    row.style.background = "rgba(255,255,255,.5)";
    row.innerHTML = `<span class="dev">${escapeHtml(m.device.label)} · ${escapeHtml(m.interface.name)}</span>`;
    card.appendChild(row);
  }
  return card;
}

// ---------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------
function wireSeg(rootSel, onChange) {
  const root = $(rootSel);
  root.querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    root.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", "false"));
    b.setAttribute("aria-pressed", "true");
    onChange(b.dataset.value);
  }));
}
wireSeg("#projectionSeg", (v) => {
  projection = v;
  stage.classList.toggle("overlay", v === "overlay");
  render();
});
wireSeg("#confidenceSeg", (v) => { confFilter = v; applyConfidenceFilter(); });
$("#mgmtToggle").addEventListener("change", (ev) => { showManagement = ev.target.checked; render(); });

$("#exportSvg").addEventListener("click", exportSvg);
function exportSvg() {
  const clone = svgLayer.cloneNode(true);
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
  style.textContent = `
    text{font-family:Arial,Helvetica,sans-serif;}
    .confirmed{stroke:rgba(0,26,71,.42);stroke-width:1.6;fill:none;}
    .inferred{stroke:#2006F7;stroke-opacity:.8;stroke-width:1.5;stroke-dasharray:6 5;fill:none;}
    .assumed{stroke:#6A889B;stroke-width:1.4;stroke-dasharray:2 4;fill:none;}
    .tunnel{stroke:#00A6C7;stroke-width:1.9;stroke-dasharray:7 4;fill:none;}
    .stale{stroke:#C2CEDD;stroke-width:1.4;stroke-dasharray:3 5;fill:none;}
    .lit{stroke:#2006F7;stroke-width:2.4;fill:none;}`;
  clone.prepend(style);
  for (const n of model.nodes) {
    const p = layout.get(n.id);
    if (!p || p.hidden) continue;
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", p.x - p.w / 2); rect.setAttribute("y", p.y - p.h / 2);
    rect.setAttribute("width", p.w); rect.setAttribute("height", p.h);
    rect.setAttribute("rx", "12"); rect.setAttribute("fill", "#fff"); rect.setAttribute("stroke", "rgba(0,26,71,.2)");
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", p.x - p.w / 2 + 12); text.setAttribute("y", p.y + 4);
    text.setAttribute("font-size", "12"); text.setAttribute("font-weight", "700"); text.setAttribute("fill", "#16222c");
    text.textContent = n.label;
    g.append(rect, text);
    clone.appendChild(g);
  }
  const blob = new Blob([new XMLSerializer().serializeToString(clone)], { type: "image/svg+xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "sfos-topology.svg";
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------------
// Fleet panel (write-gated; the entry point itself is hidden on a silent
// probe returning 404, so a viewer with no admin secret configured never
// even sees that the surface exists).
// ---------------------------------------------------------------------
$("#fleetBtn").addEventListener("click", () => openFleetPanel());
probeFleetAvailable().then(available => { $("#fleetBtn").hidden = !available; });

// ---------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------
async function load() {
  let res;
  try { res = await fetch("/graph.json", { cache: "no-store" }); }
  catch { showFatal("Could not reach the collector."); return; }
  if (!res.ok) { showFatal(`No graph available yet (HTTP ${res.status}).`); return; }
  doc = await res.json();
  model = buildModel(doc);
  syncStaleBanner();
  syncFreshness();
  render();
}

function showFatal(msg) {
  $("#stale").innerHTML = "";
  $("#stale").appendChild(el("div", "banner bad", `<div>${warnSvg()}</div><div>${escapeHtml(msg)}</div>`));
  $("#stale").hidden = false;
}

function syncStaleBanner() {
  const staleBox = $("#stale");
  if (!model.staleLabels.length) { staleBox.hidden = true; staleBox.innerHTML = ""; return; }
  staleBox.hidden = false;
  staleBox.innerHTML = "";
  staleBox.appendChild(el("div", "banner warn",
    `<div>${warnSvg()}</div><div>Collection pass failed for <b>${model.staleLabels.map(escapeHtml).join(", ")}</b>. Showing the last good graph for it; nothing has been blanked out.</div>`));
}

function syncFreshness() {
  const pill = $("#freshness");
  const t = new Date(doc.generatedAt);
  const mins = Math.max(0, Math.round((Date.now() - t.getTime()) / 60000));
  const label = mins < 1 ? "just now" : `${mins} min ago`;
  if (model.staleLabels.length) {
    pill.textContent = `Last good pass ${label}`;
    pill.classList.add("stale");
  } else {
    pill.textContent = `Collected ${label}`;
    pill.classList.remove("stale");
  }
}

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && drawer.classList.contains("open")) closeDrawer();
});

// Assign the shared SVG paths once.
svgLayer.innerHTML = `<path class="confirmed"/><path class="inferred"/><path class="assumed"/><path class="tunnel"/><path class="stale"/><path class="lit"/>`;
stageInner.prepend(svgLayer);
[pathConfirmed, pathInferred, pathAssumed, pathTunnel, pathStale, pathLit] = svgLayer.querySelectorAll("path");

load();
// Poll on the same cadence the server refreshes on; a fetch failure keeps
// the current graph rather than blanking the view.
setInterval(async () => {
  try {
    const res = await fetch("/graph.json", { cache: "no-store" });
    if (!res.ok) { syncFreshness(); return; }
    doc = await res.json();
    model = buildModel(doc);
    syncStaleBanner();
    syncFreshness();
    render();
  } catch { /* keep showing the current graph */ }
}, 60000);
