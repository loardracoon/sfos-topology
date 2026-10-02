// policy.js — the access policy matrix (GET /policy).
//
// The rule-intent preview and the Apply write path both already exist on
// the server (package policy + cmd/sfos-topology's applyCell): this view
// renders what /api/policy already computes rather than re-deriving
// reachability client-side, so the preview never drifts from what Apply
// would actually do.
import { probeFleetAvailable, openFleetPanel } from "./fleet.js";

const TOKEN_KEY = "sfos-admin-token";
let token = sessionStorage.getItem(TOKEN_KEY) || "";
let doc = null;            // { networks, cells }
let selected = null;       // { source, destination }
let cellApplyResults = {}; // cellKey -> device apply results, persists across selection

const $ = (sel, root) => (root || document).querySelector(sel);
const el = (tag, cls, html) => { const n = document.createElement(tag); if (cls) n.className = cls; if (html !== undefined) n.innerHTML = html; return n; };
const escapeHtml = (s) => (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cellKey = (source, destination) => `${source}>${destination}`;

async function apiFetch(path, opts) {
  opts = opts || {};
  const headers = Object.assign({}, opts.headers, token ? { "X-Admin-Token": token } : {});
  if (opts.body) headers["Content-Type"] = "application/json";
  let res;
  try { res = await fetch(path, Object.assign({}, opts, { headers })); }
  catch { return { ok: false, status: 0, body: { error: "could not reach the server" } }; }
  let body = null;
  try { body = await res.json(); } catch { /* no body */ }
  return { ok: res.ok, status: res.status, body };
}

function cellFor(source, destination) {
  return (doc.cells || []).find(c => c.source === source && c.destination === destination);
}
function netLabel(id) {
  const n = (doc.networks || []).find(x => x.id === id);
  if (!n) return id;
  const members = n.members || [];
  if (!members.length) return n.label;
  const fws = [...new Set(members.map(m => m.deviceLabel))].join(", ");
  const names = [...new Set(members.map(m => m.zoneName))].join("/");
  return `[${fws}] ${names}`;
}

// ---------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------
const mainEl = $("#pMain");

function load() {
  mainEl.innerHTML = "";
  mainEl.appendChild(el("p", "empty-note", "Loading…"));
  if (!token) { showTokenPrompt(); return; }

  apiFetch("/api/policy").then(({ ok, status, body }) => {
    if (status === 404) { showDisabled(); return; }
    if (status === 401) {
      token = ""; sessionStorage.removeItem(TOKEN_KEY);
      showTokenPrompt("That token was rejected.");
      return;
    }
    if (!ok) { showError((body && body.error) || `HTTP ${status}`); return; }
    doc = body;
    renderMain();
  });
}

function showTokenPrompt(message) {
  const wrap = el("div");
  wrap.style.maxWidth = "30rem"; wrap.style.margin = "3rem auto";
  if (message) wrap.appendChild(el("div", "banner bad", `<div>${escapeHtml(message)}</div>`));
  wrap.appendChild(el("p", null,
    "This page needs the admin token the collector was started with (SFOS_ADMIN_TOKEN)."));
  const field = el("div");
  field.innerHTML = `<label class="eyebrow" for="polToken">Admin token</label>`;
  const input = document.createElement("input");
  input.type = "password"; input.id = "polToken"; input.placeholder = "••••••••";
  input.style.display = "block"; input.style.width = "100%"; input.style.marginTop = ".4rem";
  field.appendChild(input);
  wrap.appendChild(field);
  const go = el("button", "primary", "Continue"); go.type = "button"; go.style.marginTop = ".8rem";
  go.addEventListener("click", () => {
    const v = input.value.trim();
    if (!v) return;
    token = v; sessionStorage.setItem(TOKEN_KEY, token);
    load();
  });
  input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") go.click(); });
  wrap.appendChild(go);
  mainEl.innerHTML = "";
  mainEl.appendChild(wrap);
}

function showDisabled() {
  mainEl.innerHTML = "";
  mainEl.appendChild(el("p", "empty-note",
    "The policy matrix is disabled on this server. Set SFOS_ADMIN_TOKEN in its environment and restart to enable it."));
}
function showError(msg) {
  mainEl.innerHTML = "";
  mainEl.appendChild(el("div", "banner bad", `<div>${escapeHtml(msg)}</div>`));
}

// ---------------------------------------------------------------------
// Matrix + editor
// ---------------------------------------------------------------------
function renderMain() {
  $("#pMeta").textContent = `${doc.networks.length} networks · ${(doc.cells || []).length} policies`;
  updateApplyAllButton();
  mainEl.innerHTML = "";
  const body = el("div", "policy-body");
  const matrixPane = el("div", "matrix-pane");
  matrixPane.appendChild(buildMatrix());
  matrixPane.appendChild(buildLegend());
  const editorPane = el("div", "editor-pane", "");
  editorPane.id = "editorPane";
  body.append(matrixPane, editorPane);
  mainEl.appendChild(body);
  renderEditor();
}

function iconAllow() { return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M4 12l5 5L20 6"/></svg>`; }
function iconDeny() { return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M6 12h12"/></svg>`; }
function iconEmpty() { return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12h6" stroke-dasharray="2 3"/></svg>`; }

function buildMatrix() {
  const nets = doc.networks;
  const table = el("table", "pmatrix");
  const thead = el("thead");
  const headRow = el("tr");
  headRow.appendChild(el("th", "corner"));
  for (const n of nets) {
    const th = el("th", "col");
    th.innerHTML = n.isAny ? `<span class="any-tag">${escapeHtml(n.label)}</span>` : escapeHtml(shortLabel(n));
    th.title = netLabel(n.id);
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  for (const rowNet of nets) {
    const tr = el("tr");
    const rowTh = el("th", "row");
    rowTh.innerHTML = rowNet.isAny ? `<span class="any-tag">${escapeHtml(rowNet.label)}</span>` : escapeHtml(shortLabel(rowNet));
    rowTh.title = netLabel(rowNet.id);
    tr.appendChild(rowTh);
    for (const colNet of nets) {
      const td = document.createElement("td");
      if (rowNet.id === colNet.id) {
        td.appendChild(el("div", "pcell diag"));
        tr.appendChild(td);
        continue;
      }
      const c = cellFor(rowNet.id, colNet.id);
      const btn = el("button", `pcell ${c ? c.action : "empty"}`);
      btn.type = "button";
      btn.innerHTML = c ? (c.action === "allow" ? iconAllow() : iconDeny()) : iconEmpty();
      if (c && (c.requireHeartbeat || c.requireAuth)) btn.appendChild(el("span", "req-dot"));
      btn.setAttribute("aria-label", `${netLabel(rowNet.id)} to ${netLabel(colNet.id)}, ${c ? c.action : "no policy"}`);
      if (selected && selected.source === rowNet.id && selected.destination === colNet.id) btn.setAttribute("aria-pressed", "true");
      btn.addEventListener("click", () => { selected = { source: rowNet.id, destination: colNet.id }; renderMain(); });
      td.appendChild(btn);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  return table;
}

function shortLabel(n) {
  const members = n.members || [];
  if (!members.length) return n.label;
  return [...new Set(members.map(m => m.zoneName))].join("/");
}

function buildLegend() {
  const wrap = el("div", "p-legend");
  const item = (cls, icon, text) => `<span><span class="ex ${cls}">${icon}</span>${text}</span>`;
  wrap.innerHTML =
    item("allow", iconAllow(), "Allow") +
    item("deny", iconDeny(), "Deny") +
    item("empty", iconEmpty(), "No policy") +
    `<span><span class="req-dot" style="position:static;display:inline-block;margin-right:.35rem"></span>Heartbeat and/or user auth required</span>`;
  return wrap;
}

function renderEditor() {
  const pane = $("#editorPane");
  pane.innerHTML = "";
  if (!selected) {
    pane.appendChild(el("h2", null, "Nothing selected"));
    pane.appendChild(el("p", "empty-note", "Click a cell in the matrix to design or edit its policy."));
    return;
  }
  const { source, destination } = selected;
  const existing = cellFor(source, destination);

  const title = el("div", "editor-title",
    `<h2>${escapeHtml(netLabel(source))} → ${escapeHtml(netLabel(destination))}</h2>
     <div class="mono">${escapeHtml(source)} → ${escapeHtml(destination)}</div>`);
  pane.appendChild(title);

  const s1 = el("div", "editor-section");
  const seg = el("div", "seg");
  const allowBtn = el("button", null, "Allow"); allowBtn.type = "button";
  const denyBtn = el("button", null, "Deny"); denyBtn.type = "button";
  let action = existing ? existing.action : "allow";
  const paint = () => { allowBtn.setAttribute("aria-pressed", String(action === "allow")); denyBtn.setAttribute("aria-pressed", String(action === "deny")); };
  allowBtn.addEventListener("click", () => { action = "allow"; paint(); });
  denyBtn.addEventListener("click", () => { action = "deny"; paint(); });
  seg.append(allowBtn, denyBtn); paint();
  s1.appendChild(seg);

  const hb = checkline("Require Security Heartbeat", existing ? existing.requireHeartbeat : false);
  const auth = checkline("Require authenticated user", existing ? existing.requireAuth : false);
  const bidi = checkline(cellFor(destination, source) ? "Also overwrite the reverse policy with these same settings" : "Bidirectional — defines two independent cells now", false);
  s1.append(hb.row, auth.row, bidi.row);
  s1.appendChild(el("p", "fixed-line", "Service scope: any service — by design."));
  pane.appendChild(s1);

  const actions = el("div"); actions.style.display = "flex"; actions.style.gap = ".5rem"; actions.style.marginBottom = "1.3rem";
  const save = el("button", "primary", existing ? "Save changes" : "Create policy"); save.type = "button";
  save.addEventListener("click", () => {
    save.disabled = true;
    apiFetch("/api/policy/cell", {
      method: "PUT",
      body: JSON.stringify({ source, destination, action, requireHeartbeat: hb.input.checked, requireAuth: auth.input.checked, bidi: bidi.input.checked }),
    }).then(({ ok, status, body }) => {
      save.disabled = false;
      if (!ok) { flashError((body && body.error) || `HTTP ${status}`); return; }
      doc = body;
      delete cellApplyResults[cellKey(source, destination)];
      renderMain();
    });
  });
  actions.appendChild(save);

  if (existing) {
    const del = el("button", "danger", "Delete"); del.type = "button";
    del.addEventListener("click", () => {
      if (!confirm(`Remove the policy ${netLabel(source)} → ${netLabel(destination)}?`)) return;
      const q = new URLSearchParams({ source, destination });
      apiFetch("/api/policy/cell?" + q.toString(), { method: "DELETE" }).then(({ ok, status, body }) => {
        if (!ok) { flashError((body && body.error) || `HTTP ${status}`); return; }
        doc = body;
        delete cellApplyResults[cellKey(source, destination)];
        selected = null;
        renderMain();
      });
    });
    actions.appendChild(del);

    const apply = el("button", "primary", "Apply"); apply.type = "button";
    apply.title = "Create or update the real rule (and any missing address object) on every applicable firewall";
    apply.addEventListener("click", () => {
      if (!confirm(`Apply ${netLabel(source)} → ${netLabel(destination)} (${existing.action}) for real?\n\nThis creates or updates a live firewall rule — and any missing address object — on every applicable appliance.`)) return;
      apply.disabled = true;
      const q = new URLSearchParams({ source, destination });
      apiFetch("/api/policy/apply?" + q.toString(), { method: "POST" }).then(({ ok, status, body }) => {
        apply.disabled = false;
        if (!ok) { flashError((body && body.error) || `HTTP ${status}`); return; }
        cellApplyResults[cellKey(source, destination)] = body.results || [];
        renderEditor();
      });
    });
    actions.appendChild(apply);
  }
  pane.appendChild(actions);

  const s2 = el("div", "editor-section");
  s2.appendChild(el("h3", "eyebrow", "Rule-intent preview"));
  const intents = existing ? existing.intents : [];
  const applied = cellApplyResults[cellKey(source, destination)] || [];
  if (!existing) {
    s2.appendChild(el("p", "empty-note", "Set a policy above to see which firewalls it would touch."));
  } else if (!intents || !intents.length) {
    s2.appendChild(el("p", "empty-note",
      "No appliance — neither side is directly wired to any appliance, so this cell implies no rule anywhere."));
  } else {
    for (const it of intents) {
      const row = el("div", "intent-row");
      const result = applied.find(r => r.device === it.device.label);
      const pillHtml = result
        ? (result.status === "error" ? `<span class="pill bad">apply failed</span>` : `<span class="pill ok">${escapeHtml(result.status)}</span>`)
        : `<span class="pill ${(it.sourceObjectExists && it.destObjectExists) ? "ok" : "warn"}">${(it.sourceObjectExists && it.destObjectExists) ? "update" : "create"}</span>`;
      row.innerHTML = `<div class="head">${pillHtml}<span class="dev">${escapeHtml(it.device.label)}</span><span class="rule">${escapeHtml(it.ruleName)}</span></div>
        <div class="sentence">${escapeHtml(it.sourceLabel)} → ${escapeHtml(it.destLabel)} · ${escapeHtml(it.service)} · ${escapeHtml(it.action)} · appended at the end of the rule table</div>`;
      const tags = el("div", "tags");
      if (it.requireHeartbeat) tags.innerHTML += `<span class="pill blue">heartbeat</span>`;
      if (it.requireAuth) tags.innerHTML += `<span class="pill blue">user auth</span>`;
      if (!it.sourceObjectExists) tags.innerHTML += `<span class="pill warn">would create source object</span>`;
      if (!it.destObjectExists) tags.innerHTML += `<span class="pill warn">would create dest object</span>`;
      if (result) tags.innerHTML += result.status === "error" ? `<span class="pill bad">${escapeHtml(result.error)}</span>` : "";
      if (tags.innerHTML) row.appendChild(tags);
      s2.appendChild(row);
    }
  }
  pane.appendChild(s2);

  pane.appendChild(el("div", "placement-note",
    "Placement is a deliberate trade-off. New rules are appended at the end, so a pre-existing catch-all deny can shadow them. Inserting at the top would instead shadow a rule someone placed on purpose."));
}

function checkline(text, checked) {
  const row = el("label", "checkline");
  const input = document.createElement("input");
  input.type = "checkbox"; input.checked = checked;
  row.append(input, document.createTextNode(text));
  return { row, input };
}

function flashError(msg) {
  const e = el("div", "banner bad", `<div>${escapeHtml(msg)}</div>`);
  e.style.marginBottom = "1rem";
  mainEl.prepend(e);
  setTimeout(() => e.remove(), 4000);
}

// ---------------------------------------------------------------------
// Apply all
// ---------------------------------------------------------------------
const applyAllBtn = $("#applyAllBtn");
function updateApplyAllButton() {
  const count = doc ? (doc.cells || []).length : 0;
  applyAllBtn.disabled = count === 0;
  applyAllBtn.textContent = count ? `Apply all (${count})` : "Apply all";
}
applyAllBtn.addEventListener("click", () => {
  const count = (doc.cells || []).length;
  if (!confirm(`Apply all ${count} saved polic${count === 1 ? "y" : "ies"} for real?\n\nThis creates or updates a live firewall rule — and any missing address object — on every applicable appliance, for every policy currently saved in the matrix.`)) return;
  applyAllBtn.disabled = true;
  apiFetch("/api/policy/apply-all", { method: "POST" }).then(({ ok, status, body }) => {
    updateApplyAllButton();
    if (!ok) { flashError((body && body.error) || `HTTP ${status}`); return; }
    for (const cell of body.results || []) cellApplyResults[cellKey(cell.source, cell.destination)] = cell.results;
    renderApplyAllSummary(body.results || []);
    renderEditor();
  });
});

function renderApplyAllSummary(results) {
  let ok = 0, failed = 0;
  const failures = [];
  for (const cell of results) {
    for (const r of cell.results) {
      if (r.status === "error") { failed++; failures.push(`${netLabel(cell.source)} → ${netLabel(cell.destination)} on ${r.device}: ${r.error}`); }
      else ok++;
    }
  }
  const total = ok + failed;
  const div = el("div", `apply-summary ${failed ? "banner bad" : "banner info"}`);
  div.innerHTML = `<div>${total
    ? `Apply all: ${ok}/${total} rule${total === 1 ? "" : "s"} applied across ${results.length} polic${results.length === 1 ? "y" : "ies"}.`
    : `Apply all: none of the ${results.length} saved polic${results.length === 1 ? "y" : "ies"} touched any firewall (no directly-connected device on either side).`}</div>`;
  if (failures.length) {
    const ul = document.createElement("ul");
    for (const line of failures) ul.appendChild(el("li", null, escapeHtml(line)));
    div.appendChild(ul);
  }
  mainEl.prepend(div);
}

// ---------------------------------------------------------------------
// Fleet panel entry point
// ---------------------------------------------------------------------
$("#fleetBtn").addEventListener("click", () => openFleetPanel());
probeFleetAvailable().then(available => { $("#fleetBtn").hidden = !available; });

load();
