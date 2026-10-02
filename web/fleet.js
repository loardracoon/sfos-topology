// fleet.js — the write-gated fleet management panel, shared by the graph
// view and the policy view. It renders nothing and logs nothing until
// GET /api/devices answers with something other than 404, so the surface
// does not even hint at existing for someone who has not opted in with
// SFOS_ADMIN_TOKEN (see PROJECT_OVERVIEW.md).

const TOKEN_KEY = "sfos-admin-token";
let token = sessionStorage.getItem(TOKEN_KEY) || "";
let panelEl = null;

function el(tag, cls, html) { const n = document.createElement(tag); if (cls) n.className = cls; if (html !== undefined) n.innerHTML = html; return n; }
function escapeHtml(s) { return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

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

// probeFleetAvailable resolves true only when the write surface is enabled
// at all (any status other than 404), so a caller can decide whether to
// offer an entry point in the first place.
export async function probeFleetAvailable() {
  const { status } = await apiFetch("/api/devices");
  return status !== 404;
}

function ensurePanel() {
  if (panelEl) return panelEl;
  panelEl = el("aside", "drawer fleet-drawer");
  panelEl.innerHTML = `
    <div class="drawer-head">
      <div class="top">
        <div class="tile"><svg class="icon" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/><path d="M8 19h8"/></svg></div>
        <div class="titles"><div class="title">Fleet</div><div class="subtitle">Add, edit or remove appliances</div></div>
        <button class="icon-btn" id="fleetClose" type="button" aria-label="Close fleet panel"><svg class="icon" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
      </div>
    </div>
    <div class="drawer-body" id="fleetBody"></div>`;
  document.body.appendChild(panelEl);
  panelEl.querySelector("#fleetClose").addEventListener("click", closeFleetPanel);
  panelEl.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeFleetPanel(); });
  return panelEl;
}

export function closeFleetPanel() {
  if (panelEl) panelEl.classList.remove("open");
}

export async function openFleetPanel() {
  const panel = ensurePanel();
  panel.classList.add("open");
  const body = panel.querySelector("#fleetBody");
  body.innerHTML = "";
  body.appendChild(el("p", "empty-note", "Loading…"));

  if (!token) { renderTokenPrompt(body); return; }
  loadFleet(body);
}

function renderTokenPrompt(body, message) {
  body.innerHTML = "";
  if (message) body.appendChild(el("div", "banner bad", `<div>${message}</div>`));
  body.appendChild(el("p", null,
    "This panel needs the admin token the server was started with (SFOS_ADMIN_TOKEN)."));
  const field = el("div");
  field.innerHTML = `<label class="eyebrow" for="fleetToken">Admin token</label>`;
  const input = document.createElement("input");
  input.type = "password"; input.id = "fleetToken"; input.placeholder = "••••••••";
  input.style.display = "block"; input.style.width = "100%"; input.style.marginTop = ".4rem";
  field.appendChild(input);
  body.appendChild(field);
  const go = el("button", "primary", "Continue");
  go.type = "button"; go.style.marginTop = ".8rem";
  go.addEventListener("click", () => {
    const v = input.value.trim();
    if (!v) return;
    token = v;
    sessionStorage.setItem(TOKEN_KEY, token);
    loadFleet(body);
  });
  input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") go.click(); });
  body.appendChild(go);
}

// fetchReports reads the current /graph.json (unauthenticated, always
// up to date) for each device's live collection outcome -- reachable now,
// or the error from the last attempt. Fetched fresh on every render rather
// than handed in by the caller, so clicking "Refresh fleet" shows the
// result of THAT pass immediately instead of whatever the caller's own
// polling cycle last cached.
async function fetchReports() {
  try {
    const res = await fetch("/graph.json", { cache: "no-store" });
    if (!res.ok) return new Map();
    const doc = await res.json();
    return new Map((doc.devices || []).map(d => [d.label, d]));
  } catch {
    return new Map();
  }
}

async function loadFleet(body) {
  const { ok, status, body: devices } = await apiFetch("/api/devices");
  if (status === 401) {
    token = ""; sessionStorage.removeItem(TOKEN_KEY);
    renderTokenPrompt(body, "That token was rejected.");
    return;
  }
  if (status === 404) {
    body.innerHTML = "";
    body.appendChild(el("p", "empty-note", "The fleet panel is disabled on this server."));
    return;
  }
  if (!ok) {
    body.innerHTML = "";
    body.appendChild(el("div", "banner bad", `<div>${escapeHtml((devices && devices.error) || "HTTP " + status)}</div>`));
    return;
  }

  const reports = await fetchReports();

  body.innerHTML = "";
  body.appendChild(el("div", "fleet-lock",
    "Write surface is opt-in. Without an admin secret every fleet and policy call answers 404, not 401."));

  const refreshBtn = el("button", "outline", "Refresh fleet");
  refreshBtn.type = "button"; refreshBtn.style.marginBottom = ".8rem";
  refreshBtn.title = "Re-collect every appliance now, instead of waiting for the next scheduled refresh";
  refreshBtn.addEventListener("click", async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = "Refreshing…";
    const { ok, status, body: resp } = await apiFetch("/api/devices/refresh", { method: "POST" });
    if (!ok) {
      result.innerHTML = "";
      result.appendChild(el("div", "banner bad", `<div>${escapeHtml((resp && resp.error) || "HTTP " + status)}</div>`));
      refreshBtn.disabled = false;
      refreshBtn.textContent = "Refresh fleet";
      return;
    }
    loadFleet(body);
  });
  body.appendChild(refreshBtn);
  const result = el("div"); body.appendChild(result);

  const list = el("div");
  for (const d of devices) {
    const report = reports.get(d.label);
    const row = el("div", "fleet-row");
    let dotCls = "ok", stateText = "Collected";
    if (d.offlineDir) { dotCls = "replay"; stateText = "Replayed"; }
    else if (report && report.error) { dotCls = "bad"; stateText = `Unreachable · ${escapeHtml(report.error).slice(0, 40)}`; }
    const src = d.offlineDir ? `capture · ${escapeHtml(d.offlineDir)}` : d.tokenEnv ? `env ${escapeHtml(d.tokenEnv)}` : d.hasToken ? "secrets file" : "no credential";
    row.innerHTML = `<span class="state-dot ${dotCls}"></span>
      <span class="label">${escapeHtml(d.label)}</span>
      <span class="host">${escapeHtml(d.host || "")}</span>
      <span class="src">${src}</span>
      <span class="pill ${dotCls === "ok" ? "ok" : dotCls === "bad" ? "bad" : "ghost"}" style="${dotCls === "replay" ? "background:var(--n100);color:var(--n600)" : ""}">${stateText}</span>`;
    const edit = el("button", "ghost", "Edit"); edit.type = "button"; edit.style.marginLeft = ".4rem";
    edit.addEventListener("click", () => renderForm(body, d));
    const del = el("button", "ghost", "Remove"); del.type = "button";
    del.addEventListener("click", async () => {
      if (!confirm(`Remove ${d.label}?`)) return;
      await apiFetch("/api/devices/" + encodeURIComponent(d.label), { method: "DELETE" });
      loadFleet(body);
    });
    row.append(edit, del);
    list.appendChild(row);
  }
  body.appendChild(list);

  const addBtn = el("button", "primary", "Add appliance");
  addBtn.type = "button"; addBtn.style.marginTop = "1rem";
  addBtn.addEventListener("click", () => renderForm(body, null));
  body.appendChild(addBtn);

  body.appendChild(el("div", "fleet-foot",
    "devices.json is safe to share · devices.secrets.json never leaves the host."));
}

function renderForm(body, existing) {
  body.innerHTML = "";
  body.appendChild(el("h3", null, existing ? `Edit ${existing.label}` : "Add appliance"));

  const mk = (labelText, id, value, type) => {
    const f = el("div"); f.style.marginBottom = ".8rem";
    f.innerHTML = `<label class="eyebrow" for="${id}">${labelText}</label>`;
    const input = document.createElement("input");
    input.type = type || "text"; input.id = id; input.value = value || "";
    input.style.display = "block"; input.style.width = "100%"; input.style.marginTop = ".35rem";
    f.appendChild(input);
    body.appendChild(f);
    return input;
  };
  const label = mk("Label", "fLabel", existing?.label);
  const host = mk("Host and port, or a capture directory", "fHost", existing?.host || existing?.offlineDir);
  const token = mk("API key", "fToken", "", "password");
  token.placeholder = existing ? "leave blank to keep the current key" : "sfos_...";
  const pin = mk("Certificate pin (SHA-256, optional)", "fPin", existing?.pinSha256);
  body.appendChild(el("p", "empty-note",
    "The key is written to the sibling secrets file, never into devices.json and never returned by the API -- entering nothing on an edit keeps the existing one. A device whose host is manually set up with tokenEnv in devices.json instead keeps working too; Settings only ever writes here, never there."));

  const result = el("div"); body.appendChild(result);

  const actions = el("div"); actions.style.display = "flex"; actions.style.gap = ".5rem"; actions.style.marginTop = "1rem";
  const save = el("button", "primary", existing ? "Save" : "Add"); save.type = "button";
  save.addEventListener("click", async () => {
    save.disabled = true;
    const payload = { label: label.value.trim(), host: host.value.trim(), token: token.value, pinSha256: pin.value.trim() };
    const { ok, status, body: resp } = existing
      ? await apiFetch("/api/devices/" + encodeURIComponent(existing.label), { method: "PUT", body: JSON.stringify(payload) })
      : await apiFetch("/api/devices", { method: "POST", body: JSON.stringify(payload) });
    save.disabled = false;
    if (!ok) {
      result.innerHTML = "";
      result.appendChild(el("div", "banner bad", `<div>${escapeHtml((resp && resp.error) || "HTTP " + status)}</div>`));
      return;
    }
    const dev = resp.device;
    result.innerHTML = "";
    result.appendChild(el("div", `banner ${dev && dev.error ? "bad" : "info"}`,
      `<div>${dev && dev.error ? `Saved, but unreachable: ${escapeHtml(dev.error)}` : "Saved and reachable."}</div>`));
    loadFleet(body);
  });
  const cancel = el("button", "ghost", "Cancel"); cancel.type = "button";
  cancel.addEventListener("click", () => loadFleet(body));
  actions.append(save, cancel);
  body.appendChild(actions);
}
