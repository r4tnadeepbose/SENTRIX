/* Wintermute console: hash-routed SPA over the JSON API. */
"use strict";

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => [...(root || document).querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

const state = {
  user: null, view: "overview", filters: { severity: "", surface: "", status: "", q: "" },
  sort: "created", page: 1, pageSize: 25, selection: new Set(),
  drawerId: null, drawerTab: "details", paused: false, settingsSection: "profile",
  logLevel: "", logTab: "system", gPending: false,
};

const SEVS = ["critical", "high", "medium", "low", "info"];
const SURFACES = ["ide", "pre_push", "ci", "git", "cloud", "slack", "confluence", "jira", "postman", "filesystem"];
const SURFACE_LABEL = { ide: "IDE", pre_push: "Pre-push", ci: "CI", git: "Git", cloud: "Cloud", slack: "Slack", confluence: "Confluence", jira: "Jira", postman: "Postman", filesystem: "Filesystem" };
const CHECKLIST_STEPS = [
  "Rotate the credential at its provider",
  "Remove the exposure from the source file",
  "Purge the value from history, docs and chat",
  "Update consumers to the replacement secret",
  "Re-scan the location to verify",
];

const HELP = {
  overview: "The Overview shows the unified pipeline: events arrive from a surface (editor, git hook, CI, schedule, SaaS export), the shared engine scans them, new findings are stored and alerted, and remediation closes the loop. Counters update live; every stage also writes a line to the Logs view.",
  findings: "Findings are detections from every layer. Secrets are masked and fingerprinted - raw values are never stored. Duplicates bump the occurrence counter instead of creating noise. Use filters, saved filters and bulk actions to work through them; open a row for notes, history, triage and remediation.",
  playground: "The Playground runs the detector registry and entropy scoring against text you paste, without storing anything. Use it to test patterns or confirm a value is detected before it reaches a repository.",
  jobs: "Jobs are background scans with an incremental cache: unchanged files are skipped on re-runs. Schedules trigger jobs automatically at a fixed interval. Two jobs run concurrently; queued jobs can be cancelled.",
  activity: "Activity shows pipeline events (left) and delivered alerts (right). Alerts obey channel rules, quiet hours and a dedupe window; acknowledge them to record that someone is handling the finding. The feed pauses with the toggle.",
  logs: "Logs is the live system journal: auth, scans, alerts, remediation, scheduler and mutation requests all write entries here (SQLite system_log). The Audit tab records security-relevant actions with user and detail. Use the level filter to focus on warnings and errors.",
  allowlist: "The allowlist is the false-positive registry. Entries are keyed by SHA-256 fingerprint of the secret, so the same known-safe value never alerts again on any surface. Built-in placeholders (example keys, your-api-key) are always allowed.",
  settings: "Settings groups administration: profile and password, users and roles, API tokens for CI, detector tuning, alert channel rules, and data operations (backup, retention, export). Each section explains itself with the ? button.",
  "settings-profile": "Your account and password. Passwords are stored as PBKDF2-SHA256 hashes (200k iterations). Changing the demo password removes the demo card from the login page.",
  "settings-users": "Local accounts with three roles: admin (everything), analyst (manage findings and scans), viewer (read-only). Disabled accounts cannot sign in.",
  "settings-tokens": "API tokens authenticate scripts and CI with 'Authorization: Bearer wmt_...'. A token is shown once at creation and stored only as a hash; revoke it when a pipeline is retired.",
  "settings-detectors": "One detector registry powers every layer. Disable noisy detectors or override severity here; custom detectors can be added in config.toml. Tuning applies immediately to new scans.",
  "settings-rules": "Channel rules set the minimum severity a channel receives. Quiet hours defer network channels; the outbox always records. Unconfigured webhooks run in dry-run mode.",
  "settings-data": "Operate the store: SQLite backup, retention purge of closed findings, vacuum, and CSV/JSON export for reporting. Import restores a previous dump.",
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { location.href = "/login"; throw new Error("unauthenticated"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<span class="toast-msg">${esc(msg)}</span>`;
  $("#toast-root").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function confirmDialog(title, body, onYes, yesLabel = "Confirm") {
  const root = $("#dialog-root");
  root.innerHTML = `<div class="dialog-overlay"><div class="dialog" role="dialog" aria-modal="true">
    <div class="dialog-body"><strong>${esc(title)}</strong><p class="muted">${esc(body)}</p></div>
    <div class="dialog-actions"><button class="btn btn-ghost" data-no>Cancel</button>
    <button class="btn btn-danger" data-yes>${esc(yesLabel)}</button></div></div></div>`;
  const close = () => { root.innerHTML = ""; };
  $("[data-no]", root).onclick = close;
  $(".dialog-overlay", root).onclick = (e) => { if (e.target === e.currentTarget) close(); };
  $("[data-yes]", root).onclick = () => { close(); onYes(); };
}

function helpBtn(key) {
  return `<button class="help-btn" type="button" data-help="${esc(key)}" aria-label="Explain this section">?</button>`;
}

function showHelp(key, anchor) {
  const root = $("#popover-root");
  const text = HELP[key] || HELP[state.view] || "";
  root.innerHTML = `<div class="popover" role="tooltip">
    <div class="popover-title">How this works</div><div class="popover-body">${esc(text)}</div></div>`;
  const pop = $(".popover", root);
  const r = anchor.getBoundingClientRect();
  pop.style.top = `${Math.min(r.bottom + 8, window.innerHeight - 180)}px`;
  pop.style.left = `${Math.max(8, Math.min(r.left - 140, window.innerWidth - 320))}px`;
  setTimeout(() => {
    const off = (e) => { if (!pop.contains(e.target) && e.target !== anchor) { root.innerHTML = ""; document.removeEventListener("click", off); } };
    document.addEventListener("click", off);
  }, 0);
}

function relTime(iso) {
  if (!iso) return "-";
  const then = new Date(iso + "Z").getTime();
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}
const absTime = (iso) => iso ? iso.replace("T", " ") + " UTC" : "-";
const sevBadge = (s) => `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
const canWrite = () => state.user && state.user.role !== "viewer";

function viewHead(title, sub, helpKey) {
  return `<div class="view-head"><h1>${esc(title)}</h1>${helpBtn(helpKey || state.view)}
    <p class="view-sub">${esc(sub)}</p></div>`;
}
const skeleton = () => `<div class="skel"><div class="skel-row"></div><div class="skel-line"></div><div class="skel-line"></div><div class="skel-row"></div></div>`;

/* ---------- svg chart builders ---------- */

const SEV_COLOR = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)" };
const STATUS_COLOR = { open: "var(--high)", triaged: "var(--info)", remediated: "var(--low)", false_positive: "var(--muted)" };

function donut(series, colorOf, center) {
  const total = series.reduce((a, s) => a + s.value, 0) || 1;
  const R = 40, C = 2 * Math.PI * R;
  let offset = 0;
  const arcs = series.filter((s) => s.value > 0).map((s) => {
    const len = (s.value / total) * C;
    const el = `<circle class="arc" cx="50" cy="50" r="${R}" fill="none" style="stroke:${colorOf(s.label)}" stroke-width="13" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 50 50)"><title>${esc(s.label)}: ${s.value}</title></circle>`;
    offset += len;
    return el;
  }).join("");
  return `<svg viewBox="0 0 100 100" width="116" height="116" role="img" aria-label="${esc(center)} distribution">
    <circle cx="50" cy="50" r="${R}" fill="none" style="stroke:var(--panel-2)" stroke-width="13"/>
    ${arcs}<text x="50" y="47" text-anchor="middle" class="donut-center" style="fill:var(--text)" font-size="17" font-weight="650">${total === 1 && series.every((s) => s.value === 0) ? 0 : series.reduce((a, s) => a + s.value, 0)}</text>
    <text x="50" y="60" text-anchor="middle" class="axis-label">${esc(center)}</text></svg>`;
}

function legend(series, colorOf) {
  return `<div class="legend">${series.map((s) => `<div class="legend-row"><span class="swatch" style="background:${colorOf(s.label)}"></span><span>${esc(s.label.replace(/_/g, " "))}</span><span class="legend-val">${s.value}</span></div>`).join("")}</div>`;
}

function areaChart(points) {
  const W = 440, H = 150, P = { l: 26, r: 8, t: 10, b: 20 };
  const max = Math.max(1, ...points.map((p) => p.count));
  const x = (i) => P.l + (i / (points.length - 1)) * (W - P.l - P.r);
  const y = (v) => P.t + (1 - v / max) * (H - P.t - P.b);
  const line = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.count).toFixed(1)}`).join(" ");
  const area = `${line} L${x(points.length - 1).toFixed(1)},${y(0)} L${x(0).toFixed(1)},${y(0)} Z`;
  const grid = [0, 0.5, 1].map((t) => `<line class="grid-line" x1="${P.l}" x2="${W - P.r}" y1="${y(max * t)}" y2="${y(max * t)}"/><text class="axis-label" x="${P.l - 5}" y="${y(max * t) + 3}" text-anchor="end">${Math.round(max * t)}</text>`).join("");
  const labels = points.map((p, i) => i % 4 === 0 ? `<text class="axis-label" x="${x(i)}" y="${H - 6}" text-anchor="middle">${esc(p.date.slice(5))}</text>` : "").join("");
  const dots = points.map((p, i) => `<circle class="dot" cx="${x(i)}" cy="${y(p.count)}" r="2.6" style="fill:var(--info)"><title>${esc(p.date)}: ${p.count} new</title></circle>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="150" role="img" aria-label="New findings per day">
    <defs><linearGradient id="area-fill" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" style="stop-color:var(--info)" stop-opacity="0.35"/>
      <stop offset="1" style="stop-color:var(--info)" stop-opacity="0.02"/>
    </linearGradient></defs>
    ${grid}<path d="${area}" fill="url(#area-fill)"/><path d="${line}" fill="none" style="stroke:var(--info)" stroke-width="1.8"/>${dots}${labels}</svg>`;
}

function barChart(series, colorOf) {
  const max = Math.max(1, ...series.map((s) => s.value));
  const W = 300, rowH = 24, H = series.length * rowH + 4;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Distribution bars">
    ${series.map((s, i) => {
      const w = (s.value / max) * (W - 110);
      return `<text class="axis-label" x="0" y="${i * rowH + 14}" style="font-size:10px">${esc(s.label.replace(/_/g, " "))}</text>
        <rect class="bar" x="86" y="${i * rowH + 5}" width="${Math.max(2, w).toFixed(1)}" height="10" rx="2" style="fill:${colorOf(s.label, i)}"><title>${esc(s.label)}: ${s.value}</title></rect>
        <text class="axis-label" x="${86 + Math.max(2, w) + 6}" y="${i * rowH + 14}">${s.value}</text>`;
    }).join("")}</svg>`;
}

function scatterChart(points) {
  const W = 300, H = 170, P = { l: 26, r: 10, t: 10, b: 22 };
  const order = ["critical", "high", "medium", "low", "info"];
  const x = (e) => P.l + (Math.min(6, e) / 6) * (W - P.l - P.r);
  const y = (sev, i) => P.t + 12 + order.indexOf(sev) * ((H - P.t - P.b - 20) / 4) + ((i % 3) - 1) * 5;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Entropy by severity">
    <line class="grid-line" x1="${P.l}" x2="${W - P.r}" y1="${H - P.b}" y2="${H - P.b}"/>
    <line class="grid-line" x1="${P.l}" x2="${P.l}" y1="${P.t}" y2="${H - P.b}"/>
    ${[0, 2, 4, 6].map((v) => `<text class="axis-label" x="${x(v)}" y="${H - 8}" text-anchor="middle">${v}</text>`).join("")}
    <text class="axis-label" x="${W - P.r}" y="${H - 8}" text-anchor="end">entropy</text>
    ${order.map((s, i) => `<text class="axis-label" x="${P.l - 5}" y="${y(s, 1) + 3}" text-anchor="end">${s.slice(0, 4)}</text>`).join("")}
    ${points.map((p, i) => `<circle class="dot" cx="${x(p.entropy).toFixed(1)}" cy="${y(p.severity, i).toFixed(1)}" r="3.4" style="fill:${SEV_COLOR[p.severity] || "var(--accent)"}" fill-opacity="0.85"><title>${esc(p.title)} - entropy ${p.entropy}, seen ${p.occurrences}x</title></circle>`).join("")}</svg>`;
}

/* ---------- views ---------- */

async function renderOverview() {
  $("#view").innerHTML = viewHead("Overview", "Company-wide detection posture across every layer.") + skeleton();
  const [d, ov, logs] = await Promise.all([
    api("/api/dashboard"), api("/api/overview"), api("/api/logs?limit=6")]);
  const k = d.kpis;
  const st = ov.stages;
  $("#view").innerHTML = viewHead("Overview", "Company-wide detection posture across every layer.") + `
    <div class="pipeline" aria-label="Detection pipeline">
      ${[["Events", st.events], ["Scan", st.scans], ["Findings", st.findings], ["Alert", st.alerts], ["Remediate", st.remediations]]
        .map(([name, count], i) => `${i ? '<span class="pipe-arrow" aria-hidden="true">→</span>' : ""}
          <div class="stage"><div class="stage-name">${name}</div><div class="stage-count">${count}</div></div>`).join("")}
    </div>
    <div class="kpi-row">
      <div class="kpi"><div class="kpi-label">Total findings</div><div class="kpi-value">${k.total}</div><div class="kpi-sub">all surfaces</div></div>
      <div class="kpi"><div class="kpi-label">Open</div><div class="kpi-value">${k.open}</div><div class="kpi-sub">need action</div></div>
      <div class="kpi"><div class="kpi-label">Critical + high</div><div class="kpi-value bad">${k.critical_high}</div><div class="kpi-sub">priority queue</div></div>
      <div class="kpi"><div class="kpi-label">Alerts sent</div><div class="kpi-value">${k.alerts}</div><div class="kpi-sub">all channels</div></div>
      <div class="kpi"><div class="kpi-label">Remediated</div><div class="kpi-value">${k.remediations}</div><div class="kpi-sub">closed loop</div></div>
      <div class="kpi"><div class="kpi-label">False positives</div><div class="kpi-value">${k.false_positives}</div><div class="kpi-sub">allowlisted</div></div>
    </div>
    <div class="chart-grid">
      <div class="chart-card"><h2>New findings per day</h2><div class="chart-sub">Last 14 days, all surfaces</div>${areaChart(d.timeline)}</div>
      <div class="chart-card"><h2>By severity</h2><div class="chart-sub">Share of detections</div><div class="chart-body">${donut(d.severity, (l) => SEV_COLOR[l] || "var(--accent)", "total")}${legend(d.severity, (l) => SEV_COLOR[l] || "var(--accent)")}</div></div>
      <div class="chart-card"><h2>By status</h2><div class="chart-sub">Workflow state</div><div class="chart-body">${donut(d.status, (l) => STATUS_COLOR[l] || "var(--accent)", "total")}${legend(d.status, (l) => STATUS_COLOR[l] || "var(--accent)")}</div></div>
    </div>
    <div class="chart-grid">
      <div class="chart-card"><h2>By surface</h2><div class="chart-sub">Where secrets appear</div>${barChart(d.surfaces, () => "var(--info)")}</div>
      <div class="chart-card"><h2>Alert channels</h2><div class="chart-sub">Delivery volume</div>${barChart(d.channels.length ? d.channels : [{ label: "none", value: 0 }], () => "var(--low)")}</div>
      <div class="chart-card"><h2>Entropy by severity</h2><div class="chart-sub">Each dot is a finding, positioned by severity band</div>${scatterChart(d.scatter)}</div>
    </div>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Team workload</h2>${helpBtn("overview")}</div>
        ${d.team.map((t) => `<div class="team-row"><span class="team-avatar">${esc(t.username[0].toUpperCase())}</span>
          <div><div class="team-name">${esc(t.username)}</div><div class="team-title">${esc(t.title || t.role)}</div></div>
          <span class="team-load">${t.assigned} assigned · ${t.owned} owned</span></div>`).join("")}</div>
      <div class="panel"><div class="panel-head"><h2>Recent system log</h2><a class="btn btn-ghost btn-sm" href="#/logs">Open Logs</a></div>
        <div class="log-mini">${logs.logs.map((l) => `<div class="log-line"><span class="log-ts">${esc(absTime(l.ts))}</span><span class="log-level ${esc(l.level)}">${esc(l.level)}</span><span class="log-msg">${esc(l.message)}</span></div>`).join("") || '<p class="muted">No entries yet.</p>'}</div>
        <div class="panel-head" style="margin-top:12px"><h2>How it works</h2></div>
        <ol class="how-list">${ov.how.map((h) => `<li>${esc(h.replace(/^\d+\.\s*/, ""))}</li>`).join("")}</ol></div>
    </div>
    ${k.total === 0 ? `<div class="panel"><div class="empty"><div class="empty-title">No findings yet</div><div class="empty-sub">Load synthetic demo data to explore every view.</div>${canWrite() ? '<button class="btn btn-primary" id="demo-btn">Load demo data</button>' : ""}</div></div>` : ""}`;
  const demo = $("#demo-btn");
  if (demo) demo.onclick = async () => { await api("/api/demo", { method: "POST", body: {} }); toast("Demo data loaded", "success"); renderOverview(); };
}

async function renderFindings() {
  $("#view").innerHTML = viewHead("Findings", "Investigate, triage and remediate detections.") + skeleton();
  const f = state.filters;
  const params = new URLSearchParams({ sort: state.sort, page: state.page, page_size: state.pageSize });
  for (const [k, v] of Object.entries(f)) if (v) params.set(k, v);
  const [data, filters] = await Promise.all([
    api(`/api/findings?${params}`), api("/api/filters")]);
  const rows = data.findings;
  const pages = Math.max(1, Math.ceil(data.total / state.pageSize));
  $("#view").innerHTML = viewHead("Findings", "Investigate, triage and remediate detections. Select a row for full detail.") + `
    <div class="toolbar">
      <input type="search" id="f-q" placeholder="Search title, path, detector" value="${esc(f.q)}" aria-label="Search findings">
      <select id="f-severity" aria-label="Severity">${["", ...SEVS].map((s) => `<option value="${s}" ${f.severity === s ? "selected" : ""}>${s ? s : "All severities"}</option>`).join("")}</select>
      <select id="f-surface" aria-label="Surface">${["", ...SURFACES].map((s) => `<option value="${s}" ${f.surface === s ? "selected" : ""}>${s ? SURFACE_LABEL[s] : "All surfaces"}</option>`).join("")}</select>
      <select id="f-status" aria-label="Status">${["", "open", "triaged", "false_positive", "remediated"].map((s) => `<option value="${s}" ${f.status === s ? "selected" : ""}>${s ? s.replace("_", " ") : "All statuses"}</option>`).join("")}</select>
      <select id="f-sort" aria-label="Sort">${["created", "severity", "occurrences", "pinned"].map((s) => `<option ${state.sort === s ? "selected" : ""}>${s}</option>`).join("")}</select>
      <select id="f-saved" aria-label="Saved filters"><option value="">Saved filters</option>${filters.filters.map((x) => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("")}</select>
      ${canWrite() ? '<button class="btn btn-ghost btn-sm" id="f-save">Save filter</button>' : ""}
    </div>
    <div class="table-wrap findings-table"><table class="table">
      <thead><tr>${canWrite() ? '<th class="check-by"></th>' : ""}<th></th><th>Severity</th><th>Title</th><th>Surface</th><th>Location</th><th>Seen</th><th>Assignee</th><th>Status</th><th>Age</th></tr></thead>
      <tbody>${rows.map((r) => `<tr data-id="${esc(r.id)}" class="${state.selection.has(r.id) ? "row-selected" : ""}">
        ${canWrite() ? `<td class="check-by"><input type="checkbox" data-select="${esc(r.id)}" ${state.selection.has(r.id) ? "checked" : ""} aria-label="Select finding"></td>` : ""}
        <td class="pin-cell"><button class="icon-btn" data-pin="${esc(r.id)}" aria-label="Pin">${r.pinned ? "★" : "☆"}</button></td>
        <td>${sevBadge(r.severity_override || r.severity)}${r.severity_override ? "*" : ""}</td>
        <td><button class="btn-link" data-open="${esc(r.id)}">${esc(r.title)}</button><div class="detector-id">${esc(r.detector_id)}</div></td>
        <td>${esc(SURFACE_LABEL[r.surface] || r.surface)}</td>
        <td class="mono-block truncate">${esc(r.path)}:${r.line}</td>
        <td>${r.occurrences}×</td><td>${esc(r.assignee || "-")}</td>
        <td><span class="chip">${esc(r.status.replace("_", " "))}</span></td>
        <td class="nowrap" title="${esc(absTime(r.created_at))}">${relTime(r.created_at)}</td></tr>`).join("")}</tbody>
    </table></div>
    <div class="cards">${rows.map((r) => `<div class="f-card" data-open="${esc(r.id)}">
      <div class="f-card-top">${sevBadge(r.severity_override || r.severity)}<span class="chip">${esc(r.status.replace("_", " "))}</span></div>
      <div class="f-card-title">${esc(r.title)}</div><div class="loc">${esc(r.path)}:${r.line}</div>
      <div class="f-card-meta"><span>${esc(SURFACE_LABEL[r.surface] || r.surface)}</span><span>${r.occurrences}× seen</span><span>${relTime(r.created_at)}</span></div></div>`).join("")}</div>
    ${rows.length === 0 ? '<div class="empty"><div class="empty-title">No findings match</div><div class="empty-sub">Adjust filters, or run a scan from Jobs or the Playground.</div></div>' : ""}
    <div class="pagination"><button class="btn btn-ghost btn-sm" id="pg-prev" ${state.page <= 1 ? "disabled" : ""}>Prev</button>
      <span class="muted">Page ${data.page} of ${pages} · ${data.total} findings</span>
      <button class="btn btn-ghost btn-sm" id="pg-next" ${state.page >= pages ? "disabled" : ""}>Next</button></div>
    <div id="bulkbar-slot"></div>`;
  const rerender = () => { state.page = 1; renderFindings(); };
  $("#f-q").oninput = (e) => { clearTimeout(state.qTimer); state.qTimer = setTimeout(() => { f.q = e.target.value.trim(); rerender(); }, 300); };
  for (const key of ["severity", "surface", "status"]) $(`#f-${key}`).onchange = (e) => { f[key] = e.target.value; rerender(); };
  $("#f-sort").onchange = (e) => { state.sort = e.target.value; rerender(); };
  $("#pg-prev").onclick = () => { state.page--; renderFindings(); };
  $("#pg-next").onclick = () => { state.page++; renderFindings(); };
  const saved = $("#f-saved");
  saved.onchange = () => {
    const entry = filters.filters.find((x) => x.id === saved.value);
    if (entry) { Object.assign(state.filters, entry.params); state.page = 1; renderFindings(); }
  };
  const saveBtn = $("#f-save");
  if (saveBtn) saveBtn.onclick = () => {
    const name = prompt("Filter name:");
    if (name) api("/api/filters", { method: "POST", body: { name, params: state.filters } }).then(() => { toast("Filter saved", "success"); renderFindings(); });
  };
  $$("[data-select]").forEach((cb) => cb.onchange = () => {
    cb.checked ? state.selection.add(cb.dataset.select) : state.selection.delete(cb.dataset.select);
    renderBulkbar();
  });
  $$("[data-pin]").forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    const row = rows.find((r) => r.id === b.dataset.pin);
    await api(`/api/findings/${row.id}/pin`, { method: "POST", body: { pinned: !row.pinned } });
    renderFindings();
  });
  renderBulkbar();
}

function renderBulkbar() {
  const slot = $("#bulkbar-slot");
  if (!slot) return;
  if (!canWrite() || state.selection.size === 0) { slot.innerHTML = ""; return; }
  slot.innerHTML = `<div class="bulkbar"><span>${state.selection.size} selected</span>
    <select id="bulk-status"><option value="">Set status…</option>${["open", "triaged", "false_positive", "remediated"].map((s) => `<option>${s}</option>`).join("")}</select>
    <button class="btn btn-sm" id="bulk-apply">Apply</button>
    <button class="btn btn-sm" id="bulk-allow">Allowlist</button>
    <input id="bulk-assign" placeholder="Assignee"><button class="btn btn-sm" id="bulk-assign-btn">Assign</button>
    <input id="bulk-tag" placeholder="Tag"><button class="btn btn-sm" id="bulk-tag-btn">Tag</button>
    <button class="btn btn-ghost btn-sm" id="bulk-clear">Clear</button></div>`;
  const ids = [...state.selection];
  const run = (action, value) => api("/api/bulk", { method: "POST", body: { ids, action, value } })
    .then(() => { state.selection.clear(); toast(`Bulk ${action} applied to ${ids.length}`, "success"); renderFindings(); });
  $("#bulk-apply").onclick = () => { const v = $("#bulk-status").value; if (v) run("status", v); };
  $("#bulk-allow").onclick = () => confirmDialog("Allowlist selected", "Mark selected findings as false positives and register their fingerprints.", () => run("allowlist", "bulk"));
  $("#bulk-assign-btn").onclick = () => run("assign", $("#bulk-assign").value.trim());
  $("#bulk-tag-btn").onclick = () => run("tag", $("#bulk-tag").value.trim());
  $("#bulk-clear").onclick = () => { state.selection.clear(); renderFindings(); };
}

async function openDrawer(id) {
  state.drawerId = id;
  const root = $("#drawer-root");
  root.innerHTML = `<div class="drawer-overlay"><aside class="drawer" role="dialog" aria-modal="true">${skeleton()}</aside></div>`;
  $(".drawer-overlay", root).onclick = (e) => { if (e.target === e.currentTarget) closeDrawer(); };
  await loadDrawer();
}
function closeDrawer() { state.drawerId = null; $("#drawer-root").innerHTML = ""; }

async function loadDrawer() {
  const id = state.drawerId;
  if (!id) return;
  const d = await api(`/api/findings/${id}`);
  const f = d.finding, ex = d.extra;
  const tabs = ["details", "notes", "history", "checklist"];
  const body = state.drawerTab === "details" ? `
    <div class="drawer-section"><div class="meta-grid">
      <span class="muted">Detector</span><span class="mono-block">${esc(f.detector_id)}</span>
      <span class="muted">Location</span><span class="mono-block">${esc(f.path)}:${f.line}</span>
      <span class="muted">Secret (masked)</span><span class="mono-block">${esc(f.secret_masked)}</span>
      <span class="muted">Entropy</span><span>${f.entropy} bits/char</span>
      <span class="muted">Occurrences</span><span>${ex.occurrences} · first ${esc(absTime(ex.first_seen))}</span>
      <span class="muted">Fingerprint</span><span class="mono-block truncate">${esc(f.fingerprint)}</span>
    </div>
    <div class="section-label">How did that get there?</div>
    <div class="meta-grid">
      <span class="muted">Surface</span><span>${esc(SURFACE_LABEL[f.surface] || f.surface)}</span>
      <span class="muted">Responsible</span><span>${esc(f.owner || ex.assignee || "unknown")}</span>
      <span class="muted">First seen</span><span>${esc(absTime(ex.first_seen || f.created_at))}</span>
      ${Object.entries(f.meta.origin || {}).map(([k, v]) => `<span class="muted">${esc(k)}</span><span class="mono-block">${esc(String(v))}</span>`).join("")}
    </div>
    ${canWrite() ? `<div class="btn-row"><button class="btn btn-sm" id="d-allow">Add to allowlist</button>
      <button class="btn btn-sm" id="d-mute">${ex.muted ? "Unmute" : "Mute alerts"}</button></div>
    <div class="form-row"><label>Assignee</label><input id="d-assign" value="${esc(ex.assignee)}"><button class="btn btn-sm" id="d-assign-btn">Set</button></div>
    <div class="form-row"><label>Tags</label><input id="d-tags" value="${esc(ex.tags.join(", "))}"><button class="btn btn-sm" id="d-tags-btn">Set</button></div>
    <div class="form-row"><label>Severity override</label><select id="d-sev"><option value="">none</option>${SEVS.map((s) => `<option ${ex.severity_override === s ? "selected" : ""}>${s}</option>`).join("")}</select><button class="btn btn-sm" id="d-sev-btn">Set</button></div>` : ""}
    </div>
    <div class="drawer-section"><div class="section-label">Status</div>
      <div class="btn-row">${["open", "triaged", "false_positive", "remediated"].map((s) => `<button class="btn btn-sm status-btn ${f.status === s ? "btn-primary" : ""}" data-status="${s}" ${!canWrite() ? "disabled" : ""}>${s.replace("_", " ")}</button>`).join("")}</div></div>
    <div class="drawer-section"><div class="section-label">Assisted triage</div>
      ${d.triage ? `<div class="triage-box"><div class="triage-head"><span class="triage-verdict">${esc(d.triage.verdict.replace(/_/g, " "))}</span><span class="muted">${Math.round(d.triage.confidence * 100)}% · ${esc(d.triage.source)}</span></div>
        <ul class="triage-reasons">${d.triage.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
        <div class="triage-reco">${esc(d.triage.recommendation)}</div></div>` : '<p class="muted">No assessment yet.</p>'}
      ${canWrite() ? '<button class="btn btn-sm" id="d-triage">Run triage</button>' : ""}</div>
    <div class="drawer-section"><div class="section-label">Remediation</div>
      <div class="action-grid">${canWrite() ? ["rotate-guide", "preview-redact", "redact", "quarantine", "restore", "ticket", "verify"].map((a) => `<button class="btn btn-sm" data-rem="${a}">${a.replace(/-/g, " ")}</button>`).join("") : '<p class="muted">Read-only role.</p>'}</div>
      <div id="d-rem-out"></div></div>
    ${d.remediations.length ? `<div class="drawer-section"><div class="section-label">Remediation log</div><div class="timeline">${d.remediations.map((r) => `<div class="feed-item"><div class="feed-top"><span>${esc(r.action)}</span><span class="feed-ts">${esc(absTime(r.ts))}</span></div><div class="feed-msg">${esc(r.detail)}</div></div>`).join("")}</div></div>` : ""}
  ` : state.drawerTab === "notes" ? `
    <div class="drawer-section">${d.notes.map((n) => `<div class="note-item"><div class="note-head"><strong>${esc(n.username)}</strong><span class="feed-ts">${esc(absTime(n.ts))}</span></div><div class="note-body">${esc(n.body)}</div></div>`).join("") || '<p class="muted">No notes yet.</p>'}
    ${canWrite() ? `<div class="form-row"><textarea id="d-note" rows="3" placeholder="Add a note"></textarea><button class="btn btn-sm" id="d-note-btn">Add note</button></div>` : ""}</div>
  ` : state.drawerTab === "history" ? `
    <div class="drawer-section"><div class="timeline">${d.history.map((h) => `<div class="feed-item"><div class="feed-top"><span>${esc(h.old)} → ${esc(h.new)}</span><span class="feed-ts">${esc(absTime(h.ts))}</span></div><div class="feed-msg">by ${esc(h.username)}</div></div>`).join("") || '<p class="muted">No status changes yet.</p>'}</div></div>
  ` : `
    <div class="drawer-section">${CHECKLIST_STEPS.map((s, i) => `<label class="check-step"><input type="checkbox" data-step="${i}" ${d.checklist[i] && d.checklist[i].done ? "checked" : ""} ${!canWrite() ? "disabled" : ""}> ${esc(s)}</label>`).join("")}</div>
  `;
  $(".drawer", $("#drawer-root")).innerHTML = `
    <div class="drawer-head"><div class="drawer-title-row"><div class="drawer-title">${esc(f.title)}</div>
      <button class="icon-btn" id="d-close" aria-label="Close">×</button></div>
      <div class="drawer-id">${sevBadge(f.severity)} <span class="chip">${esc(f.status.replace("_", " "))}</span> <span class="muted">${esc(SURFACE_LABEL[f.surface] || f.surface)}</span> <span class="mono-block muted">${esc(f.id)}</span></div>
      <div class="drawer-tabs">${tabs.map((t) => `<button class="drawer-tab ${state.drawerTab === t ? "active" : ""}" data-tab="${t}">${t}</button>`).join("")}</div></div>
    <div class="drawer-body">${body}</div>`;
  $("#d-close").onclick = closeDrawer;
  $$(".drawer-tab").forEach((t) => t.onclick = () => { state.drawerTab = t.dataset.tab; loadDrawer(); });
  $$("[data-status]").forEach((b) => b.onclick = async () => {
    await api(`/api/findings/${id}/status`, { method: "POST", body: { status: b.dataset.status } });
    toast("Status updated", "success"); loadDrawer(); refreshView();
  });
  const on = (sel, fn) => { const el = $(sel); if (el) el.onclick = fn; };
  on("#d-triage", async () => { await api("/api/triage", { method: "POST", body: { id } }); loadDrawer(); });
  on("#d-allow", () => confirmDialog("Allowlist fingerprint", "Register this fingerprint as a false positive across all surfaces.", async () => {
    await api("/api/allowlist", { method: "POST", body: { fingerprint: f.fingerprint, reason: "drawer" } });
    toast("Allowlisted", "success"); loadDrawer(); refreshView();
  }));
  on("#d-mute", async () => { await api(`/api/findings/${id}/mute`, { method: "POST", body: { muted: !ex.muted } }); loadDrawer(); });
  on("#d-assign-btn", async () => { await api(`/api/findings/${id}/assign`, { method: "POST", body: { assignee: $("#d-assign").value.trim() } }); toast("Assignee set", "success"); loadDrawer(); });
  on("#d-tags-btn", async () => { await api(`/api/findings/${id}/tags`, { method: "POST", body: { tags: $("#d-tags").value.split(",").map((t) => t.trim()).filter(Boolean) } }); toast("Tags set", "success"); loadDrawer(); });
  on("#d-sev-btn", async () => { await api(`/api/findings/${id}/severity`, { method: "POST", body: { severity: $("#d-sev").value } }); loadDrawer(); refreshView(); });
  on("#d-note-btn", async () => { await api(`/api/findings/${id}/notes`, { method: "POST", body: { body: $("#d-note").value } }); loadDrawer(); });
  $$("[data-step]").forEach((cb) => cb.onchange = () => api(`/api/findings/${id}/checklist`, { method: "POST", body: { idx: +cb.dataset.step, done: cb.checked } }));
  $$("[data-rem]").forEach((b) => b.onclick = () => {
    const action = b.dataset.rem;
    const exec = async () => {
      const res = await api("/api/remediate", { method: "POST", body: { id, action } });
      $("#d-rem-out").innerHTML = `<div class="mono-block">${esc(res.detail)}</div>`;
      toast(`${action}: done`, "success"); loadDrawer(); refreshView();
    };
    if (["redact", "quarantine"].includes(action)) confirmDialog(`${action} finding`, "This modifies or moves the source file. The credential must still be rotated.", exec, action);
    else exec();
  });
}

async function renderPlayground() {
  $("#view").innerHTML = viewHead("Playground", "Test the detectors against pasted text. Results are masked and never stored.") + `
    <div class="play-grid"><div class="panel"><div class="panel-head"><h2>Text to scan</h2>${helpBtn("playground")}</div>
      <textarea id="pg-text" rows="8" placeholder='AWS_KEY = "AKIA..."'></textarea>
      <div class="form-row"><label>Path label</label><input id="pg-path" value="playground.txt"></div>
      <div class="btn-row"><button class="btn btn-primary" id="pg-scan">Scan text</button></div></div>
      <div class="panel"><div class="panel-head"><h2>Results</h2></div><div id="pg-results"><p class="muted">Run a scan to see detections.</p></div></div></div>`;
  $("#pg-scan").onclick = async () => {
    const res = await api("/api/scan", { method: "POST", body: { text: $("#pg-text").value, path: $("#pg-path").value || "playground.txt" } });
    $("#pg-results").innerHTML = res.findings.length ? res.findings.map((f) => `
      <div class="result-card"><div class="f-card-top">${sevBadge(f.severity)}<span class="muted">${esc(f.detector_id)}</span></div>
        <div class="f-card-title">${esc(f.title)}</div>
        <div class="f-card-meta"><span class="mono-block">${esc(f.path)}:${f.line}</span><span class="mono-block">${esc(f.secret_masked)}</span><span>${f.entropy} bits/char</span></div></div>`).join("")
      : '<div class="empty"><div class="empty-title">No secrets detected</div><div class="empty-sub">The text did not match any detector.</div></div>';
  };
}

async function renderJobs() {
  $("#view").innerHTML = viewHead("Jobs", "Background scans with an incremental cache, plus scheduled runs.") + skeleton();
  const [jobs, scheds] = await Promise.all([api("/api/jobs"), api("/api/schedules")]);
  $("#view").innerHTML = viewHead("Jobs", "Background scans with an incremental cache, plus scheduled runs.") + `
    ${canWrite() ? `<div class="panel"><div class="panel-head"><h2>New scan job</h2>${helpBtn("jobs")}</div>
      <div class="inline-form"><input id="job-path" placeholder="Path on server host (e.g. examples/vulnerable)"><select id="job-surface">${SURFACES.map((s) => `<option>${s}</option>`).join("")}</select><button class="btn btn-primary" id="job-run">Run job</button></div></div>` : ""}
    <div class="panel"><div class="panel-head"><h2>Recent jobs</h2></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>Job</th><th>Path</th><th>Status</th><th>Files</th><th>New</th><th>By</th><th>Started</th><th></th></tr></thead>
      <tbody>${jobs.jobs.map((j) => `<tr><td class="mono-block">${esc(j.id)}</td><td class="truncate">${esc(j.path)}</td><td><span class="chip">${esc(j.status)}</span></td><td>${j.files}</td><td>${j.findings}</td><td>${esc(j.triggered_by)}</td><td class="nowrap">${relTime(j.started)}</td><td>${canWrite() && ["queued", "running"].includes(j.status) ? `<button class="btn btn-ghost btn-sm" data-cancel="${esc(j.id)}">Cancel</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="8" class="muted">No jobs yet.</td></tr>'}</tbody></table></div></div>
    <div class="panel"><div class="panel-head"><h2>Schedules</h2></div>
      ${canWrite() ? `<div class="inline-form"><input id="sch-path" placeholder="Path"><input id="sch-interval" type="number" value="3600" min="60" aria-label="Interval seconds"><button class="btn" id="sch-add">Add schedule</button></div>` : ""}
      <div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Path</th><th>Every</th><th>Enabled</th><th></th></tr></thead>
      <tbody>${scheds.schedules.map((s) => `<tr><td class="mono-block">${esc(s.id)}</td><td class="truncate">${esc(s.path)}</td><td>${s.interval_seconds}s</td><td>${s.enabled ? "yes" : "no"}</td><td>${canWrite() ? `<button class="btn btn-ghost btn-sm" data-schtoggle="${esc(s.id)}">${s.enabled ? "Disable" : "Enable"}</button> <button class="btn btn-ghost btn-sm" data-schdel="${esc(s.id)}">Delete</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No schedules.</td></tr>'}</tbody></table></div></div>`;
  const run = $("#job-run");
  if (run) run.onclick = async () => {
    const res = await api("/api/jobs", { method: "POST", body: { path: $("#job-path").value || ".", surface: $("#job-surface").value } });
    toast(`Job ${res.id} queued`, "success"); setTimeout(renderJobs, 700);
  };
  const add = $("#sch-add");
  if (add) add.onclick = async () => {
    await api("/api/schedules", { method: "POST", body: { path: $("#sch-path").value || ".", interval_seconds: +$("#sch-interval").value || 3600 } });
    toast("Schedule added", "success"); renderJobs();
  };
  $$("[data-cancel]").forEach((b) => b.onclick = async () => { await api(`/api/jobs/${b.dataset.cancel}/cancel`, { method: "POST", body: {} }); renderJobs(); });
  $$("[data-schtoggle]").forEach((b) => b.onclick = async () => { await api(`/api/schedules/${b.dataset.schtoggle}/toggle`, { method: "POST", body: {} }); renderJobs(); });
  $$("[data-schdel]").forEach((b) => b.onclick = () => confirmDialog("Delete schedule", "The scheduled scan will stop running.", async () => { await api(`/api/schedules/${b.dataset.schdel}/delete`, { method: "POST", body: {} }); renderJobs(); }));
}

async function renderActivity() {
  const [events, alerts] = await Promise.all([api("/api/events?limit=30"), api("/api/alerts?limit=30")]);
  $("#view").innerHTML = viewHead("Activity", "Pipeline events and delivered alerts, refreshed every 5 seconds.") + `
    <div class="btn-row"><button class="btn btn-ghost btn-sm" id="act-pause">${state.paused ? "Resume" : "Pause"}</button></div>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Events</h2>${helpBtn("activity")}</div><div class="feed">${events.events.map((e) => `<div class="feed-item"><div class="feed-top"><span class="chip">${esc(e.kind)}</span><span class="muted">${esc(e.surface)}</span><span class="feed-ts" title="${esc(absTime(e.ts))}">${relTime(e.ts)}</span></div><div class="feed-payload mono-block">${esc(JSON.stringify(e.payload))}</div></div>`).join("") || '<p class="muted">No events.</p>'}</div></div>
      <div class="panel"><div class="panel-head"><h2>Alerts</h2></div><div class="feed">${alerts.alerts.map((a) => `<div class="feed-item"><div class="feed-top"><span class="chip">${esc(a.channel)}</span><span class="muted">${esc(a.status)}</span><span class="feed-ts">${relTime(a.ts)}</span></div><div class="feed-msg">${esc(a.message)}</div>${canWrite() && !a.ack ? `<button class="btn btn-ghost btn-sm" data-ack="${esc(a.id)}">Acknowledge</button>` : a.ack ? `<span class="muted small">ack by ${esc(a.ack.username)}</span>` : ""}</div>`).join("") || '<p class="muted">No alerts.</p>'}</div></div>
    </div>`;
  $("#act-pause").onclick = () => { state.paused = !state.paused; renderActivity(); };
  $$("[data-ack]").forEach((b) => b.onclick = async () => { await api(`/api/alerts/${b.dataset.ack}/ack`, { method: "POST", body: {} }); renderActivity(); });
}

async function renderLogs() {
  const [logs, audit] = await Promise.all([
    api(`/api/logs?limit=150${state.logLevel ? `&level=${state.logLevel}` : ""}`), api("/api/audit?limit=100")]);
  $("#view").innerHTML = viewHead("Logs", "Live system journal and audit trail - every pipeline stage writes here.") + `
    <div class="toolbar"><select id="log-level" aria-label="Level">${["", "info", "warn", "error"].map((l) => `<option value="${l}" ${state.logLevel === l ? "selected" : ""}>${l || "All levels"}</option>`).join("")}</select>
      <button class="btn btn-ghost btn-sm" id="log-pause">${state.paused ? "Resume" : "Pause"}</button>${helpBtn("logs")}</div>
    <div class="tabs"><button class="tab ${state.logTab !== "audit" ? "active" : ""}" data-logtab="system">System log</button><button class="tab ${state.logTab === "audit" ? "active" : ""}" data-logtab="audit">Audit</button></div>
    ${state.logTab !== "audit" ? `<div class="log-stream panel">${logs.logs.map((l) => `<div class="log-line"><span class="log-ts">${esc(absTime(l.ts))}</span><span class="log-level ${esc(l.level)}">${esc(l.level)}</span><span class="log-src">${esc(l.source)}</span><span class="log-msg">${esc(l.message)}</span></div>`).join("") || '<p class="muted">No log entries.</p>'}</div>`
      : `<div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr></thead><tbody>${audit.audit.map((a) => `<tr><td class="nowrap">${esc(absTime(a.ts))}</td><td>${esc(a.username)}</td><td class="mono-block">${esc(a.action)}</td><td class="truncate">${esc(a.detail)}</td></tr>`).join("")}</tbody></table></div>`}`;
  $("#log-level").onchange = (e) => { state.logLevel = e.target.value; renderLogs(); };
  $("#log-pause").onclick = () => { state.paused = !state.paused; renderLogs(); };
  $$("[data-logtab]").forEach((t) => t.onclick = () => { state.logTab = t.dataset.logtab; renderLogs(); });
}

async function renderAllowlist() {
  const entries = await api("/api/allowlist");
  $("#view").innerHTML = viewHead("Allowlist", "False-positive registry keyed by secret fingerprint.") + `
    ${canWrite() ? `<div class="panel"><div class="inline-form"><input id="al-fp" placeholder="Fingerprint (SHA-256)"><input id="al-reason" placeholder="Reason"><button class="btn" id="al-add">Add entry</button></div></div>` : ""}
    <div class="table-wrap"><table class="table"><thead><tr><th>Fingerprint</th><th>Reason</th><th>Added</th></tr></thead>
    <tbody>${entries.entries.map((e) => `<tr><td class="mono-block truncate">${esc(e.fingerprint)}</td><td>${esc(e.reason)}</td><td class="nowrap">${esc(absTime(e.created_at))}</td></tr>`).join("") || '<tr><td colspan="3" class="muted">No entries. Built-in placeholders are always allowed.</td></tr>'}</tbody></table></div>`;
  const add = $("#al-add");
  if (add) add.onclick = async () => {
    await api("/api/allowlist", { method: "POST", body: { fingerprint: $("#al-fp").value.trim(), reason: $("#al-reason").value.trim() } });
    toast("Entry added", "success"); renderAllowlist();
  };
}

async function renderSettings() {
  const sections = ["profile", "users", "tokens", "detectors", "rules", "data"];
  const labels = { profile: "Profile", users: "Users", tokens: "API tokens", detectors: "Detectors", rules: "Alert rules", data: "Data" };
  $("#view").innerHTML = viewHead("Settings", "Administration, tuning and data operations.") + `
    <div class="settings-layout"><nav class="settings-nav">${sections.map((s) => `<button class="btn btn-ghost ${state.settingsSection === s ? "btn-primary" : ""}" data-sec="${s}">${labels[s]}</button>`).join("")}</nav>
    <div id="settings-body">${skeleton()}</div></div>`;
  $$("[data-sec]").forEach((b) => b.onclick = () => { state.settingsSection = b.dataset.sec; renderSettings(); });
  await renderSettingsSection();
}

async function renderSettingsSection() {
  const slot = $("#settings-body");
  const sec = state.settingsSection;
  const head = (title) => `<div class="settings-section-head"><h2>${title}</h2>${helpBtn("settings-" + sec)}</div><p class="settings-desc">${esc(HELP["settings-" + sec] || "")}</p>`;
  const admin = state.user.role === "admin";
  if (sec === "profile") {
    slot.innerHTML = head("Profile") + `<div class="panel"><div class="meta-grid"><span class="muted">Username</span><span>${esc(state.user.username)}</span><span class="muted">Role</span><span>${esc(state.user.role)}</span></div>
      <div class="form-grid"><label>Current password</label><input id="pw-old" type="password"><label>New password (10+ chars)</label><input id="pw-new" type="password"><button class="btn" id="pw-save">Change password</button></div></div>`;
    $("#pw-save").onclick = async () => {
      try { await api("/api/auth/password", { method: "POST", body: { old: $("#pw-old").value, new: $("#pw-new").value } }); toast("Password changed", "success"); }
      catch (e) { toast(e.message, "error"); }
    };
  } else if (sec === "users") {
    if (!admin) { slot.innerHTML = head("Users") + '<p class="muted">Admin role required.</p>'; return; }
    const users = await api("/api/users");
    slot.innerHTML = head("Users") + `<div class="panel"><div class="inline-form"><input id="u-name" placeholder="Username"><input id="u-pw" type="password" placeholder="Password (10+)"><select id="u-role">${["viewer", "analyst", "admin"].map((r) => `<option>${r}</option>`).join("")}</select><button class="btn" id="u-add">Add user</button></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>User</th><th>Title</th><th>Role</th><th>Disabled</th><th></th></tr></thead><tbody>${users.users.map((u) => `<tr><td>${esc(u.username)}</td><td>${esc(u.title || "-")}</td><td><select data-urole="${esc(u.username)}">${["admin", "analyst", "viewer"].map((r) => `<option ${u.role === r ? "selected" : ""}>${r}</option>`).join("")}</select></td><td>${u.disabled ? "yes" : "no"}</td><td><button class="btn btn-ghost btn-sm" data-udis="${esc(u.username)}" data-dis="${u.disabled ? 0 : 1}">${u.disabled ? "Enable" : "Disable"}</button></td></tr>`).join("")}</tbody></table></div></div>`;
    $("#u-add").onclick = async () => { await api("/api/users", { method: "POST", body: { username: $("#u-name").value, password: $("#u-pw").value, role: $("#u-role").value } }); toast("User added", "success"); renderSettingsSection(); };
    $$("[data-urole]").forEach((s) => s.onchange = () => api(`/api/users/${s.dataset.urole}/role`, { method: "POST", body: { role: s.value } }));
    $$("[data-udis]").forEach((b) => b.onclick = async () => { await api(`/api/users/${b.dataset.udis}/disable`, { method: "POST", body: { disabled: b.dataset.dis === "1" } }); renderSettingsSection(); });
  } else if (sec === "tokens") {
    if (!admin) { slot.innerHTML = head("API tokens") + '<p class="muted">Admin role required.</p>'; return; }
    const tokens = await api("/api/tokens");
    slot.innerHTML = head("API tokens") + `<div class="panel"><div class="inline-form"><input id="t-name" placeholder="Token name (e.g. ci)"><select id="t-role">${["analyst", "viewer", "admin"].map((r) => `<option>${r}</option>`).join("")}</select><button class="btn" id="t-create">Create token</button></div><div id="t-reveal"></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Name</th><th>Role</th><th>Revoked</th><th></th></tr></thead><tbody>${tokens.tokens.map((t) => `<tr><td class="mono-block">${esc(t.id)}</td><td>${esc(t.name)}</td><td>${esc(t.role)}</td><td>${t.revoked ? "yes" : "no"}</td><td>${!t.revoked ? `<button class="btn btn-ghost btn-sm" data-trev="${esc(t.id)}">Revoke</button>` : ""}</td></tr>`).join("")}</tbody></table></div></div>`;
    $("#t-create").onclick = async () => {
      const res = await api("/api/tokens", { method: "POST", body: { name: $("#t-name").value || "ci", role: $("#t-role").value } });
      $("#t-reveal").innerHTML = `<div class="token-reveal mono-block">${esc(res.token)}</div><p class="token-warn">Copy now - this token is shown only once.</p>`;
    };
    $$("[data-trev]").forEach((b) => b.onclick = async () => { await api(`/api/tokens/${b.dataset.trev}/revoke`, { method: "POST", body: {} }); renderSettingsSection(); });
  } else if (sec === "detectors") {
    const dets = await api("/api/detectors");
    slot.innerHTML = head("Detectors") + `<div class="panel"><div class="table-wrap"><table class="table"><thead><tr><th>Enabled</th><th>ID</th><th>Title</th><th>Family</th><th>Severity</th></tr></thead><tbody>${dets.detectors.map((d) => `<tr><td><input type="checkbox" data-det="${esc(d.id)}" ${d.enabled ? "checked" : ""} ${!canWrite() ? "disabled" : ""}></td><td class="mono-block">${esc(d.id)}</td><td>${esc(d.title)}</td><td>${esc(d.family)}</td><td><select data-detsev="${esc(d.id)}" ${!canWrite() ? "disabled" : ""}>${SEVS.map((s) => `<option ${d.severity === s ? "selected" : ""}>${s}</option>`).join("")}</select></td></tr>`).join("")}</tbody></table></div>
      ${canWrite() ? '<div class="btn-row"><button class="btn" id="det-apply">Apply tuning</button></div>' : ""}</div>`;
    const apply = $("#det-apply");
    if (apply) apply.onclick = async () => {
      const disabled = $$("[data-det]").filter((c) => !c.checked).map((c) => c.dataset.det);
      const overrides = {};
      $$("[data-detsev]").forEach((s) => { overrides[s.dataset.detsev] = s.value; });
      await api("/api/detectors/tuning", { method: "POST", body: { disabled, severity_overrides: overrides } });
      toast("Detector tuning applied", "success");
    };
  } else if (sec === "rules") {
    const rules = await api("/api/rules");
    slot.innerHTML = head("Alert rules") + `<div class="panel">${canWrite() ? `<div class="inline-form"><select id="r-channel">${["console", "outbox", "slack", "webhook"].map((c) => `<option>${c}</option>`).join("")}</select><select id="r-sev">${SEVS.map((s) => `<option>${s}</option>`).join("")}</select><button class="btn" id="r-add">Add rule</button></div>` : ""}
      <div class="table-wrap"><table class="table"><thead><tr><th>Channel</th><th>Min severity</th><th>Enabled</th><th></th></tr></thead><tbody>${rules.rules.map((r) => `<tr><td>${esc(r.channel)}</td><td>${esc(r.min_severity)}</td><td>${r.enabled ? "yes" : "no"}</td><td>${canWrite() ? `<button class="btn btn-ghost btn-sm" data-rtoggle="${esc(r.id)}">${r.enabled ? "Disable" : "Enable"}</button> <button class="btn btn-ghost btn-sm" data-rdel="${esc(r.id)}">Delete</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="4" class="muted">No rules - channels receive everything.</td></tr>'}</tbody></table></div></div>`;
    const add = $("#r-add");
    if (add) add.onclick = async () => { await api("/api/rules", { method: "POST", body: { channel: $("#r-channel").value, min_severity: $("#r-sev").value } }); renderSettingsSection(); };
    $$("[data-rtoggle]").forEach((b) => b.onclick = async () => { await api(`/api/rules/${b.dataset.rtoggle}/toggle`, { method: "POST", body: {} }); renderSettingsSection(); });
    $$("[data-rdel]").forEach((b) => b.onclick = async () => { await api(`/api/rules/${b.dataset.rdel}/delete`, { method: "POST", body: {} }); renderSettingsSection(); });
  } else {
    const ops = await api("/api/ops/stats");
    slot.innerHTML = head("Data") + `<div class="panel"><div class="ops-line muted">Database ${(ops.db_bytes / 1024).toFixed(1)} KiB · ${ops.jobs} jobs · ${ops.schedules} schedules · ${ops.users} users</div>
      <div class="btn-row"><a class="btn" href="/api/export?format=csv">Export CSV</a><a class="btn" href="/api/export?format=json">Export JSON</a>
      ${admin ? `<button class="btn" id="ops-backup">Backup</button><button class="btn" id="ops-vacuum">Vacuum</button>` : ""}</div>
      ${admin ? `<div class="inline-form"><input id="ops-days" type="number" value="90" min="1" aria-label="Retention days"><button class="btn btn-danger" id="ops-purge">Purge closed findings older than</button></div>` : ""}</div>`;
    const backup = $("#ops-backup");
    if (backup) backup.onclick = async () => { const r = await api("/api/ops/backup", { method: "POST", body: {} }); toast(`Backup: ${r.path}`, "success"); };
    const vacuum = $("#ops-vacuum");
    if (vacuum) vacuum.onclick = async () => { await api("/api/ops/vacuum", { method: "POST", body: {} }); toast("Vacuum done", "success"); };
    const purge = $("#ops-purge");
    if (purge) purge.onclick = () => confirmDialog("Purge closed findings", "Removes remediated and false-positive findings older than the given days, plus old log lines.", async () => {
      const r = await api("/api/ops/purge", { method: "POST", body: { days: +$("#ops-days").value || 90 } });
      toast(`Purged ${r.removed} findings`, "success");
    }, "Purge");
  }
}

/* ---------- shell ---------- */

const VIEWS = { overview: renderOverview, findings: renderFindings, playground: renderPlayground, jobs: renderJobs, activity: renderActivity, logs: renderLogs, allowlist: renderAllowlist, settings: renderSettings };

function refreshView() { if (VIEWS[state.view]) VIEWS[state.view](); }

function route() {
  const hash = location.hash.replace("#/", "") || "overview";
  state.view = VIEWS[hash] ? hash : "overview";
  state.selection.clear();
  $$("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === state.view));
  $("#view").setAttribute("aria-busy", "true");
  VIEWS[state.view]().finally(() => $("#view").setAttribute("aria-busy", "false"));
}

function openPalette() {
  const items = [
    ...Object.keys(VIEWS).map((v) => ({ label: `Go to ${v}`, run: () => { location.hash = "#/" + v; } })),
    { label: "Load demo data", run: async () => { await api("/api/demo", { method: "POST", body: {} }); toast("Demo data loaded", "success"); refreshView(); } },
    { label: "Export CSV", run: () => { location.href = "/api/export?format=csv"; } },
    { label: "Sign out", run: async () => { await api("/api/auth/logout", { method: "POST", body: {} }); location.href = "/login"; } },
  ];
  const root = $("#palette-root");
  root.innerHTML = `<div class="palette-overlay"><div class="palette" role="dialog" aria-modal="true">
    <input id="pal-q" placeholder="Type a command or view" aria-label="Command palette">
    <div class="palette-list" id="pal-list"></div><div class="palette-foot">Enter to run · Esc to close</div></div></div>`;
  const input = $("#pal-q");
  const draw = () => {
    const q = input.value.toLowerCase();
    const match = items.filter((i) => i.label.toLowerCase().includes(q));
    $("#pal-list").innerHTML = match.map((i, n) => `<button class="palette-item" data-pal="${n}">${esc(i.label)}</button>`).join("") || '<div class="palette-empty">No match</div>';
    $$(".palette-item").forEach((b) => b.onclick = () => { root.innerHTML = ""; match[+b.dataset.pal].run(); });
  };
  input.oninput = draw;
  input.onkeydown = (e) => { if (e.key === "Enter") { const first = $(".palette-item"); if (first) first.click(); } };
  $(".palette-overlay", root).onclick = (e) => { if (e.target === e.currentTarget) root.innerHTML = ""; };
  draw();
  input.focus();
}

async function boot() {
  try {
    const me = await api("/api/auth/me");
    state.user = me.user;
  } catch { return; }
  $("#user-name").textContent = state.user.username;
  $("#user-role").textContent = state.user.role;
  $("#user-initial").textContent = state.user.username[0].toUpperCase();
  $("#menu-user").textContent = state.user.username;
  $("#menu-role").textContent = state.user.role + (state.user.title ? " · " + state.user.title : "");
  $("#theme-toggle").onclick = () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("wm.theme", next); } catch (e) {}
  };
  const health = await api("/api/health").catch(() => null);
  if (health) {
    $("#live-label").textContent = "Live";
    $("#live").classList.add("ok");
    $("#sidebar-version").textContent = `Wintermute ${health.version}`;
  }
  const menu = $("#usermenu");
  $("#usermenu-btn").onclick = () => { menu.hidden = !menu.hidden; };
  $("#menu-signout").onclick = async () => { await api("/api/auth/logout", { method: "POST", body: {} }); location.href = "/login"; };
  $("#menu-password").onclick = () => { menu.hidden = true; state.settingsSection = "profile"; location.hash = "#/settings"; };
  $("#palette-open").onclick = openPalette;
  document.addEventListener("click", (e) => {
    const help = e.target.closest("[data-help]");
    if (help) { showHelp(help.dataset.help, help); return; }
    const open = e.target.closest("[data-open]");
    if (open) { state.drawerTab = "details"; openDrawer(open.dataset.open); }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); $("#palette-root").innerHTML = ""; $("#popover-root").innerHTML = ""; $("#usermenu").hidden = true; return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); return; }
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "?") { showHelp(state.view, $("#view h1") || document.body); return; }
    if (e.key === "g") { state.gPending = true; setTimeout(() => { state.gPending = false; }, 900); return; }
    if (state.gPending) {
      const map = { o: "overview", f: "findings", p: "playground", j: "jobs", a: "activity", l: "logs", w: "allowlist", s: "settings" };
      if (map[e.key]) { location.hash = "#/" + map[e.key]; state.gPending = false; }
    }
  });
  window.addEventListener("hashchange", route);
  route();
  setInterval(async () => {
    const h = await api("/api/health").catch(() => null);
    $("#live-label").textContent = h ? "Live" : "Offline";
    $("#live").classList.toggle("ok", !!h);
  }, 10000);
  setInterval(() => {
    if (state.paused) return;
    if (state.view === "activity") renderActivity();
    if (state.view === "logs") renderLogs();
  }, 5000);
}

boot();