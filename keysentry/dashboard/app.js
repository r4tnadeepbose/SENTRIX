(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const SURFACES = {
    ide: "IDE", pre_push: "Pre-push", ci: "CI", git: "Git", cloud: "Cloud",
    slack: "Slack", confluence: "Confluence", jira: "Jira", postman: "Postman", filesystem: "Filesystem",
  };
  const STATUSES = { open: "Open", triaged: "Triaged", false_positive: "False positive", remediated: "Remediated" };
  const REMEDIATIONS = { redact: "Redact", quarantine: "Quarantine", ticket: "Create ticket", "rotate-guide": "Rotation guide" };
  const VERDICTS = {
    likely_true_positive: "Likely true positive",
    likely_false_positive: "Likely false positive",
    needs_review: "Needs review",
  };
  const VIEWS = ["overview", "findings", "playground", "activity", "allowlist", "settings"];
  const THEME_KEY = "keysentry.theme";

  const state = {
    view: "overview",
    stats: null,
    health: null,
    recent: [],
    findings: [],
    events: [],
    alerts: [],
    allowlist: [],
    filters: { severity: "", surface: "", status: "", q: "" },
    activityPaused: false,
    drawerId: null,
    drawerFinding: null,
    lastFocus: null,
  };

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function cap(value) {
    const s = String(value ?? "");
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function parseDate(iso) {
    if (!iso) return null;
    let s = String(iso).trim();
    // The backend emits UTC timestamps without a zone suffix; treat those as UTC.
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(s)) s = s.replace(" ", "T") + "Z";
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  function fmtTime(iso) {
    const d = parseDate(iso);
    if (!d) return iso ? String(iso) : "-";
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
  }

  function fmtUptime(seconds) {
    const sec = Math.max(0, Math.floor(Number(seconds) || 0));
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function fmtCount(n) {
    return (Number(n) || 0).toLocaleString("en-US");
  }

  async function api(path, opts = {}) {
    const headers = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
    if (!res.ok) {
      throw new Error(data.error || data.message || `Request failed (${res.status})`);
    }
    return data;
  }

  function toast(message, kind = "info") {
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.setAttribute("role", kind === "error" ? "alert" : "status");
    el.innerHTML = `<span class="toast-msg">${esc(message)}</span><button class="toast-close" type="button" aria-label="Dismiss notification">&times;</button>`;
    $("#toasts").appendChild(el);
    const remove = () => {
      el.classList.add("out");
      setTimeout(() => el.remove(), 200);
    };
    el.querySelector(".toast-close").addEventListener("click", remove);
    setTimeout(remove, 4500);
  }

  function emptyState(title, hint) {
    return `<div class="empty"><p class="empty-title">${esc(title)}</p><p class="empty-hint">${esc(hint)}</p></div>`;
  }

  function severityBadge(sev) {
    const s = SEVERITIES.includes(sev) ? sev : "info";
    return `<span class="badge sev-${s}">${esc(SEVERITY_LABELS[s])}</span>`;
  }

  function statusBadge(status) {
    const key = String(status ?? "");
    return `<span class="badge status-${esc(key)}">${esc(STATUSES[key] || cap(key) || "Unknown")}</span>`;
  }

  function surfaceLabel(surface) {
    return SURFACES[surface] || cap(surface) || "-";
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $$("[data-theme-toggle]").forEach((btn) => {
      btn.setAttribute("aria-checked", String(theme === "light"));
      btn.setAttribute("aria-label", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
    });
  }

  function initTheme() {
    let theme = null;
    try { theme = localStorage.getItem(THEME_KEY); } catch { theme = null; }
    if (theme !== "light" && theme !== "dark") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    applyTheme(theme);
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem(THEME_KEY, next); } catch { /* storage unavailable; theme still applies for this page */ }
    applyTheme(next);
  }

  async function pollHealth() {
    const wrap = $("#status");
    const dot = $("#status-dot");
    const label = $("#status-label");
    try {
      const h = await api("/api/health");
      state.health = h;
      dot.className = "dot ok";
      label.textContent = "Live";
      const detail = `KeySentry ${h.version || ""} - up ${fmtUptime(h.uptime_seconds)}`.trim();
      wrap.title = detail;
      wrap.setAttribute("aria-label", `Server status: online. ${detail}`);
      if (state.view === "settings") renderHealth();
    } catch {
      state.health = null;
      dot.className = "dot err";
      label.textContent = "Offline";
      wrap.title = "Cannot reach the KeySentry server";
      wrap.setAttribute("aria-label", "Server status: offline");
      if (state.view === "settings") renderHealth();
    }
  }

  function statCard(label, value, sub, tone) {
    return `<div class="card stat-card${tone ? ` ${tone}` : ""}">
      <span class="stat-label">${esc(label)}</span>
      <span class="stat-value">${esc(fmtCount(value))}</span>
      <span class="stat-sub">${esc(sub)}</span>
    </div>`;
  }

  function renderBars(el, rows) {
    const max = Math.max(1, ...rows.map((r) => r.value));
    el.innerHTML = rows.map((r) => `<div class="bar-row">
      <span class="bar-label" title="${esc(r.label)}">${esc(r.label)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(r.value / max) * 100}%;background:${r.color}"></span></span>
      <span class="bar-value">${esc(fmtCount(r.value))}</span>
    </div>`).join("");
  }

  async function loadOverview() {
    try {
      const [stats, recent] = await Promise.all([api("/api/stats"), api("/api/findings?limit=5")]);
      state.stats = stats;
      state.recent = recent.findings || [];
      renderOverview();
    } catch (err) {
      toast(`Could not load overview: ${err.message}`, "error");
    }
  }

  function renderOverview() {
    const s = state.stats || {};
    const sev = s.by_severity || {};
    const surf = s.by_surface || {};
    const status = s.by_status || {};
    const critHigh = (sev.critical || 0) + (sev.high || 0);
    $("#stat-cards").innerHTML = [
      statCard("Total findings", s.total, "Across all detection layers"),
      statCard("Open", s.open, `${fmtCount(status.triaged)} triaged - ${fmtCount(status.remediated)} remediated`),
      statCard("Critical + high", critHigh, "Highest priority findings", critHigh > 0 ? "danger" : ""),
      statCard("Alerts sent", s.alerts_sent, `${fmtCount(s.events_processed)} events processed`),
    ].join("");
    $("#overview-meta").textContent =
      `${fmtCount(s.events_processed)} events processed - ${fmtCount(s.remediations)} remediations applied - ${fmtCount(status.false_positive)} false positives`;
    $("#demo-banner").hidden = (s.total || 0) > 0;
    renderBars($("#chart-severity"), SEVERITIES.map((k) => ({
      label: SEVERITY_LABELS[k], value: sev[k] || 0, color: `var(--sev-${k})`,
    })));
    renderBars($("#chart-surface"), Object.keys(SURFACES).map((k) => ({
      label: SURFACES[k], value: surf[k] || 0, color: "var(--accent)",
    })));
    renderRecent();
  }

  function renderRecent() {
    const el = $("#recent-findings");
    if (!state.recent.length) {
      el.innerHTML = emptyState("No findings yet", "Run a scan from the Playground or load demo data to see detections here.");
      return;
    }
    el.innerHTML = state.recent.map((f) => `<button class="recent-row" type="button" data-open="${esc(f.id)}">
      ${severityBadge(f.severity)}
      <span class="recent-title">
        <span class="recent-name">${esc(f.title)}</span>
        <span class="recent-sub">${esc(surfaceLabel(f.surface))} - ${esc(f.path || "-")}</span>
      </span>
      <time class="recent-time" datetime="${esc(f.created_at)}">${esc(fmtTime(f.created_at))}</time>
    </button>`).join("");
  }

  let findingsReq = 0;
  let searchTimer = null;

  async function loadFindings() {
    const seq = ++findingsReq;
    const params = new URLSearchParams();
    Object.entries(state.filters).forEach(([k, v]) => { if (v) params.set(k, v); });
    params.set("limit", "200");
    try {
      const data = await api(`/api/findings?${params.toString()}`);
      if (seq !== findingsReq) return;
      state.findings = data.findings || [];
      renderFindings();
    } catch (err) {
      if (seq !== findingsReq) return;
      toast(`Could not load findings: ${err.message}`, "error");
    }
  }

  function renderFindings() {
    const count = state.findings.length;
    $("#findings-count").textContent = `${fmtCount(count)} finding${count === 1 ? "" : "s"}`;
    $("#findings-wrap").hidden = count === 0;
    const emptyEl = $("#findings-empty");
    emptyEl.hidden = count > 0;
    if (!count) {
      emptyEl.innerHTML = emptyState("No findings match", "Adjust the filters, run a scan, or load demo data from the Overview.");
    }
    $("#findings-body").innerHTML = state.findings.map((f) => `<tr data-row="${esc(f.id)}" tabindex="0" aria-label="Open finding: ${esc(f.title)}">
      <td data-label="Severity">${severityBadge(f.severity)}</td>
      <td data-label="Title"><span class="cell-main"><button class="linklike cell-title" type="button">${esc(f.title)}</button><span class="cell-sub">${esc(f.detector_id || "-")}</span></span></td>
      <td data-label="Surface"><span>${esc(surfaceLabel(f.surface))}</span></td>
      <td data-label="Location"><code class="mono wrap">${esc(f.path || "-")}${f.line ? `:${esc(f.line)}` : ""}</code></td>
      <td data-label="Secret"><code class="mono wrap secret">${esc(f.secret_masked || "-")}</code></td>
      <td data-label="Status">${statusBadge(f.status)}</td>
      <td data-label="Created"><time datetime="${esc(f.created_at)}">${esc(fmtTime(f.created_at))}</time></td>
    </tr>`).join("");
  }

  function fillSelect(el, entries, allLabel) {
    el.innerHTML = `<option value="">${esc(allLabel)}</option>` +
      Object.entries(entries).map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
  }

  function triageHtml(t) {
    if (!t) return "";
    const verdict = VERDICTS[t.verdict] || cap(t.verdict);
    const confidence = Math.round((Number(t.confidence) || 0) * 100);
    const cls = t.verdict === "likely_true_positive" ? "sev-high"
      : t.verdict === "likely_false_positive" ? "sev-low" : "sev-medium";
    return `<div class="triage">
      <div class="triage-head">
        <span class="badge ${cls}">${esc(verdict)}</span>
        <span class="hint">${confidence}% confidence - ${esc(t.source || "heuristic")}</span>
      </div>
      ${Array.isArray(t.reasons) && t.reasons.length ? `<ul class="reasons">${t.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      ${t.recommendation ? `<p class="recommendation">${esc(t.recommendation)}</p>` : ""}
    </div>`;
  }

  async function openDrawer(id) {
    state.drawerId = id;
    state.drawerFinding = null;
    state.lastFocus = document.activeElement;
    $("#drawer-backdrop").classList.add("show");
    $("#drawer").classList.add("open");
    document.body.classList.add("no-scroll");
    $("#drawer-title").textContent = "Finding detail";
    $("#drawer-body").innerHTML = `<div class="drawer-loading">Loading finding...</div>`;
    $("#drawer-close").focus();
    await reloadDrawer();
  }

  async function reloadDrawer() {
    const id = state.drawerId;
    if (!id) return;
    try {
      const data = await api(`/api/findings/${encodeURIComponent(id)}`);
      if (state.drawerId !== id) return;
      renderDrawer(data.finding, data.remediations || [], data.triage || null);
    } catch (err) {
      if (state.drawerId !== id) return;
      $("#drawer-body").innerHTML = emptyState("Could not load this finding", err.message);
    }
  }

  function closeDrawer() {
    state.drawerId = null;
    state.drawerFinding = null;
    $("#drawer-backdrop").classList.remove("show");
    $("#drawer").classList.remove("open");
    document.body.classList.remove("no-scroll");
    if (state.lastFocus && typeof state.lastFocus.focus === "function") state.lastFocus.focus();
  }

  function renderDrawer(f, remediations, triage) {
    if (!f) {
      $("#drawer-body").innerHTML = emptyState("Finding unavailable", "It may have been removed.");
      return;
    }
    state.drawerFinding = f;
    $("#drawer-title").textContent = f.title || "Finding detail";
    const statusButtons = Object.entries(STATUSES).map(([key, label]) =>
      `<button class="btn small${key === f.status ? " current" : ""}" type="button" data-status="${key}"${key === f.status ? " disabled" : ""}>${esc(label)}</button>`
    ).join("");
    const remediationButtons = Object.entries(REMEDIATIONS).map(([action, label]) =>
      `<button class="btn small" type="button" data-remediate="${action}">${esc(label)}</button>`
    ).join("");
    const hasMeta = f.meta && typeof f.meta === "object" && Object.keys(f.meta).length > 0;
    $("#drawer-body").innerHTML = `
      <div class="drawer-badges">${severityBadge(f.severity)} ${statusBadge(f.status)} <span class="badge surface">${esc(surfaceLabel(f.surface))}</span></div>
      <dl class="detail-grid">
        <dt>Finding ID</dt><dd><code class="mono">${esc(f.id)}</code></dd>
        <dt>Detector</dt><dd><code class="mono">${esc(f.detector_id || "-")}</code></dd>
        <dt>Location</dt><dd><code class="mono wrap">${esc(f.path || "-")}${f.line ? `:${esc(f.line)}` : ""}</code></dd>
        <dt>Secret (masked)</dt><dd><code class="mono wrap">${esc(f.secret_masked || "-")}</code></dd>
        <dt>Entropy</dt><dd>${esc(Number(f.entropy || 0).toFixed(2))} bits/char</dd>
        <dt>Owner</dt><dd>${esc(f.owner || "Unassigned")}</dd>
        <dt>Created</dt><dd>${esc(fmtTime(f.created_at))}</dd>
        <dt>Updated</dt><dd>${esc(fmtTime(f.updated_at))}</dd>
        <dt>Fingerprint</dt>
        <dd>
          <div class="fp-row"><code class="mono wrap">${esc(f.fingerprint || "-")}</code><button class="btn small" type="button" id="btn-allowlist">Add to allowlist</button></div>
          <form id="allowlist-form" class="inline-form" hidden>
            <input type="text" id="allowlist-reason" placeholder="Reason for allowlisting" aria-label="Reason for allowlisting" autocomplete="off" required>
            <button class="btn small primary" type="submit">Confirm</button>
          </form>
        </dd>
      </dl>
      ${hasMeta ? `<h3>Metadata</h3><pre class="code-block small">${esc(JSON.stringify(f.meta, null, 2))}</pre>` : ""}
      <h3>Status</h3>
      <div class="btn-row">${statusButtons}</div>
      <h3>Triage</h3>
      <div id="triage-panel">
        ${triage ? triageHtml(triage) : `<p class="hint">No triage yet. Run an automated assessment for a verdict and recommendation.</p>`}
        <button class="btn small" type="button" id="btn-triage">${triage ? "Re-run triage" : "Run triage"}</button>
      </div>
      <h3>Remediation</h3>
      <div class="btn-row">${remediationButtons}</div>
      ${remediations.length ? `<h3>Remediation history</h3><ul class="history">${remediations.map((r) => `<li>
        <span class="badge surface">${esc(r.action)}</span>
        <span class="hist-detail">${esc(r.detail || "-")}</span>
        <time datetime="${esc(r.ts)}">${esc(fmtTime(r.ts))}</time>
      </li>`).join("")}</ul>` : ""}
    `;
  }

  async function afterMutation() {
    try {
      const [stats, recent] = await Promise.all([api("/api/stats"), api("/api/findings?limit=5")]);
      state.stats = stats;
      state.recent = recent.findings || [];
      if (state.view === "overview") renderOverview();
    } catch { /* keep previously rendered stats if the refresh fails */ }
    await loadFindings();
    if (state.drawerId) await reloadDrawer();
  }

  async function changeStatus(status, btn) {
    const id = state.drawerId;
    if (!id) return;
    if (btn) btn.disabled = true;
    try {
      await api(`/api/findings/${encodeURIComponent(id)}/status`, { method: "POST", body: { status } });
      toast(`Status set to ${STATUSES[status] || status}`, "success");
      await afterMutation();
    } catch (err) {
      toast(err.message, "error");
      if (btn) btn.disabled = false;
    }
  }

  async function remediate(action) {
    const id = state.drawerId;
    if (!id) return;
    try {
      const res = await api("/api/remediate", { method: "POST", body: { id, action } });
      toast(res.detail || `${REMEDIATIONS[action] || action} completed`, "success");
      await afterMutation();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function runTriage() {
    const id = state.drawerId;
    if (!id) return;
    const btn = $("#btn-triage");
    if (btn) { btn.disabled = true; btn.textContent = "Running..."; }
    try {
      const res = await api("/api/triage", { method: "POST", body: { id } });
      if (state.drawerId !== id) return;
      $("#triage-panel").innerHTML = triageHtml(res.triage) +
        `<button class="btn small" type="button" id="btn-triage">Re-run triage</button>`;
      toast("Triage complete", "success");
    } catch (err) {
      toast(err.message, "error");
      if (btn && document.body.contains(btn)) { btn.disabled = false; btn.textContent = "Run triage"; }
    }
  }

  async function addAllowlistFromDrawer() {
    const f = state.drawerFinding;
    if (!f) return;
    const reason = $("#allowlist-reason").value.trim();
    if (!reason) { toast("A reason is required", "error"); return; }
    try {
      await api("/api/allowlist", { method: "POST", body: { fingerprint: f.fingerprint, reason } });
      toast("Fingerprint added to allowlist", "success");
      if (state.view === "allowlist") loadAllowlist();
      await afterMutation();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function runScan(body, btn) {
    btn.disabled = true;
    $("#pg-results").innerHTML = `<div class="card"><p class="drawer-loading">Scanning...</p></div>`;
    try {
      const res = await api("/api/scan", { method: "POST", body });
      const findings = res.findings || [];
      const files = res.scanned_files || 0;
      renderPlaygroundResults(findings, files);
      toast(`Scan complete: ${findings.length} finding${findings.length === 1 ? "" : "s"}, ${files} file${files === 1 ? "" : "s"} scanned`, "success");
    } catch (err) {
      $("#pg-results").innerHTML = "";
      toast(`Scan failed: ${err.message}`, "error");
    } finally {
      btn.disabled = false;
    }
  }

  function renderPlaygroundResults(findings, files) {
    const el = $("#pg-results");
    if (!findings.length) {
      el.innerHTML = `<div class="card">${emptyState("No secrets detected", `${files} file${files === 1 ? "" : "s"} scanned. Nothing matched the detectors.`)}</div>`;
      return;
    }
    el.innerHTML = `<div class="card-head"><h2>Results</h2><span class="hint">${findings.length} finding${findings.length === 1 ? "" : "s"} - ${files} file${files === 1 ? "" : "s"} scanned</span></div>
      <div class="pg-grid">${findings.map((f) => `<div class="card pg-card">
        <div class="pg-card-head">${severityBadge(f.severity)}<span class="badge surface">${esc(surfaceLabel(f.surface))}</span></div>
        <h3>${esc(f.title)}</h3>
        <p class="cell-sub">${esc(f.detector_id || "-")}</p>
        <dl class="detail-grid compact">
          <dt>Location</dt><dd><code class="mono wrap">${esc(f.path || "-")}${f.line ? `:${esc(f.line)}` : ""}</code></dd>
          <dt>Secret</dt><dd><code class="mono wrap">${esc(f.secret_masked || "-")}</code></dd>
          <dt>Entropy</dt><dd>${esc(Number(f.entropy || 0).toFixed(2))}</dd>
        </dl>
      </div>`).join("")}</div>`;
  }

  async function loadActivity() {
    try {
      const [ev, al] = await Promise.all([api("/api/events?limit=50"), api("/api/alerts?limit=50")]);
      state.events = ev.events || [];
      state.alerts = al.alerts || [];
      if (!state.activityPaused) $("#activity-note").textContent = "";
      renderActivity();
    } catch {
      $("#activity-note").textContent = "Feed unavailable - retrying every 5 seconds.";
    }
  }

  function renderActivity() {
    $("#events-feed").innerHTML = state.events.length ? state.events.map((ev) => {
      const hasPayload = ev.payload && typeof ev.payload === "object" && Object.keys(ev.payload).length > 0;
      return `<div class="feed-item">
        <div class="feed-top">
          <span class="feed-kind">${esc(ev.kind || "event")}</span>
          <span class="badge surface">${esc(surfaceLabel(ev.surface))}</span>
          <time datetime="${esc(ev.ts)}">${esc(fmtTime(ev.ts))}</time>
        </div>
        ${hasPayload ? `<details class="payload"><summary>Payload</summary><pre class="code-block small">${esc(JSON.stringify(ev.payload, null, 2))}</pre></details>` : ""}
      </div>`;
    }).join("") : emptyState("No events yet", "Events appear here as scans and integrations report in.");

    $("#alerts-feed").innerHTML = state.alerts.length ? state.alerts.map((al) => `<div class="feed-item">
      <div class="feed-top">
        <span class="feed-kind">${esc(al.channel || "alert")}</span>
        ${statusBadge(al.status)}
        <time datetime="${esc(al.ts)}">${esc(fmtTime(al.ts))}</time>
      </div>
      <p class="feed-msg">${esc(al.message || "-")}</p>
      <p class="cell-sub">Finding <button class="linklike mono" type="button" data-open="${esc(al.finding_id)}">${esc(al.finding_id)}</button></p>
    </div>`).join("") : emptyState("No alerts yet", "Alerts are listed here when findings are routed to channels.");
  }

  async function loadAllowlist() {
    try {
      const data = await api("/api/allowlist");
      state.allowlist = data.entries || [];
      renderAllowlist();
    } catch (err) {
      toast(`Could not load allowlist: ${err.message}`, "error");
    }
  }

  function renderAllowlist() {
    const count = state.allowlist.length;
    $("#allowlist-wrap").hidden = count === 0;
    const emptyEl = $("#allowlist-empty");
    emptyEl.hidden = count > 0;
    if (!count) {
      emptyEl.innerHTML = emptyState("Allowlist is empty", "Add a fingerprint above, or use a finding's detail panel, to suppress known-safe matches.");
    }
    $("#allowlist-body").innerHTML = state.allowlist.map((en) => `<tr>
      <td data-label="Fingerprint"><code class="mono wrap">${esc(en.fingerprint)}</code></td>
      <td data-label="Reason"><span>${esc(en.reason || "-")}</span></td>
      <td data-label="Created"><time datetime="${esc(en.created_at)}">${esc(fmtTime(en.created_at))}</time></td>
    </tr>`).join("");
  }

  async function loadSettings() {
    renderHealth();
    try {
      const cfg = await api("/api/config");
      $("#config-json").textContent = JSON.stringify(cfg, null, 2);
    } catch (err) {
      $("#config-json").textContent = `Configuration unavailable: ${err.message}`;
    }
  }

  function renderHealth() {
    const h = state.health;
    $("#health-info").innerHTML = h ? `
      <dt>Status</dt><dd><span class="dot ok inline"></span> ${esc(h.status || "ok")}</dd>
      <dt>Product</dt><dd>${esc(h.product || "KeySentry")}</dd>
      <dt>Version</dt><dd>${esc(h.version || "-")}</dd>
      <dt>Uptime</dt><dd>${esc(fmtUptime(h.uptime_seconds))}</dd>
      <dt>Python</dt><dd>${esc(h.python || "-")}</dd>` :
      `<dt>Status</dt><dd><span class="dot err inline"></span> Offline - the server is not responding.</dd>`;
  }

  async function loadDemo(btn) {
    btn.disabled = true;
    try {
      const res = await api("/api/demo", { method: "POST" });
      toast(`Loaded ${fmtCount(res.seeded)} demo findings`, "success");
      await afterMutation();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      btn.disabled = false;
    }
  }

  function setView(name) {
    if (!VIEWS.includes(name)) name = "overview";
    state.view = name;
    $$(".view").forEach((v) => { v.hidden = v.dataset.view !== name; });
    $$("[data-tab]").forEach((b) => {
      const active = b.dataset.tab === name;
      b.classList.toggle("active", active);
      if (active) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    if (name === "overview") loadOverview();
    if (name === "findings") loadFindings();
    if (name === "activity") loadActivity();
    if (name === "allowlist") loadAllowlist();
    if (name === "settings") loadSettings();
    window.scrollTo({ top: 0 });
  }

  function trapDrawerFocus(e) {
    const items = $$("button, input, select, textarea, a[href], [tabindex]:not([tabindex='-1'])", $("#drawer"))
      .filter((el) => !el.disabled && el.getClientRects().length > 0);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  function bindEvents() {
    $$("[data-theme-toggle]").forEach((b) => b.addEventListener("click", toggleTheme));
    $$("[data-tab]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.tab)));
    $$("[data-demo]").forEach((b) => b.addEventListener("click", () => loadDemo(b)));

    document.addEventListener("click", (e) => {
      const opener = e.target.closest("[data-open]");
      if (opener) { openDrawer(opener.dataset.open); return; }
      const goto = e.target.closest("[data-goto]");
      if (goto) setView(goto.dataset.goto);
    });

    document.addEventListener("keydown", (e) => {
      if (!state.drawerId) return;
      if (e.key === "Escape") { closeDrawer(); return; }
      if (e.key === "Tab") trapDrawerFocus(e);
    });

    ["severity", "surface", "status"].forEach((key) => {
      $(`#filter-${key}`).addEventListener("change", (e) => {
        state.filters[key] = e.target.value;
        loadFindings();
      });
    });
    $("#filter-q").addEventListener("input", (e) => {
      clearTimeout(searchTimer);
      const value = e.target.value.trim();
      searchTimer = setTimeout(() => {
        state.filters.q = value;
        loadFindings();
      }, 300);
    });

    $("#findings-body").addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-row]");
      if (tr) openDrawer(tr.dataset.row);
    });
    $("#findings-body").addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr[data-row]")) {
        e.preventDefault();
        openDrawer(e.target.dataset.row);
      }
    });

    $("#drawer-close").addEventListener("click", closeDrawer);
    $("#drawer-backdrop").addEventListener("click", closeDrawer);
    $("#drawer-body").addEventListener("click", (e) => {
      const statusBtn = e.target.closest("[data-status]");
      if (statusBtn) { changeStatus(statusBtn.dataset.status, statusBtn); return; }
      const remBtn = e.target.closest("[data-remediate]");
      if (remBtn) { remediate(remBtn.dataset.remediate); return; }
      if (e.target.closest("#btn-triage")) { runTriage(); return; }
      if (e.target.closest("#btn-allowlist")) {
        $("#allowlist-form").hidden = false;
        $("#allowlist-reason").focus();
      }
    });
    $("#drawer-body").addEventListener("submit", (e) => {
      if (e.target.id === "allowlist-form") {
        e.preventDefault();
        addAllowlistFromDrawer();
      }
    });

    $("#pg-scan").addEventListener("click", () => {
      const text = $("#pg-text").value;
      if (!text.trim()) { toast("Paste some text to scan first", "error"); return; }
      runScan({ text, path: $("#pg-path").value.trim() || "playground.txt", surface: "filesystem" }, $("#pg-scan"));
    });
    $("#pg-scan-path").addEventListener("click", () => {
      const path = $("#pg-server-path").value.trim();
      if (!path) { toast("Enter a server path to scan", "error"); return; }
      runScan({ path }, $("#pg-scan-path"));
    });

    $("#btn-pause").addEventListener("click", () => {
      state.activityPaused = !state.activityPaused;
      const btn = $("#btn-pause");
      btn.setAttribute("aria-pressed", String(state.activityPaused));
      btn.setAttribute("aria-label", state.activityPaused ? "Resume auto-refresh" : "Pause auto-refresh");
      btn.textContent = state.activityPaused ? "Resume" : "Pause";
      $("#activity-note").textContent = state.activityPaused ? "Auto-refresh paused." : "";
      if (!state.activityPaused) loadActivity();
    });

    $("#allowlist-add").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fingerprint = $("#al-fingerprint").value.trim();
      const reason = $("#al-reason").value.trim();
      if (!fingerprint || !reason) { toast("Fingerprint and reason are both required", "error"); return; }
      try {
        await api("/api/allowlist", { method: "POST", body: { fingerprint, reason } });
        toast("Entry added to allowlist", "success");
        e.target.reset();
        loadAllowlist();
        afterMutation();
      } catch (err) {
        toast(err.message, "error");
      }
    });
  }

  function init() {
    initTheme();
    fillSelect($("#filter-severity"), SEVERITY_LABELS, "All severities");
    fillSelect($("#filter-surface"), SURFACES, "All surfaces");
    fillSelect($("#filter-status"), STATUSES, "All statuses");
    bindEvents();
    setView("overview");
    pollHealth();
    setInterval(pollHealth, 10000);
    setInterval(() => {
      if (state.view === "activity" && !state.activityPaused && !document.hidden) loadActivity();
    }, 5000);
  }

  init();
})();