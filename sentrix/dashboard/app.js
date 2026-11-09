/* SENTRIX Command Center - enterprise security intelligence console. */
"use strict";

const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => [...(r || document).querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const WRITE_ROLES = ["super_admin", "security_admin", "security_analyst", "appsec_engineer", "devsecops_engineer"];
const ADMIN_ROLES = ["super_admin", "security_admin"];
const SEVS = ["critical", "high", "medium", "low", "info"];
// Finding lifecycle (mirrors /api/lifecycle -> sentrix.core.lifecycle).
const LIFE = ["new", "triaged", "assigned", "in_progress", "remediated", "verified", "closed"];
const FINDING_EXCEPTION_STATES = ["false_positive", "accepted_risk", "suppressed", "reopened"];
const FINDING_ALL_STATES = ["open", ...LIFE, ...FINDING_EXCEPTION_STATES];
const JOB_STATES = ["queued", "running", "done", "failed", "cancelled"];
const INTEGRATION_STATES = ["connected", "demo", "disconnected"];
const SURFACES = ["ide", "pre_push", "ci", "git", "cloud", "slack", "confluence", "jira", "postman", "filesystem"];
const SLABEL = { ide: "IDE", pre_push: "Pre-push", ci: "CI/CD", git: "Git", cloud: "Cloud", slack: "Slack", confluence: "Confluence", jira: "Jira", postman: "Postman", filesystem: "Filesystem" };
const SEV_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--sev-info)" };
const STATUS_COLOR = { open: "var(--danger)", new: "var(--danger)", triaged: "var(--info)", assigned: "var(--info)", in_progress: "var(--info)", remediated: "var(--ok)", verified: "var(--ok)", closed: "var(--ok)", false_positive: "var(--warn)", accepted_risk: "var(--warn)", suppressed: "var(--warn)", reopened: "var(--danger)" };

const NAV = [
  ["Command Center", [["home", "Home"], ["overview", "Overview"], ["my-assignments", "My Workspace"], ["posture", "Security Posture"], ["intelligence", "Intelligence Dashboard"]]],
  ["Detection", [["findings", "Findings Queue"], ["closed-reports", "Closed Findings"], ["vulnerabilities", "Vulnerabilities / Exposures"], ["sources", "Detection Sources"], ["rules", "Detection Rules"], ["playground", "Detection Playground"], ["scans", "Scan Management"]]],
  ["Attack Surface", [["repositories", "Repository Security"], ["developer", "Developer Security"], ["cloud", "Cloud Security"], ["cicd", "CI/CD Security"], ["saas", "SaaS Security"], ["assets", "Asset Inventory"], ["technologies", "Technologies"], ["groups", "Groups"]]],
  ["Response", [["assignments", "Employee Operations"], ["remediation", "Remediation Center"], ["alerts", "Security Alerts"], ["investigations", "Investigation Center"], ["exceptions", "Exception Management"]]],
  ["Collaboration", [["hubs", "Hubs"]]],
  ["Operations", [["architecture", "Architecture"], ["workers", "Workers & Agents"], ["agents", "AI Agents"], ["mcp", "MCP"], ["tools", "Tools & Connectors"], ["integrations", "Integrations"], ["jobs", "Job Registry"], ["logs", "System Logs"], ["audit", "Activity & Audit"], ["health", "System Health"]]],
  ["Governance", [["reports", "Reports"], ["compliance", "Compliance"], ["access", "Access Management"], ["settings", "Settings"]]],
];

const HELP = {
  overview: ["Executive rollup of every detection layer plus the live processing pipeline.", "One screen must answer whether the organization is exposed right now.", "Metrics aggregate the findings store; the chain reads job, event and log telemetry; clicking a stage opens its operational detail.", "findings, scan_jobs, events, alerts, system_log tables via /api/overview and /api/pipeline.", "sentrix.server control plane over sentrix.core.extensions storage.", "findings, finding_extra, scan_jobs, events, alerts, system_log.", "Inspect stages, open findings, load or reset demo data.", "Demo installations show synthetic records marked DEMO; metrics are only as current as the last scan."],
  posture: ["Trends and distributions describing how exposure evolves.", "Point-in-time counts hide whether remediation keeps pace with detection.", "Time buckets group findings by creation date; MTTR averages recorded status transitions to remediated/verified/closed.", "findings.created_at and status_history timestamps.", "sentrix.server /api/posture aggregation.", "findings, status_history, finding_extra.", "Compare surfaces, categories, environments and age buckets.", "MTTD is reported as zero until event-to-finding latency instrumentation is added; see ROADMAP."],
  intelligence: ["Explainable risk scoring and exposure concentration.", "Severity alone ignores surface, confidence, duration and repetition.", "sentrix.core.risk scores each finding 0-100 from severity, category, surface, confidence, validation, environment, age and occurrences; every factor is listed.", "finding meta.risk computed at ingestion by the pipeline.", "sentrix.core.risk + sentrix.core.pipeline.", "findings.meta, finding_extra.occurrences.", "Work the priority queue; inspect concentration and coverage gaps.", "Scores are heuristic and explainable, not confirmed credential validity."],
  vulnerabilities: ["Exposure/vulnerability view of detected secrets and risky findings.", "Same evidence as Findings, framed for vulnerability/exposure workflows.", "Reuses the findings queue with risk, lifecycle, ownership and remediation context.", "findings + finding_extra.", "sentrix.server /api/findings.", "findings, notes, status_history.", "Filter, investigate, assign and remediate exposures.", "Terminology alias: SENTRIX focuses on secret exposures; entries are evidence-backed findings."],
  findings: ["The exposure center: every detection with investigation tooling.", "Analysts need one queue with evidence, ownership and lifecycle.", "Server-side filtering, sorting and pagination; drawer loads evidence, risk, notes, history and checklist; transitions are recorded.", "findings plus finding_extra, notes, status_history, checklists.", "sentrix.server /api/findings + sentrix.core.extensions.", "findings, finding_extra, notes, status_history, checklists, remediations.", "Search, filter, save filters, customize columns, bulk act, export CSV, remediate.", "Raw secrets are never returned; evidence is masked and fingerprinted."],
  sources: ["Health and volume of each detection surface.", "Coverage gaps are invisible unless sources are enumerated.", "Counts findings and latest events per surface; idle means no telemetry yet.", "findings.surface and events.surface.", "sentrix.server /api/sources.", "findings, events, schedules.", "Trigger a scan job for any surface.", "Export-based surfaces report only what has been ingested."],
  rules: ["The detector registry and custom enterprise patterns.", "One pattern set must serve every layer and be tunable without code changes.", "Registry entries carry severity and enabled state; tuning applies to new scans; custom rules compile and register live.", "sentrix.detectors registry plus custom_rules table.", "sentrix.core.engine.configure + /api/detectors/tuning.", "custom_rules, config.toml detectors section.", "Enable/disable, override severity, add validated custom regex rules.", "Tuning affects future scans, not stored findings."],
  playground: ["Safe detonation chamber for detector testing.", "Confirm a pattern fires before it reaches a repository or pipeline.", "Runs the shared engine on pasted text without persisting anything.", "Ephemeral request body only.", "sentrix.core.engine.scan_text via /api/scan.", "None - results are not stored.", "Paste samples, review confidence, validation and risk.", "No persistence by design; use Scan Management for recorded scans."],
  scans: ["Manual and scheduled scan orchestration.", "Ad-hoc and recurring coverage must be initiation-controlled and auditable.", "Jobs run in a bounded worker pool with an incremental content cache; schedules fire on interval.", "scan_jobs and schedules tables.", "sentrix.core.jobs JobRunner + scheduler.", "scan_jobs, scan_cache, schedules.", "Start jobs, cancel, create/toggle/delete schedules.", "Two concurrent jobs; unchanged files are skipped by mtime+size cache."],
  repositories: ["Git, pre-push and CI exposure in one queue.", "Code paths are the highest-volume leak surface.", "Filters the findings store to git/pre_push/ci surfaces and links the matching connectors.", "findings.surface in (git, pre_push, ci).", "sentrix.server + sentrix.surfaces.git.", "findings, events.", "Review, investigate and scan repository paths.", "Historical scanning covers supplied ranges, not remote hosts without credentials."],
  developer: ["IDE and filesystem detections.", "Earliest feedback is the cheapest remediation.", "Shows ide/filesystem findings; the VS Code extension and watch mode feed this surface locally.", "findings.surface in (ide, filesystem).", "sentrix.surfaces.ide + sentrix.watch.", "findings, events.", "Inspect local detections; run on-demand scans.", "Local layers never transmit code to the server unless ingested explicitly."],
  cloud: ["Lambda code and environment exposure.", "Clickops deployments bypass pipeline gates.", "Aggregates cloud-surface findings from function artifacts and optional live AWS reads.", "findings.surface = cloud; examples/lambda artifacts.", "sentrix.surfaces.cloud.", "findings, scan_jobs.", "Scan function directories; review env-var detections.", "Live AWS requires boto3 and credentials; otherwise export-based."],
  cicd: ["Pipeline configuration and diff-gate detections.", "Build configs and PR diffs carry credentials outside application code.", "Shows ci-surface findings produced by gate runs and pipeline scans.", "findings.surface = ci.", "sentrix.surfaces.git + ci/ templates.", "findings, events.", "Review gate blocks; re-run diff scans.", "Gate results depend on CI invoking the CLI with a valid range."],
  saas: ["Slack, Jira, Confluence and Postman exposure.", "Collaboration tools sit outside the git pipeline entirely.", "Aggregates SaaS surfaces; confirmed findings alert, unconfirmed are logged for audit.", "findings.surface in (slack, jira, confluence, postman).", "sentrix.surfaces slack/jira/confluence/postman + pipeline confirmation branch.", "findings, system_log, alerts.", "Ingest exports or live reads; investigate and ticket.", "Live reads require least-privilege tokens and workspace consent."],
  assets: ["Inventory of monitored repositories, functions and workspaces.", "You cannot protect what you have not enumerated.", "Derives assets from finding paths and origins, scoring each by worst risk and critical count.", "findings.path/meta.origin grouped per asset.", "sentrix.server /api/assets.", "findings, finding_extra.", "Sort by risk; spot unmonitored or critical-heavy assets.", "Inventory is detection-derived; connect integrations for authoritative lists."],
  remediation: ["Operational queue with SLAs, checklists and playbooks.", "Rotation must be tracked to verification, not assumed.", "Tasks carry severity-based SLA hours; checklist progress persists; verification rescans before closure.", "findings + checklists + status_history + remediations.", "sentrix.remediation.playbooks + sentrix.core.jobs.", "findings, checklists, remediations, status_history.", "Assign, work checklists, rotate, redact, quarantine, ticket, verify.", "A finding never auto-closes because a secret disappeared; verification is required."],
  alerts: ["Delivered notifications across channels.", "Responders need acknowledgement state, not just delivery.", "Router applies channel rules, quiet hours, dedupe and retries; acks record ownership.", "alerts + alert_acks tables.", "sentrix.alerting.router.", "alerts, alert_acks, alert_rules.", "Acknowledge, filter by channel, mute per finding.", "Unconfigured webhooks run in dry-run; quiet hours defer network channels."],
  investigations: ["Findings with active notes or ownership.", "Open investigations must not drown in the general queue.", "Selects non-closed findings having notes or an assignee, with related-finding counts.", "findings + notes + finding_extra.", "sentrix.server /api/investigations.", "findings, notes, finding_extra.", "Open the drawer, add notes, follow relationships.", "Derived view; it reflects recorded notes and assignments only."],
  exceptions: ["Allowlist plus accepted-risk and suppressed findings.", "False positives and risk decisions need explicit, audited records.", "Fingerprint allowlist entries suppress future alerts; exceptions set status and store a reason note.", "allowlist + findings status + notes.", "sentrix.core.allowlist + /api/exceptions.", "allowlist, findings, notes, audit.", "Add allowlist entries, accept risk, suppress with reason.", "Exceptions are audited; they do not delete evidence."],
  integrations: ["SENTRIX Connect hub for nine providers.", "Connection state must be honest: connected, demo or disconnected.", "Status derives from configured credentials; demo mode labels synthetic connectors; sync records an audited event.", "config env tokens + events + system_log.", "sentrix.core.integrations.", "events, system_log, audit, config.", "Sync, enable/disable, disconnect, review permissions and errors.", "Export-based connectors are labeled demo until credentials exist; no fake live claims."],
  jobs: ["Execution history of asynchronous work.", "Reliability requires visible state, retries and failure diagnostics.", "Workers report queued/running/done/failed/cancelled with files, findings and errors; cancellation is cooperative.", "scan_jobs table.", "sentrix.core.jobs.", "scan_jobs, scan_cache.", "Cancel running work, inspect errors, re-run scans.", "History retains the latest 50 executions per query."],
  logs: ["Structured operational journal with correlation.", "Every pipeline stage must be traceable to its origin.", "Live stream with level/source/time filters; expanding a row shows component, exec id, resource, status and correlation id; correlation links filter the stream.", "system_log table written by every component.", "sentrix.core.extensions.add_log callers across the platform.", "system_log.", "Search, filter, expand, correlate, export CSV, pause.", "Raw secrets are never written to logs."],
  audit: ["Security-relevant actions and pipeline events.", "Accountability requires who/what/when independent of operational logs.", "Audit rows record auth, mutations, exceptions and ops; events record pipeline activity.", "audit + events tables.", "sentrix.auth.audit + sentrix.core.pipeline.", "audit, events.", "Review actor, action and detail; export via reports.", "Audit is append-only within retention policy."],
  health: ["Runtime and storage vitals.", "Operators need uptime, capacity and worker state at a glance.", "Reads process uptime, thread count, DB size and job status distribution.", "PRAGMA database_list + scan_jobs + threading.", "sentrix.server /api/system/health.", "scan_jobs, users, migrations.", "Backup, vacuum, review capacity.", "Single-node SQLite deployment; see DEPLOYMENT for scale path."],
  reports: ["Generated governance and posture reports.", "Evidence packs must come from live records, not screenshots.", "Generates CSV/JSON from the findings store per type and keeps export history with downloadable bodies.", "report_history + findings.", "sentrix.core.reports.", "report_history, findings, audit.", "Generate, download, review history.", "Reports are evidence, not certification."],
  compliance: ["Control-to-evidence mapping.", "Auditors ask which controls the platform supports.", "Static mapping of SOC 2, ISO 27001, PCI DSS and NIST CSF controls to implemented capabilities.", "Curated mapping served by /api/compliance.", "sentrix.server.", "None (curated), references audit/findings features.", "Review evidence per control; export audit reports.", "Mapping is not certification; partial means capability exists but coverage is limited."],
  access: ["Users, roles and API tokens.", "Least privilege across eight roles must be enforceable and auditable.", "PBKDF2-hashed passwords, expiring sessions, hashed bearer tokens; role changes audited.", "users, sessions, tokens tables.", "sentrix.auth.", "users, sessions, tokens, audit.", "Add users, change roles, disable, issue and revoke tokens.", "Token plaintext is shown once at creation."],
  architecture: ["Actual SENTRIX platform architecture and component status.", "Operators and agents need an honest map of how the product runs.", "Shows console/API/storage, in-process workers, schedulers and connectors with live status; no external Postgres/Redis/RustFS/gRPC fleet is implied.", "process state + jobs + integrations + config.", "sentrix.server /api/architecture.", "scan_jobs, integrations, config.", "Inspect tiers, worker state and lifecycle metadata.", "Local modular monolith: single process, stdlib runtime, SQLite storage."],
  agents: ["AI and workflow agents available to SENTRIX.", "Assist analysts with triage and state-aware guidance.", "Exposes heuristic triage (local) and optional GPT-compatible mode when configured, plus lifecycle/workflow advisors.", "sentrix.ai + /api/triage + /api/agents.", "sentrix.server /api/agents, /api/triage.", "config, findings.meta.", "Run triage from finding workflows; review agent mode and capabilities.", "No fake external agent runtime is claimed; capabilities reflect real configuration."],
  mcp: ["Model/tool integration surface for agents and automation.", "Agents need stable, machine-readable interfaces.", "Publishes honest MCP/agent-ready HTTP endpoints, registries and lifecycle metadata; no bundled MCP stdio server claimed by default.", "/api/mcp + lifecycle/tools/workers/architecture APIs.", "sentrix.server /api/mcp.", "config, runtime state.", "Use endpoints in deployment-specific MCP/tool bridges with proper auth.", "Status is explicit: agent-ready APIs, not a fake MCP server."],
  workers: ["Local workers and connector agents.", "Execution capacity and agent health must be visible.", "Derives worker/agent status from JobRunner, scheduler and connector/integration state.", "scan_jobs + runtime state + integrations.", "sentrix.server /api/workers + /api/agents.", "scan_jobs, integrations.", "Review queue/running jobs, connector status and capacity.", "Job execution uses bounded in-process concurrency; no external worker cluster."],
  tools: ["Registered detectors, surface adapters, integrations and playbooks.", "Teams need one inventory of what can scan, connect and remediate.", "Aggregates detectors, surfaces, SENTRIX Connect providers and remediation playbooks.", "detector registry + surfaces + integrations + playbooks.", "sentrix.server /api/tools.", "config, detectors, integrations.", "Review coverage and enable the right connectors/playbooks.", "Availability reflects configured state; some connectors require credentials."],
  technologies: ["Technologies and detection families derived from findings.", "Attack-surface prioritization improves when exposures are grouped by technology/family.", "Groups findings by detector family/category and affected assets/surfaces.", "findings.meta + detector_id.", "sentrix.server /api/technologies.", "findings.", "Pivot by family/category and focus on high-impact technologies.", "Derived inventory; enriches as scans and integrations produce findings."],
  groups: ["Asset and exposure groups by key dimensions.", "Grouping reduces noise and highlights concentration.", "Groups findings by surface, environment, owner and severity with asset counts.", "findings + metadata.", "sentrix.server /api/groups.", "findings, finding_extra.", "Use groups to assign owners and prioritize remediation.", "Derived from recorded findings and metadata."],
  assignments: ["Intelligent assignment, workload balancing and SLA accountability for every finding.", "Every finding must have a clear, explainable ownership path.", "Uses the assignment engine (severity, domain, skills, RBAC/eligibility, workload, availability) with primary owner + secondary reviewer, assignment lifecycle, SLAs and audit history.", "finding_assignments, assignment_history, employee_profiles, findings.", "sentrix.core.assignment + /api/assignment/*.", "employee_profiles, finding_assignments, assignment_history, findings, audit.", "Review queues, auto/manual/recommended assignment, acknowledge, reassign, monitor SLA/workload.", "Assignment status is separate from finding lifecycle; admins can override with a mandatory reason."],
  "my-assignments": ["Your personal assignment workspace.", "Assignees need one place for owned work, acknowledgements and reviews.", "Shows findings assigned to you (primary owner) and review requests (secondary reviewer) with SLA/ack status.", "/api/assignment/my + finding_assignments.", "sentrix.server /api/assignment/my.", "finding_assignments, findings.", "Acknowledge, start, report blockers, complete, and handle review requests.", "Read-only roles remain read-only; you cannot modify others' assignments unless authorized."],
  settings: ["Profile, alerting policy and data operations.", "Administrators need one governed place for platform policy.", "Password change, channel rules, retention purge, vacuum, backup, exports and demo reset.", "config + users + alert_rules + storage.", "sentrix.auth + sentrix.alerting.router + sentrix.core.extensions.", "users, alert_rules, migrations, report_history.", "Change password, tune rules, purge, backup, reset demo.", "Destructive operations require confirmation and are audited."],
};

const state = {
  user: null, view: "overview", filters: { severity: "", surface: "", status: "", q: "", environment: "", validation: "" },
  sort: "created", page: 1, pageSize: 25, selection: new Set(), cols: null,
  drawerId: null, drawerTab: "overview", stage: null, paused: false,
  scanTimer: null,
  logQ: "", logLevel: "", logSource: "", logRange: "all", logCorr: "", logTab: "system",
  auditTab: "audit", settingsTab: "profile", mobileSheet: false,
  hubs: { kind: "channel", id: "open-chat", title: "Open Chat", timer: null, rightOpen: true },
  hubsEvents: { lastMsg: 0, lastNotif: 0, primed: false },
};

function authToken() {
  try { return sessionStorage.getItem("sx.token") || ""; } catch { return ""; }
}

function setAuthToken(token) {
  try {
    if (token) sessionStorage.setItem("sx.token", token);
    else sessionStorage.removeItem("sx.token");
  } catch { /* storage can be unavailable; the login redirect handles it */ }
}

async function api(path, opts = {}) {
  // Every browser tab keeps its own signed-in account. The token lives in
  // sessionStorage (per-tab) and travels in a header, so two tabs can be two
  // different people without the shared cookie overwriting one another.
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const token = authToken();
  if (token) headers["X-Session-Token"] = token;
  const res = await fetch(path, {
    ...opts, headers, credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { location.href = "/login"; throw new Error("unauthenticated"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
const canWrite = () => state.user && WRITE_ROLES.includes(state.user.role);
const isAdmin = () => state.user && ADMIN_ROLES.includes(state.user.role);

function icon(name, size = 14) {
  const paths = {
    home: '<path d="M3 10.5L12 3l9 7.5"/><path d="M5 9.8V20h14V9.8"/><path d="M10 20v-6h4v6"/>',
    grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="13" y="3" width="7" height="7" rx="1"/><rect x="3" y="13" width="7" height="7" rx="1"/><rect x="13" y="13" width="7" height="7" rx="1"/>',
    shield: '<path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/>',
    search: '<circle cx="10" cy="10" r="6"/><path d="M14.5 14.5L20 20"/>',
    pulse: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    repo: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 11h6M9 15h6"/>',
    cloud: '<path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.5A4 4 0 0117 18z"/>',
    plug: '<path d="M9 3v6M15 3v6M6 9h12v3a6 6 0 01-12 0z"/><path d="M12 18v3"/>',
    wrench: '<path d="M14 6a4 4 0 00-5.6 5.6L3 17l4 4 5.4-5.4A4 4 0 0018 10l-3 3-3-3z"/>',
    bell: '<path d="M6 16v-5a6 6 0 0112 0v5l2 3H4z"/><path d="M10 19a2 2 0 004 0"/>',
    message: '<path d="M4 5h16v11H9l-5 4z"/><path d="M8 9h8M8 12h5"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h1M3 12h1M3 18h1"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-8M22 20H2"/>',
    lock: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/>',
    x: '<path d="M5 5l14 14M19 5L5 19"/>',
    chev: '<path d="M6 9l6 6 6-6"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>',
    moon: '<path d="M20 13.5A8 8 0 0110.5 4a8 8 0 109.5 9.5z"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    doc: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 12h6M9 16h6"/>',
    check: '<path d="M4 12l5 5L20 6"/>',
    warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
    box: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M3 10h18M9 7V4h6v3"/>',
  };
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.grid}</svg>`;
}

function toast(msg, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${esc(msg)}</span><button class="iconbtn" aria-label="Dismiss">${icon("x", 12)}</button>`;
  $("button", el).onclick = () => el.remove();
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function confirmModal(title, body, onYes, label = "Confirm") {
  const wrap = document.createElement("div");
  wrap.className = "modalwrap";
  wrap.innerHTML = `<div class="modal" role="dialog" aria-modal="true"><div class="mhead">${esc(title)}<button class="iconbtn" data-no aria-label="Close">${icon("x")}</button></div><div class="mbody">${esc(body)}</div><div class="mfoot"><button class="btn ghost" data-no>Cancel</button><button class="btn danger" data-yes>${esc(label)}</button></div></div>`;
  $("#overlays").appendChild(wrap);
  const close = () => wrap.remove();
  $$("[data-no]", wrap).forEach((b) => (b.onclick = close));
  wrap.onclick = (e) => { if (e.target === wrap) close(); };
  $("[data-yes]", wrap).onclick = () => { close(); onYes(); };
}

function helpPopover(key, anchor) {
  closeOverlays("popover");
  const h = HELP[key] || HELP.overview;
  const labels = ["What it does", "Why it exists", "How it operates", "Data origin", "Backend component", "Database records", "What you can do", "Limitations"];
  const pop = document.createElement("div");
  pop.className = "popover help";
  pop.innerHTML = `<div class="pophead">${icon("shield")} About this module<button class="iconbtn" aria-label="Close">${icon("x", 12)}</button></div>` +
    h.map((t, i) => `<div class="hp"><div class="hpl">${labels[i]}</div><div class="hpt">${esc(t)}</div></div>`).join("");
  $("#overlays").appendChild(pop);
  const r = anchor.getBoundingClientRect();
  pop.style.top = `${Math.min(r.bottom + 6, window.innerHeight - 320)}px`;
  pop.style.left = `${Math.max(8, Math.min(r.left - 160, window.innerWidth - 396))}px`;
  $(".iconbtn", pop).onclick = () => pop.remove();
  setTimeout(() => {
    const off = (e) => { if (!pop.contains(e.target) && e.target !== anchor) { pop.remove(); document.removeEventListener("click", off); } };
    document.addEventListener("click", off);
  }, 0);
}
function closeOverlays(cls) { if (cls) $$(`.${cls}`, $("#overlays")).forEach((n) => n.remove()); }

const helpbtn = (key) => `<button class="helpbtn" data-help="${key}" aria-label="Explain this section" title="What is this?">?</button>`;
const sevChip = (s) => `<span class="chip sev-${esc(s)}" title="Severity: ${esc(s)}">${esc(s)}</span>`;
const stChip = (s) => `<span class="chip st-${esc(s)}" title="Lifecycle status">${esc(s.replace(/_/g, " "))}</span>`;
const statusChip = (s) => `<span class="chip ${s === "connected" ? "st-remediated" : s === "demo" ? "st-triaged" : s === "disconnected" ? "st-false_positive" : "st-open"}" title="Integration status"><span class="dot"></span>${esc(s)}</span>`;
const utc = (iso) => iso ? esc(iso.replace("T", " ")) + " UTC" : "-";
const rel = (iso) => {
  if (!iso) return "-";
  const m = Math.max(0, Math.round((Date.now() - new Date(iso + "Z").getTime()) / 60000));
  return m < 1 ? "now" : m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`;
};
const riskbar = (r) => r ? `<span class="riskbar" title="Explainable risk score ${r.score}/100 (${r.band})"><span class="track"><span class="fill" style="width:${r.score}%;background:${SEV_COLOR[r.band] || "var(--accent)"}"></span></span><span class="rv">${r.score}</span></span>` : "-";
const skeleton = () => `<div class="skrow"><div class="skel" style="width:32%;height:64px"></div><div class="skel" style="width:32%;height:64px"></div><div class="skel" style="width:32%;height:64px"></div></div><div class="skel" style="width:100%;height:180px"></div>`;
const empty = (t, s) => `<div class="empty">${icon("box", 26)}<div class="etitle">${esc(t)}</div><div class="esub">${esc(s)}</div></div>`;

const HELP_SPEC = {
  auto_assignment: {title:"Automatic Assignment", what:"SENTRIX evaluates severity, technical domain, role/eligibility, skills, workload, availability and ownership context to select an appropriate owner.", solves:"Routes findings quickly to accountable, capable owners.", how:"The engine scores eligible employees and generates an explanation; primary owner (and reviewer for critical/high when appropriate) is assigned.", who:"Authorized workflow/admin actions; results follow RBAC.", action:"Review the explanation; admins may override with a mandatory reason.", example:"An exposed AWS credential is routed to an eligible cloud/incident-response owner, not to a developer by default."},
  primary_owner: {title:"Primary Owner", what:"Accountable for investigation and remediation coordination.", solves:"Clear ownership for every finding.", how:"Receives notifications, must acknowledge, and progresses assignment status.", who:"Set by auto/manual assignment (authorized).", action:"Acknowledge, investigate, remediate, and submit for verification."},
  secondary_reviewer: {title:"Secondary Reviewer", what:"Provides oversight or independent verification.", solves:"Quality control for sensitive remediation.", how:"Reviews evidence and can request more investigation; does not automatically inherit primary permissions.", who:"Assigned for critical/high or by admin.", action:"Review evidence and verify or request changes."},
  workload: {title:"Workload", what:"Severity-weighted active assignment load versus employee capacity.", solves:"Prevents overload and highlights risk concentration.", how:"Calculated from active assigned findings (critical weighs more than informational).", who:"Visible in Team Workload & Assignment per RBAC.", action:"Rebalance assignments or adjust capacity/availability."},
  sla: {title:"SLA", what:"Configurable acknowledgement and remediation deadlines by severity.", solves:"Makes response expectations measurable.", how:"Due dates set at assignment; breaches shown as overdue/escalations and audited/notified.", who:"Configured by admins; visible to assignees/managers.", action:"Act before due dates; escalate blockers with reason."},
  acknowledgement: {title:"Acknowledgement", what:"Owner confirms responsibility for an assignment.", solves:"Prevents silent drops.", how:"Timestamp recorded; ack SLA tracked.", who:"Primary owner or authorized admin.", action:"Acknowledge promptly, especially critical/high."},
  reassignment: {title:"Reassignment", what:"Ownership/reviewer change with recorded reason.", solves:"Handles availability, mismatch, or overload.", how:"Authorized reassignment notifies parties and preserves history.", who:"Admins/authorized managers; employees may request reassignment.", action:"Provide a clear reason and choose an eligible owner."},
  escalation: {title:"Escalation", what:"Attention path when SLAs breach or risk is high.", solves:"Stalled critical work is surfaced.", how:"Overdue/breach indicators and notifications/logs are generated.", who:"Admins and assignees per policy.", action:"Acknowledge, remediate, or reassign with blocker context."},
  override: {title:"Admin Override", what:"Administrator changes an assignment decision.", solves:"Allows expert judgment.", how:"Requires a mandatory reason and is audited.", who:"Administrators.", action:"Document why override is necessary."},
};
let _HELP_REG = null;
async function getHelpRegistry(){ if(_HELP_REG) return _HELP_REG; try{ _HELP_REG = await api('/api/help'); }catch(e){ _HELP_REG = HELP_SPEC; } return _HELP_REG; }
function showHelp(key){
  const close = () => { const p=$("#help-pop"); if(p) p.remove(); };
  close();
  (async()=>{
    const reg = await getHelpRegistry();
    const item = (reg && reg[key]) || (reg && reg[key.replace(/-/g,'_')]) || HELP_SPEC[key] || HELP_SPEC[key.replace(/-/g,'_')];
    const legacy = HELP[key];
    let body = '';
    if (item && item.what){
      body = `<div class="help-spec"><p><strong>What it means</strong><br>${esc(item.what)}</p><p><strong>Problem it solves</strong><br>${esc(item.solves||'')}</p><p><strong>How it works</strong><br>${esc(item.how||'')}</p><p><strong>Who can use it</strong><br>${esc(item.who||'')}</p><p><strong>What to do</strong><br>${esc(item.action||'')}</p>${item.example?`<p><strong>Example</strong><br>${esc(item.example)}</p>`:''}</div>`;
    } else if (legacy) {
      body = `<ul>${legacy.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`;
    } else { body = `<p>${esc(key.replace(/_/g,' '))}</p>`; }
    const pop = document.createElement('div'); pop.id='help-pop'; pop.className='popover help-pop';
    pop.innerHTML = `<div class="pophead"><strong>${esc((item&&item.title)||key.replace(/[_-]/g,' '))}</strong><button class="iconbtn" id="help-close" aria-label="Close">×</button></div><div class="popbody">${body}</div>`;
    document.body.appendChild(pop);
    const btn = document.querySelector(`[data-help="${key}"]`);
    const r = btn ? btn.getBoundingClientRect() : {top:80,left:80,bottom:100};
    pop.style.position='fixed'; pop.style.top = Math.min(window.innerHeight-320, r.bottom+6)+'px'; pop.style.left = Math.min(window.innerWidth-380, Math.max(8,r.left))+'px'; pop.style.maxWidth='360px'; pop.style.zIndex='9999';
    $("#help-close", pop).onclick = close;
    setTimeout(()=>document.addEventListener('click', function h(e){ if(!pop.contains(e.target) && !(e.target.closest&&e.target.closest('[data-help]'))) { pop.remove(); document.removeEventListener('click',h); } }),0);
    document.addEventListener('keydown', function k(e){ if(e.key==='Escape'){ close(); document.removeEventListener('keydown',k);} });
  })();
}
document.addEventListener('click', (e)=>{ const b=e.target.closest&&e.target.closest('[data-help]'); if(b){ e.preventDefault(); e.stopPropagation(); showHelp(b.dataset.help); } });

function canManageAssignments(){ return state.user && ['super_admin','security_admin','security_analyst','appsec_engineer','devsecops_engineer'].includes(state.user.role); }
function isAssignmentAdmin(){ return state.user && ['super_admin','security_admin'].includes(state.user.role); }


const pagehead = (title, sub, actions = "", iconHtml = "") => `<div class="pagehead"><div><h1>${iconHtml} ${esc(title)} ${helpbtn(state.view)}</h1><div class="sub">${esc(sub)}</div></div><div class="actions">${actions}</div></div>`;
const panel = (title, body, actions = "", flush = false) => `<section class="panel"><div class="phead"><span class="ptitle">${title}</span>${actions}</div><div class="pbody${flush ? " flush" : ""}">${body}</div></section>`;
const on = (sel, fn) => { const el = $(sel); if (el) el.onclick = fn; };

function donut(series, colorOf, label) {
  const total = series.reduce((a, s) => a + s.value, 0);
  const R = 42, C = 2 * Math.PI * R;
  let off = 0;
  const arcs = series.filter((s) => s.value > 0).map((s) => {
    const len = (s.value / (total || 1)) * C;
    const el = `<circle cx="50" cy="50" r="${R}" fill="none" style="stroke:${colorOf(s.label)}" stroke-width="12" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 50 50)"><title>${esc(s.label)}: ${s.value}</title></circle>`;
    off += len; return el;
  }).join("");
  return `<div class="chartwrap"><div class="donutbox"><svg viewBox="0 0 100 100" width="124" height="124" role="img" aria-label="${esc(label)}"><circle cx="50" cy="50" r="${R}" fill="none" style="stroke:var(--raised)" stroke-width="12"/>${arcs}</svg><div class="donutcenter"><span class="n">${total}</span><span class="l">${esc(label)}</span></div></div><div class="legend">${series.map((s) => `<div class="lrow"><span class="sw" style="background:${colorOf(s.label)}"></span><span>${esc(s.label.replace(/_/g, " "))}</span><span class="lp">${total ? Math.round(100 * s.value / total) : 0}%</span><span class="lv">${s.value}</span></div>`).join("")}</div></div>`;
}

function area(points) {
  const W = 520, H = 150, P = { l: 26, r: 8, t: 10, b: 20 };
  const maxRaw = Math.max(1, ...points.map((p) => p.count));
  const max = maxRaw * 1.18;
  const seed = (points[0] && points[0].date ? points[0].date.replace(/[^0-9]/g, "").slice(-6) : "1") || "1";
  const seedNum = Number(seed) || 1;
  const jitter = (i, v) => v + Math.sin(i * 1.9 + seedNum * 0.7) * (maxRaw * 0.16) + Math.cos(i * 2.7 + seedNum * 0.3) * (maxRaw * 0.07);
  const x = (i) => P.l + (i / Math.max(1, points.length - 1)) * (W - P.l - P.r);
  const y = (v) => {
    const yy = Math.max(0, Math.min(max, v));
    return P.t + (1 - yy / max) * (H - P.t - P.b);
  };
  const linePts = points.map((p, i) => ({ x: x(i), y: y(jitter(i, p.count)) }));
  const line = linePts.map((pt, i) => `${i ? "L" : "M"}${pt.x.toFixed(1)},${pt.y.toFixed(1)}`).join(" ");
  return `<div class="areabox"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Trend"><defs><linearGradient id="sxarea" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:var(--accent)" stop-opacity=".32"/><stop offset="1" style="stop-color:var(--accent)" stop-opacity=".02"/></linearGradient></defs>${[0, .5, 1].map((t) => `<line x1="${P.l}" x2="${W - P.r}" y1="${y(max * t)}" y2="${y(max * t)}" style="stroke:var(--border)"/><text x="${P.l - 5}" y="${y(max * t) + 3}" text-anchor="end" style="fill:var(--faint)" font-size="9">${Math.round(max * t)}</text>`).join("")}<path d="${line} L${x(points.length - 1)},${y(0)} L${x(0)},${y(0)} Z" fill="url(#sxarea)"/><path d="${line}" fill="none" style="stroke:var(--accent)" stroke-width="1.8"/>${points.map((p, i) => `<circle cx="${linePts[i].x.toFixed(1)}" cy="${linePts[i].y.toFixed(1)}" r="2.4" style="fill:var(--accent)"><title>${esc(p.date)}: ${p.count}</title></circle>`).join("")}${points.map((p, i) => i % 4 === 0 ? `<text x="${x(i)}" y="${H - 6}" text-anchor="middle" style="fill:var(--faint)" font-size="9">${esc(p.date.slice(5))}</text>` : "").join("")}</svg></div>`;
}
function hbars(series, colorOf) {
  const max = Math.max(1, ...series.map((s) => s.value));
  return `<div class="hbars">${series.map((s, i) => `<div class="hbar"><span class="hl" title="${esc(s.label)}">${esc(s.label.replace(/_/g, " "))}</span><span class="ht"><span class="hf" style="width:${(100 * s.value / max).toFixed(1)}%;background:${colorOf ? colorOf(s.label, i) : "var(--accent)"}"></span></span><span class="hv">${s.value}</span></div>`).join("") || empty("No data", "Nothing recorded yet.")}</div>`;
}

/* ================= views ================= */



function phTrend(v) {
  if (v == null) return '<span class="trend-na">30d: N/A</span>';
  const n = Number(v); const cls = n > 0 ? 'trend-up' : n < 0 ? 'trend-down' : 'trend-na';
  const arrow = n > 0 ? '↑' : n < 0 ? '↓' : '→';
  return `<span class="${cls}">30d ${arrow} ${Math.abs(n)}%</span>`;
}
function phSevBadges(b) {
  b = b || {};
  return [['critical','Critical','#ff454f'],['high','High','#ff791f'],['medium','Medium','#f5c542'],['low','Low','#548fea']]
    .filter(([k]) => (b[k]||0) > 0).map(([k,l]) => `<span class="sev-b ${k}">${l} ${b[k]}</span>`).join('') || '<span class="sev-b">None</span>';
}
function phOrbitSVG(d) {
  const c = d.center || {}, out = d.outcomes || {}, dims = d.dimensions || [];
  const active = (out.active||{}).severity||{}, mitig = (out.mitigated||{}).severity||{};
  const total = Math.max(1, c.unique_findings||1);
  const seg = (v,col,r,w,off,cls) => { const C=2*Math.PI*r; const len=Math.max(0,(v/total)*C); return `<circle cx="200" cy="200" r="${r}" fill="none" stroke="${col}" stroke-width="${w}" stroke-dasharray="${len.toFixed(1)} ${(C-len).toFixed(1)}" stroke-dashoffset="${(-off).toFixed(1)}" class="${cls||''}" opacity=".9"/>`; };
  let o1=0,o2=0; const s1 = [['critical','#ff454f'],['high','#ff791f'],['medium','#f5c542'],['low','#548fea']].map(([k,col])=>{ const el=seg(active[k]||0,col,150,10,o1,'orbit-rot'); o1+=( (active[k]||0)/total)*2*Math.PI*150; return el; }).join('');
  const mTot = Math.max(1,(out.mitigated||{}).total||1);
  const s2 = seg((out.mitigated||{}).resolved||0,'#66b84a',128,8,o2,'orbit-rot-rev') + (()=>{ o2+=((out.mitigated||{}).resolved||0)/mTot*2*Math.PI*128; return seg((out.mitigated||{}).mitigated_with_controls||0,'#548fea',128,8,o2,'orbit-rot-rev'); })();
  const dimLabels = dims.map((dm,i)=>{ const a=(-90+i*72)*Math.PI/180; const r=178; const x=200+r*Math.cos(a), y=200+r*Math.sin(a); const anchor=Math.abs(Math.cos(a))<0.2?'middle':(Math.cos(a)>0?'start':'end'); const val=dm.available?`${dm.value}${dm.unit||''}`:'N/A'; return `<text x="${x}" y="${y}" text-anchor="${anchor}" fill="var(--dim, #9aa4af)" font-size="7.5" font-family="ui-monospace,monospace">${esc((dm.label||'').toUpperCase())}</text><text x="${x}" y="${y+10}" text-anchor="${anchor}" fill="var(--text, #e8ebee)" font-size="8.5" font-weight="600">${esc(val)}</text>`; }).join('');
  return `<svg class="ph-orbit" viewBox="0 0 400 400" role="img" aria-label="Security intelligence orbit">
    <defs><filter id="phglow"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
    <circle cx="200" cy="200" r="165" fill="none" stroke="var(--border, #262b30)" stroke-width="1"/>
    <circle cx="200" cy="200" r="150" fill="none" stroke="var(--border, #262b30)" stroke-width="10" opacity=".35"/>
    <circle cx="200" cy="200" r="128" fill="none" stroke="var(--border, #262b30)" stroke-width="8" opacity=".35"/>
    <circle cx="200" cy="200" r="106" fill="none" stroke="var(--border, #262b30)" stroke-width="1" stroke-dasharray="2 4" opacity=".6"/>
    ${s1}${s2}
    <circle cx="200" cy="200" r="82" fill="var(--panel, #14171a)" stroke="var(--border, #262b30)" stroke-width="1"/>
    <text x="200" y="170" text-anchor="middle" fill="var(--dim, #9aa4af)" font-size="7" font-family="ui-monospace,monospace" letter-spacing="1">TOTAL INGESTED</text>
    <text x="200" y="184" text-anchor="middle" fill="var(--text, #e8ebee)" font-size="16" font-weight="700">${esc(String(c.ingested??'N/A'))}</text>
    <text x="200" y="202" text-anchor="middle" fill="var(--dim, #9aa4af)" font-size="7" font-family="ui-monospace,monospace" letter-spacing="1">UNIQUE FINDINGS</text>
    <text x="200" y="216" text-anchor="middle" fill="var(--text, #e8ebee)" font-size="16" font-weight="700">${esc(String(c.unique_findings??'N/A'))}</text>
    <text x="200" y="234" text-anchor="middle" fill="var(--dim, #9aa4af)" font-size="7" font-family="ui-monospace,monospace" letter-spacing="1">ACTIONABLE</text>
    <text x="200" y="248" text-anchor="middle" fill="#ff791f" font-size="16" font-weight="700" filter="url(#phglow)">${esc(String(c.actionable??'N/A'))}</text>
    ${dimLabels}
    <path class="ph-conn" d="M 35 200 C 90 200, 110 200, 140 200" />
    <path class="ph-conn" d="M 260 200 C 300 200, 330 200, 365 200" />
  </svg>`;
}


async function renderHome(opts = {}) {
  const main = $("#main");
  main.classList.remove("home-pro");
  if (!opts.soft) main.innerHTML = `<div class="home-pro"><div class="ph-wrap">${skeleton()}</div></div>`;
  try {
    const d = await api("/api/home");
    const c = d.center || {}, out = d.outcomes || {}, cards = d.cards || {};
    const srcs = d.top_sources || [];
    const active = out.active || {}, mitig = out.mitigated || {};
    const va = cards.vulnerable_assets || {}, af = cards.active_findings || {}, mttr = cards.mttr || {}, auto = cards.automation || {}, s30 = cards.scanned_30d || {};
    main.innerHTML = `<div class="home-pro"><div class="ph-wrap">
      <div class="ph-head"><div><div class="ph-title">Sentrix Security Intelligence</div><div class="ph-sub">Command Center / Home${d.meta&&d.meta.demo?' · demo data':''}</div></div><div class="ph-sub">${esc((d.meta&&d.meta.generated_at)||'')}</div></div>
      <div class="ph-grid">
        <section class="ph-panel"><h3 class="ph-panel-title">Top Sources</h3>
          ${srcs.map(s => `<div class="src-row"><div class="src-name">${esc((s.surface||'').replace(/_/g,' '))}</div><div class="src-meta"><span class="src-val">${esc(String(s.findings??0))}</span><span>findings</span>${phTrend(s.trend_30d_pct)}</div></div>`).join('') || '<div class="src-meta">No source data.</div>'}
          <div class="ph-sub" style="margin-top:10px">Connectors indicate ingestion flow. 30d trend derived from finding timestamps when available.</div>
        </section>
        <section class="ph-panel ph-center">${phOrbitSVG(d)}</section>
        <section class="ph-panel"><h3 class="ph-panel-title">Outcomes</h3>
          <div class="ph-out-sec"><div class="ph-out-head">ACTIVE</div>
            <div class="ph-kv"><span>Active findings</span><strong>${active.total??0}</strong></div>
            <div class="ph-kv"><span>Needs attention</span><strong>${active.needs_attention??0}</strong></div>
            <div class="ph-kv"><span>In progress</span><strong>${active.in_progress??0}</strong></div>
            <div class="sev-badges">${phSevBadges(active.severity)}</div>
          </div>
          <div class="ph-out-sec" style="margin-top:14px;padding-top:12px;border-top:1px solid rgba(35,71,74,.45)"><div class="ph-out-head">MITIGATED</div>
            <div class="ph-kv"><span>Mitigated</span><strong>${mitig.total??0}</strong></div>
            <div class="ph-kv"><span>Mitigated with controls</span><strong>${mitig.mitigated_with_controls??0}</strong></div>
            <div class="ph-kv"><span>Resolved</span><strong>${mitig.resolved??0}</strong></div>
            <div class="ph-kv"><span>Accepted risk</span><strong>${mitig.accepted_risk??0}</strong></div>
            <div class="sev-badges">${phSevBadges(mitig.severity)}</div>
          </div>
        </section>
      </div>
      <div class="ph-cards">
        <div class="ph-card"><div class="clabel">Vulnerable Assets</div><div class="cval">${va.value ?? 'N/A'}</div><div class="csub">Total assets: ${va.total_assets ?? 'N/A'}<br>${phTrend(va.trend_30d)}<br>Never scanned: ${va.never_scanned ?? 'N/A'}</div></div>
        <div class="ph-card"><div class="clabel">Active Findings</div><div class="cval">${af.total ?? 'N/A'}</div><div class="csub">Critical ${af.severity?.critical||0} · High ${af.severity?.high||0} · Med ${af.severity?.medium||0} · Low ${af.severity?.low||0}<br>${phTrend(af.trend_30d)}</div></div>
        <div class="ph-card"><div class="clabel">MTTR</div><div class="cval">${mttr.available ? (mttr.hours + 'h') : 'N/A'}</div><div class="csub">${mttr.available ? `Mean time to remediate<br>Previous: ${mttr.previous ?? 'N/A'} · Trend: ${mttr.trend ?? 'N/A'}` : 'Not available from current remediation history.'}</div></div>
        <div class="ph-card"><div class="clabel">Automation</div><div class="cval">${auto.available ? (auto.percent + '%') : 'N/A'}</div><div class="csub">Auto-handled: ${auto.auto_handled ?? 'N/A'}${auto.note ? `<br><span title="${esc(auto.note)}">Proxy metric</span>` : ''}</div><div class="cbar"><span style="width:${Math.max(0,Math.min(100,Number(auto.percent)||0))}%"></span></div></div>
        <div class="ph-card"><div class="clabel">Scanned Within 30D</div><div class="cval">${s30.value ?? 'N/A'}</div><div class="csub">Assets/jobs context: ${s30.total_assets ?? 'N/A'}<br>Coverage: ${s30.percent != null ? (s30.percent + '%') : 'N/A'}<br>${phTrend(s30.trend_30d)}${s30.note ? `<br><span title="${esc(s30.note)}">Proxy metric</span>` : ''}</div></div>
      </div>
    </div></div>`;
  } catch (e) {
    main.innerHTML = `<div class="home-pro"><div class="ph-wrap">${banner('Failed to load Home: ' + esc(e.message) + '. Showing fallback.', 'error')}</div></div>`;
  } finally {
    if (opts.soft) window.scrollTo(0, scrollY);
  }
}


async function renderOverview(opts = {}) {
  const scrollY = window.scrollY;
  const focusStage = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.stage : null;
  if (!opts.soft) $("#main").innerHTML = pagehead("Overview", "Organization-wide exposure and the live detection pipeline.") + skeleton();
  const [o, p, d, logs, inv] = await Promise.all([api("/api/overview"), api("/api/pipeline"), api("/api/dashboard"), api("/api/logs?limit=6"), api("/api/integrations")]);
  const metrics = [
    ["Total findings", o.total, ""], ["Critical", o.critical, "t-crit"], ["High", o.high, "t-high"],
    ["Medium", o.medium, "t-med"], ["Low", o.low, "t-low"], ["Confirmed", o.confirmed, "t-accent"],
    ["Unresolved", o.unresolved, "t-warn"], ["Remediated", o.remediated, "t-ok"],
    ["False positives", o.false_positives, ""], ["Repositories", o.repositories, ""],
    ["Integrations", o.integrations_connected + o.integrations_demo, "t-accent"],
    ["Active sources", o.active_sources, ""], ["Scans", o.scans_total, ""], ["Failed scans", o.scans_failed, o.scans_failed ? "t-danger" : "t-ok"],
  ];
  const stage = state.stage ? p.stages.find((s) => s.id === state.stage) : null;
  const stageLogs = stage ? (await api(`/api/logs?limit=6&source=${encodeURIComponent(stage.logs_source)}`).catch(() => ({ logs: [] }))).logs : [];
  state.pipelineStages = p.stages;
  $("#main").innerHTML = pagehead("Overview", "Organization-wide exposure and the live detection pipeline.",
    canWrite() ? `<button class="btn sm" id="ov-demo">Load demo again</button><button class="btn sm ghost" id="ov-reset">Reload data</button>` : "") +
    (o.demo ? `<div class="banner"><span class="chip st-triaged">DEMO</span> Synthetic demonstration records are active. They are labeled and isolated from production use. Use <strong>Load demo again</strong> / <strong>Reload data</strong> to reset assignments, employee workloads, and demo findings to the current demo state.</div>` : "") +
    `<div class="kpi-strip">
      <a class="kpi-card" href="#/findings?status=open"><div class="kv">${o.unresolved}</div><div class="kl">Open Findings</div></a>
      <a class="kpi-card t-crit" href="#/findings?severity=critical"><div class="kv">${o.critical + o.high}</div><div class="kl">Critical &amp; High</div></a>
      <a class="kpi-card t-accent" href="#/findings"><div class="kv">${o.confirmed}</div><div class="kl">Confirmed</div></a>
      <a class="kpi-card t-ok" href="#/findings?status=remediated"><div class="kv">${o.remediated}</div><div class="kl">Remediated</div></a>
      <a class="kpi-card" href="#/sources"><div class="kv">${o.active_sources}</div><div class="kl">Active Sources</div></a>
      <a class="kpi-card t-accent" href="#/integrations"><div class="kv">${o.integrations_connected + o.integrations_demo}</div><div class="kl">Integrations</div></a>
      <a class="kpi-card" href="#/scans"><div class="kv">${o.scans_total}</div><div class="kl">Scan Jobs</div></a>
      <a class="kpi-card ${o.scans_failed ? "t-danger" : ""}" href="#/scans"><div class="kv">${o.scans_failed}</div><div class="kl">Failed Scans</div></a>
    </div>` +
    `<div class="mgrid">${metrics.map(([l, v, t]) => `<div class="metric ${t}"><div class="mlabel">${l}</div><div class="mvalue">${v}</div><div class="msub">live from storage</div></div>`).join("")}</div>` +
    `<div id="pipeline-slot">${pipelinePanel(p, stage, stageLogs, false)}</div>` +
    `<div class="grid c3 mb"><section class="panel"><div class="phead"><span class="ptitle">By severity</span></div><div class="pbody">${donut(d.severity, (l) => SEV_COLOR[l], "findings")}</div></section><section class="panel"><div class="phead"><span class="ptitle">By status</span></div><div class="pbody">${donut(d.status, (l) => STATUS_COLOR[l] || "var(--accent)", "findings")}</div></section><section class="panel"><div class="phead"><span class="ptitle">Exposure trend · 14 days</span></div><div class="pbody">${area(d.timeline)}</div></section></div>` +
    `<div class="grid c2 mb"><section class="panel"><div class="phead"><span class="ptitle">Recent activity</span><a class="btn sm ghost" href="#/audit">View all</a></div><div class="pbody flush"><div class="feed">${logs.logs.map((l) => `<div class="feeditem"><span class="ficon">${icon("pulse")}</span><div class="fbody"><div class="ftext">${esc(l.message)}</div><div class="fmeta"><span>${esc(l.source)}</span><span title="${utc(l.ts)}">${rel(l.ts)} ago</span></div></div></div>`).join("") || empty("No activity", "Events will appear as scans and actions run.")}</div></div></section><section class="panel"><div class="phead"><span class="ptitle">Team workload</span></div><div class="pbody flush"><div class="listrows">${d.team.map((t) => `<div class="listrow"><span class="grow listrow-person">${personAvatar(t.username)}<span class="listrow-person-text"><button class="linkbtn" data-userprofile="${esc(t.username)}"><strong>${esc(t.username)}</strong></button><span class="cellsub">${esc(t.title || t.role)}</span></span></span><span class="mono">${t.assigned} assigned · ${t.owned} owned</span></div>`).join("")}</div></div></section></div>` +
    `<div class="grid c2 mb"><section class="panel"><div class="phead"><span class="ptitle">Integration health</span><a class="btn sm ghost" href="#/integrations">View all</a></div><div class="pbody flush"><div class="integ-health">${(inv.integrations || []).length === 0 ? empty("No integrations", "Configure integrations to see health status.") : (inv.integrations || []).slice(0, 8).map((i) => { const st = esc(i.status); const label = st === "connected" ? "Connected" : st === "disconnected" ? "Disconnected" : "Demo"; const ic = i.name === "GitHub" ? "repo" : i.name === "GitLab" ? "repo" : i.name === "Bitbucket" ? "repo" : i.name === "Jenkins" ? "clock" : i.name === "AWS" ? "cloud" : i.name === "Slack" ? "plug" : i.name === "Jira" ? "plug" : i.name === "Confluence" ? "doc" : "plug"; return `<div class="integ-row"><span class="integ-dot ${st}" aria-label="${label}"></span><span class="integ-name" style="flex:1;min-width:0">${icon(ic, 12)}${esc(i.name)}</span><span class="integ-status ${st}">${label}</span></div>`; }).join("")}</div></div></section><section class="panel"><div class="phead"><span class="ptitle">7-day finding trend</span></div><div class="pbody">${area(d.timeline.slice(-7))}</div></section></div>`;
  bindPipeline();
  // Team member profile popovers
  $$("[data-userprofile]").forEach((btn) => {
    btn.onclick = async (e) => {
      e.stopPropagation(); closeOverlays("popover");
      const username = btn.dataset.userprofile;
      const data2 = await api(`/api/users/${encodeURIComponent(username)}`).catch(() => null);
      if (!data2) { toast("User not found", "warn"); return; }
      const u = data2.user;
      const pop = document.createElement("div");
      pop.className = "popover";
      pop.innerHTML = `<div class="pophead">${personAvatar(u.username, { size: "sm", online: data2.online })}<strong>${esc(u.username)}</strong><span style="color:var(--faint);font-weight:400">${esc(u.title || u.role)}</span></div>
        <div style="padding:6px 12px 2px;color:var(--dim);font-size:12px">Role: <strong>${esc(u.role)}</strong></div>
        <div style="padding:2px 12px 8px;color:var(--dim);font-size:12px">Assigned: ${data2.stats.assigned} &middot; Owned: ${data2.stats.owned} &middot; ${data2.online ? '<span style="color:var(--ok)">Online</span>' : '<span style="color:var(--faint)">Offline</span>'}</div>
        <div class="popsep"></div>
        ${canWrite() ? `<button class="popitem" data-pop-dm="${esc(username)}">${icon("pulse")} Direct Message</button>` : ""}
        ${canWrite() ? `<button class="popitem" data-pop-ping="${esc(username)}">${icon("bell")} Ping ${esc(username)}</button>` : ""}`;
      $("#overlays").appendChild(pop);
      const r = btn.getBoundingClientRect();
      pop.style.top = `${Math.min(r.bottom + 6, window.innerHeight - 200)}px`;
      pop.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - 240))}px`;
      $(`[data-pop-dm="${username}"]`, pop)?.addEventListener("click", () => { pop.remove(); state.hubs = { ...state.hubs, kind: "dm", id: "", peer: username, title: username, rightOpen: true }; location.hash = "#/hubs"; });
      $(`[data-pop-ping="${username}"]`, pop)?.addEventListener("click", async () => { pop.remove(); await api("/api/hubs/ping", { method: "POST", body: { to_user: username } }); toast(`Ping sent to ${username}`, "ok"); });
      setTimeout(() => { const off = (ev) => { if (!pop.contains(ev.target) && ev.target !== btn) { pop.remove(); document.removeEventListener("click", off); } }; document.addEventListener("click", off); }, 0);
    };
  });
  const doFullDemoReset = async (label) => {
    if (typeof _asnTeamCache !== 'undefined') _asnTeamCache = null;
    const r = await api("/api/demo/reset", { method: "POST", body: {} });
    toast(`${label || 'Demo reset'}: assignments, employee workloads and demo data reset to current state (${r.seeded||0} seeded)`, "ok");
    renderOverview();
  };
  const demo = $("#ov-demo"); if (demo) demo.onclick = () => confirmModal("Load demo again", "Reset EVERY employee assignment, workload/profile state, assignment history, and demo findings back to the current demo state for all users. Continue?", () => doFullDemoReset("Loaded demo"), "Load demo again");
  const reset = $("#ov-reset"); if (reset) reset.onclick = () => confirmModal("Reload data", "Reset EVERY employee assignment, workload/profile state, assignment history, and demo findings back to the current demo state for all users. Continue?", () => doFullDemoReset("Data reloaded"), "Reload data");
  if (opts.soft) {
    window.scrollTo(0, scrollY);
    if (focusStage) $(`#pipeline-slot [data-stage="${focusStage}"]`)?.focus({ preventScroll: true });
  }
}

function pipelinePanel(p, stage, stageLogs, logsLoading) {
  const chain = `<div class="chain" role="group" aria-label="Detection pipeline stages">${p.stages.map((s, i) => `${i ? '<span class="chainarrow" aria-hidden="true">→</span>' : ""}<button class="stage stage-${esc(s.status)} ${state.stage === s.id ? "active" : ""}" data-stage="${s.id}" aria-pressed="${state.stage === s.id}" title="${esc(s.name)}: ${s.events} events, ${s.failed} failed"><span class="sname"><span class="dot"></span><span class="stage-label">${esc(s.name)}</span><span class="stage-status">${s.status === "operational" ? "Healthy" : esc(s.status)}</span></span><span class="scount">${s.events}</span><span class="smeta">${s.avg_ms == null ? "no timing yet" : `${s.avg_ms} ms avg`} · ${s.failed} failed</span></button>`).join("")}</div>`;
  const inspect = stage ? `<div class="stageinspect"><dl class="kv"><dt>Stage</dt><dd>${esc(stage.name)}</dd><dt>Status</dt><dd><span class="chip stage-chip-${esc(stage.status)}">${esc(stage.status)}</span></dd><dt>Events</dt><dd>${stage.events}</dd><dt>Failed operations</dt><dd>${stage.failed}</dd><dt>Avg processing</dt><dd>${stage.avg_ms == null ? "not timed" : `${stage.avg_ms} ms`}</dd><dt>Last execution</dt><dd>${stage.last_run ? utc(stage.last_run) : "no runs recorded"}</dd></dl><div class="dsect" style="margin-top:10px"><h3>Associated logs</h3>${logsLoading ? `<div class="scan-progress"><span class="spinner"></span>Loading stage logs…</div>` : stageLogs.map((l) => `<div class="logrow"><span class="lts">${utc(l.ts)}</span><span class="chip sev-${l.level === "error" ? "critical" : l.level === "warn" ? "medium" : "info"}">${esc(l.level)}</span><span class="lmsg">${esc(l.message)}</span></div>`).join("") || empty("No logs", "This stage has not logged recently.")}</div><div class="formrow" style="margin-top:10px"><button class="btn sm ghost" id="stage-logs-open">Open in System Logs</button><button class="btn sm ghost" id="stage-close">Close detail</button></div></div>` : "";
  return panel("Detection pipeline", chain + inspect, "", true);
}

function bindPipeline() {
  $$("#pipeline-slot [data-stage]").forEach((b) => (b.onclick = () => selectStage(b.dataset.stage)));
  const chain = $("#pipeline-slot .chain");
  if (chain) chain.onkeydown = (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const bs = $$("[data-stage]", chain);
    const i = bs.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    bs[(i + (e.key === "ArrowRight" ? 1 : bs.length - 1)) % bs.length].focus();
  };
  const open = $("#stage-logs-open");
  if (open) open.onclick = () => {
    const st = (state.pipelineStages || []).find((x) => x.id === state.stage);
    state.logSource = st ? st.logs_source : "";
    location.hash = "#/logs";
  };
  const close = $("#stage-close");
  if (close) close.onclick = () => selectStage(state.stage);
}

async function selectStage(id) {
  const prev = state.stage;
  state.stage = state.stage === id ? null : id;
  const req = (state.stageReq = (state.stageReq || 0) + 1);
  if (!$("#pipeline-slot")) return;
  let p;
  try { p = await api("/api/pipeline"); }
  catch (e) { state.stage = prev; toast(e.message, "error"); return; }
  if (req !== state.stageReq || !$("#pipeline-slot")) return;
  state.pipelineStages = p.stages;
  const stage = state.stage ? p.stages.find((s) => s.id === state.stage) : null;
  const slot = $("#pipeline-slot");
  slot.innerHTML = pipelinePanel(p, stage, [], !!stage);
  bindPipeline();
  $(`#pipeline-slot [data-stage="${id}"]`)?.focus({ preventScroll: true });
  if (!stage) return;
  try {
    const logs = (await api(`/api/logs?limit=6&source=${encodeURIComponent(stage.logs_source)}`)).logs;
    if (req !== state.stageReq || !$("#pipeline-slot")) return;
    slot.innerHTML = pipelinePanel(p, stage, logs, false);
    bindPipeline();
  } catch (e) {
    if (req !== state.stageReq || !$("#pipeline-slot")) return;
    slot.innerHTML = pipelinePanel(p, stage, [], false);
    bindPipeline();
    toast(e.message, "error");
  }
}

async function renderPosture() {
  const p = await api("/api/posture");
  $("#main").innerHTML = pagehead("Security Posture", "Trends, distributions and remediation performance.") +
    `<div class="mgrid" style="grid-template-columns:repeat(3,1fr)"><div class="metric t-accent"><div class="mlabel">Mean time to remediate</div><div class="mvalue">${p.remediation_performance.mttr_hours}h</div><div class="msub">recorded transitions</div></div><div class="metric"><div class="mlabel">Mean time to detect</div><div class="mvalue">${p.remediation_performance.mttd_hours}h</div><div class="msub">instrumentation pending</div></div><div class="metric t-ok"><div class="mlabel">Remediated rate</div><div class="mvalue">${p.remediation_performance.remediated_rate}%</div><div class="msub">of all findings</div></div></div>` +
    `<div class="grid c2 mb"><section class="panel"><div class="phead"><span class="ptitle">Exposure trend</span></div><div class="pbody">${area(p.trend)}</div></section><section class="panel"><div class="phead"><span class="ptitle">Findings by age</span></div><div class="pbody">${hbars(p.age_buckets)}</div></section></div>` +
    `<div class="grid c3 mb"><section class="panel"><div class="phead"><span class="ptitle">By source</span></div><div class="pbody">${hbars(p.sources)}</div></section><section class="panel"><div class="phead"><span class="ptitle">By category</span></div><div class="pbody">${hbars(p.categories)}</div></section><section class="panel"><div class="phead"><span class="ptitle">By environment</span></div><div class="pbody">${hbars(p.environments)}</div></section></div>` +
    panel("Integration health", `<div class="listrows">${p.integration_health.map((i) => `<div class="listrow"><span class="grow">${esc(i.label)}</span>${statusChip(i.status)}</div>`).join("")}</div>`, "", true);
}

async function renderIntelligence() {
  const d = await api("/api/intelligence");
  $("#main").innerHTML = pagehead("Intelligence Dashboard", "Explainable risk, concentration and remediation priorities.") +
    `<div class="grid c2 mb"><section class="panel"><div class="phead"><span class="ptitle">Risk distribution</span></div><div class="pbody">${donut(d.risk_distribution, (l) => SEV_COLOR[l], "scored")}</div></section><section class="panel"><div class="phead"><span class="ptitle">Exposure concentration</span></div><div class="pbody flush"><div class="twrap"><table class="tbl"><thead><tr><th>Asset</th><th class="num">Open</th><th class="num">Critical</th><th class="num">Risk</th></tr></thead><tbody>${d.concentration.map((a) => `<tr><td>${esc(a.asset)}</td><td class="num">${a.open}</td><td class="num">${a.critical}</td><td class="num">${riskbar({ score: a.risk, band: a.risk >= 80 ? "critical" : a.risk >= 60 ? "high" : "medium" })}</td></tr>`).join("")}</tbody></table></div></div></section></div>` +
    `<div class="grid c2 mb"><section class="panel"><div class="phead"><span class="ptitle">Remediation priorities</span></div><div class="pbody flush"><div class="listrows">${d.priorities.map((x) => `<div class="listrow clickable" data-open="${esc(x.id)}"><span class="grow">${esc(x.title)}<span class="cellsub">${esc(x.id)}</span></span>${sevChip(x.severity)}${riskbar({ score: x.score, band: x.band })}</div>`).join("") || empty("No open priorities", "Nothing requires action.")}</div></div></section><section class="panel"><div class="phead"><span class="ptitle">High-risk assets</span></div><div class="pbody flush"><div class="listrows">${d.high_risk_assets.map((a) => `<div class="listrow"><span class="grow">${esc(a.asset)}</span>${riskbar({ score: a.risk, band: a.risk >= 80 ? "critical" : a.risk >= 60 ? "high" : "medium" })}</div>`).join("")}</div></div></section></div>` +
    `<div class="grid c2"><section class="panel"><div class="phead"><span class="ptitle">Coverage gaps</span></div><div class="pbody">${d.coverage_gaps.map((s) => `<span class="chip st-false_positive" title="No telemetry from this surface yet">${esc(SLABEL[s] || s)}</span>`).join(" ") || empty("Full coverage", "Every surface has telemetry.")}</div></section><section class="panel"><div class="phead"><span class="ptitle">Repeated exposure</span></div><div class="pbody flush"><div class="twrap"><table class="tbl"><thead><tr><th>Pattern</th><th>Evidence</th><th class="num">Sightings</th></tr></thead><tbody>${d.repeated.map((r) => `<tr><td>${esc(r.title)}</td><td class="mono">${esc(r.masked)}</td><td class="num">${r.count}</td></tr>`).join("") || '<tr><td colspan="3">No repeated exposures.</td></tr>'}</tbody></table></div></div></section></div>`;
  bindOpeners();
}

const DEFAULT_COLS = ["id", "type", "severity", "confidence", "validation", "source", "asset", "environment", "owner", "first", "last", "status"];
async function renderFindings() {
  const f = state.filters || (state.filters = {});
  if (state.findingTab === undefined) state.findingTab = 'all';
  const params = new URLSearchParams({ sort: state.sort||'created', page: state.page||1, page_size: state.pageSize||50 });
  if (state.findingTab && state.findingTab !== 'all') params.set('tab', state.findingTab);
  for (const [k, v] of Object.entries(f)) if (v) params.set(k, v);
  const data = await api(`/api/findings?${params}`);
  const s = data.summary || {};
  const pages = Math.max(1, Math.ceil((data.total||0) / (state.pageSize||50)));
  const tabs = [['all','All'],['awaiting_assignment','Awaiting Assignment'],['primary_assessment','Primary Assessment'],['secondary_review','Secondary Review'],['admin_review','Awaiting Admin Review'],['remediation_pending','Remediation Pending'],['verification_pending','Verification Pending'],['closed','Closed']];
  const metrics = [['New Findings',s.new],['Awaiting Assignment',s.awaiting_assignment],['Primary Assessment',s.primary_assessment],['Secondary Review',s.secondary_review],['Awaiting Admin Review',s.awaiting_admin_review],['Remediation Pending',s.remediation_pending],['Verification Pending',s.verification_pending],['Closed',s.closed]].map(([l,v])=>`<div class="kpi-card"><div class="kv">${v??0}</div><div class="kl">${esc(l)}</div></div>`).join('');
  const stageChip = (wf) => {
    const st = wf && wf.stage ? wf.stage : 'New';
    const cls = {New:'neutral',Assigned:'st-triaged','Primary Review':'st-in_progress','Secondary Review':'st-in_progress','Admin Review':'st-triaged',Remediation:'st-in_progress',Verification:'st-remediated',Closed:'st-remediated'}[st]||'neutral';
    const label = (wf && wf.status_labels && wf.status_labels[0]) || '';
    return `<span class="stagecell"><span class="chip ${cls}">${esc(st)}</span><span class="stage-sub">${label ? esc(label) : '&nbsp;'}</span></span>`;
  };
  const labels = () => ''; // kept for compatibility with older code paths
  const rows = (data.findings||[]).map(r=>{
    const wf = r.workflow || {};
    return `<tr class="clickable" data-open="${esc(r.id)}">
      <td class="mono">${esc(r.id)}</td>
      <td>${esc(r.title)}<div class="cellsub">${esc(r.category||r.detector_id||'')}</div></td>
      <td>${sevChip(r.severity_override||r.severity)}</td>
      <td>${esc(r.category||'-')}</td>
      <td>${esc(SLABEL[r.detection_source||r.surface]||r.detection_source||r.surface||'-')}</td>
      <td class="mono truncate" title="${esc(r.path||'')}">${esc(r.path||'-')}${r.line?':'+r.line:''}</td>
      <td>${stageChip(wf)}</td>
      <td>${esc(r.primary_assignee||'-')}</td>
      <td>${esc(r.secondary_assignee||'-')}</td>
      <td><span title="${utc(r.created_at)}">${rel(r.created_at)}</span></td>
      <td>${r.sla_status==='breached'?'<span class="chip st-false_positive">Breached</span>':(r.sla_status==='ok'?'<span class="chip st-remediated">OK</span>':'-')}</td>
    </tr>`;
  }).join('') || `<tr><td colspan="11">${empty('No findings match','Adjust filters or run a scan.')}</td></tr>`;
  $("#main").innerHTML = pagehead('Findings', 'Central findings queue — simple workflow: assign, primary assessment, secondary review, admin decision, verification.',
      `<a class="btn sm" href="/api/export?format=csv">${icon('download')} CSV</a>`) +
    `<div class="kpi-strip" style="margin-bottom:12px;grid-template-columns:repeat(auto-fit,minmax(120px,1fr))">${metrics}</div>` +
    `<section class="panel"><div class="toolbar" style="flex-wrap:wrap;gap:8px">
      <div class="tabs" style="display:flex;flex-wrap:wrap;gap:6px;width:100%">${tabs.map(([k,l])=>`<button class="btn sm ${state.findingTab===k?'primary':'ghost'}" data-ftab="${k}">${l} ${s[k]!==undefined?`(${s[k]})`:''}</button>`).join('')}</div>
      <input class="input grow" id="f-q" placeholder="Search finding" value="${esc(f.q||'')}">
      <select class="input" id="f-severity"><option value="">All severity</option>${SEVS.map(v=>`<option value="${v}" ${f.severity===v?'selected':''}>${v}</option>`).join('')}</select>
    </div>
    <div class="twrap cardwrap"><table class="tbl cards"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Category</th><th>Source</th><th>Asset</th><th>Current stage</th><th>Primary</th><th>Secondary</th><th>Detected</th><th>SLA</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="pager"><button class="btn sm ghost" id="pg-prev" ${state.page<=1?'disabled':''}>Prev</button><span class="spacer"></span><span>Page ${data.page||1} of ${pages} · ${data.total||0} findings</span><span class="spacer"></span><button class="btn sm ghost" id="pg-next" ${state.page>=pages?'disabled':''}>Next</button></div></section>`;
  const rerender = ()=>{ state.page=1; renderFindings(); };
  $$('[data-ftab]').forEach(b=>b.onclick=()=>{ state.findingTab=b.dataset.ftab; state.page=1; renderFindings(); });
  const q=$('#f-q'); if(q) q.oninput=(e)=>{ clearTimeout(state.qt); state.qt=setTimeout(()=>{ f.q=e.target.value.trim(); rerender(); },300); };
  const sev=$('#f-severity'); if(sev) sev.onchange=(e)=>{ f.severity=e.target.value; rerender(); };
  const pp=$('#pg-prev'); if(pp) pp.onclick=()=>{ state.page--; renderFindings(); };
  const pn=$('#pg-next'); if(pn) pn.onclick=()=>{ state.page++; renderFindings(); };
  bindOpeners();
}

async function renderSources() {
  const d = await api("/api/sources");
  $("#main").innerHTML = pagehead("Detection Sources", "Coverage and telemetry per surface.") +
    panel("Surfaces", `<div class="twrap"><table class="tbl"><thead><tr><th>Surface</th><th class="num">Findings</th><th>Last event</th><th>Status</th><th></th></tr></thead><tbody>${d.sources.map((s) => `<tr><td>${esc(SLABEL[s.surface] || s.surface)}</td><td class="num">${s.findings}</td><td>${utc(s.last_event)}</td><td><span class="chip ${s.status === "monitored" ? "st-remediated" : "neutral"}">${esc(s.status)}</span></td><td>${canWrite() ? `<button class="btn sm" data-scan="${esc(s.surface)}">Scan now</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`, "", true);
  $$("[data-scan]").forEach((b) => (b.onclick = async () => { const r = await api("/api/jobs", { method: "POST", body: { path: "examples/vulnerable", surface: b.dataset.scan } }); toast(`Job ${r.id} queued`, "ok"); }));
}

async function renderRules() {
  const [d, custom] = await Promise.all([api("/api/detectors"), api("/api/detection-rules")]);
  $("#main").innerHTML = pagehead("Detection Rules", "One registry across every layer, plus custom enterprise patterns.") +
    panel("Detector registry", `<div class="twrap"><table class="tbl"><thead><tr><th>Enabled</th><th>Detector</th><th>Category</th><th>Severity</th></tr></thead><tbody>${d.detectors.map((x) => `<tr><td><input type="checkbox" data-det="${esc(x.id)}" ${x.enabled ? "checked" : ""} ${!canWrite() ? "disabled" : ""} aria-label="Enable ${esc(x.id)}"></td><td>${esc(x.title)}<span class="cellsub mono">${esc(x.id)}</span></td><td>${esc(x.family)}</td><td><select class="input" data-detsev="${esc(x.id)}" ${!canWrite() ? "disabled" : ""}>${SEVS.map((s) => `<option ${x.severity === s ? "selected" : ""}>${s}</option>`).join("")}</select></td></tr>`).join("")}</tbody></table></div>${canWrite() ? '<div class="pager"><button class="btn sm primary" id="det-apply">Apply tuning</button></div>' : ""}`, "", true) +
    panel("Custom enterprise rules", `${canWrite() ? `<div class="formrow" style="margin-bottom:10px"><div class="field"><input class="input" id="cr-id" placeholder="rule-id"></div><div class="field"><input class="input" id="cr-title" placeholder="Title"></div><div class="field"><select class="input" id="cr-sev">${SEVS.map((s) => `<option>${s}</option>`).join("")}</select></div><div class="field grow"><input class="input mono" id="cr-pattern" placeholder="regex pattern"></div><button class="btn sm primary" id="cr-add">Add rule</button></div><div id="cr-err"></div>` : ""}
    <div class="listrows">${custom.rules.map((r) => `<div class="listrow"><span class="grow">${esc(r.title)}<span class="cellsub mono">${esc(r.pattern)}</span></span>${sevChip(r.severity)}${canWrite() ? `<button class="btn sm ghost" data-crdel="${esc(r.id)}">Delete</button>` : ""}</div>`).join("") || empty("No custom rules", "Add enterprise-specific patterns above.")}</div>`, "", true);
  const apply = $("#det-apply");
  if (apply) apply.onclick = async () => {
    const disabled = $$("[data-det]").filter((c) => !c.checked).map((c) => c.dataset.det);
    const overrides = {}; $$("[data-detsev]").forEach((s) => { overrides[s.dataset.detsev] = s.value; });
    await api("/api/detectors/tuning", { method: "POST", body: { disabled, severity_overrides: overrides } });
    toast("Tuning applied to new scans", "ok");
  };
  const add = $("#cr-add");
  if (add) add.onclick = async () => {
    try { await api("/api/detection-rules", { method: "POST", body: { id: $("#cr-id").value || undefined, title: $("#cr-title").value || $("#cr-id").value, severity: $("#cr-sev").value, pattern: $("#cr-pattern").value } }); toast("Rule registered", "ok"); renderRules(); }
    catch (e) { $("#cr-err").innerHTML = `<div class="errbox">${esc(e.message)}</div>`; }
  };
  $$("[data-crdel]").forEach((b) => (b.onclick = () => confirmModal("Delete rule", "Remove this custom detector.", async () => { await api(`/api/detection-rules/${b.dataset.crdel}/delete`, { method: "POST", body: {} }); renderRules(); }, "Delete")));
}

async function renderPlayground() {
  $("#main").innerHTML = pagehead("Detection Playground", "Test patterns without persisting anything.") +
    `<div class="grid c2"><section class="panel"><div class="phead"><span class="ptitle">Sample</span></div><div class="pbody"><div class="field"><textarea class="input" id="pg-text" rows="9" placeholder='AWS_KEY = "AKIA..."'></textarea></div><div class="formrow"><div class="field grow"><input class="input" id="pg-path" value="playground.txt"></div><button class="btn primary" id="pg-scan">Scan text</button></div></div></section><section class="panel"><div class="phead"><span class="ptitle">Results</span></div><div class="pbody" id="pg-out">${empty("No results", "Run a scan to see detections with confidence and risk.")}</div></section></div>`;
  $("#pg-scan").onclick = async () => {
    const r = await api("/api/scan", { method: "POST", body: { text: $("#pg-text").value, path: $("#pg-path").value || "playground.txt" } });
    $("#pg-out").innerHTML = r.findings.map((f) => `<div class="rcard"><div class="rhead">${sevChip(f.severity)}<span class="rtitle">${esc(f.title)}</span><span class="chip neutral">${Math.round((f.meta?.confidence || 0.6) * 100)}% confidence</span></div><div class="mono">${esc(f.secret_masked)}</div><div class="fmeta" style="margin-top:6px">${esc(f.path)}:${f.line} · entropy ${f.entropy} · ${esc(f.meta?.validation || "")}</div></div>`).join("") || empty("No secrets detected", "The sample did not match any detector.");
  };
}

async function renderScans() {
  const [jobs, scheds] = await Promise.all([api("/api/jobs"), api("/api/schedules")]);
  const active = jobs.jobs.filter((j) => ["queued", "running"].includes(j.status)).length;
  $("#main").innerHTML = pagehead("Scan Management", "Manual and scheduled coverage.",
    active ? `<span class="scan-live"><span class="dot"></span>${active} active ${active === 1 ? "scan" : "scans"}</span>` : "") +
    (canWrite() ? panel("New scan", `<div class="formrow"><div class="field grow"><label class="fld" for="sc-path">Server path</label><input class="input" id="sc-path" placeholder="e.g. examples/vulnerable" required></div><div class="field"><label class="fld" for="sc-surface">Detection surface</label><select class="input" id="sc-surface">${SURFACES.map((s) => `<option>${s}</option>`).join("")}</select></div><button class="btn primary" id="sc-run">Run scan</button></div><div class="scan-feedback" id="sc-feedback" role="status" aria-live="polite"></div>`) : "") +
    panel("Schedules", `${canWrite() ? `<div class="formrow" style="margin-bottom:10px"><div class="field grow"><input class="input" id="sh-path" placeholder="Path"></div><div class="field"><input class="input" id="sh-int" type="number" value="3600" min="60"></div><button class="btn sm" id="sh-add">Add schedule</button></div>` : ""}<div class="twrap"><table class="tbl"><thead><tr><th>ID</th><th>Path</th><th>Interval</th><th>Enabled</th><th></th></tr></thead><tbody>${scheds.schedules.map((s) => `<tr><td class="mono">${esc(s.id)}</td><td>${esc(s.path)}</td><td class="num">${s.interval_seconds}s</td><td>${s.enabled ? "yes" : "no"}</td><td>${canWrite() ? `<button class="btn sm ghost" data-sht="${esc(s.id)}">${s.enabled ? "Disable" : "Enable"}</button> <button class="btn sm ghost" data-shd="${esc(s.id)}">Delete</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="5">No schedules.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("Recent executions", `<div class="twrap"><table class="tbl"><thead><tr><th>Job</th><th>Path</th><th>Status</th><th class="num">Files</th><th class="num">New</th></tr></thead><tbody>${jobs.jobs.slice(0, 10).map((j) => `<tr><td class="mono">${esc(j.id)}</td><td class="truncate">${esc(j.path)}</td><td><span class="chip ${j.status === "done" ? "st-remediated" : j.status === "failed" ? "st-false_positive" : "st-open"}">${esc(j.status)}</span></td><td class="num">${j.files}</td><td class="num">${j.findings}</td></tr>`).join("")}</tbody></table></div>`, '<a class="btn sm ghost" href="#/jobs">All jobs</a>', true);
  const run = $("#sc-run");
  if (run) run.onclick = async () => {
    const path = $("#sc-path").value.trim();
    const feedback = $("#sc-feedback");
    if (!path) {
      feedback.innerHTML = `<div class="errbox">Enter a server path before starting a scan.</div>`;
      $("#sc-path").focus();
      return;
    }
    run.disabled = true;
    run.textContent = "Starting…";
    feedback.innerHTML = `<div class="scan-progress"><span class="spinner"></span>Submitting scan…</div>`;
    try {
      const r = await api("/api/jobs", { method: "POST", body: { path, surface: $("#sc-surface").value } });
      toast(`Scan ${r.id} queued`, "ok");
      feedback.innerHTML = `<div class="scan-progress"><span class="spinner"></span>Scan queued. Waiting for worker…</div>`;
      watchScan(r.id);
    } catch (e) {
      run.disabled = false;
      run.textContent = "Run scan";
      feedback.innerHTML = `<div class="errbox">${esc(e.message)}</div>`;
    }
  };
  const add = $("#sh-add"); if (add) add.onclick = async () => { await api("/api/schedules", { method: "POST", body: { path: $("#sh-path").value || ".", interval_seconds: +$("#sh-int").value || 3600 } }); toast("Schedule added", "ok"); renderScans(); };
  $$("[data-sht]").forEach((b) => (b.onclick = async () => { await api(`/api/schedules/${b.dataset.sht}/toggle`, { method: "POST", body: {} }); renderScans(); }));
  $$("[data-shd]").forEach((b) => (b.onclick = () => confirmModal("Delete schedule", "Stop this recurring scan.", async () => { await api(`/api/schedules/${b.dataset.shd}/delete`, { method: "POST", body: {} }); renderScans(); }, "Delete")));
}

function watchScan(id) {
  if (state.scanTimer) clearInterval(state.scanTimer);
  const poll = async () => {
    try {
      const { job } = await api(`/api/jobs/${encodeURIComponent(id)}`);
      const feedback = $("#sc-feedback");
      if (!feedback) return;
      if (job.status === "queued" || job.status === "running") {
        feedback.innerHTML = `<div class="scan-progress"><span class="spinner"></span>Scan ${esc(job.status)}… ${job.files || 0} files checked</div>`;
        return;
      }
      clearInterval(state.scanTimer);
      state.scanTimer = null;
      if (job.status === "done") {
        feedback.innerHTML = `<div class="okbox">Scan complete: ${job.files} files checked, ${job.findings} new findings.</div>`;
      } else if (job.status === "cancelled") {
        feedback.innerHTML = `<div class="errbox">Scan cancelled before completion.</div>`;
      } else {
        feedback.innerHTML = `<div class="errbox">Scan failed: ${esc(job.error || "The worker returned an unknown error.")}</div>`;
      }
      const run = $("#sc-run");
      if (run) { run.disabled = false; run.textContent = "Run scan"; }
    } catch (e) {
      clearInterval(state.scanTimer);
      state.scanTimer = null;
      const feedback = $("#sc-feedback");
      if (feedback) feedback.innerHTML = `<div class="errbox">${esc(e.message)}</div>`;
      const run = $("#sc-run");
      if (run) { run.disabled = false; run.textContent = "Run scan"; }
    }
  };
  poll();
  state.scanTimer = setInterval(poll, 1000);
}

const SURFACE_SETS = { repositories: ["git", "pre_push", "ci"], developer: ["ide", "filesystem"], cloud: ["cloud"], cicd: ["ci"], saas: ["slack", "jira", "confluence", "postman"] };
const SURFACE_TITLES = { repositories: ["Repository Security", "Git, pre-push and CI exposure."], developer: ["Developer Security", "IDE and local filesystem exposure."], cloud: ["Cloud Security", "Lambda code and environment exposure."], cicd: ["CI/CD Security", "Pipeline configuration and diff-gate exposure."], saas: ["SaaS Security", "Collaboration and API-collection exposure."] };
async function renderSurfaceView() {
  const set = SURFACE_SETS[state.view];
  const [title, sub] = SURFACE_TITLES[state.view];
  const [all, sources] = await Promise.all([api("/api/findings?limit=500"), api("/api/sources")]);
  const rows = all.findings.filter((f) => set.includes(f.surface));
  $("#main").innerHTML = pagehead(title, sub, canWrite() ? `<button class="btn sm" id="sv-scan">Scan now</button>` : "") +
    `<div style="margin-bottom:12px">${set.map((s) => { const src = sources.sources.find((x) => x.surface === s); return `<span class="chip ${src && src.status === "monitored" ? "st-remediated" : "neutral"}" title="${src ? src.findings + " findings" : ""}">${esc(SLABEL[s])}</span>`; }).join(" ")}</div>` +
    panel(`${rows.length} findings`, `<div class="twrap"><table class="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Asset</th><th>Owner</th><th>Status</th></tr></thead><tbody>${rows.map((r) => `<tr class="clickable" data-open="${esc(r.id)}"><td>${sevChip(r.severity)}</td><td>${esc(r.title)}<span class="cellsub mono">${esc(r.detector_id)}</span></td><td>${esc(SLABEL[r.surface])}</td><td class="mono truncate">${esc(r.path)}:${r.line}</td><td>${esc(r.assignee || r.owner || "-")}</td><td>${stChip(r.status)}</td></tr>`).join("") || `<tr><td colspan="6">${empty("No findings", "This surface group is clean.")}</td></tr>`}</tbody></table></div>`, "", true);
  const scan = $("#sv-scan"); if (scan) scan.onclick = async () => { const r = await api("/api/jobs", { method: "POST", body: { path: "examples/vulnerable", surface: set[0] } }); toast(`Job ${r.id} queued`, "ok"); };
  bindOpeners();
}

async function renderAssets() {
  const d = await api("/api/assets");
  const critical = d.assets.filter((a) => a.critical > 0).length;
  $("#main").innerHTML = pagehead("Asset Inventory", "Detection-derived inventory with risk concentration.") +
    `<div class="mgrid" style="grid-template-columns:repeat(3,1fr)"><div class="metric"><div class="mlabel">Assets</div><div class="mvalue">${d.assets.length}</div><div class="msub">monitored</div></div><div class="metric t-crit"><div class="mlabel">With critical findings</div><div class="mvalue">${critical}</div><div class="msub">prioritize</div></div><div class="metric t-ok"><div class="mlabel">Monitored</div><div class="mvalue">${d.assets.filter((a) => a.monitored).length}</div><div class="msub">active coverage</div></div></div>` +
    panel("Assets", `<div class="twrap"><table class="tbl"><thead><tr><th>Asset</th><th>Type</th><th>Owner</th><th>Environment</th><th class="num">Findings</th><th class="num">Critical</th><th>Technologies</th><th>Risk</th><th>Last scan</th></tr></thead><tbody>${d.assets.map((a) => `<tr><td>${esc(a.name)}<span class="cellsub mono">${esc(a.id)}</span></td><td>${esc(SLABEL[a.type] || a.type)}</td><td>${esc(a.owner || "-")}</td><td>${esc(a.environment)}</td><td class="num">${a.findings}</td><td class="num">${a.critical}</td><td>${esc((a.technologies||[]).slice(0,3).join(", ")||"-")}</td><td>${riskbar({ score: a.risk, band: a.risk >= 80 ? "critical" : a.risk >= 60 ? "high" : "medium" })}</td><td>${utc(a.last_scan)}</td></tr>`).join("") || '<tr><td colspan="9">No assets derived yet.</td></tr>'}</tbody></table></div>`, "", true);
}

async function renderRemediation() {
  const d = await api("/api/remediation");
  $("#main").innerHTML = pagehead("Remediation Center", "SLA-tracked tasks, checklists and rotation playbooks.") +
    `<div class="mgrid" style="grid-template-columns:repeat(3,1fr)"><div class="metric t-danger"><div class="mlabel">SLA breached</div><div class="mvalue">${d.sla.breached}</div><div class="msub">escalate now</div></div><div class="metric t-warn"><div class="mlabel">At risk</div><div class="mvalue">${d.sla.at_risk}</div><div class="msub">approaching SLA</div></div><div class="metric"><div class="mlabel">Open tasks</div><div class="mvalue">${d.tasks.length}</div><div class="msub">in queue</div></div></div>` +
    panel("Task queue", `<div class="twrap"><table class="tbl"><thead><tr><th>Finding</th><th>Severity</th><th>Assignee</th><th>SLA</th><th>Age</th><th>Checklist</th><th></th></tr></thead><tbody>${d.tasks.map((t) => `<tr><td>${esc(t.title)}<span class="cellsub mono">${esc(t.finding_id)}</span></td><td>${sevChip(t.severity)}</td><td>${esc(t.assignee || "-")}</td><td class="num">${t.sla_hours}h</td><td class="num" style="${t.breached ? "color:var(--danger)" : ""}">${t.age_hours}h</td><td><span class="progress"><span class="track"><span class="fill" style="width:${20 * t.checklist_done}%"></span></span><span class="pv">${t.checklist_done}/${t.checklist_total}</span></span></td><td><button class="btn sm" data-open="${esc(t.finding_id)}">Open</button></td></tr>`).join("") || '<tr><td colspan="7">Queue is clear.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("Rotation playbooks", d.playbooks.map((p) => `<div class="acc"><button class="acc-head">${esc(p.family.replace(/-/g, " "))} ${icon("chev")}</button><div class="acc-body"><ol>${p.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div></div>`).join(""));
  $$(".acc-head").forEach((h) => (h.onclick = () => h.parentElement.classList.toggle("open")));
  bindOpeners();
}

async function renderAlerts() {
  const d = await api("/api/alerts?limit=60");
  $("#main").innerHTML = pagehead("Security Alerts", "Delivered notifications with acknowledgement state.") +
    panel("Alerts", `<div class="feed">${d.alerts.map((a) => `<div class="feeditem"><span class="ficon">${icon("bell")}</span><div class="fbody"><div class="ftext">${esc(a.message)}</div><div class="fmeta"><span class="chip neutral">${esc(a.channel)}</span><span>${esc(a.status)}</span><span title="${utc(a.ts)}">${rel(a.ts)} ago</span>${a.ack ? `<span>ack by ${esc(a.ack.username)}</span>` : canWrite() ? `<button class="btn sm ghost" data-ack="${esc(a.id)}">Acknowledge</button>` : ""}</div></div></div>`).join("") || empty("No alerts", "Alerts appear when findings are confirmed.")}</div>`, "", true);
  $$("[data-ack]").forEach((b) => (b.onclick = async () => { await api(`/api/alerts/${b.dataset.ack}/ack`, { method: "POST", body: {} }); toast("Acknowledged", "ok"); renderAlerts(); }));
}

async function renderInvestigations() {
  const d = await api("/api/investigations");
  $("#main").innerHTML = pagehead("Investigation Center", "Findings with active notes or ownership.") +
    panel("Open investigations", `<div class="twrap"><table class="tbl"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Assignee</th><th class="num">Notes</th><th class="num">Related</th><th></th></tr></thead><tbody>${d.investigations.map((i) => `<tr><td>${esc(i.title)}<span class="cellsub mono">${esc(i.id)}</span></td><td>${sevChip(i.severity)}</td><td>${stChip(i.status)}</td><td>${esc(i.assignee || "-")}</td><td class="num">${i.notes}</td><td class="num">${i.related}</td><td><button class="btn sm" data-open="${esc(i.id)}">Investigate</button></td></tr>`).join("") || '<tr><td colspan="7">No active investigations.</td></tr>'}</tbody></table></div>`, "", true);
  bindOpeners();
}

async function renderExceptions() {
  const d = await api("/api/exceptions");
  $("#main").innerHTML = pagehead("Exception Management", "Allowlist, accepted risk and suppression with audited reasons.") +
    (canWrite() ? panel("Record exception", `<div class="formrow"><div class="field"><input class="input mono" id="ex-id" placeholder="finding id"></div><div class="field"><select class="input" id="ex-kind"><option value="accepted_risk">accepted risk</option><option value="suppressed">suppressed</option></select></div><div class="field grow"><input class="input" id="ex-reason" placeholder="Reason (audited)"></div><button class="btn sm primary" id="ex-add">Record</button></div>`) : "") +
    panel("Fingerprint allowlist", `${canWrite() ? `<div class="formrow" style="margin-bottom:10px"><div class="field grow"><input class="input mono" id="al-fp" placeholder="SHA-256 fingerprint"></div><div class="field grow"><input class="input" id="al-reason" placeholder="Reason"></div><button class="btn sm" id="al-add">Add</button></div>` : ""}<div class="twrap"><table class="tbl"><thead><tr><th>Fingerprint</th><th>Reason</th><th>Added</th></tr></thead><tbody>${d.allowlist.map((e) => `<tr><td class="mono truncate">${esc(e.fingerprint)}</td><td>${esc(e.reason)}</td><td>${utc(e.created_at)}</td></tr>`).join("") || '<tr><td colspan="3">No entries.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("Excepted findings", `<div class="twrap"><table class="tbl"><thead><tr><th>Finding</th><th>Status</th><th>Owner</th><th></th></tr></thead><tbody>${d.exceptions.map((f) => `<tr><td>${esc(f.title)}<span class="cellsub mono">${esc(f.id)}</span></td><td>${stChip(f.status)}</td><td>${esc(f.owner || "-")}</td><td><button class="btn sm" data-open="${esc(f.id)}">Open</button></td></tr>`).join("") || '<tr><td colspan="4">None.</td></tr>'}</tbody></table></div>`, "", true);
  const ex = $("#ex-add"); if (ex) ex.onclick = async () => { try { await api("/api/exceptions", { method: "POST", body: { finding_id: $("#ex-id").value.trim(), kind: $("#ex-kind").value, reason: $("#ex-reason").value } }); toast("Exception recorded", "ok"); renderExceptions(); } catch (e) { toast(e.message, "error"); } };
  const al = $("#al-add"); if (al) al.onclick = async () => { await api("/api/allowlist", { method: "POST", body: { fingerprint: $("#al-fp").value.trim(), reason: $("#al-reason").value } }); toast("Allowlisted", "ok"); renderExceptions(); };
  bindOpeners();
}

async function renderIntegrations() {
  const d = await api("/api/integrations");
  $("#main").innerHTML = pagehead("Integrations", "SENTRIX Connect: honest connection state for every provider.") +
    `<div class="cardgrid">${d.integrations.map((i) => `<div class="icard"><div class="ihead"><span class="iname">${esc(i.name)}</span>${statusChip(i.status)}</div>
      <div class="irow"><span class="k">Auth</span><span class="v">${esc(i.auth)}</span></div>
      <div class="irow"><span class="k">Last sync</span><span class="v">${utc(i.last_sync)}</span></div>
      <div class="irow"><span class="k">Findings</span><span class="v">${i.findings}</span></div>
      <div class="irow"><span class="k">Rate limit</span><span class="v">${esc(i.rate_limit)}</span></div>
      <div class="irow"><span class="k">Resources</span><span class="v">${i.resources.map(esc).join(", ") || "-"}</span></div>
      <div>${i.permissions.map((p) => `<span class="perm">${esc(p)}</span>`).join("")}</div>
      ${i.errors.length ? `<div class="errbox">${i.errors.map(esc).join("<br>")}</div>` : ""}
      ${canWrite() ? `<div class="iactions"><button class="btn sm" data-sync="${esc(i.id)}">Sync</button><button class="btn sm ghost" data-itoggle="${esc(i.id)}">Toggle</button><button class="btn sm ghost" data-idisc="${esc(i.id)}">Disconnect</button></div>` : ""}</div>`).join("")}</div>`;
  $$("[data-sync]").forEach((b) => (b.onclick = async () => { await api(`/api/integrations/${b.dataset.sync}/sync`, { method: "POST", body: {} }); toast("Sync recorded", "ok"); renderIntegrations(); }));
  $$("[data-itoggle]").forEach((b) => (b.onclick = async () => { await api(`/api/integrations/${b.dataset.itoggle}/toggle`, { method: "POST", body: {} }); renderIntegrations(); }));
  $$("[data-idisc]").forEach((b) => (b.onclick = () => confirmModal("Disconnect integration", "Mark this connector disconnected.", async () => { await api(`/api/integrations/${b.dataset.idisc}/disconnect`, { method: "POST", body: {} }); renderIntegrations(); }, "Disconnect")));
}

async function renderJobs() {
  const d = await api("/api/jobs");
  $("#main").innerHTML = pagehead("Background Jobs", "Execution history, cancellation and failure diagnostics.") +
    panel("Executions", `<div class="searchbar" style="margin-bottom:8px"><span class="chip neutral">Total ${d.jobs.length}</span> <span class="chip st-remediated">Done ${d.jobs.filter(j=>j.status==="done").length}</span> <span class="chip st-false_positive">Failed ${d.jobs.filter(j=>j.status==="failed").length}</span> <span class="chip st-triaged">Active ${d.jobs.filter(j=>["queued","running"].includes(j.status)).length}</span> <a class="btn sm ghost" href="#/workers">Workers & Agents</a></div><div class="twrap"><table class="tbl"><thead><tr><th>Job</th><th>Path</th><th>Initiator</th><th>Status</th><th>Started</th><th>Finished</th><th class="num">Files</th><th class="num">New</th><th></th></tr></thead><tbody>${d.jobs.map((j) => `<tr class="clickable" data-job="${esc(j.id)}"><td class="mono">${esc(j.id)}</td><td class="truncate">${esc(j.path)}</td><td>${esc(j.triggered_by)}</td><td><span class="chip ${j.status === "done" ? "st-remediated" : j.status === "failed" ? "st-false_positive" : j.status === "cancelled" ? "neutral" : "st-open"}" title="Job status">${esc(j.status)}</span></td><td>${utc(j.started)}</td><td>${utc(j.finished)}</td><td class="num">${j.files}</td><td class="num">${j.findings}</td><td>${canWrite() && ["queued", "running"].includes(j.status) ? `<button class="btn sm ghost" data-cancel="${esc(j.id)}">Cancel</button>` : ""}</td></tr>${j.error ? `<tr class="detailrow"><td colspan="9"><div class="errbox">${esc(j.error)}</div></td></tr>` : ""}`).join("") || '<tr><td colspan="9">No jobs yet.</td></tr>'}</tbody></table></div>`, "", true);
  $$("[data-cancel]").forEach((b) => (b.onclick = async (e) => { e.stopPropagation(); await api(`/api/jobs/${b.dataset.cancel}/cancel`, { method: "POST", body: {} }); toast("Cancellation requested", "warn"); renderJobs(); }));
}

async function renderLogs() {
  const d = await api(`/api/logs?limit=200${state.logLevel ? `&level=${state.logLevel}` : ""}${state.logSource ? `&source=${encodeURIComponent(state.logSource)}` : ""}`);
  let logs = d.logs;
  if (state.logCorr) logs = logs.filter((l) => l.correlation_id === state.logCorr);
  if (state.logQ) logs = logs.filter((l) => (l.message + l.source + l.component).toLowerCase().includes(state.logQ.toLowerCase()));
  if (state.logRange !== "all") {
    const hours = { "1h": 1, "24h": 24, "7d": 168 }[state.logRange];
    logs = logs.filter((l) => Date.now() - new Date(l.ts + "Z").getTime() < hours * 3600000);
  }
  $("#main").innerHTML = pagehead("System Logs", "Structured journal with correlation across pipeline stages.",
    `<a class="btn sm" href="/api/logs/export">${icon("download")} Export</a>`) +
    `<section class="panel"><div class="toolbar"><input class="input grow" id="lg-q" placeholder="Search messages" value="${esc(state.logQ)}"><select class="input" id="lg-level"><option value="">All levels</option>${["info", "warn", "error"].map((l) => `<option ${state.logLevel === l ? "selected" : ""}>${l}</option>`).join("")}</select><select class="input" id="lg-source"><option value="">All sources</option>${[...new Set([...d.logs.map((l) => l.source), ...(state.logSource ? [state.logSource] : [])])].map((s) => `<option ${state.logSource === s ? "selected" : ""}>${esc(s)}</option>`).join("")}</select><select class="input" id="lg-range">${["all", "1h", "24h", "7d"].map((r) => `<option value="${r}" ${state.logRange === r ? "selected" : ""}>${r === "all" ? "All time" : r}</option>`).join("")}</select><button class="btn sm ghost" id="lg-pause">${state.paused ? "Resume" : "Pause"}</button>${state.logCorr ? `<button class="btn sm" id="lg-clearcorr">corr: ${esc(state.logCorr)} ×</button>` : ""}</div>
    <div>${logs.map((l) => `<div class="logrow expandable" data-log="${l.id}"><span class="lts">${utc(l.ts)}</span><span class="chip sev-${l.level === "error" ? "critical" : l.level === "warn" ? "medium" : "info"}">${esc(l.level)}</span><span class="chip neutral">${esc(l.source)}</span><span class="lmsg">${esc(l.message)}</span>${l.correlation_id ? `<button class="corrlink" data-corr="${esc(l.correlation_id)}">${esc(l.correlation_id)}</button>` : ""}</div><div class="logdetail" id="ld-${l.id}" hidden><dl class="kv"><dt>Component</dt><dd>${esc(l.component || l.source)}</dd><dt>Event type</dt><dd>${esc(l.event_type || "-")}</dd><dt>Execution id</dt><dd class="mono">${esc(l.exec_id || "-")}</dd><dt>Resource</dt><dd>${esc(l.resource || "-")}</dd><dt>Status</dt><dd>${esc(l.status || "-")}</dd><dt>Correlation</dt><dd class="mono">${esc(l.correlation_id || "-")}</dd></dl></div>`).join("") || empty("No log entries", "Adjust filters or wait for activity.")}</div></section>`;
  $("#lg-q").oninput = (e) => { clearTimeout(state.lqt); state.lqt = setTimeout(() => { state.logQ = e.target.value; renderLogs(); }, 250); };
  $("#lg-level").onchange = (e) => { state.logLevel = e.target.value; renderLogs(); };
  $("#lg-source").onchange = (e) => { state.logSource = e.target.value; renderLogs(); };
  $("#lg-range").onchange = (e) => { state.logRange = e.target.value; renderLogs(); };
  $("#lg-pause").onclick = () => { state.paused = !state.paused; renderLogs(); };
  const cc = $("#lg-clearcorr"); if (cc) cc.onclick = () => { state.logCorr = ""; renderLogs(); };
  $$("[data-corr]").forEach((b) => (b.onclick = (e) => { e.stopPropagation(); state.logCorr = b.dataset.corr; renderLogs(); }));
  $$("[data-log]").forEach((r) => (r.onclick = () => { const d = $(`#ld-${r.dataset.log}`); d.hidden = !d.hidden; }));
}

async function renderAudit() {
  const [a, e] = await Promise.all([api("/api/audit?limit=150"), api("/api/events?limit=100")]);
  $("#main").innerHTML = pagehead("Activity & Audit", "Accountability trail and pipeline events.") +
    `<div class="tabs"><button class="tab ${state.auditTab === "audit" ? "active" : ""}" data-atab="audit">Audit</button><button class="tab ${state.auditTab === "events" ? "active" : ""}" data-atab="events">Events</button></div>` +
    (state.auditTab === "audit" ? panel("Audit trail", `<div class="twrap"><table class="tbl"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>${a.audit.map((x) => `<tr><td>${utc(x.ts)}</td><td>${esc(x.username)}</td><td class="mono">${esc(x.action)}</td><td class="truncate">${esc(x.detail)}</td></tr>`).join("")}</tbody></table></div>`, "", true)
      : panel("Pipeline events", `<div class="feed">${e.events.map((x) => `<div class="feeditem"><span class="ficon">${icon("pulse")}</span><div class="fbody"><div class="ftext mono">${esc(x.kind)}</div><div class="fmeta"><span>${esc(x.surface)}</span><span>${utc(x.ts)}</span><span class="mono">${esc(JSON.stringify(x.payload))}</span></div></div></div>`).join("")}</div>`, "", true));
  $$("[data-atab]").forEach((b) => (b.onclick = () => { state.auditTab = b.dataset.atab; renderAudit(); }));
}

async function renderHealth() {
  const h = await api("/api/system/health");
  $("#main").innerHTML = pagehead("System Health", "Runtime, storage and worker vitals.",
    isAdmin() ? `<button class="btn sm" id="hl-backup">Backup</button><button class="btn sm ghost" id="hl-vacuum">Vacuum</button>` : "") +
    `<div class="mgrid" style="grid-template-columns:repeat(4,1fr)"><div class="metric t-accent"><div class="mlabel">Uptime</div><div class="mvalue">${Math.round(h.uptime_seconds / 60)}m</div><div class="msub">${h.uptime_seconds}s</div></div><div class="metric"><div class="mlabel">Database</div><div class="mvalue">${(h.db_bytes / 1024).toFixed(0)}K</div><div class="msub">bytes on disk</div></div><div class="metric"><div class="mlabel">Threads</div><div class="mvalue">${h.threads}</div><div class="msub">active</div></div><div class="metric"><div class="mlabel">Users</div><div class="mvalue">${h.users}</div><div class="msub">accounts</div></div></div>` +
    `<div class="grid c2"><section class="panel"><div class="phead"><span class="ptitle">Jobs by status</span></div><div class="pbody">${hbars(Object.entries(h.jobs).map(([label, value]) => ({ label, value })))}</div></section><section class="panel"><div class="phead"><span class="ptitle">Runtime</span></div><div class="pbody"><dl class="kv"><dt>Version</dt><dd>SENTRIX ${esc(h.version)}</dd><dt>Python</dt><dd>${esc(h.python)}</dd><dt>Storage</dt><dd class="mono">${esc(h.storage)}</dd></dl></div></section></div>`;
  const b = $("#hl-backup"); if (b) b.onclick = async () => { const r = await api("/api/ops/backup", { method: "POST", body: {} }); toast(`Backup: ${r.path}`, "ok"); };
  const v = $("#hl-vacuum"); if (v) v.onclick = async () => { await api("/api/ops/vacuum", { method: "POST", body: {} }); toast("Vacuum complete", "ok"); };
}

async function renderReports() {
  const d = await api("/api/reports");
  $("#main").innerHTML = pagehead("Reports", "Governance and posture packs generated from live records.") +
    (canWrite() ? panel("Generate report", `<div class="formrow"><div class="field grow"><select class="input" id="rp-type">${d.types.map((t) => `<option value="${t.id}">${esc(t.title)}</option>`).join("")}</select></div><div class="field"><select class="input" id="rp-fmt"><option value="csv">CSV</option><option value="json">JSON</option></select></div><button class="btn primary" id="rp-gen">Generate</button></div>`) : "") +
    panel("Export history", `<div class="twrap"><table class="tbl"><thead><tr><th>ID</th><th>Type</th><th>Format</th><th>By</th><th class="num">Rows</th><th>Created</th><th></th></tr></thead><tbody>${d.reports.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.type)}</td><td>${esc(r.format)}</td><td>${esc(r.created_by)}</td><td class="num">${r.rows}</td><td>${utc(r.created_at)}</td><td><a class="btn sm" href="${esc(r.id ? `/api/reports/${r.id}/download` : "#")}">${icon("download")} Download</a></td></tr>`).join("") || '<tr><td colspan="7">No reports generated yet.</td></tr>'}</tbody></table></div>`, "", true) +
    `<p class="pnote" style="color:var(--faint);font-size:11.5px">Reports are evidence generated from storage; they do not certify compliance.</p>`;
  const g = $("#rp-gen"); if (g) g.onclick = async () => { const r = await api("/api/reports", { method: "POST", body: { type: $("#rp-type").value, format: $("#rp-fmt").value } }); toast(`Report ${r.id} generated (${r.rows} rows)`, "ok"); renderReports(); };
}

async function renderCompliance() {
  const d = await api("/api/compliance");
  $("#main").innerHTML = pagehead("Compliance", "Control-to-evidence mapping across frameworks.") +
    panel("Evidence mapping", `<div class="twrap"><table class="tbl"><thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Evidence</th><th>Status</th></tr></thead><tbody>${d.mappings.map((m) => `<tr><td>${esc(m.framework)}</td><td class="mono">${esc(m.control)}</td><td>${esc(m.title)}</td><td>${m.evidence.map((e) => `<span class="chip neutral">${esc(e)}</span>`).join(" ")}</td><td><span class="chip ${m.status === "supported" ? "st-remediated" : "st-triaged"}">${esc(m.status)}</span></td></tr>`).join("")}</tbody></table></div>`, "", true) +
    `<div class="banner"><span class="chip st-triaged">NOTE</span> ${esc(d.note)}</div>`;
}

async function renderAccess() {
  const [u, t] = await Promise.all([api("/api/users"), api("/api/tokens")]);
  const roles = ["super_admin", "security_admin", "security_analyst", "appsec_engineer", "devsecops_engineer", "developer", "auditor", "viewer"];
  $("#main").innerHTML = pagehead("Access Management", "Eight-role RBAC, accounts and API tokens.") +
    panel("Users", `${isAdmin() ? `<div class="banner" style="margin-bottom:10px">Company roster is fixed at six people. New accounts cannot be created, and roles or titles are restored to the canonical roster on restart.</div>` : ""}<div class="twrap"><table class="tbl"><thead><tr><th>User</th><th>Title</th><th>Role</th><th>Disabled</th><th></th></tr></thead><tbody>${u.users.map((x) => `<tr><td><span class="user-cell">${personAvatar(x.username, { size: "sm" })}<span>${esc(x.username)}</span></span></td><td>${esc(x.title || "-")}</td><td>${isAdmin() ? `<select class="input" data-urole="${esc(x.username)}">${roles.map((r) => `<option ${x.role === r ? "selected" : ""}>${r}</option>`).join("")}</select>` : esc(x.role)}</td><td>${x.disabled ? "yes" : "no"}</td><td>${isAdmin() ? `<button class="btn sm ghost" data-udis="${esc(x.username)}" data-dis="${x.disabled ? 0 : 1}">${x.disabled ? "Enable" : "Disable"}</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`, "", true) +
    panel("API tokens", `${isAdmin() ? `<div class="formrow" style="margin-bottom:10px"><div class="field"><input class="input" id="tk-name" placeholder="token name"></div><div class="field"><select class="input" id="tk-role">${roles.map((r) => `<option>${r}</option>`).join("")}</select></div><button class="btn sm primary" id="tk-create">Create token</button></div><div id="tk-reveal"></div>` : ""}<div class="twrap"><table class="tbl"><thead><tr><th>ID</th><th>Name</th><th>Role</th><th>Revoked</th><th></th></tr></thead><tbody>${t.tokens.map((x) => `<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.name)}</td><td>${esc(x.role)}</td><td>${x.revoked ? "yes" : "no"}</td><td>${isAdmin() && !x.revoked ? `<button class="btn sm ghost" data-trev="${esc(x.id)}">Revoke</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="5">No tokens.</td></tr>'}</tbody></table></div>`, "", true);
  $$("[data-urole]").forEach((s) => (s.onchange = () => api(`/api/users/${s.dataset.urole}/role`, { method: "POST", body: { role: s.value } })));
  $$("[data-udis]").forEach((b) => (b.onclick = async () => { await api(`/api/users/${b.dataset.udis}/disable`, { method: "POST", body: { disabled: b.dataset.dis === "1" } }); renderAccess(); }));
  const tc = $("#tk-create"); if (tc) tc.onclick = async () => { const r = await api("/api/tokens", { method: "POST", body: { name: $("#tk-name").value || "ci", role: $("#tk-role").value } }); $("#tk-reveal").innerHTML = `<div class="okbox mono">${esc(r.token)}</div><p style="color:var(--warn);font-size:11.5px">Copy now - shown once.</p>`; };
  $$("[data-trev]").forEach((b) => (b.onclick = async () => { await api(`/api/tokens/${b.dataset.trev}/revoke`, { method: "POST", body: {} }); renderAccess(); }));
}

async function renderSettings() {
  const tabs = [["profile", "Profile"], ["rules", "Alert rules"], ["data", "Data operations"], ["about", "About"]];
  $("#main").innerHTML = pagehead("Settings", "Profile, alerting policy and data operations.", "", icon("gear")) +
    `<div class="tabs">${tabs.map(([id, label]) => `<button class="tab ${state.settingsTab === id ? "active" : ""}" data-stab="${id}">${label}</button>`).join("")}</div><div id="st-body">${skeleton()}</div>`;
  $$("[data-stab]").forEach((b) => (b.onclick = () => { state.settingsTab = b.dataset.stab; renderSettings(); }));
  const body = $("#st-body");
  if (state.settingsTab === "profile") {
    body.innerHTML = panel("Profile", `<div class="profile-head">${personAvatar(state.user.username, { size: "lg" })}<div class="profile-ident"><strong>${esc(state.user.username)}</strong><span>${esc(state.user.title || state.user.role)}</span></div></div>` + `${canWrite() ? "" : `<div class="banner" style="margin-bottom:10px">This is a read-only account, so you can't send Hubs messages or pings. You can still read conversations and receive messages.</div>`}<dl class="kv"><dt>Username</dt><dd>${esc(state.user.username)}</dd><dt>Role</dt><dd>${esc(state.user.role)}</dd><dt>Title</dt><dd>${esc(state.user.title || "-")}</dd></dl><div class="formrow" style="margin-top:12px"><div class="field"><input class="input" id="pw-old" type="password" placeholder="Current password"></div><div class="field"><input class="input" id="pw-new" type="password" placeholder="New password (10+)"></div><button class="btn primary" id="pw-save">Change password</button></div>`);
    $("#pw-save").onclick = async () => { try { await api("/api/auth/password", { method: "POST", body: { old: $("#pw-old").value, new: $("#pw-new").value } }); toast("Password changed", "ok"); } catch (e) { toast(e.message, "error"); } };
  } else if (state.settingsTab === "rules") {
    const d = await api("/api/rules");
    body.innerHTML = panel("Channel rules", `${canWrite() ? `<div class="formrow" style="margin-bottom:10px"><div class="field"><select class="input" id="ar-ch">${["console", "outbox", "slack", "webhook"].map((c) => `<option>${c}</option>`).join("")}</select></div><div class="field"><select class="input" id="ar-sev">${SEVS.map((s) => `<option>${s}</option>`).join("")}</select></div><button class="btn sm" id="ar-add">Add rule</button></div>` : ""}<div class="twrap"><table class="tbl"><thead><tr><th>Channel</th><th>Min severity</th><th>Enabled</th><th></th></tr></thead><tbody>${d.rules.map((r) => `<tr><td>${esc(r.channel)}</td><td>${esc(r.min_severity)}</td><td>${r.enabled ? "yes" : "no"}</td><td>${canWrite() ? `<button class="btn sm ghost" data-art="${esc(r.id)}">${r.enabled ? "Disable" : "Enable"}</button> <button class="btn sm ghost" data-ard="${esc(r.id)}">Delete</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="4">No rules - channels receive everything.</td></tr>'}</tbody></table></div>`, "", true);
    const add = $("#ar-add"); if (add) add.onclick = async () => { await api("/api/rules", { method: "POST", body: { channel: $("#ar-ch").value, min_severity: $("#ar-sev").value } }); renderSettings(); };
    $$("[data-art]").forEach((b) => (b.onclick = async () => { await api(`/api/rules/${b.dataset.art}/toggle`, { method: "POST", body: {} }); renderSettings(); }));
    $$("[data-ard]").forEach((b) => (b.onclick = async () => { await api(`/api/rules/${b.dataset.ard}/delete`, { method: "POST", body: {} }); renderSettings(); }));
  } else if (state.settingsTab === "data") {
    const ops = await api("/api/ops/stats");
    body.innerHTML = panel("Data operations", `<dl class="kv"><dt>Database</dt><dd>${(ops.db_bytes / 1024).toFixed(1)} KiB</dd><dt>Jobs</dt><dd>${ops.jobs}</dd><dt>Schedules</dt><dd>${ops.schedules}</dd><dt>Users</dt><dd>${ops.users}</dd></dl>
      <div class="formrow" style="margin-top:12px"><a class="btn" href="/api/export?format=csv">Export CSV</a><a class="btn" href="/api/export?format=json">Export JSON</a>${isAdmin() ? `<button class="btn" id="do-backup">Backup</button><button class="btn ghost" id="do-vacuum">Vacuum</button>` : ""}</div>
      ${isAdmin() ? `<div class="formrow" style="margin-top:10px"><div class="field"><input class="input" id="do-days" type="number" value="90" min="1"></div><button class="btn danger" id="do-purge">Purge closed findings older than (days)</button></div>` : ""}
      ${canWrite() ? `<div class="formrow" style="margin-top:10px"><button class="btn ghost" id="do-demo">Load demo again (reset all employee/demo data)</button></div>` : ""}`);
    const b = $("#do-backup"); if (b) b.onclick = async () => { const r = await api("/api/ops/backup", { method: "POST", body: {} }); toast(`Backup: ${r.path}`, "ok"); };
    const v = $("#do-vacuum"); if (v) v.onclick = async () => { await api("/api/ops/vacuum", { method: "POST", body: {} }); toast("Vacuum complete", "ok"); };
    const p = $("#do-purge"); if (p) p.onclick = () => confirmModal("Purge closed findings", "Removes remediated/false-positive findings older than the given days.", async () => { const r = await api("/api/ops/purge", { method: "POST", body: { days: +$("#do-days").value || 90 } }); toast(`Purged ${r.removed}`, "ok"); }, "Purge");
    const dm = $("#do-demo"); if (dm) dm.onclick = () => confirmModal("Load demo again", "Reset EVERY employee assignment, workload/profile state, assignment history, and demo findings back to the current demo state for all users. Continue?", async () => { if (typeof _asnTeamCache !== 'undefined') _asnTeamCache = null; await api("/api/demo/reset", { method: "POST", body: {} }); toast("Demo data and all employee/assignment state reset to current demo state", "ok"); }, "Load demo again");
  } else {
    const cfg = await api("/api/config");
    const h = await api("/api/health");
    body.innerHTML = panel("About SENTRIX", `<dl class="kv"><dt>Product</dt><dd>SENTRIX ${esc(h.version)}</dd><dt>Full name</dt><dd>Secret Exposure & Network Threat Response Intelligence eXchange</dd><dt>Tagline</dt><dd>One Intelligence. Every Exposure. Total Control.</dd><dt>Python</dt><dd>${esc(h.python)}</dd></dl><pre class="codeblock">${esc(JSON.stringify(cfg, null, 2))}</pre>`);
  }
}

/* ================= drawer ================= */

function bindOpeners() {
  $$("[data-open]").forEach((el) => {
    if (el.dataset.bound) return;
    el.dataset.bound = "1";
    el.addEventListener("click", (e) => {
      if (e.target.closest("input,select,button[data-select]")) return;
      state.drawerId = el.dataset.open; state.drawerTab = "overview"; openDrawer();
    });
  });
}

async function openDrawer() {
  const id = state.drawerId;
  if (!id) return;
  $("#overlays").insertAdjacentHTML("beforeend", `<div class="scrim" id="dscrim"></div><aside class="drawer" role="dialog" aria-modal="true"><div class="dbody">${skeleton()}</div></aside>`);
  $("#dscrim").onclick = closeDrawer;
  await loadDrawer();
}
function closeDrawer() { state.drawerId = null; $("#dscrim")?.remove(); $(".drawer")?.remove(); }

async function loadDrawer() {
  const id = state.drawerId;
  if (!id) return;
  const d = await api(`/api/findings/${id}`);
  const f = d.finding, ex = d.extra || {};
  const asn = d.assignment || {};
  const asH = d.assignment_history || [];
  const wf = d.workflow || asn.workflow || {stage:'New', stages:['New','Assigned','Primary Review','Secondary Review','Admin Review','Remediation','Verification','Closed'], status_labels:[]};
  const canManage = (typeof canManageAssignments==='function' && canManageAssignments());
  const isAdmin = (typeof isAssignmentAdmin==='function' && isAssignmentAdmin()) || canManage;
  const me = state.user && state.user.username;
  const isPrimary = me && asn.primary_owner === me;
  const isSecondary = me && asn.secondary_reviewer === me;
  const meta = f.meta || {}; const origin = meta.origin || {};
  const curStage = wf.stage || 'New';
  const stages = wf.stages || ['New','Assigned','Primary Review','Secondary Review','Admin Review','Remediation','Verification','Closed'];
  const si = stages.indexOf(curStage);
  const stageBar = `<div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center;margin:8px 0 10px">${stages.map((s,i)=>`<span class="chip ${i<si?'st-remediated':i===si?'st-in_progress':'neutral'}" style="opacity:${i<=si?1:.45};font-size:11px">${i<si?'✓ ':''}${esc(s)}</span>`).join('<span style="color:var(--faint)">→</span>')}</div>`;
  const labels = (wf.status_labels||[]).map(x=>`<span class="chip neutral" style="margin-right:4px">${esc(x)}</span>`).join('');
  const essential = `<div class="dsect"><h3>Finding</h3><dl class="kv"><dt>Finding ID</dt><dd class="mono">${esc(f.id)}</dd><dt>Severity</dt><dd>${sevChip(f.severity)}</dd><dt>Risk score</dt><dd>${Math.round(((meta.risk||{}).score)||0)}</dd><dt>Description</dt><dd>${esc(meta.description||f.title||'')}</dd><dt>Detection source</dt><dd>${esc(SLABEL[f.surface]||f.surface||'-')}</dd><dt>Affected asset</dt><dd class="mono">${esc(f.path||'-')}${f.line?':'+f.line:''}</dd><dt>Detection date</dt><dd>${utc(f.created_at)}</dd><dt>Current workflow stage</dt><dd><strong>${esc(curStage)}</strong> ${labels}</dd></dl>${stageBar}</div>`;

  const assessBlock = (title, who, cls, reason, evidence, submitted) => submitted ? `<div class="dsect" style="border:1px solid var(--border);border-radius:10px;padding:10px"><h4 style="margin:0 0 6px">${esc(title)} — ${esc(who||'-')}</h4><dl class="kv"><dt>Classification / outcome</dt><dd><strong>${esc((cls||'').replace(/_/g,' ')||'-')}</strong></dd><dt>Submitted</dt><dd>${utc(submitted)}</dd></dl><div style="margin-top:8px"><div class="cellsub">Reasoning / notes</div><div style="font-size:12px;white-space:pre-wrap">${esc(reason||'-')}</div></div>${evidence?`<div style="margin-top:8px"><div class="cellsub">Evidence</div><div style="font-size:12px;white-space:pre-wrap">${esc(String(evidence).slice(0,1200))}</div></div>`:''}</div>` : `<div class="okbox">${esc(title)}: not submitted yet.</div>`;

  let primaryAction = '';
  if (curStage === 'New' || !asn.primary_owner) {
    primaryAction = canManage ? `<div class="dsect"><button class="btn primary" id="wf-assign-open">Assign Finding</button></div>
      <div class="dsect" id="wf-assign-form" style="display:none;border:1px solid var(--border);border-radius:10px;padding:10px">
        <h4 style="margin:0 0 8px">Assign Primary & Secondary</h4>
        <div id="as-picker-owner"></div>
        <div class="formrow" style="margin-top:8px"><div class="field"><label class="cellsub">Primary Assignee</label><input class="input" id="as-owner" placeholder="Primary (click or type)"></div><div class="field"><label class="cellsub">Secondary Assignee</label><input class="input" id="as-reviewer" placeholder="Secondary (optional)"></div></div>
        <div id="as-picker-reviewer"></div>
        <div class="field" style="margin-top:8px"><label class="cellsub">Assignment instructions</label><input class="input" id="as-reason" placeholder="Instructions / deadline notes"></div>
        <div class="formrow" style="margin-top:8px"><button class="btn primary" id="as-manual-btn">Confirm Assignment</button></div>
      </div>` : `<div class="okbox">Awaiting admin assignment.</div>`;
   } else if (curStage === 'Assigned' || curStage === 'Primary Review') {
     // Employee flow: after admin assignment, the employee goes directly to assessment.
     // There is no mandatory Acknowledge step blocking the review; acknowledgement is recorded automatically on submit.
     if (isPrimary || isAdmin) {
       if (!asn.primary_submitted_at) primaryAction = `<div class="dsect"><h4>Primary Assessment</h4><p class="cellsub">Severity ${esc(f.severity)} · Assigned by ${esc(asn.assigned_by||'Admin')}. Review evidence and classify.</p>
         ${asn.assignment_instructions?`<div class="cellsub" style="margin:6px 0"><strong>Instructions:</strong> ${esc(asn.assignment_instructions)}</div>`:''}
         <div class="formrow" style="margin:8px 0"><label><input type="radio" name="pclass" value="true_positive"> True Positive</label> <label style="margin-left:12px"><input type="radio" name="pclass" value="false_positive"> False Positive</label></div>
         <div class="field"><label class="cellsub">Evidence / reason (optional)</label><textarea class="input" id="wf-primary-reason" rows="2" placeholder="Optional reason or evidence"></textarea></div>
         <div class="formrow" style="margin-top:8px"><button class="btn primary" id="wf-primary-submit">Send to Secondary</button></div></div>`;
       else primaryAction = `<div class="okbox">Primary assessment submitted (${esc((asn.primary_classification||'').replace(/_/g,' '))}). Read-only. Automatically routed to Secondary Review.</div>`;
     } else if (isSecondary) {
       primaryAction = `<div class="okbox">Awaiting Primary Assessment by ${esc(asn.primary_owner||'-')}.</div>`;
     } else {
       primaryAction = `<div class="okbox">Awaiting Primary Triage by ${esc(asn.primary_owner||'-')}.</div>`;
     }
   } else if (curStage === 'Secondary Review') {
     if (isSecondary || isAdmin) {
       if (!asn.secondary_submitted_at) primaryAction = `<div class="dsect"><h4>Secondary Triage Review</h4>
         <div class="okbox" style="margin-bottom:8px;white-space:pre-wrap"><strong>Primary assessment:</strong> ${esc((asn.primary_classification||'').replace(/_/g,' '))}${asn.primary_submitted_at?` · submitted ${utc(asn.primary_submitted_at)}`:''}${asn.primary_reasoning?`<br><strong>Primary notes:</strong> ${esc(asn.primary_reasoning)}`:''}${asn.primary_evidence?`<br><strong>Primary evidence:</strong> ${esc(String(asn.primary_evidence).slice(0,600))}`:''}</div>
         <p class="cellsub" style="margin-bottom:8px">Review independently and confirm True or False Positive.</p>
         <div class="formrow" style="margin-bottom:8px;flex-wrap:wrap;gap:12px"><label><input type="radio" name="sclass" value="true_positive"> True Positive</label><label><input type="radio" name="sclass" value="false_positive"> False Positive</label></div>
         <label class="cellsub" style="display:block;margin-bottom:8px"><input type="checkbox" id="wf-s-disagree"> I disagree with the Primary assessment (explain below)</label>
         <div class="field"><label class="cellsub">Evidence / reason (optional)</label><textarea class="input" id="wf-secondary-reason" rows="2" placeholder="Optional reason or evidence"></textarea></div>
         <div class="formrow" style="margin-top:8px"><button class="btn primary" id="wf-secondary-submit">Send to Admin</button></div></div>`;
       else primaryAction = `<div class="okbox">Secondary Review complete (${esc((asn.secondary_outcome||'').replace(/_/g,' '))}). Awaiting Admin Final Review.</div>`;
     } else primaryAction = `<div class="okbox">Awaiting Secondary Triage Review by ${esc(asn.secondary_reviewer||'-')}.</div>`;
  } else if (curStage === 'Admin Review') {
    const sClass = (asn.secondary_outcome||'').replace('disagree_','').replace('confirm_',''); const disagree = asn.primary_classification && (asn.secondary_outcome||'').startsWith('disagree') || (asn.primary_classification && sClass && ['true_positive','false_positive'].includes(sClass) && sClass!==asn.primary_classification);
    const comparison = `<div class="dsect"><h3>Review comparison</h3>${disagree?'<div class="errbox" style="margin-bottom:8px">Assessments disagree — admin decision required.</div>':''}
      <div class="twrap"><table class="tbl"><thead><tr><th>Item</th><th>Primary</th><th>Secondary</th></tr></thead><tbody>
      <tr><td>Assessment</td><td>${esc((asn.primary_classification||'-').replace(/_/g,' '))}</td><td>${esc(((asn.secondary_outcome||'-').replace('disagree_','').replace(/_/g,' ')))} ${ (asn.secondary_outcome||'').startsWith('disagree') ? '<span class="chip st-false_positive" style="margin-left:4px">Disagrees</span>' : ''}</td></tr>
      <tr><td>Evidence</td><td>${asn.primary_evidence?'Available':'-'}</td><td>${asn.secondary_evidence?'Available':'-'}</td></tr>
      <tr><td>Notes</td><td>${asn.primary_reasoning?'Available':'-'}</td><td>${asn.secondary_reasoning?'Available':'-'}</td></tr>
      <tr><td>Review status</td><td>${asn.primary_submitted_at?'Submitted':'Pending'}</td><td>${asn.secondary_submitted_at?'Submitted':'Pending'}</td></tr>
      </tbody></table></div></div>
      ${assessBlock('Primary Assessment', 'Primary', asn.primary_classification, asn.primary_reasoning, asn.primary_evidence, asn.primary_submitted_at)}
      ${assessBlock('Secondary Assessment', 'Secondary', asn.secondary_outcome, asn.secondary_reasoning, asn.secondary_evidence, asn.secondary_submitted_at)}`;
    if (isAdmin) primaryAction = comparison + `<div class="dsect"><h3>Final decision</h3>
      <p class="cellsub" style="margin-bottom:10px">Select one option only, enter your justification, then submit. This is an admin-only decision and cannot be undone from this screen.</p>
      <div class="formrow" style="margin-bottom:8px;gap:12px;flex-wrap:wrap"><label><input type="checkbox" name="adec" id="adec-tp" value="confirm_true_positive"> True Positive</label><label><input type="checkbox" name="adec" id="adec-fp" value="confirm_false_positive"> False Positive</label></div>
      <div class="field"><label class="cellsub">Justification (required)</label><textarea class="input" id="wf-admin-reason" rows="2" placeholder="Why are you marking this as True / False Positive?"></textarea></div>
      <div class="formrow" style="margin-top:10px;gap:10px"><button class="btn primary" id="wf-adec-tp-btn">Send to Remediation Center</button><button class="btn ghost" id="wf-adec-fp-btn">Mark as False Positive &amp; Close</button></div>
      <p class="cellsub" style="margin-top:8px"><strong>True Positive</strong> → sends the finding to the Remediation Center for remediation and verification. <strong>False Positive</strong> → closes the finding immediately.</p></div>`;
    else primaryAction = comparison + `<div class="okbox">Awaiting admin final review.</div>`;
  } else if (curStage === 'Remediation') {
    primaryAction = `<div class="dsect"><h3>Remediation</h3><dl class="kv"><dt>Remediation owner</dt><dd>${esc(asn.remediation_owner||asn.primary_owner||'-')}</dd><dt>Status</dt><dd>${esc(asn.remediation_status||'pending')}</dd></dl></div>`;
    if (isAdmin) primaryAction += `<div class="dsect"><div class="formrow"><input class="input grow" id="wf-rem-owner2" value="${esc(asn.remediation_owner||asn.primary_owner||'')}" placeholder="Remediation owner"><button class="btn sm" id="wf-assign-rem">Assign remediation</button></div></div>`;
    if (isPrimary || isAdmin || me === asn.remediation_owner) primaryAction += `<div class="dsect"><h4>Submit remediation</h4><div class="field"><textarea class="input" id="wf-rem-note" rows="2" placeholder="Remediation notes/evidence (required)"></textarea></div><div class="formrow" style="margin-top:8px"><button class="btn primary" id="wf-submit-rem">Submit for Verification</button></div></div>`;
  } else if (curStage === 'Verification') {
    primaryAction = `<div class="dsect"><h3>Verification</h3><p class="cellsub">Remediation submitted. ${asn.verification_requested_at?'Verification requested — awaiting admin review.':'Request verification, then admin approves or rejects.'}</p>${asn.remediation_note?`<div class="okbox" style="margin-top:8px;white-space:pre-wrap">${esc(asn.remediation_note)}</div>`:''}</div>`;
    if ((isPrimary || isAdmin || me===asn.remediation_owner) && !asn.verification_requested_at) primaryAction += `<div class="formrow"><button class="btn primary" id="wf-req-ver">Request Verification</button></div>`;
    if (isAdmin && asn.verification_requested_at && !asn.verification_decision) primaryAction += `<div class="dsect"><div class="field"><input class="input" id="as-vreason" placeholder="Approval/rejection reason"></div><div class="formrow" style="margin-top:8px"><button class="btn primary" id="as-vapprove-btn">Approve Verification</button><button class="btn ghost" id="as-vreject-btn">Reject</button></div></div>`;
  } else if (curStage === 'Closed') {
    primaryAction = `<div class="okbox">Workflow closed. ${wf.admin_decision==='confirm_false_positive'?'False Positive confirmed by admin.':'Finding verified/closed.'} ${asn.admin_decision_reason?`<br>Reason: ${esc(asn.admin_decision_reason)}`:''}${isAdmin?`<div class="formrow" style="margin-top:12px"><button class="btn ghost" id="wf-reopen">Reopen finding</button></div>`:''}</div>`;
  }

  const tabs = [['workflow','Workflow'],['evidence','Evidence'],['notes_history','Notes & History'],['checklist','Checklist']];
  if (!tabs.find(t=>t[0]===state.drawerTab)) state.drawerTab = 'workflow';
  const hideAssignmentBlock = isAdmin && curStage === 'Admin Review';
  const assignmentBlock = hideAssignmentBlock ? '' : `<div class="dsect"><h3>Assignment</h3><dl class="kv"><dt>Primary</dt><dd>${esc(asn.primary_owner||'-')}</dd><dt>Secondary</dt><dd>${esc(asn.secondary_reviewer||'-')}</dd><dt>Assigned by</dt><dd>${esc(asn.assigned_by||'-')}</dd><dt>Instructions</dt><dd>${esc(asn.assignment_instructions||'-')}</dd></dl></div>`;
  const bodyMap = {
    workflow: `${essential}${primaryAction}${assignmentBlock}<div class="dsect"><h3>Activity timeline</h3><div class="feed">${asH.map(h=>`<div class="feeditem"><span class="ficon">${icon('clock')}</span><div class="fbody"><div class="ftext">${esc(h.action)} ${h.to_owner?`→ ${esc(h.to_owner)}`:''} ${h.reason?`— ${esc(h.reason)}`:''}</div><div class="fmeta"><span>${esc(h.actor||'')}</span><span>${utc(h.ts)}</span></div></div></div>`).join('') || '<p style="color:var(--faint);font-size:12px">No activity yet.</p>'}</div></div>`,
    evidence: `<div class="dsect"><h3>Masked evidence</h3><pre class="codeblock evidence">${esc(f.secret_masked||'')}</pre><dl class="kv" style="margin-top:10px"><dt>Fingerprint</dt><dd class="mono">${esc(f.fingerprint||'')}</dd><dt>Entropy</dt><dd>${f.entropy}</dd><dt>Validation</dt><dd>${esc(meta.validation||'pattern_match')}</dd></dl><p style="color:var(--faint);font-size:11.5px;margin-top:8px">Raw values are never stored or returned.</p></div>`,
    notes_history: `<div class="dsect"><h3>Investigation notes</h3>${(d.notes||[]).map(n=>`<div class="feeditem"><span class="ficon">${icon('doc')}</span><div class="fbody"><div class="ftext">${esc(n.body)}</div><div class="fmeta"><span>${esc(n.username)}</span><span>${utc(n.ts)}</span></div></div></div>`).join('') || '<p style="color:var(--faint);font-size:12px">No notes.</p>'}${canWrite()?`<div class="field" style="margin-top:10px"><textarea class="input" id="d-note" rows="3" placeholder="Add note"></textarea></div><button class="btn sm" id="d-note-btn">Add note</button>`:''}</div><div class="dsect"><h3>Audit history</h3><div class="feed">${(d.history||[]).map(h=>`<div class="feeditem"><span class="ficon">${icon('clock')}</span><div class="fbody"><div class="ftext">${esc(h.old)} → ${esc(h.new)}</div><div class="fmeta"><span>${esc(h.username)}</span><span>${utc(h.ts)}</span></div></div></div>`).join('') || '<p style="color:var(--faint);font-size:12px">No transitions recorded.</p>'}</div></div>`,
    checklist: `<div class="dsect"><h3>Remediation checklist</h3>${["Rotate the credential at its provider", "Remove the exposure from the source", "Purge from history, docs and chat", "Update consumers to the replacement", "Re-scan and verify remediation"].map((s, i) => `<label class="ckitem ${d.checklist?.[i]?.done ? 'done' : ''}"><input type="checkbox" data-step="${i}" ${d.checklist?.[i]?.done ? 'checked' : ''} ${!canWrite() ? 'disabled' : ''}><span><span class="cktext">${esc(s)}</span>${d.checklist?.[i]?.username ? `<span class="ckmeta">by ${esc(d.checklist[i].username)}</span>` : ''}</span></label>`).join('')}</div>${canWrite() ? `<div class="dsect"><h3>Actions</h3><div class="formrow">${["rotate-guide", "preview-redact", "redact", "quarantine", "restore", "ticket", "verify"].map(a=>`<button class="btn sm" data-rem="${a}">${a.replace(/-/g, ' ')}</button>`).join('')}</div><div id="d-rem-out" style="margin-top:8px"></div></div>` : ''}`,
  };
  $(".drawer").innerHTML = `<div class="dhead"><div style="min-width:0;flex:1"><div class="dtitle">${esc(f.title)}</div><div class="dsub">${sevChip(f.severity)} <span class="chip neutral">${esc(curStage)}</span> <span class="mono">${esc(f.id)}</span></div></div><button class="iconbtn" id="d-close" aria-label="Close">${icon('x')}</button></div><div class="dtabs">${tabs.map(([id2,label])=>`<button class="dtab ${state.drawerTab===id2?'active':''}" data-dtab="${id2}">${label}</button>`).join('')}</div><div class="dbody">${bodyMap[state.drawerTab]||bodyMap.workflow}</div>`;
  $("#d-close").onclick = closeDrawer;
  $$("[data-dtab]").forEach(b => (b.onclick = () => { state.drawerTab = b.dataset.dtab; loadDrawer(); }));
  $$("[data-step]").forEach(cb => (cb.onchange = () => api(`/api/findings/${id}/checklist`, { method:'POST', body:{ idx:+cb.dataset.step, done:cb.checked } }).then(loadDrawer)));
  const on = (sel, fn) => { const el = $(sel); if (el) el.onclick = fn; };
  on('#d-note-btn', async () => { await api(`/api/findings/${id}/notes`, { method:'POST', body:{ body: $('#d-note').value } }); loadDrawer(); });
  on('#wf-assign-open', () => { const f=$('#wf-assign-form'); if(f) f.style.display='block'; });
  if (canManage && typeof getAssignmentTeam==='function') { getAssignmentTeam().then(team=>{ const o=$('#as-picker-owner'), r=$('#as-picker-reviewer'); if(o) o.innerHTML=assignmentPersonPicker('as-owner', team, {label:'Primary Assignee — click a name'}); if(r) r.innerHTML=assignmentPersonPicker('as-reviewer', team, {label:'Secondary Assignee — click a name'}); }).catch(()=>{}); }
  on('#as-manual-btn', async () => { try{ const owner=$('#as-owner')?.value.trim(); const reviewer=$('#as-reviewer')?.value.trim(); const reason=$('#as-reason')?.value.trim(); const r=await api(`/api/assignment/finding/${id}/assign`,{method:'POST',body:{primary_owner:owner,secondary_reviewer:reviewer,reason,instructions:reason}}); if(r.ok||r.assignment||!r.error){ toast('Assignment saved — employees notified','ok'); } else { toast(r.error||'Failed','error'); } loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-ack', async()=>{ try{ await api(`/api/assignment/finding/${id}/ack`,{method:'POST',body:{}}); toast('Acknowledged','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-ack-sec', async()=>{ try{ await api(`/api/assignment/finding/${id}/ack`,{method:'POST',body:{}}); toast('Acknowledged','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-primary-start', async()=>{ try{ await api(`/api/assignment/finding/${id}/primary-start-investigation`,{method:'POST',body:{}}); toast('Investigation started','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-primary-submit', async()=>{ try{ const classification=(document.querySelector('input[name="pclass"]:checked')||{}).value; const reasoning=$('#wf-primary-reason')?.value.trim(); const r=await api(`/api/assignment/finding/${id}/primary-submit-assessment`,{method:'POST',body:{classification,reasoning}}); if(r.ok){ toast('Assessment submitted to secondary reviewer','ok'); } else toast(r.error||'Failed','error'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-secondary-start', async()=>{ try{ await api(`/api/assignment/finding/${id}/secondary-start-review`,{method:'POST',body:{}}); toast('Secondary review started','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-secondary-submit', async()=>{ try{ const classification=(document.querySelector('input[name="sclass"]:checked')||{}).value; const disagrees=!!($('#wf-s-disagree')&&$('#wf-s-disagree').checked); const reasoning=$('#wf-secondary-reason')?.value.trim(); const r=await api(`/api/assignment/finding/${id}/secondary-submit-assessment`,{method:'POST',body:{classification,disagrees,reasoning}}); if(r.ok){ toast('Review submitted to admin','ok'); } else toast(r.error||'Failed','error'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-adec-tp-btn', async()=>{ try{ const tp=$('#adec-tp'); const fp=$('#adec-fp'); if (!tp || !tp.checked) { toast('Select the True Positive checkbox first','error'); return; } if (fp && fp.checked) { toast('Only one decision can be selected','error'); return; } const reason=$('#wf-admin-reason')?.value.trim(); if (!reason) { toast('Justification required','error'); return; } const r=await api(`/api/assignment/finding/${id}/admin-final-decision`,{method:'POST',body:{decision:'confirm_true_positive',reason}}); if(r.ok){ toast('Finding sent to Remediation Center','ok'); } else toast(r.error||'Failed','error'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-adec-fp-btn', async()=>{ try{ const tp=$('#adec-tp'); const fp=$('#adec-fp'); if (!fp || !fp.checked) { toast('Select the False Positive checkbox first','error'); return; } if (tp && tp.checked) { toast('Only one decision can be selected','error'); return; } const reason=$('#wf-admin-reason')?.value.trim(); if (!reason) { toast('Justification required','error'); return; } const r=await api(`/api/assignment/finding/${id}/admin-final-decision`,{method:'POST',body:{decision:'confirm_false_positive',reason}}); if(r.ok){ toast('Finding closed as False Positive','ok'); } else toast(r.error||'Failed','error'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-reopen', async()=>{ if(!confirm('Reopen this finding? This will clear the review state and make it available for reassignment.')) return; try{ await api(`/api/findings/${id}/reopen`,{method:'POST',body:{}}); toast('Finding reopened','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-assign-rem', async()=>{ try{ await api(`/api/assignment/finding/${id}/assign-remediation`,{method:'POST',body:{remediation_owner:$('#wf-rem-owner2')?.value.trim()}}); toast('Remediation assigned','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-submit-rem', async()=>{ try{ const note=$('#wf-rem-note')?.value.trim(); const r=await api(`/api/assignment/finding/${id}/submit-remediation`,{method:'POST',body:{note,reason:note}}); if(r.ok){ toast('Remediation submitted','ok'); } else toast(r.error||'Failed','error'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#wf-req-ver', async()=>{ try{ await api(`/api/assignment/finding/${id}/request-verification`,{method:'POST',body:{note:'Verification requested after remediation'}}); toast('Verification requested','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#as-assist-btn', async()=>{ const reason=prompt('What assistance do you need from Admin?')||'Assistance requested'; try{ await api(`/api/assignment/finding/${id}/request-assistance`,{method:'POST',body:{reason}}); toast('Request sent to admin','ok'); }catch(e){ toast(e.message,'error'); } });
  on('#as-vapprove-btn', async()=>{ try{ await api(`/api/assignment/finding/${id}/approve-verification`,{method:'POST',body:{reason:($('#as-vreason')||{}).value||'Approved'}}); toast('Verification approved','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  on('#as-vreject-btn', async()=>{ const reason=($('#as-vreason')||{}).value||'Rejected'; try{ await api(`/api/assignment/finding/${id}/reject-verification`,{method:'POST',body:{reason}}); toast('Verification rejected','ok'); loadDrawer(); refresh(); }catch(e){ toast(e.message,'error'); } });
  $$('[data-rem]').forEach(b => (b.onclick = () => {
    const action = b.dataset.rem;
    const exec = async () => { const r = await api('/api/remediate', { method:'POST', body:{ id, action } }); $('#d-rem-out').innerHTML = `<pre class="codeblock">${esc(r.detail)}</pre>`; toast(`${action} complete`, 'ok'); loadDrawer(); refresh(); };
    if (['redact','quarantine'].includes(action)) confirmModal(`${action} finding`, 'Modifies or moves the source file. The credential must still be rotated.', exec, action);
    else exec();
  }));
  bindOpeners();
}

/* ================= Hubs ================= */

/* ================= Hubs ================= */

const HUBS_TICK_MS = 3000;

function personAvatar(name, opts = {}) {
  const username = name || "?";
  const initial = esc(username[0].toUpperCase());
  const src = `/static/avatars/${encodeURIComponent(username)}.jpg`;
  const size = opts.size ? ` ${esc(opts.size)}` : "";
  return `<span class="person-avatar${size}">${initial}<img src="${esc(src)}" alt="" loading="lazy" onerror="this.remove()">${opts.online ? '<i class="person-avatar-dot" title="Online" aria-label="Online"></i>' : ""}</span>`;
}
function hubsTime(value) { return value ? utc(value) : ""; }
function dmKey(a, b) { return [a, b].sort().join(":"); }

let hubsAudio = null;
let hubsTonePending = false;
function hubsAudioContext() {
  if (hubsAudio) return hubsAudio;
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) return null;
  try { hubsAudio = new Ctx(); } catch (_) { return null; }
  return hubsAudio;
}
function hubsPlayTone(ctx) {
  const now = ctx.currentTime;
  [0, 0.16].forEach((offset, index) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(index ? 1046.5 : 880, now + offset);
    gain.gain.setValueAtTime(0.0001, now + offset);
    gain.gain.exponentialRampToValueAtTime(0.14, now + offset + 0.012);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.14);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now + offset);
    osc.stop(now + offset + 0.15);
  });
}
function hubsAudioUnlock() {
  const ctx = hubsAudioContext();
  if (!ctx) return null;
  if (ctx.state === "suspended") {
    ctx.resume().then(() => {
      if (hubsTonePending && ctx.state === "running") {
        hubsTonePending = false;
        hubsPlayTone(ctx);
      }
    }).catch(() => {});
  } else if (ctx.state === "running" && hubsTonePending) {
    hubsTonePending = false;
    hubsPlayTone(ctx);
  }
  return ctx;
}
function hubsInstallAudioUnlock() {
  const unlock = () => hubsAudioUnlock();
  ["pointerdown", "keydown", "touchstart"].forEach((event) => {
    document.addEventListener(event, unlock, { passive: true });
  });
}
function hubsPingTone() {
  try {
    const ctx = hubsAudioContext();
    if (!ctx) return;
    if (ctx.state === "running") {
      hubsTonePending = false;
      hubsPlayTone(ctx);
      return;
    }
    // A ping can arrive before the first user gesture. Remember it and play
    // the tone the moment the browser allows audio to start.
    hubsTonePending = true;
    ctx.resume().then(() => {
      if (hubsTonePending && ctx.state === "running") {
        hubsTonePending = false;
        hubsPlayTone(ctx);
      }
    }).catch(() => {});
  } catch (_) { /* audio is decorative; never break a ping because of it */ }
}
function hubsSenderTitle(name, people) {
  const person = people.get(name);
  if (person) return person.title || person.role || "";
  if (state.user && name === state.user.username) {
    return state.user.title || state.user.role || "";
  }
  return "";
}

async function renderHubs() {
  const h = state.hubs;
  if (h.timer) { clearTimeout(h.timer); h.timer = null; }

  const [workspace, prefsResult, directory, inbox] = await Promise.all([
    api("/api/hubs/channels"),
    api("/api/hubs/prefs"),
    api("/api/hubs/users"),
    api("/api/hubs/notifications"),
  ]);
  const prefs = prefsResult.prefs || {};
  const people = (directory.users || []).slice().sort(
    (a, b) => a.username.localeCompare(b.username));
  const peopleByName = new Map(people.map((person) => [person.username, person]));
  const dms = (workspace.dms || []).filter((dm) => peopleByName.has(dm.peer));
  const openChat = (workspace.channels || []).find((c) => c.id === "open-chat")
    || { id: "open-chat", name: "Open Chat", unread: 0 };

  // Keep the selected conversation valid even after an account or thread
  // disappears, so polling never strands the page on a dead route.
  if (h.kind === "dm" && (!h.peer || h.peer === state.user.username || !peopleByName.has(h.peer))) {
    h.kind = "channel"; h.id = "open-chat"; h.peer = null;
  }
  if (h.kind !== "dm") { h.kind = "channel"; h.id = "open-chat"; }
  if (h.kind === "dm" && (!h.id || !String(h.id).includes(":"))) {
    h.id = dmKey(state.user.username, h.peer);
  }
  const isChannel = h.kind === "channel";
  const readOnly = !canWrite();
  h.title = isChannel ? (openChat.name || "Open Chat") : h.peer;

  const threadUrl = isChannel
    ? `/api/hubs/channels/${encodeURIComponent("open-chat")}/messages`
    : `/api/hubs/dm/${encodeURIComponent(h.peer)}/messages`;
  let thread;
  try { thread = await api(threadUrl); }
  catch (err) { thread = { messages: [], members: [], error: err.message }; }
  if (!isChannel && thread.dm_key) h.id = thread.dm_key;
  const messages = thread.messages || [];

  if (messages.length) {
    const last = messages[messages.length - 1];
    api("/api/hubs/mark-read", {
      method: "POST",
      body: isChannel
        ? { channel_id: "open-chat", last_id: last.id }
        : { dm_key: h.id, last_id: last.id },
    }).catch(() => {});
  }

  // Live refresh replaces the whole panel; carry the draft, caret and scroll
  // position across so polling never interrupts typing or reading.
  const threadKey = `${h.kind}:${isChannel ? "open-chat" : h.peer}`;
  const oldShell = $("#main .hubs-shell");
  const sameThread = oldShell?.dataset.thread === threadKey;
  const oldInput = $("#hubs-body");
  const draft = sameThread ? (oldInput?.value || "") : "";
  const hadFocus = sameThread && oldInput === document.activeElement;
  const caret = hadFocus ? oldInput.selectionStart : 0;
  const oldScroller = $("#hubs-messages");
  const wasAtBottom = !oldScroller
    || oldScroller.scrollHeight - oldScroller.scrollTop - oldScroller.clientHeight < 60;
  const previousScroll = oldScroller?.scrollTop || 0;

  const notifications = inbox.notifications || [];
  const messageList = messages.map((message) => {
    const mine = message.sender === state.user.username;
    const title = hubsSenderTitle(message.sender, peopleByName);
    return `<article class="hubs-message ${mine ? "mine" : ""}">${personAvatar(message.sender)}<div class="hubs-msg-body"><div class="hubs-msg-meta"><strong>${esc(message.sender)}</strong>${title ? `<span class="hubs-msg-role">${esc(title)}</span>` : ""}<time>${hubsTime(message.created_at)}${message.edited ? " · edited" : ""}</time>${mine ? `<button class="hubs-msg-delete" data-hdelete="${esc(message.id)}" title="Delete message" aria-label="Delete message">×</button>` : ""}</div><p>${esc(message.body).replace(/\n/g, "<br>")}</p></div></article>`;
  }).join("");
  const emptyState = `<div class="hubs-empty-state">${icon(isChannel ? "message" : "lock")}<strong>${isChannel ? "No messages yet" : "This conversation is private"}</strong><span>${isChannel ? "Say hello — everyone in the company can read and reply here." : `Only you and ${esc(h.peer)} can read this conversation.`}</span></div>`;

  const dmList = dms.map((dm) => {
    const active = !isChannel && (h.id === dm.dm_key || h.peer === dm.peer);
    return `<button class="hubs-item hubs-dm-row ${active ? "active" : ""}" data-hdm="${esc(dm.peer)}" data-hdmkey="${esc(dm.dm_key)}" data-hsearch="${esc(`${dm.peer} ${peopleByName.get(dm.peer)?.title || ""}`.toLowerCase())}">${personAvatar(dm.peer, { online: peopleByName.get(dm.peer)?.online })}<span>${esc(dm.peer)}<small>${esc(dm.last_message?.body || "No messages yet")}</small></span>${dm.unread ? `<b>${dm.unread}</b>` : ""}</button>`;
  }).join("");

  const peopleList = people.map((person) => `<div class="hubs-person" data-hsearch="${esc(`${person.username} ${person.title || ""} ${person.role || ""}`.toLowerCase())}"><button class="hubs-user" data-hdm="${esc(person.username)}" data-hdmkey="${esc(dmKey(state.user.username, person.username))}" title="Message ${esc(person.username)}">${personAvatar(person.username, { online: person.online })}<span>${esc(person.username)}<small>${esc(person.title || person.role)}</small></span></button><button class="hubs-mini" data-hping="${esc(person.username)}" title="${readOnly ? "Read-only account: pings are disabled" : `Ping ${esc(person.username)}`}" aria-label="Ping ${esc(person.username)}" ${readOnly ? "disabled" : ""}>Ping</button></div>`).join("");

  const context = isChannel
    ? `<div class="hubs-section">PARTICIPANTS<span class="hubs-pill">${(thread.members || []).length}</span></div><div class="hubs-roster">${(thread.members || []).map((member) => `<div class="hubs-user hubs-static">${personAvatar(member.username)}<span>${esc(member.username)}<small>${esc(member.title || member.user_role || "member")}</small></span></div>`).join("")}</div>`
    : `<div class="hubs-section">PROFILE</div><div class="hubs-profile">${personAvatar(h.peer)}<div><strong>${esc(h.peer)}</strong><small>${esc(thread.peer?.title || peopleByName.get(h.peer)?.title || "SENTRIX user")}</small></div></div><button class="btn sm hubs-wide" id="hubs-ping-panel" data-hping-dm="${esc(h.peer || "")}" ${readOnly ? 'disabled title="Read-only account: pings are disabled"' : ""}>Ping ${esc(h.peer || "user")}</button><p class="hubs-privacy">${icon("lock", 12)} Only you and ${esc(h.peer)} can read this conversation.</p>`;

  const notificationsHtml = notifications.slice(0, 12).map((note) => `<button class="hubs-item hubs-notif ${note.read ? "" : "unread"}" data-hnotif="${note.id}">${personAvatar(note.sender)}<span>${esc(note.sender)}<small>${esc(note.body || note.type.replace(/_/g, " "))}</small></span>${note.read ? "" : '<i class="hubs-dot"></i>'}</button>`).join("") || '<span class="hubs-empty">All caught up.</span>';

  $("#main").innerHTML = `<div class="hubs-shell" data-thread="${esc(threadKey)}">
    <aside class="hubs-left">
      <div class="hubs-brand"><div><strong>HUBS</strong><span>Private team messaging</span></div><span class="hubs-roster-pill">${people.length + 1} people</span></div>
      <input class="input hubs-search" id="hubs-search" placeholder="Search conversations and people" autocomplete="off" aria-label="Search Hubs">
      <div class="hubs-section">COMPANY CHAT</div>
      <button class="hubs-open ${isChannel ? "active" : ""}" data-hchannel="open-chat"><span class="hubs-hash">#</span><span class="hubs-open-label">${esc(openChat.name || "Open Chat")}<small>Everyone · company-wide</small></span>${openChat.unread ? `<b>${openChat.unread}</b>` : ""}</button>
      <div class="hubs-section">DIRECT MESSAGES <button class="btn sm ghost" id="hubs-new-dm" title="Start a direct message">New</button></div>
      <div class="hubs-list">${dmList || '<span class="hubs-empty">No private conversations yet. Pick a person to start one.</span>'}</div>
      <div class="hubs-section">PEOPLE</div>
      <div class="hubs-list" id="hubs-people">${peopleList || '<span class="hubs-empty">No colleagues available.</span>'}</div>
    </aside>
    <section class="hubs-center">
      <header class="hubs-head"><div class="hubs-head-main"><div class="hubs-head-title"><strong>${isChannel ? "# " : ""}${esc(h.title)}</strong><div class="hubs-head-tags">${isChannel ? '<span class="hubs-tag">Company-wide</span>' : '<span class="hubs-tag private">Private</span>'}${readOnly ? '<span class="hubs-tag readonly">Read-only account</span>' : ""}</div></div><small>${isChannel ? "Everyone in the company can read and reply here." : `Private conversation between you and ${esc(h.peer)}.`}</small></div><div class="hubs-head-actions">${isChannel ? "" : `<button class="btn sm" id="hubs-ping-head" data-hping-dm="${esc(h.peer || "")}" ${readOnly ? 'disabled title="Read-only account: pings are disabled"' : ""}>Ping</button>`}<button class="btn sm ghost" id="hubs-right-toggle">${h.rightOpen ? "Hide context" : "Context"}</button></div></header>
      <div class="hubs-messages" id="hubs-messages">${thread.error ? `<div class="errbox">${esc(thread.error)}</div>` : (messageList || emptyState)}</div>
      <div class="hubs-compose-wrap">${readOnly
        ? `<div class="hubs-readonly" role="status" aria-live="polite">${icon("lock", 16)}<div><strong>Read-only account</strong><span>This is a read-only account, so you can't send messages or pings. You can still read every conversation and receive messages.</span></div></div>`
        : `<form class="hubs-compose" id="hubs-compose"><textarea class="input" id="hubs-body" rows="2" placeholder="${isChannel ? "Message the whole company…" : `Message ${esc(h.peer)}…`}"></textarea><button class="btn primary">Send</button></form><div class="hubs-compose-hint">Enter to send · Shift + Enter for a new line</div>`}</div>
    </section>
    <aside class="hubs-right ${h.rightOpen ? "" : "collapsed"}">
      ${context}
      <div class="hubs-section">NOTIFICATIONS <button class="btn sm ghost" id="hubs-read-all">Read all</button></div>
      <div class="hubs-notifications">${notificationsHtml}</div>
      <div class="hubs-section">PREFERENCES</div>
      <label class="hubs-check"><input type="checkbox" id="hubs-sound" ${prefs.sound_enabled ? "checked" : ""}> Play ping sound</label>
    </aside>
  </div>`;

  const newInput = $("#hubs-body");
  if (newInput && draft) newInput.value = draft;
  if (newInput && hadFocus) {
    newInput.focus();
    try { newInput.setSelectionRange(caret, caret); } catch (_) { /* not a text input */ }
  }
  const newScroller = $("#hubs-messages");
  if (newScroller) {
    newScroller.scrollTop = wasAtBottom
      ? newScroller.scrollHeight
      : Math.min(previousScroll, newScroller.scrollHeight);
  }

  const open = (next) => {
    state.hubs = { ...h, ...next };
    renderHubs().catch((err) => toast(err.message || "Could not open conversation", "error"));
  };
  $$('[data-hchannel]').forEach((button) => {
    button.onclick = () => open({ kind: "channel", id: "open-chat", peer: null, title: "Open Chat" });
  });
  $$('[data-hdm]').forEach((button) => {
    button.onclick = () => {
      const peer = button.dataset.hdm;
      open({ kind: "dm", id: button.dataset.hdmkey || dmKey(state.user.username, peer), peer, title: peer });
    };
  });
  $("#hubs-new-dm").onclick = () => {
    $("#hubs-people")?.scrollIntoView({ behavior: "smooth", block: "start" });
    $("#hubs-search")?.focus();
  };
  $("#hubs-search").oninput = (event) => {
    const query = event.target.value.trim().toLowerCase();
    $$(".hubs-dm-row, .hubs-person").forEach((row) => {
      row.hidden = Boolean(query && !(row.dataset.hsearch || "").includes(query));
    });
  };
  $("#hubs-right-toggle").onclick = () => { h.rightOpen = !h.rightOpen; renderHubs(); };
  $("#hubs-compose")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $("#hubs-body");
    const body = input.value.trim();
    if (!body) return;
    try {
      await api(threadUrl, { method: "POST", body: { body } });
      input.value = "";
      renderHubs();
    } catch (err) { toast(err.message || "Could not send message", "error"); }
  });
  $("#hubs-body")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      $("#hubs-compose").requestSubmit();
    }
  });
  $$('[data-hdelete]').forEach((button) => {
    button.onclick = async () => {
      if (!confirm("Delete this message?")) return;
      try {
        await api(`/api/hubs/messages/${button.dataset.hdelete}/delete`, { method: "POST", body: {} });
        renderHubs();
      } catch (err) { toast(err.message || "Could not delete message", "error"); }
    };
  });
  const ping = async (target) => {
    if (!target) return;
    hubsAudioUnlock();
    try {
      await api("/api/hubs/ping", { method: "POST", body: { to_user: target } });
      toast(`Ping sent to ${target}`, "ok");
    } catch (err) { toast(err.message || "Could not send ping", "error"); }
  };
  $$('[data-hping], [data-hping-dm]').forEach((button) => {
    button.onclick = (event) => {
      event.stopPropagation();
      ping(button.dataset.hping || button.dataset.hpingDm);
    };
  });
  $("#hubs-read-all")?.addEventListener("click", async () => {
    await api("/api/hubs/notifications/read", { method: "POST", body: {} });
    updateHubsNotificationBadge();
    renderHubs();
  });
  $$('[data-hnotif]').forEach((button) => {
    button.onclick = async () => {
      const note = notifications.find((item) => String(item.id) === button.dataset.hnotif);
      if (!note) return;
      await api("/api/hubs/notifications/read", { method: "POST", body: { ids: [note.id] } });
      openHubsNotification(note);
      updateHubsNotificationBadge();
      renderHubs();
    };
  });
  $("#hubs-sound")?.addEventListener("change", (event) => {
    api("/api/hubs/prefs", { method: "POST", body: { sound_enabled: event.target.checked } })
      .catch((err) => toast(err.message, "error"));
  });

  h.timer = setTimeout(() => {
    if (state.view === "hubs") renderHubs().catch(() => {});
  }, HUBS_TICK_MS);
}

/* ================= shell ================= */


async function renderArchitecture() {
  const d = await api("/api/architecture");
  const tiers = d.tiers || [];
  const total = tiers.reduce((sum, t) => sum + ((t.components || []).length), 0);
  const active = tiers.reduce((sum, t) => sum + (t.components || []).filter(c => c.status === 'active' || c.status === 'running').length, 0);
  const surfaces = (tiers.find(t => t.tier === 5) || { tiers: [], components: [] }).components?.find(c => c.id === 'surfaces');
  const lifecycle = (d.lifecycle || {}).finding || {};
  const path = (lifecycle.lifecycle_path || []).slice(0, 7);
  const tierColor = ['var(--accent)','var(--info)','var(--warn)','var(--ok)','var(--crit)'];

  const flowRow = `<div class="flowchain"><div class="flowchain-item"><span class="chip st-triaged">Client</span><div class="fc-head">SENTRIX Command Center</div><div class="cellsub">Hash-routed SPA · per-tab sessions · RBAC-aware UI</div></div><span class="flowchain-arrow">→</span><div class="flowchain-item"><span class="chip st-in_progress">Core API</span><div class="fc-head">Stdlib HTTP Server</div><div class="cellsub">JSON API · auth · CSRF · lifecycle · audit</div></div><span class="flowchain-arrow">→</span><div class="flowchain-item"><span class="chip st-triaged">Detection</span><div class="fc-head">Pipeline & Intelligence</div><div class="cellsub">26 detectors · risk engine · dedupe</div></div><span class="flowchain-arrow">→</span><div class="flowchain-item"><span class="chip st-remediated">Storage</span><div class="fc-head">SQLite</div><div class="cellsub">Findings · assignments · audit</div></div></div>`;

  $("#main").innerHTML = pagehead("Architecture", "SENTRIX-native platform tiers, components, lifecycle and data flow.", '', icon("layers")) +
    `<div class="banner"><span class="chip st-triaged">HONEST MAP</span> ${esc(d.note || "Single-process, stdlib-only. No external database, queue, or worker fleet required.")}</div>` +
    `<div class="kpi-strip" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))"><div class="kpi-card"><div class="kv">${tiers.length}</div><div class="kl">Tiers</div></div><div class="kpi-card t-accent"><div class="kv">${total}</div><div class="kl">Components</div></div><div class="kpi-card t-ok"><div class="kv">${active}</div><div class="kl">Active</div></div><div class="kpi-card"><div class="kv">v${esc(d.version || "2.0.0")}</div><div class="kl">Version</div></div><div class="kpi-card"><div class="kv" style="font-size:12px;white-space:nowrap">Local monolith</div><div class="kl">${esc(d.mode || "single process")}</div></div></div>` +
    panel("Data flow — request lifecycle", flowRow, 'Client request enters the Core API, passes through authentication and CSRF checks, is enriched by the detection/risk layer, stored in SQLite, and returned to the console.', true) +
    panel("Finding lifecycle", `<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:4px 0">${path.map((s,i)=>`<span class="chip ${i===0?'st-triaged':i===path.length-1?'st-remediated':'st-in_progress'}" style="font-size:12px;padding:4px 10px">${esc(s.replace(/_/g,' ').toUpperCase())}</span>${i<path.length-1?'<span style="color:var(--faint)">→</span>':''}`).join('') || '<span class="cellsub">No lifecycle path recorded.</span>'}</div><p class="cellsub" style="margin-top:6px">Transitions are advisory/permissive for compatibility and exposed via <code>GET /api/lifecycle</code>.</p>`, '', true) +
    tiers.map(t => {
      const color = tierColor[(t.tier - 1) % tierColor.length];
      return panel(`<div style="display:flex;align-items:center;gap:12px;margin:0"><div class="chip neutral" style="padding:6px 10px;font-size:12px">T${t.tier}</div><h3 style="margin:0">${esc(t.name)}</h3></div>`,
        `<div class="twrap"><table class="tbl"><thead><tr><th>Component</th><th>Type</th><th>Status</th><th>What it does</th></tr></thead><tbody>${(t.components||[]).map(c => `<tr><td>${esc(c.name)}<div class="cellsub mono">${esc(c.id || '')}</div></td><td>${esc(c.type || '-')}</td><td><span class="chip ${c.status==='active'||c.status==='running'?'st-remediated':'st-triaged'}">${esc(c.status || 'unknown')}</span></td><td class="cellsub" style="max-width:420px;white-space:normal">${esc(c.details || '-')}</td></tr>`).join('') || '<tr><td colspan="4"><span class="cellsub">None.</span></td></tr>'}</tbody></table></div>`, '', true);
    }).join('');
}

async function renderWorkers() {
  const [d, jobs, sched] = await Promise.all([api("/api/workers"), api("/api/jobs").catch(()=>({jobs:[]})), api("/api/schedules").catch(()=>({schedules:[]}))]);
  const agents = d.workers || d.agents || [];
  const running = (d.jobs_by_status && d.jobs_by_status.running) || 0;
  const queued = (d.jobs_by_status && d.jobs_by_status.queued) || 0;
  $("#main").innerHTML = pagehead("Workers & Agents", "Local execution agents, job registry and schedules.", "", icon("pulse")) +
    `<div class="mgrid" style="grid-template-columns:repeat(4,1fr)"><div class="metric"><div class="mlabel">Agents</div><div class="mvalue">${agents.length}</div><div class="msub">registered</div></div><div class="metric t-accent"><div class="mlabel">Running jobs</div><div class="mvalue">${running}</div><div class="msub">active</div></div><div class="metric"><div class="mlabel">Queued jobs</div><div class="mvalue">${queued}</div><div class="msub">waiting</div></div><div class="metric"><div class="mlabel">Schedules</div><div class="mvalue">${(sched.schedules||[]).length}</div><div class="msub">configured</div></div></div>` +
    panel("Agent registry", `<div class="twrap"><table class="tbl"><thead><tr><th>Agent</th><th>Kind</th><th>Status</th><th>Runtime</th><th>Capabilities</th><th>Details</th></tr></thead><tbody>${agents.map(a => `<tr><td>${esc(a.name)}<span class="cellsub mono">${esc(a.id)}</span></td><td>${esc(a.kind)}</td><td><span class="chip ${['running','active','monitored','connected','demo'].includes(a.status)?'st-remediated':'st-triaged'}">${esc(a.status)}</span></td><td>${esc(a.runtime||"-")}</td><td>${esc((a.capabilities||[]).slice(0,4).join(", ") || "-")}</td><td class="mono">${a.running!=null?`running ${a.running} / queued ${a.queued}`:a.findings!=null?`${a.findings} findings`:a.last_sync?utc(a.last_sync):"-"}</td></tr>`).join("") || '<tr><td colspan="6">No agents.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("Recent jobs (registry)", `<div class="twrap"><table class="tbl"><thead><tr><th>Job</th><th>Target</th><th>Status</th><th>By</th><th>Started</th></tr></thead><tbody>${(jobs.jobs||[]).slice(0,12).map(j => `<tr><td class="mono">${esc(j.id)}</td><td class="mono truncate">${esc(j.path||j.target||"-")}</td><td><span class="chip ${j.status==='done'?'st-remediated':j.status==='failed'?'st-false_positive':'st-triaged'}">${esc(j.status)}</span></td><td>${esc(j.triggered_by||"-")}</td><td>${utc(j.started||j.created_at||j.finished)}</td></tr>`).join("") || '<tr><td colspan="5">No jobs.</td></tr>'}</tbody></table></div><div style="margin-top:8px"><a class="btn sm ghost" href="#/jobs">Open full job registry</a></div>`, "", true);
}


async function renderAIAgents() {
  const d = await api("/api/agents");
  const agents = d.agents || [];
  $("#main").innerHTML = pagehead("AI Agents", "Triage and workflow agents with honest capability status.", "", icon("pulse")) +
    `<div class="mgrid" style="grid-template-columns:repeat(3,1fr)"><div class="metric"><div class="mlabel">Agents</div><div class="mvalue">${agents.length}</div><div class="msub">available</div></div><div class="metric t-accent"><div class="mlabel">Triage mode</div><div class="mvalue">${esc((d.ai&&d.ai.mode)||"heuristic")}</div><div class="msub">active</div></div><div class="metric"><div class="mlabel">AI configured</div><div class="mvalue">${d.ai&&d.ai.configured?"yes":"local"}</div><div class="msub">external model</div></div></div>` +
    `<div class="cardgrid">${agents.map(a => `<div class="icard"><div class="ihead"><span class="iname">${esc(a.name)}</span><span class="chip st-remediated">${esc(a.status)}</span></div><div class="irow"><span class="k">Kind</span><span class="v">${esc(a.kind)}</span></div><div class="irow"><span class="k">Mode</span><span class="v">${esc(a.mode||"-")}</span></div><div class="irow"><span class="k">Endpoint</span><span class="v mono">${esc(a.endpoint||"-")}</span></div><div>${(a.capabilities||[]).map(c=>`<span class="perm">${esc(c)}</span>`).join("")}</div><p style="margin:8px 0 0;color:var(--dim);font-size:12px">${esc(a.details||"")}</p></div>`).join("")}</div>`;
}

async function renderMcp() {
  const d = await api("/api/mcp");
  const m = d.mcp || {};
  $("#main").innerHTML = pagehead("MCP", "Agent/tool integration status and machine-readable endpoints.", "", icon("plug")) +
    `<div class="banner"><span class="chip ${m.server_implemented?'st-remediated':'st-triaged'}">${m.server_implemented?'IMPLEMENTED':'AGENT-READY APIs'}</span> ${esc(m.note||"")}</div>` +
    panel("Agent-ready endpoints", `<div class="twrap"><table class="tbl"><thead><tr><th>Endpoint</th><th>Purpose</th><th>Auth</th></tr></thead><tbody>${(m.agent_ready_endpoints||[]).map(e => `<tr><td class="mono">${esc(e.path)}</td><td>${esc(e.purpose)}</td><td>${esc((m.configuration&&m.configuration.auth)||"session/bearer")}</td></tr>`).join("") || '<tr><td colspan="3">None.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("Configuration (honest)", `<dl class="kv"><dt>Transport</dt><dd>${esc((m.configuration&&m.configuration.transport)||"-")}</dd><dt>Auth</dt><dd>${esc((m.configuration&&m.configuration.auth)||"-")}</dd><dt>External MCP bridge</dt><dd>${esc((m.configuration&&m.configuration.external_mcp_bridge)||"deployment-specific")}</dd><dt>Status</dt><dd>${esc(m.status||"-")}</dd></dl>`, "", true);
}

async function renderTools() {
  const d = await api("/api/tools");
  const tools = d.tools || [];
  const q = (state.toolsQ || "").toLowerCase();
  const rows = q ? tools.filter(t => (t.name+" "+t.kind+" "+t.status+" "+(t.capabilities||[]).join(" ")).toLowerCase().includes(q)) : tools;
  $("#main").innerHTML = pagehead("Tools & Connectors", "Detectors, adapters, integrations, playbooks and tool/MCP-ready registry.", "", icon("wrench")) +
    `<div class="mgrid" style="grid-template-columns:repeat(4,1fr)"><div class="metric"><div class="mlabel">Tools</div><div class="mvalue">${(d.counts&&d.counts.tools)||tools.length}</div><div class="msub">registry items</div></div><div class="metric t-accent"><div class="mlabel">Detectors</div><div class="mvalue">${(d.counts&&d.counts.detectors)||(d.detectors||[]).length}</div><div class="msub">rules loaded</div></div><div class="metric"><div class="mlabel">Playbooks</div><div class="mvalue">${tools.filter(t=>t.kind==='playbook').length}</div><div class="msub">remediation guides</div></div><div class="metric"><div class="mlabel">MCP / AX</div><div class="mvalue">API</div><div class="msub">lifecycle + registry</div></div></div>` +
    panel("Tool registry", `<div class="searchbar"><input class="input" id="tools-q" placeholder="Search tools, kinds, capabilities…" value="${esc(state.toolsQ||"")}"></div><div class="twrap"><table class="tbl"><thead><tr><th>Tool</th><th>Kind</th><th>Status</th><th>Capabilities</th></tr></thead><tbody>${rows.map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.kind)}</td><td><span class="chip ${['available','enabled','connected','demo'].includes(t.status)?'st-remediated':'st-false_positive'}">${esc(t.status)}</span></td><td>${esc((t.capabilities||[]).join(", ") || (t.steps!=null?`${t.steps} steps`:"-"))}</td></tr>`).join("") || '<tr><td colspan="4">No matching tools.</td></tr>'}</tbody></table></div>`, "", true) +
    panel("MCP & agent tooling", `<div class="banner"><span class="chip st-triaged">HONEST STATUS</span> SENTRIX exposes machine-readable workflow metadata (<code>/api/lifecycle</code>) and registries (<code>/api/tools</code>, <code>/api/workers</code>, <code>/api/architecture</code>). External MCP server wiring is deployment-specific; no fake MCP server is claimed by default.</div>`, "", true);
  const qEl = $("#tools-q"); if (qEl) qEl.oninput = () => { state.toolsQ = qEl.value; renderTools(); };
}

async function renderTechnologies() {
  const d = await api("/api/technologies");
  const rows = d.technologies || [];
  $("#main").innerHTML = pagehead("Technologies", "Detection families and technology categories derived from findings.") +
    `<div class="mgrid" style="grid-template-columns:repeat(3,1fr)"><div class="metric"><div class="mlabel">Technologies</div><div class="mvalue">${rows.length}</div><div class="msub">derived</div></div><div class="metric t-crit"><div class="mlabel">With critical findings</div><div class="mvalue">${rows.filter(r=>r.critical>0).length}</div><div class="msub">prioritize</div></div><div class="metric"><div class="mlabel">Findings mapped</div><div class="mvalue">${rows.reduce((s,r)=>s+(r.findings||0),0)}</div><div class="msub">total</div></div></div>` +
    panel("Technology inventory", `<div class="twrap"><table class="tbl"><thead><tr><th>Technology</th><th>Family</th><th class="num">Assets</th><th class="num">Findings</th><th class="num">Critical</th><th>Surfaces</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.name)}<span class="cellsub mono">${esc(r.category||"")}</span></td><td>${esc(r.family||"-")}</td><td class="num">${r.assets||0}</td><td class="num">${r.findings||0}</td><td class="num">${r.critical||0}</td><td>${esc((r.surfaces||[]).join(", ")||"-")}</td></tr>`).join("") || '<tr><td colspan="6">No technologies derived yet.</td></tr>'}</tbody></table></div>`, "", true);
}

async function renderGroups() {
  const d = await api("/api/groups");
  const rows = d.groups || [];
  $("#main").innerHTML = pagehead("Groups", "Exposure groups by surface, environment, owner and severity.") +
    panel("Group inventory", `<div class="twrap"><table class="tbl"><thead><tr><th>Group</th><th>Dimension</th><th class="num">Assets</th><th class="num">Findings</th><th class="num">Critical</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(r.dimension)}</td><td class="num">${r.assets||0}</td><td class="num">${r.findings||0}</td><td class="num">${r.critical||0}</td></tr>`).join("") || '<tr><td colspan="5">No groups derived yet.</td></tr>'}</tbody></table></div>`, "", true);
}



function assignmentPersonPicker(targetId, team, opts={}){
  const list=(team||[]).filter(u=>u && u.username);
  if(!list.length) return '';
  const label = opts.label || 'Pick assignee (click name)';
  return `<div class="asn-picker" style="margin:6px 0"><div class="cellsub" style="margin-bottom:4px">${esc(label)}</div><div style="display:flex;flex-wrap:wrap;gap:6px">${list.map(u=>`<button type="button" class="btn sm ghost asn-pick" data-target="${esc(targetId)}" data-user="${esc(u.username)}" title="${esc((u.role||'').replace(/_/g,' ')+(u.title?' - '+u.title:''))}" ${u.availability_status && u.availability_status!=='available'?'style="opacity:.65"':''}>${typeof personAvatar==='function'?personAvatar(u.username,{size:'sm'}):''}<span>${esc(u.username)}</span>${u.username==='admin'?'<span class="chip neutral" style="margin-left:4px;font-size:10px">Admin</span>':''}</button>`).join('')}</div></div>`;
}
document.addEventListener('click',(e)=>{ const b=e.target.closest&&e.target.closest('.asn-pick'); if(!b) return; e.preventDefault(); const inp=document.getElementById(b.dataset.target); if(inp){ inp.value=b.dataset.user; inp.dispatchEvent(new Event('input',{bubbles:true})); } });
let _asnTeamCache=null;
async function getAssignmentTeam(){ if(_asnTeamCache) return _asnTeamCache; try{ if(typeof canManageAssignments==='function' && canManageAssignments()){ const d=await api('/api/assignment/profiles'); _asnTeamCache=d.profiles? (d.profiles.map(p=>Object.assign({username:p.username},(d.workloads||{})[p.username]||{},p))) : (Object.values(d.workloads||{})); } }catch(e){} if(!_asnTeamCache){ _asnTeamCache=(state.users||[]).map(u=>({username:u.username,role:u.role,title:u.title})); }
  if(!_asnTeamCache||!_asnTeamCache.length){ _asnTeamCache=[{username:'admin',role:'super_admin',title:'Platform Administrator'},{username:'r.sharma',role:'appsec_engineer'},{username:'p.patel',role:'security_analyst'},{username:'a.kumar',role:'devsecops_engineer'},{username:'n.singh',role:'auditor'},{username:'v.iyer',role:'developer'}]; }
  return _asnTeamCache; }

async function renderAssignments() {
  _asnTeamCache = null;
  if (!canManageAssignments()) { $("#main").innerHTML = pagehead("Team Workload & Assignment","Intelligent assignment and workload management.") + empty("Access restricted","Your role does not have access to this dashboard. Use My Assignments for your own work."); return; }
  $("#main").innerHTML = pagehead("Team Workload & Assignment","Explainable ownership, workload balancing, SLA and accountability.") + skeleton();
  let d; try { d = await api('/api/assignment/dashboard'); } catch(e){ $("#main").innerHTML = pagehead("Team Workload & Assignment","") + banner(esc(e.message),'error'); return; }
  const m = d.metrics||{}; const q = d.queues||{}; const team = d.team||[]; const sla = d.sla_config||{};
  function helpBtnSmall(key){ return `<button class="helpbtn" data-help="${key}" aria-label="Help" style="margin-left:4px">?</button>`; }
  const kpis = `<div class="kpi-strip">
    ${[['Total findings',m.total_findings,'auto_assignment'],['Unassigned',m.unassigned,'auto_assignment'],['Critical unassigned',m.critical_unassigned,'severity'],['High assigned',m.high_assigned,'severity'],['Pending ack',m.pending_ack,'acknowledgement'],['Overdue',m.overdue,'sla'],['Reassignment requests',m.reassignment_requests,'reassignment'],['SLA breaches',m.sla_breaches,'escalation']].map(([l,v,k])=>`<div class="kpi-card"><div class="kv">${v??0}</div><div class="kl">${esc(l)} ${helpBtnSmall(k)}</div></div>`).join('')}
  </div>`;
  const teamTbl = `<div class="twrap"><table class="tbl"><thead><tr><th>Employee</th><th>Role/Expertise</th><th>Active</th><th>Critical/High</th><th>Workload ${helpBtnSmall('workload')}</th><th>Capacity</th><th>Availability</th><th>Overdue</th>${isAssignmentAdmin()?'<th>Admin</th>':''}</tr></thead><tbody>${team.map(u=>`<tr><td>${typeof personAvatar==='function'?personAvatar(u.username,{size:'sm'}):''} <strong>${esc(u.username)}</strong><div class="cellsub">${esc(u.title||'')}</div></td><td>${esc((u.role||'').replace(/_/g,' '))}<div class="cellsub">${esc((u.skills||[]).slice(0,3).join(', ')||'-')}</div></td><td>${u.active_findings||0}</td><td>${u.critical_high||0}</td><td><div style="display:flex;align-items:center;gap:6px"><div style="flex:1;height:6px;background:var(--raised);border-radius:99px;min-width:60px"><span style="display:block;height:100%;width:${Math.min(100,u.workload_pct||0)}%;background:${(u.workload_pct||0)>=90?'var(--danger)':(u.workload_pct||0)>=70?'var(--warn)':'var(--ok)'};border-radius:99px"></span></div><span>${u.workload_pct||0}%</span></div><div class="cellsub">${u.workload_points||0}/${u.max_capacity||20} pts</div></td><td>${u.available_capacity||0} pts</td><td><span class="chip ${u.availability_status==='available'?'st-remediated':'st-false_positive'}">${esc(u.availability_status||'available')}</span></td><td>${u.overdue||0}</td>${isAssignmentAdmin()?`<td><button class="btn sm ghost" data-prof-edit="${esc(u.username)}" data-cap="${u.max_capacity||20}" data-avail="${esc(u.availability_status||'available')}" data-elig="${u.assignment_eligible?1:0}">Edit</button></td>`:''}</tr>`).join('') || '<tr><td colspan="9">No team data.</td></tr>'}</tbody></table></div>`;
  function queuePanel(name, key, opts={}){
    const rows=q[key]||[]; const bulk = opts.bulk && canManageAssignments();
    return panel(`${name} (${rows.length}) ${opts.help?helpBtnSmall(opts.help):''}`, `<div class="twrap"><table class="tbl"><thead><tr>${bulk?'<th><input type="checkbox" data-bulk-all="'+key+'"></th>':''}<th>Finding</th><th>Severity</th><th>Primary owner</th><th>Reviewer</th><th>Status</th><th>SLA</th><th></th></tr></thead><tbody>${rows.map(r=>`<tr>${bulk?`<td><input type="checkbox" class="bulk-sel" data-q="${key}" value="${esc(r.finding_id)}"></td>`:''}<td>${esc(r.title)}<div class="cellsub mono">${esc(r.finding_id)}</div></td><td>${typeof sevChip==='function'?sevChip(r.severity):esc(r.severity)}</td><td>${esc(r.primary_owner||'-')}</td><td>${esc(r.secondary_reviewer||'-')}</td><td><span class="chip neutral">${esc((r.assignment_status||'').replace(/_/g,' '))}</span></td><td>${r.sla_breached?'<span class="chip st-false_positive">Breached</span>':'<span class="chip st-remediated">OK</span>'}</td><td><button class="btn sm ghost" data-open="${esc(r.finding_id)}">Open</button> ${canManageAssignments() && key==='unassigned'?`<button class="btn sm" data-as-auto="${esc(r.finding_id)}">Auto</button>`:''}</td></tr>`).join('') || `<tr><td colspan="${bulk?8:7}">None.</td></tr>`}</tbody></table></div>${bulk?`<div style="margin-top:8px">${assignmentPersonPicker(`bulk-owner-${key}`, team, {label:'Assign selected to (click name)'})}<div class="formrow"><div class="field"><input class="input" id="bulk-owner-${key}" placeholder="Primary owner"></div><div class="field grow"><input class="input" id="bulk-reason-${key}" placeholder="Reason"></div><button class="btn sm primary" data-bulk-assign="${key}">Bulk assign selected</button></div></div>`:''}`, '', true);
  }
  // Current assignments by employee — compact live table showing every active task
  let allTasksHtml = '';
  try {
    const all = await api('/api/findings?page_size=400');
    const active = (all.findings || []).filter(r => (r.workflow_stage || 'New') !== 'Closed' && (r.primary_assignee || r.secondary_assignee || r.remediation_owner));
    const by = {};
    active.forEach(f => {
      const sev = (f.severity_override || f.severity || 'medium').toLowerCase();
      const sla = f.sla_status === 'breached' ? '<span class="chip st-false_positive">Breached</span>' : (f.sla_status === 'ok' ? '<span class="chip st-remediated">OK</span>' : '<span class="cellsub">-</span>');
      const roleRow = (who, role) => ({
        who, role, fid: f.finding_id || f.id, title: f.title, severity: sev,
        stage: f.workflow_stage || 'New', sla, due: f.due_at || '',
      });
      if (f.primary_assignee) (by[f.primary_assignee] = by[f.primary_assignee] || []).push(roleRow(f.primary_assignee, 'Primary'));
      if (f.secondary_assignee) (by[f.secondary_assignee] = by[f.secondary_assignee] || []).push(roleRow(f.secondary_assignee, 'Secondary'));
      if (f.remediation_owner) (by[f.remediation_owner] = by[f.remediation_owner] || []).push(roleRow(f.remediation_owner, 'Remediation'));
    });
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    Object.values(by).forEach(arr => arr.sort((a, b) => (sevOrder[a.severity] ?? 99) - (sevOrder[b.severity] ?? 99) || String(a.stage || '').localeCompare(String(b.stage || ''))));
    const groupRow = (u, items) => `<tr class="group-row"><td colspan="7" style="padding:8px 10px;background:var(--raised);border-top:1px solid var(--border)"><div style="display:flex;align-items:center;gap:8px">${typeof personAvatar==='function'?personAvatar(u.username,{size:'sm'}):''}<div><strong>${esc(u.username)}</strong><div class="cellsub">${esc((u.role||'').replace(/_/g,' '))} · ${esc(u.title||'')} · <span class="chip ${u.availability_status==='available'?'st-remediated':'st-false_positive'}">${esc(u.availability_status||'available')}</span></div></div><span class="mono" style="margin-left:auto;color:var(--faint)">${items.length} active</span></div></td></tr>`;
    const taskRow = (t) => `<tr><td>${esc(t.role)}</td><td>${esc(t.title)}<div class="cellsub mono">${esc(t.fid)}</div></td><td>${sevChip?sevChip(t.severity):esc(t.severity)}</td><td><span class="chip neutral">${esc(t.stage)}</span></td><td>${esc(t.who||'-')}</td><td>${t.sla}</td><td><button class="btn sm ghost" data-open="${esc(t.fid)}">Open</button></td></tr>`;
    const sortedTeam = [...team].sort((a, b) => a.username.localeCompare(b.username));
    allTasksHtml = sortedTeam.map(u => {
      const items = by[u.username] || [];
      return groupRow(u, items) + (items.length ? items.map(taskRow).join('') : `<tr><td colspan="7"><span class="cellsub">No active tasks.</span></td></tr>`);
    }).join('') || '<tr><td colspan="7">No assignments found.</td></tr>';
  } catch (e) {
    allTasksHtml = `<tr><td colspan="7"><span class="cellsub">Could not load live assignments: ${esc(e.message || e)}</span></td></tr>`;
  }
  const allTasksPanel = `<div class="twrap"><table class="tbl compact"><thead><tr><th>Role</th><th>Finding</th><th>Severity</th><th>Stage</th><th>Assigned to</th><th>SLA</th><th></th></tr></thead><tbody>${allTasksHtml}</tbody></table></div>`;

  const adminControls = isAssignmentAdmin() ? panel('Administrator controls '+helpBtnSmall('override'), `
    <div class="grid c2">
      <div><h4 style="margin:0 0 8px">Assignment policy & SLA ${helpBtnSmall('sla')}</h4>
        <div class="formrow"><label class="field">Assignment mode ${helpBtnSmall('auto_assignment')}<select class="input" id="asn-mode"><option value="automatic" ${(sla.assignment_mode||'admin_approval')==='automatic'?'selected':''}>Fully automatic</option><option value="admin_approval" ${(sla.assignment_mode||'admin_approval')==='admin_approval'?'selected':''}>Admin approval (recommended)</option><option value="manual" ${(sla.assignment_mode||'admin_approval')==='manual'?'selected':''}>Manual assignment</option></select></label><label class="field">Engine enabled<select class="input" id="asn-enabled"><option value="1" ${sla.assignment_enabled!==false?'selected':''}>Enabled</option><option value="0" ${sla.assignment_enabled===false?'selected':''}>Disabled</option></select></label></div>
        <div class="formrow"><label class="field">Critical ack (hrs)<input class="input" id="sla-c-ack" type="number" min="0" step="0.5" value="${esc(((sla.ack_hours||{}).critical)||4)}"></label><label class="field">Critical remediate (hrs)<input class="input" id="sla-c-rem" type="number" min="0" step="0.5" value="${esc(((sla.remediate_hours||{}).critical)||4)}"></label></div>
        <div class="formrow"><label class="field">High ack (hrs)<input class="input" id="sla-h-ack" type="number" min="0" step="0.5" value="${esc(((sla.ack_hours||{}).high)||4)}"></label><label class="field">High remediate (hrs)<input class="input" id="sla-h-rem" type="number" min="0" step="0.5" value="${esc(((sla.remediate_hours||{}).high)||24)}"></label></div>
        <button class="btn sm" id="sla-save">Save policy/SLA</button> <button class="btn sm ghost" id="sla-escalate">Run escalation check</button>
      </div>
      <div><h4 style="margin:0 0 8px">Employee profile (admin)</h4>
        ${assignmentPersonPicker('prof-user', team, {label:'Select employee (click name)'})}<div class="formrow"><div class="field"><input class="input" id="prof-user" placeholder="username (e.g. r.sharma)"></div><div class="field"><input class="input" id="prof-cap" type="number" min="1" step="0.5" placeholder="Max capacity pts"></div></div>
        <div class="formrow"><div class="field"><select class="input" id="prof-avail"><option value="available">available</option><option value="unavailable">unavailable</option><option value="leave">leave</option></select></div><div class="field"><select class="input" id="prof-elig"><option value="1">assignment eligible</option><option value="0">not eligible</option></select></div></div>
        <button class="btn sm" id="prof-save">Save profile</button>
        <p class="cellsub" style="margin-top:8px">Profile changes affect eligibility and workload capacity. RBAC permissions remain unchanged.</p>
      </div>
    </div>`) : '';
  $("#main").innerHTML = pagehead("Employee Operations","Compact view of every active task across the team.", `<button class="btn sm" id="as-refresh">Refresh</button>`) +
    (state.user && typeof canWrite==='function' && !canWrite() ? banner('Read-only role: you can view assignment data but cannot perform mutations. '+helpBtnSmall('read_only'), 'warn') : '') +
    kpis +
    panel("Current assignments — every active task", allTasksPanel, 'Click any row to open the finding.', true) +
    panel("Team workload overview "+helpBtnSmall('workload'), teamTbl, '', true) +
    adminControls +
    `<div class="grid c2" style="margin-top:12px">` + queuePanel('Unassigned','unassigned',{help:'auto_assignment',bulk:true}) + queuePanel('Awaiting acknowledgement','awaiting_ack',{help:'acknowledgement'}) + `</div>` +
    `<div class="grid c2" style="margin-top:12px">` + queuePanel('In progress / Acknowledged','in_progress') + queuePanel('Overdue / SLA risk','overdue',{help:'sla'}) + `</div>` +
    `<div class="grid c2" style="margin-top:12px">` + queuePanel('Reassignment requests','reassignment_requests',{help:'reassignment'}) + queuePanel('Blocked','blocked') + `</div>` +
    panel("Recommended / awaiting admin approval", `<div class="twrap"><table class="tbl"><thead><tr><th>Finding</th><th>Severity</th><th>Suggested owner</th><th>Explanation</th><th></th></tr></thead><tbody>${(q.recommended||[]).map(r=>`<tr><td>${esc(r.title)}<div class="cellsub mono">${esc(r.finding_id)}</div></td><td>${typeof sevChip==='function'?sevChip(r.severity):esc(r.severity)}</td><td>${esc(r.primary_owner||'-')}${r.secondary_reviewer?`<div class="cellsub">review: ${esc(r.secondary_reviewer)}</div>`:''}</td><td>${esc((r.explanation||'').slice(0,140))}</td><td><button class="btn sm ghost" data-open="${esc(r.finding_id)}">Open</button> ${canManageAssignments()?`<button class="btn sm" data-as-approve="${esc(r.finding_id)}">Approve</button><button class="btn sm ghost" data-as-reject="${esc(r.finding_id)}">Reject</button>`:''}</td></tr>`).join('') || '<tr><td colspan="5">None.</td></tr>'}</tbody></table></div>`, '', true);
  const rf=$("#as-refresh"); if(rf) rf.onclick=()=>renderAssignments();
  $$('[data-as-auto]').forEach(b=>b.onclick=async()=>{ try{ const r=await api(`/api/assignment/finding/${b.dataset.asAuto}/auto`,{method:'POST',body:{}}); if(r.ok) toast('Assigned: '+(r.chosen&&r.chosen.username),'ok'); else if(r.recommended) toast('Recommendation generated - admin review needed','info'); else toast(r.error||'Assignment failed','error'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  $$('[data-as-approve]').forEach(b=>b.onclick=async()=>{ if(!confirm('Approve the recommended assignment for this finding?')) return; try{ const r=await api(`/api/assignment/finding/${b.dataset.asApprove}/approve`,{method:'POST',body:{reason:'Approved recommendation'}}); if(r.ok) toast('Approved','ok'); else toast(r.error||'Failed','error'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  $$('[data-as-reject]').forEach(b=>b.onclick=async()=>{ const reason=prompt('Reason for rejecting recommendation?')||'Rejected'; try{ await api(`/api/assignment/finding/${b.dataset.asReject}/reject`,{method:'POST',body:{reason}}); toast('Rejected','ok'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  $$('[data-prof-edit]').forEach(b=>b.onclick=()=>{ const pu=$('#prof-user'),pc=$('#prof-cap'),pa=$('#prof-avail'),pe=$('#prof-elig'); if(pu)pu.value=b.dataset.profEdit; if(pc)pc.value=b.dataset.cap; if(pa)pa.value=b.dataset.avail; if(pe)pe.value=b.dataset.elig; });
  on('#sla-save', async()=>{ try{ const cfg={...sla, ack_hours:{critical:+$('#sla-c-ack').value||4,high:+$('#sla-h-ack').value||4,medium:(sla.ack_hours||{}).medium||8,low:(sla.ack_hours||{}).low||24,info:(sla.ack_hours||{}).info||48},remediate_hours:{critical:+$('#sla-c-rem').value||4,high:+$('#sla-h-rem').value||24,medium:(sla.remediate_hours||{}).medium||72,low:(sla.remediate_hours||{}).low||168,info:(sla.remediate_hours||{}).info||336},assignment_mode:($('#asn-mode')||{}).value||'admin_approval',assignment_enabled:(($('#asn-enabled')||{}).value||'1')==='1',escalate_after_ack_breach:true,escalate_after_remediation_breach:true}; await api('/api/assignment/sla-config',{method:'POST',body:cfg}); toast('Policy/SLA saved','ok'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  on('#sla-escalate', async()=>{ try{ const r=await api('/api/assignment/escalate-check',{method:'POST',body:{}}); toast('Escalation check: '+(r.escalated||0)+' emitted','ok'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  on('#prof-save', async()=>{ try{ const u=$('#prof-user').value.trim(); if(!u) return toast('Username required','error'); await api('/api/assignment/profiles/'+encodeURIComponent(u),{method:'POST',body:{max_capacity:+($('#prof-cap').value)||20,availability_status:$('#prof-avail').value,assignment_eligible:$('#prof-elig').value==='1'}}); toast('Profile updated','ok'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  $$('[data-bulk-all]').forEach(cb=>cb.onchange=()=>{ $$('.bulk-sel[data-q="'+cb.dataset.bulkAll+'"]').forEach(x=>x.checked=cb.checked); });
  $$('[data-bulk-assign]').forEach(b=>b.onclick=async()=>{ const key=b.dataset.bulkAssign; const ids=$$('.bulk-sel[data-q="'+key+'"]:checked').map(x=>x.value); if(!ids.length) return toast('Select findings first','error'); const owner=$('#bulk-owner-'+key).value.trim(); const reason=$('#bulk-reason-'+key).value.trim(); if(!owner) return toast('Primary owner required','error'); if(!confirm(`Bulk assign ${ids.length} findings to ${owner}? Each finding gets an individual audit record.`)) return; try{ await api('/api/assignment/bulk',{method:'POST',body:{action:'assign',finding_ids:ids,primary_owner:owner,reason}}); toast('Bulk assignment processed','ok'); renderAssignments(); }catch(e){ toast(e.message,'error'); } });
  if (typeof bindOpeners==='function') bindOpeners();
}

async function renderAdminWorkspace(d) {
  const card = (r) => `<div class="panel" style="padding:12px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start"><div><strong>${esc(r.title)}</strong><div class="cellsub mono">${esc(r.finding_id)}</div></div>${(typeof sevChip==='function')?sevChip(r.severity):esc(r.severity)}</div>
    <div class="cellsub" style="margin-top:6px">Stage: <strong>${esc(r.workflow_stage||'-')}</strong> ${(r.status_labels||[]).map(x=>`<span class="chip neutral">${esc(x)}</span>`).join(' ')}</div>
    <div class="formrow" style="margin-top:8px"><button class="btn sm primary" data-open="${esc(r.finding_id)}">Open for final review</button></div></div>`;
  const section = (name, arr, hint) => `<section class="panel" style="margin-bottom:12px"><div class="phead"><span class="ptitle">${esc(name)} (${arr.length})</span></div><div class="pbody">${hint?`<p class="cellsub" style="margin-bottom:8px">${esc(hint)}</p>`:''}${arr.length?arr.map(card).join(''):'<p style="color:var(--faint);font-size:12px">None.</p>'}</div></section>`;
  $("#main").innerHTML = pagehead("My Workspace","Awaiting final review and in-progress remediation decisions.") +
    `<div class="kpi-strip"><div class="kpi-card t-warn"><div class="kv">${(d.awaiting_final_review||[]).length}</div><div class="kl">Awaiting final review</div></div><div class="kpi-card"><div class="kv">${(d.remediation_progress||[]).length}</div><div class="kl">Remediation in progress</div></div><div class="kpi-card"><div class="kv">${(d.admin_decided||[]).length}</div><div class="kl">Decisions made (recent)</div></div></div>` +
    section('Awaiting Final Review', d.awaiting_final_review||[], 'Open, review the primary/secondary assessments, and submit final decision.') +
    section('Remediation In Progress', d.remediation_progress||[], 'Remediation is in progress after your decision.') +
    `<a class="btn sm ghost" href="#/remediation" style="display:inline-block;margin-top:8px">Open Remediation Center</a>`;
  bindOpeners();
}

async function renderMyAssignments() {
  $("#main").innerHTML = pagehead("My Workspace","Simple view of your assignments and what to do next.") + skeleton();
  let d; try { d = await api('/api/assignment/my'); } catch(e){ $("#main").innerHTML = pagehead("My Workspace","") + banner(esc(e.message),'error'); return; }
  if (typeof isAssignmentAdmin==='function' && isAssignmentAdmin()) { renderAdminWorkspace(d); return; }
  const card = (r) => `<div class="panel" style="padding:12px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start"><div><strong>${esc(r.title)}</strong><div class="cellsub mono">${esc(r.finding_id)}</div></div>${sevChip?sevChip(r.severity):esc(r.severity)}</div>
    <div class="cellsub" style="margin-top:6px">Stage: <strong>${esc(r.workflow_stage||'-')}</strong> ${(r.status_labels||[]).map(x=>`<span class="chip neutral">${esc(x)}</span>`).join(' ')} · Role: ${esc(r.my_role||'-')}</div>
    ${r.assignment_instructions?`<div style="font-size:12px;margin-top:6px">${esc(r.assignment_instructions)}</div>`:''}
    <div class="formrow" style="margin-top:8px"><button class="btn sm primary" data-open="${esc(r.finding_id)}">Open task</button></div></div>`;
  const section = (name, arr, hint) => `<section class="panel" style="margin-bottom:12px"><div class="phead"><span class="ptitle">${esc(name)} (${arr.length})</span></div><div class="pbody">${hint?`<p class="cellsub" style="margin-bottom:8px">${esc(hint)}</p>`:''}${arr.length?arr.map(card).join(''):'<p style="color:var(--faint);font-size:12px">None.</p>'}</div></section>`;
  $("#main").innerHTML = pagehead("My Workspace","Open your task, review evidence, decide True/False Positive, submit. Open a task to take the next action.") +
    `<div class="kpi-strip"><div class="kpi-card t-warn"><div class="kv">${(d.pending_ack||[]).length}</div><div class="kl">Awaiting my action</div></div><div class="kpi-card"><div class="kv">${(d.primary_reviews||[]).length}</div><div class="kl">Primary Assignments</div></div><div class="kpi-card"><div class="kv">${(d.secondary_reviews||[]).length}</div><div class="kl">Secondary Review</div></div><div class="kpi-card"><div class="kv">${(d.remediation_tasks||[]).length}</div><div class="kl">Remediation tasks</div></div><div class="kpi-card"><div class="kv">${((d.completed||[]).length)}</div><div class="kl">My Completed Reviews</div></div></div>` +
    section('Awaiting My Action', d.pending_ack||[], 'Review evidence, decide True/False Positive, and submit.') +
    section('Primary Assignments', d.primary_reviews||[], 'Review evidence, classify True/False Positive, and submit to secondary reviewer.') +
    section('Secondary Review', d.secondary_reviews||[], 'Independently review the primary assessment and submit to Admin.') +
    section('My Remediation Tasks', d.remediation_tasks||[], 'Complete remediation and submit for verification.') +
    section('My Verification Requests', d.verification_requests||[], 'Verification in progress.') +
    section('My Completed Reviews', (d.completed||[]).slice(0,30), '');
  bindOpeners();
}

async function renderAdminReview() {
  if (!canManageAssignments()) { $("#main").innerHTML = pagehead("Awaiting Final Review","Admin only.") + empty("Access restricted","Only administrators can access final review."); return; }
  $("#main").innerHTML = pagehead("Awaiting Final Review","Findings with completed secondary assessment — make the final decision.") + skeleton();
  let data; try { data = await api('/api/findings?tab=admin_review&page_size=100'); } catch(e){ $("#main").innerHTML = pagehead("Awaiting Final Review","") + banner(esc(e.message),'error'); return; }
  const rows = (data.findings||[]).map(r=>`<tr class="clickable" data-open="${esc(r.id)}"><td class="mono">${esc(r.id)}</td><td>${esc(r.title)}</td><td>${sevChip?sevChip(r.severity):esc(r.severity)}</td><td><span class="chip st-triaged">Awaiting Admin Final Review</span></td><td>${esc(r.due_at||'-')}</td></tr>`).join('') || `<tr><td colspan="5">${empty('No findings awaiting final review','Secondary submissions will appear here.')}</td></tr>`;
  $("#main").innerHTML = pagehead("Awaiting Final Review","Make the final decision on each finding.") +
    panel("Awaiting Admin Final Review", `<div class="twrap"><table class="tbl"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Stage</th><th>Due</th></tr></thead><tbody>${rows}</tbody></table></div>`, '', true);
  bindOpeners();
}

async function renderClosedReports() {
  if (!canManageAssignments()) { $("#main").innerHTML = pagehead("Closed Findings","Admin only.") + empty("Access restricted","Only administrators can access the Closed Findings section."); return; }
  $("#main").innerHTML = pagehead("Closed Findings","All findings finally closed. Historical records retained.") + skeleton();
  let data; try { data = await api('/api/findings?tab=closed&page_size=200'); } catch(e){ $("#main").innerHTML = pagehead("Closed Findings","") + banner(esc(e.message),'error'); return; }
  const ids = (data.findings||[]).map(f=>f.id).slice(0,200);
  const details = await Promise.all(ids.map(id=>api(`/api/findings/${id}`).catch(()=>null)));
  const rows = details.filter(Boolean).map(d=>{
    const f=d.finding||{}, a=d.assignment||{}, wf=d.workflow||{};
    const final = a.admin_decision==='confirm_false_positive'?'False Positive':(a.admin_decision==='confirm_true_positive'?'True Positive (closed)':(wf.stage||'Closed'));
    const closedAt = a.verified_at || a.completed_at || a.admin_decision_at || f.updated_at || f.created_at;
    return `<tr class="clickable" data-open="${esc(f.id)}"><td class="mono">${esc(f.id)}</td><td>${esc(f.title)}</td><td>${sevChip?sevChip(f.severity):esc(f.severity)}</td><td>${esc(a.primary_owner||'-')}</td><td>${esc(a.secondary_reviewer||'-')}</td><td>${esc((a.primary_classification||'-').replace(/_/g,' '))}</td><td>${esc((a.secondary_outcome||a.secondary_classification||'-').replace(/_/g,' '))}</td><td>${esc(final)}</td><td>${utc(closedAt)}</td><td>${esc((a.admin_decision_reason||a.verification_rejection_reason||'').slice(0,120))}</td><td><button class="btn sm ghost" data-reopen="${esc(f.id)}">Reopen</button></td></tr>`;
  }).join('') || `<tr><td colspan="11">${empty('No closed findings yet','Closed findings will appear here automatically.')}</td></tr>`;
  $("#main").innerHTML = pagehead("Closed Findings","Admin Command Centre — all closed findings (retained).") +
    panel("Closed Findings", `<div class="twrap"><table class="tbl"><thead><tr><th>Finding ID</th><th>Title</th><th>Severity</th><th>Primary</th><th>Secondary</th><th>Primary assessment</th><th>Secondary assessment</th><th>Final Admin decision</th><th>Closure date</th><th>Closure reason</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div>`, 'Open any finding to inspect full investigation history, assessments, evidence and final decision. Use Reopen to send a closed finding back for triage/assignment.', true);
  bindOpeners();
  $$('[data-reopen]').forEach(b => b.onclick = (e) => {
    e.stopPropagation();
    if (!confirm('Reopen this closed finding? This will clear the current review state and you can reassign primary/secondary.')) return;
    api(`/api/findings/${b.dataset.reopen}/reopen`, { method:'POST', body:{} }).then(() => { toast('Finding reopened','ok'); renderClosedReports(); }).catch(e => toast(e.message,'error'));
  });
}



const VIEWS = {
  home: renderHome, overview: renderOverview, "my-assignments": renderMyAssignments, posture: renderPosture, intelligence: renderIntelligence,
  findings: renderFindings, "admin-review": renderAdminReview, "closed-reports": renderClosedReports, vulnerabilities: renderFindings, sources: renderSources, rules: renderRules, playground: renderPlayground,
  scans: renderScans, repositories: renderSurfaceView, developer: renderSurfaceView, cloud: renderSurfaceView,
  cicd: renderSurfaceView, saas: renderSurfaceView, assets: renderAssets, technologies: renderTechnologies, groups: renderGroups, assignments: renderAssignments, remediation: renderRemediation,
  alerts: renderAlerts, investigations: renderInvestigations, exceptions: renderExceptions, hubs: renderHubs,
  architecture: renderArchitecture, workers: renderWorkers, agents: renderAIAgents, mcp: renderMcp, tools: renderTools, integrations: renderIntegrations, jobs: renderJobs, logs: renderLogs, audit: renderAudit,
  health: renderHealth, reports: renderReports, compliance: renderCompliance, access: renderAccess,
  settings: renderSettings,
};
const VIEW_ICON = { home: "home", overview: "grid", assignments: "list", "my-assignments": "doc", posture: "chart", intelligence: "pulse", findings: "search", vulnerabilities: "warn", sources: "layers", rules: "shield", playground: "box", scans: "clock", repositories: "repo", developer: "doc", cloud: "cloud", cicd: "layers", saas: "plug", assets: "box", technologies: "layers", groups: "grid", remediation: "wrench", alerts: "bell", investigations: "search", exceptions: "warn", hubs: "pulse", architecture: "layers", workers: "pulse", agents: "pulse", mcp: "plug", tools: "wrench", integrations: "plug", jobs: "clock", logs: "list", audit: "doc", health: "pulse", reports: "doc", compliance: "shield", access: "lock", settings: "gear" };

async function refresh() {
  const fn = VIEWS[state.view];
  if (!fn) return;
  const view = state.view;
  const scrollY = window.scrollY;
  const scrollX = window.scrollX;
  try {
    await fn({ soft: true });
  } catch { /* keep last good render; live dot reports connectivity */ }
  // Preserve scroll across auto-refresh (renderers replace #main.innerHTML, which resets scroll to top)
  if (state.view === view && !state.drawerId) window.scrollTo(scrollX, scrollY);
}

function route() {
  if (state.scanTimer) { clearInterval(state.scanTimer); state.scanTimer = null; }
  if (state.hubs.timer) { clearTimeout(state.hubs.timer); state.hubs.timer = null; }
  const hash = location.hash.replace("#/", "") || "home";
  state.view = VIEWS[hash] ? hash : "home";
  state.selection.clear();
  $$(".navitem").forEach((a) => a.classList.toggle("active", a.dataset.nav === state.view));
  const fav = $("#app-favicon"); if (fav) { fav.href = state.view === "home" ? "/home-favicon.png" : "/favicon.svg"; fav.type = state.view === "home" ? "image/png" : "image/svg+xml"; }
  const mainEl = $("#main");
  if (mainEl) { mainEl.classList.remove("home-pro"); mainEl.classList.toggle("home-fit", state.view === "home"); }
  mainEl.innerHTML = skeleton();
  Promise.resolve(VIEWS[state.view]()).catch((e) => {
    $("#main").innerHTML = `<div class="errbox">${esc(e.message)}</div>`;
  });
  if (state.mobileSheet) closeSheet();
}

async function updateHubsNotificationBadge() {
  const d = await api("/api/hubs/notifications").catch(() => null); if (!d) return;
  const count = d.unread || 0, badge = $("#hubs-notif-count"); if (!badge) return;
  badge.hidden = !count; badge.textContent = count > 99 ? "99+" : count;
}
function openHubsNotification(n) {
  const direct = n.type === "direct_message" || n.type === "ping" || Boolean(n.dm_key);
  state.hubs = {
    ...state.hubs,
    kind: direct ? "dm" : "channel",
    id: direct ? (n.dm_key || dmKey(state.user.username, n.sender)) : (n.channel_id || "open-chat"),
    peer: direct ? n.sender : undefined,
    title: n.sender,
  };
  location.hash = "#/hubs";
}
function buildShell() {
  $("#topbar").innerHTML = `<a class="brand" href="#/home"><img src="/logo.svg" alt=""><span><span class="word">SENTRIX</span><span class="sub" style="display:block">Security Intelligence</span></span></a>
    <span class="topspacer" style="flex:1"></span>
    <span class="livedot" id="livedot"><span class="dot"></span><span id="livetxt">Live</span></span>
    <button class="iconbtn" id="hubs-messages-btn" aria-label="Open Hubs messages" title="Messages">${icon("message")}<b class="notif-badge" id="hubs-notif-count" hidden></b></button>
    <button class="iconbtn" id="theme-toggle" aria-label="Toggle dark / white theme" title="Toggle theme">${icon("moon")}</button>
    <button class="userbtn" id="userbtn" aria-haspopup="menu">${personAvatar(state.user.username, { size: "sm", online: true })}<span><span class="uname">${esc(state.user.username)}</span><span class="urole" style="display:block">${esc(state.user.role)}${canWrite() ? "" : " · read-only"}</span></span></button>`;
  $("#sidebar").innerHTML = NAV.map(([group, items], gi) => `<div class="navgroup" data-group="${gi}"><button class="navhead">${esc(group)} ${icon("chev", 12)}</button><div class="navitems">${items.map(([id, label]) => `<a class="navitem" href="#/${id}" data-nav="${id}">${icon(VIEW_ICON[id])} ${esc(label)}</a>`).join("")}</div></div>`).join("") + `<div class="navfoot" style="padding:10px 12px;color:var(--faint);font-size:10px">SENTRIX · One Intelligence. Every Exposure. Total Control.</div>`;
  $$(".navhead").forEach((h) => (h.onclick = () => h.parentElement.classList.toggle("closed")));
  const primary = ["overview", "findings", "intelligence", "remediation", "integrations", "logs", "reports", "settings"];
  $("#tabbar").innerHTML = primary.map((id) => `<a class="tabitem" href="#/${id}" data-nav="${id}">${icon(VIEW_ICON[id], 16)}<span class="tl">${esc((NAV.flatMap((g) => g[1]).find((x) => x[0] === id) || [id, id])[1].split(" ")[0])}</span></a>`).join("") + `<button class="tabitem" id="more-btn">${icon("grid", 16)}<span class="tl">More</span></button>`;
  $("#more-btn").onclick = openSheet;
  $("#theme-toggle").onclick = () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("sx.theme", next); } catch {}
    $("#theme-toggle").innerHTML = icon(next === "dark" ? "moon" : "sun");
  };
  $("#userbtn").onclick = (e) => {
    closeOverlays("popover");
    const pop = document.createElement("div");
    pop.className = "popover";
    pop.innerHTML = `<div class="pophead">${personAvatar(state.user.username, { size: "sm", online: true })}<strong>${esc(state.user.username)}</strong><span style="color:var(--faint);font-weight:400">${esc(state.user.title || state.user.role)}</span></div><button class="popitem" id="um-settings">${icon("gear")} Settings</button><button class="popitem" id="um-access">${icon("lock")} Access management</button><div class="popsep"></div><button class="popitem danger" id="um-out">${icon("x")} Sign out</button>`;
    $("#overlays").appendChild(pop);
    const r = e.currentTarget.getBoundingClientRect();
    pop.style.top = `${r.bottom + 6}px`; pop.style.left = `${Math.max(8, r.right - 240)}px`;
    $("#um-settings", pop).onclick = () => { pop.remove(); location.hash = "#/settings"; };
    $("#um-access", pop).onclick = () => { pop.remove(); location.hash = "#/access"; };
    $("#um-out", pop).onclick = async () => {
      await api("/api/auth/logout", { method: "POST", body: {} }).catch(() => {});
      setAuthToken("");
      location.href = "/login";
    };
    setTimeout(() => { const off = (ev) => { if (!pop.contains(ev.target) && ev.target !== $("#userbtn")) { pop.remove(); document.removeEventListener("click", off); } }; document.addEventListener("click", off); }, 0);
  };
  $("#hubs-messages-btn").onclick = () => { location.hash = "#/hubs"; };
  /* The Hubs page is the notification inbox; this helper remains available to
     route a message notification to the relevant secure conversation. */
  const showHubsNotifications = async (e) => {
    const payload = await api("/api/hubs/notifications"), button = e.currentTarget;
    closeOverlays("popover"); const pop = document.createElement("div"); pop.className = "popover hubs-notif-pop";
    pop.innerHTML = `<div class="pophead">Hubs notifications <button class="btn sm" id="hubs-read-all">Mark all read</button></div>${payload.notifications.map((n) => `<button class="popitem ${n.read ? "" : "unread"}" data-notif="${n.id}">${icon(n.type === "ping" ? "pulse" : "bell")}<span><strong>${esc(n.sender)}</strong> · ${esc(n.type.replace(/_/g, " "))}<small>${esc(n.body || "")}</small></span></button>`).join("") || '<div class="hubs-empty">No notifications.</div>'}`;
    $("#overlays").appendChild(pop); const r = button.getBoundingClientRect(); pop.style.top = `${r.bottom + 6}px`; pop.style.left = `${Math.max(8, r.right - 300)}px`;
    $("#hubs-read-all", pop).onclick = async () => { await api("/api/hubs/notifications/read", { method: "POST", body: {} }); pop.remove(); updateHubsNotificationBadge(); };
    $$('[data-notif]', pop).forEach((el) => el.onclick = async () => { const n = payload.notifications.find((x) => String(x.id) === el.dataset.notif); await api("/api/hubs/notifications/read", { method: "POST", body: { ids: [n.id] } }); pop.remove(); openHubsNotification(n); updateHubsNotificationBadge(); });
  };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); closeOverlays("popover"); closeOverlays("modalwrap"); closeSheet(); }
  });
  document.addEventListener("click", (e) => {
    const h = e.target.closest("[data-help]");
    if (h) helpPopover(h.dataset.help, h);
  });
  window.addEventListener("hashchange", route);
  setInterval(async () => {
    const h = await api("/api/health").catch(() => null);
    $("#livetxt").textContent = h ? "Live" : "Offline";
    $("#livedot").classList.toggle("down", !h);
  }, 10000);
  setInterval(() => {
    if (!state.paused && !state.drawerId && VIEWS[state.view]) refresh();
  }, 10000);
}

function openSheet() {
  state.mobileSheet = true;
  $("#overlays").insertAdjacentHTML("beforeend", `<div class="sheet" id="sheet"><div class="sheet-panel"><div class="sheet-head"><strong>All modules</strong><button class="iconbtn" id="sheet-close" aria-label="Close">${icon("x")}</button></div>${NAV.map(([g, items]) => `<div class="navgroup"><div class="navhead" style="cursor:default">${esc(g)}</div><div class="navitems">${items.map(([id, label]) => `<a class="navitem" href="#/${id}" data-nav="${id}">${icon(VIEW_ICON[id])} ${esc(label)}</a>`).join("")}</div></div>`).join("")}</div></div>`);
  $("#sheet-close").onclick = closeSheet;
  $("#sheet").onclick = (e) => { if (e.target.id === "sheet") closeSheet(); };
}
function closeSheet() { state.mobileSheet = false; $("#sheet")?.remove(); }

async function boot() {
  // A tab without its own token is not signed in, even if another tab (or a
  // stale cookie) is. Send it to the login page instead of inheriting an
  // account from the shared browser session.
  if (!authToken()) { location.href = "/login"; return; }
  try { state.user = (await api("/api/auth/me")).user; } catch { return; }
  hubsInstallAudioUnlock();
  buildShell();
  updateHubsNotificationBadge();
  route();
  setInterval(async () => {
    const e = await api(`/api/hubs/events?last_msg=${state.hubsEvents.lastMsg}&last_notif=${state.hubsEvents.lastNotif}`).catch(() => null);
    if (!e) return;
    // The first poll primes the cursors so existing history is not replayed
    // as brand-new activity on every page load.
    const priming = !state.hubsEvents.primed;
    const messages = Array.isArray(e.messages) ? e.messages : [];
    const notifications = Array.isArray(e.notifications) ? e.notifications : [];
    const prefs = e.pings?.length ? await api("/api/hubs/prefs").catch(() => null) : null;
    (e.pings || []).forEach((p) => { if (prefs?.prefs?.sound_enabled) hubsPingTone(); toast(`${p.from_user} pinged you${p.message ? `: ${p.message}` : ""}`, "info"); });
    state.hubsEvents.lastMsg = Math.max(
      state.hubsEvents.lastMsg,
      Number(e.cursor?.last_msg) || 0,
      ...messages.map((m) => Number(m.seq) || 0),
    );
    state.hubsEvents.lastNotif = Math.max(
      state.hubsEvents.lastNotif,
      Number(e.cursor?.last_notif) || 0,
      ...notifications.map((n) => Number(n.id) || 0),
    );
    state.hubsEvents.primed = true;
    if (!priming && notifications.length && state.view !== "hubs") toast("New Hubs activity", "info");
    if (notifications.length) updateHubsNotificationBadge();
    if (!priming && state.view === "hubs" && messages.length) renderHubs().catch(() => {});
  }, 3000);
}
boot();
