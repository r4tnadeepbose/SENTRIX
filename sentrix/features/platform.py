from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import threading
import time
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

from sentrix.config import ROOT, cfg_get, env_secret, resolve_path
from sentrix.core import engine, net
from sentrix.core.models import Event, Finding, now_iso
from sentrix.surfaces.common import rest_json

MAX_WEBHOOK_BODY = 2 * 1024 * 1024


def _log(storage, level: str, source: str, message: str, **kw):
    try:
        if hasattr(storage, "add_log"):
            storage.add_log(level, source, message, **kw)
    except Exception:
        pass


def _event(storage, kind: str, surface: str, payload: dict):
    try:
        storage.add_event(Event(kind=kind, surface=surface, payload=payload))
    except Exception:
        pass


def _enabled(cfg: dict, key: str, default: bool = True) -> bool:
    return bool(cfg_get(cfg, f"features.{key}.enabled", default))


def ensure_features_schema(storage):
    """Additive tables for feature tracking (safe to call repeatedly)."""
    if not hasattr(storage, "_lock") or not hasattr(storage, "_db") or storage._db is None:
        return False
    with storage._lock:
        db = storage._db
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS webhook_events (
              id TEXT PRIMARY KEY, provider TEXT, event_type TEXT, delivery_id TEXT,
              status TEXT, reason TEXT, received_at TEXT, payload_meta TEXT
            );
            CREATE TABLE IF NOT EXISTS integration_health (
              key TEXT PRIMARY KEY, provider TEXT, metric TEXT, status TEXT,
              value TEXT, detail TEXT, updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_failures (
              id TEXT PRIMARY KEY, kind TEXT, source TEXT, detail TEXT, ts TEXT
            );
            CREATE TABLE IF NOT EXISTS validation_results (
              id TEXT PRIMARY KEY, finding_id TEXT, detector_id TEXT, provider TEXT,
              status TEXT, detail TEXT, ts TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_webhook_provider_ts ON webhook_events(provider, received_at);
            CREATE INDEX IF NOT EXISTS idx_scan_failures_ts ON scan_failures(ts);
            """
        )
        db.commit()
    return True


def record_webhook(storage, provider: str, event_type: str, delivery_id: str, status: str, reason: str = "", meta: dict | None = None):
    if not ensure_features_schema(storage):
        return ""
    wid = "wh-" + hashlib.sha256(f"{provider}|{delivery_id}|{time.time_ns()}".encode()).hexdigest()[:12]
    with storage._lock:
        storage._db.execute(
            "INSERT OR REPLACE INTO webhook_events(id,provider,event_type,delivery_id,status,reason,received_at,payload_meta) VALUES(?,?,?,?,?,?,?,?)",
            (wid, provider, event_type, delivery_id, status, reason, now_iso(), json.dumps(meta or {})),
        )
        storage._db.commit()
    return wid


def record_scan_failure(storage, kind: str, source: str, detail: str):
    if not ensure_features_schema(storage):
        return ""
    sid = "sf-" + hashlib.sha256(f"{kind}|{source}|{time.time_ns()}".encode()).hexdigest()[:12]
    with storage._lock:
        storage._db.execute(
            "INSERT INTO scan_failures(id,kind,source,detail,ts) VALUES(?,?,?,?,?)",
            (sid, kind, source, (detail or "")[:1000], now_iso()),
        )
        storage._db.commit()
    return sid


def list_webhook_events(storage, provider: str = "", limit: int = 100):
    ensure_features_schema(storage)
    conn = storage._connect(); conn.row_factory = __import__("sqlite3").Row
    if provider:
        rows = conn.execute("SELECT * FROM webhook_events WHERE provider=? ORDER BY received_at DESC LIMIT ?", (provider, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM webhook_events ORDER BY received_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try: d["payload_meta"] = json.loads(d.get("payload_meta") or "{}")
        except Exception: d["payload_meta"] = {}
        out.append(d)
    return out


def list_scan_failures(storage, limit: int = 100):
    ensure_features_schema(storage)
    conn = storage._connect(); conn.row_factory = __import__("sqlite3").Row
    rows = conn.execute("SELECT * FROM scan_failures ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- GitHub webhooks (PR / Push) ----------------

def _verify_github_signature(secret: str, body: bytes, signature: str) -> bool:
    if not secret:
        return True
    if not signature.startswith("sha256="):
        return False
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, signature.split("=", 1)[1])


def _github_headers(cfg: dict) -> dict:
    token = env_secret(cfg, "features.github.token_env") or env_secret(cfg, "surfaces.github.token_env")
    h = {"Accept": "application/vnd.github+json", "User-Agent": "SENTRIX"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _scan_added_patch(patch: str, path: str, surface: str, allowlist) -> list[Finding]:
    if not patch:
        return []
    lines = []
    line_no = 0
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            if m:
                line_no = int(m.group(1)) - 1
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            line_no += 1
            lines.append((line_no, raw[1:]))
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:
            line_no += 1
    findings: list[Finding] = []
    # scan per added line with correct line number
    for ln, text in lines:
        for f in engine.scan_text(text, path, surface, allowlist):
            f.line = ln
            f.id = hashlib.sha256(f"{f.fingerprint}|{f.path}|{f.line}".encode()).hexdigest()[:12]
            findings.append(f)
    return findings


def handle_github_webhook(state, headers: dict, raw_body: bytes, body: dict):
    cfg = state.cfg
    storage = state.storage
    ensure_features_schema(storage)
    if not _enabled(cfg, "github_webhooks", True):
        return {"ok": False, "error": "github webhooks disabled"}, 403
    secret = env_secret(cfg, "features.github.webhook_secret_env")
    sig = headers.get("X-Hub-Signature-256", "") or headers.get("x-hub-signature-256", "")
    if secret and not _verify_github_signature(secret, raw_body, sig):
        record_webhook(storage, "github", "unknown", headers.get("X-GitHub-Delivery", ""), "rejected", "invalid signature")
        return {"ok": False, "error": "invalid signature"}, 401
    event = headers.get("X-GitHub-Event", "") or headers.get("x-github-event", "")
    delivery = headers.get("X-GitHub-Delivery", "") or headers.get("x-github-delivery", "") or ("gh-" + hashlib.sha256(raw_body[:256]).hexdigest()[:10])
    repo = ((body.get("repository") or {}).get("full_name")) or ""
    findings: list[Finding] = []
    scanned = 0

    try:
        if event == "pull_request":
            action = body.get("action", "")
            if action not in ("opened", "synchronize", "reopened", "edited", "ready_for_review"):
                record_webhook(storage, "github", event, delivery, "ignored", f"action={action}", {"repo": repo, "action": action})
                return {"ok": True, "ignored": True, "reason": f"action {action}"}, 200
            pr = body.get("pull_request") or {}
            files = pr.get("changed_files") or 0
            # Prefer inline patches if present (some payloads/tools), else fetch PR files API if configured
            pr_files = body.get("files") or []
            if not pr_files and repo and pr.get("number") and _enabled(cfg, "github_pr_scanner", True):
                api_base = cfg_get(cfg, "features.github.api_base", "https://api.github.com").rstrip("/")
                try:
                    repo_path = "/".join(urllib.parse.quote(part, safe="") for part in str(repo).split("/"))
                    pr_num = int(pr.get("number", 0))
                    url = f"{api_base}/repos/{repo_path}/pulls/{pr_num}/files?per_page=100"
                    data = rest_json(url, headers=_github_headers(cfg))
                    if isinstance(data, list):
                        pr_files = data
                except Exception as e:
                    record_scan_failure(storage, "github_pr_fetch", repo, str(e))
            for f in pr_files:
                filename = f.get("filename") or f.get("path") or "unknown"
                patch = f.get("patch") or ""
                scanned += 1
                findings.extend(_scan_added_patch(patch, f"github:{repo}/{filename}", "git", state.pipeline.allowlist))
            # GitHub Actions automated security gate signal
            gate = "pass"
            if _enabled(cfg, "github_actions_gate", True):
                threshold = cfg_get(cfg, "scan.fail_on", "high")
                from sentrix.core.util import at_least
                if any(at_least(x.severity, threshold) for x in findings):
                    gate = "fail"
            state.pipeline.ingest(findings, kind="webhook.github.pull_request", provenance={"repo": repo, "pr": pr.get("number"), "delivery": delivery})
            record_webhook(storage, "github", event, delivery, "processed", f"gate={gate}", {"repo": repo, "scanned": scanned, "findings": len(findings), "gate": gate, "pr": pr.get("number")})
            _event(storage, "webhook.github.pull_request", "git", {"repo": repo, "pr": pr.get("number"), "gate": gate, "findings": len(findings)})
            _log(storage, "warn" if gate == "fail" else "info", "integrations", f"GitHub PR scan {repo}#{pr.get('number')}: {len(findings)} finding(s), gate={gate}", component="github", event_type="pull_request", status=gate, resource=repo)
            return {"ok": True, "event": event, "repo": repo, "scanned_files": scanned, "findings": len(findings), "gate": gate}, 200

        if event == "push":
            if not _enabled(cfg, "github_push_scanner", True):
                record_webhook(storage, "github", event, delivery, "ignored", "push scanner disabled", {"repo": repo})
                return {"ok": True, "ignored": True}, 200
            commits = body.get("commits") or []
            # scan added/modified line hunks if present in payload commits
            for c in commits:
                for key in ("added", "modified"):
                    for p in c.get(key, []) or []:
                        scanned += 1
                        # payload has filenames only; fetch content if configured and compare API available
                        if repo and _enabled(cfg, "github_push_scanner", True):
                            try:
                                api_base = cfg_get(cfg, "features.github.api_base", "https://api.github.com").rstrip("/")
                                sha = c.get("id") or body.get("after") or "HEAD"
                                repo_path = "/".join(urllib.parse.quote(part, safe="") for part in str(repo).split("/"))
                                file_path = urllib.parse.quote(str(p).lstrip("/"), safe="/")
                                ref = urllib.parse.quote(str(sha), safe="")
                                url = f"{api_base}/repos/{repo_path}/contents/{file_path}?ref={ref}"
                                data = rest_json(url, headers=_github_headers(cfg))
                                if isinstance(data, dict) and data.get("encoding") == "base64" and data.get("content"):
                                    import base64
                                    text = base64.b64decode(data["content"]).decode("utf-8", "replace")
                                    findings.extend(engine.scan_text(text, f"github:{repo}/{p}@{sha[:7]}", "git", state.pipeline.allowlist))
                                elif isinstance(data, dict) and isinstance(data.get("content"), str):
                                    findings.extend(engine.scan_text(data.get("content",""), f"github:{repo}/{p}@{sha[:7]}", "git", state.pipeline.allowlist))
                            except Exception as e:
                                record_scan_failure(storage, "github_push_fetch", f"{repo}:{p}", str(e))
            # also honor compare diff if provided
            for c in commits:
                patch = c.get("patch") or ""
                if patch:
                    findings.extend(_scan_added_patch(patch, f"github:{repo}/{c.get('id','commit')}", "git", state.pipeline.allowlist))
            state.pipeline.ingest(findings, kind="webhook.github.push", provenance={"repo": repo, "ref": body.get("ref"), "delivery": delivery})
            record_webhook(storage, "github", event, delivery, "processed", "", {"repo": repo, "scanned": scanned, "findings": len(findings), "commits": len(commits)})
            _event(storage, "webhook.github.push", "git", {"repo": repo, "ref": body.get("ref"), "findings": len(findings)})
            _log(storage, "info", "integrations", f"GitHub push scan {repo}: {len(findings)} finding(s)", component="github", event_type="push", status="processed", resource=repo)
            return {"ok": True, "event": event, "repo": repo, "scanned_files": scanned, "findings": len(findings)}, 200

        if event == "ping":
            record_webhook(storage, "github", event, delivery, "processed", "ping", {"repo": repo})
            return {"ok": True, "pong": True}, 200

        record_webhook(storage, "github", event or "unknown", delivery, "ignored", "unsupported event", {"repo": repo})
        return {"ok": True, "ignored": True, "event": event}, 200
    except Exception as e:
        record_webhook(storage, "github", event or "unknown", delivery, "failed", str(e), {"repo": repo})
        record_scan_failure(storage, "webhook.github", repo or "github", str(e))
        _log(storage, "error", "integrations", f"GitHub webhook handling failed: {e}", component="github", event_type=event or "unknown", status="failed")
        return {"ok": False, "error": "webhook processing failed"}, 500


# ---------------- AWS advanced scanning ----------------

def _aws_sessions(cfg: dict):
    try:
        import boto3
    except Exception:
        return []
    accounts = cfg_get(cfg, "features.aws_multi_account.accounts", []) or []
    sessions = []
    if accounts:
        for acct in accounts:
            if not isinstance(acct, dict):
                continue
            try:
                kwargs = {}
                if acct.get("region"):
                    kwargs["region_name"] = acct.get("region")
                if acct.get("profile"):
                    sess = boto3.Session(profile_name=acct.get("profile"), **kwargs)
                elif acct.get("role_arn"):
                    sts = boto3.client("sts", **kwargs)
                    assumed = sts.assume_role(RoleArn=acct["role_arn"], RoleSessionName=acct.get("session_name", "sentrix-scan"))
                    creds = assumed["Credentials"]
                    sess = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"], **kwargs)
                else:
                    sess = boto3.Session(**kwargs)
                sessions.append((acct.get("name") or acct.get("account_id") or "aws", sess))
            except Exception:
                continue
    else:
        try:
            sessions.append(("default", boto3.Session()))
        except Exception:
            pass
    return sessions


def scan_lambda_zip_bytes(data: bytes, name: str, allowlist):
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 1_000_000:
                    continue
                lower = info.filename.lower()
                if not lower.endswith(('.py', '.js', '.ts', '.json', '.env', '.yml', '.yaml', '.txt', '.sh')):
                    continue
                try:
                    text = zf.read(info).decode('utf-8', 'replace')
                except Exception:
                    continue
                findings.extend(engine.scan_text(text, f"lambda-zip:{name}/{info.filename}", "cloud", allowlist))
    except Exception:
        return findings
    return findings


def aws_lambda_advanced_scan(cfg: dict, storage, allowlist):
    findings: list[Finding] = []
    if not _enabled(cfg, "aws_lambda_monitoring", True) and not _enabled(cfg, "aws_multi_account", True):
        # still allow explicit use via cloud scan enhancements when provider aws
        pass
    sessions = _aws_sessions(cfg)
    if not sessions:
        return findings
    include_zip = bool(cfg_get(cfg, "features.lambda_zip_scan.enabled", True))
    for acct_name, sess in sessions:
        try:
            client = sess.client("lambda")
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fname = fn.get("FunctionName", "function")
                    try:
                        conf = client.get_function_configuration(FunctionName=fname)
                        for key, value in (conf.get("Environment", {}).get("Variables") or {}).items():
                            for f in engine.scan_text(f'{key} = "{value}"', f"lambda:{acct_name}/{fname}/env", "cloud", allowlist):
                                f.meta["env_key"] = key
                                f.meta["aws_account"] = acct_name
                                findings.append(f)
                    except Exception as e:
                        record_scan_failure(storage, "aws_lambda_config", f"{acct_name}:{fname}", str(e))
                    if include_zip:
                        try:
                            code = client.get_function(FunctionName=fname).get("Code", {})
                            loc = code.get("Location")
                            if loc:
                                # download deployment package (signed URL) safely
                                net.assert_safe_outbound_url(loc)
                                import urllib.request
                                with urllib.request.urlopen(loc, timeout=20) as resp:
                                    data = resp.read(10 * 1024 * 1024)
                                findings.extend(scan_lambda_zip_bytes(data, f"{acct_name}/{fname}", allowlist))
                        except Exception as e:
                            record_scan_failure(storage, "aws_lambda_zip", f"{acct_name}:{fname}", str(e))
        except Exception as e:
            record_scan_failure(storage, "aws_account_scan", acct_name, str(e))
            _log(storage, "error", "integrations", f"AWS scan failed for {acct_name}: {e}", component="aws", event_type="scan", status="failed")
    return findings


# ---------------- Real-time / scheduled monitoring helpers ----------------

def realtime_surface_scan(state, surface: str):
    cfg, storage = state.cfg, state.storage
    from sentrix.surfaces import slack as s_slack, confluence as s_conf, jira as s_jira, postman as s_postman, cloud as s_cloud
    findings = []
    try:
        if surface == "slack" and _enabled(cfg, "realtime_slack_monitoring", True):
            findings = s_slack.live_scan(cfg, state.pipeline.allowlist)
        elif surface == "confluence" and _enabled(cfg, "realtime_confluence_monitoring", True):
            findings = s_conf.live_scan(cfg, state.pipeline.allowlist)
        elif surface == "jira" and _enabled(cfg, "realtime_jira_monitoring", True):
            findings = s_jira.live_scan(cfg, state.pipeline.allowlist)
        elif surface == "postman" and _enabled(cfg, "postman_monitoring", True):
            # monitor configured export paths/workspace exports if provided locally
            paths = cfg_get(cfg, "features.postman.export_paths", []) or []
            for p in paths:
                try:
                    pp = Path(p)
                    if pp.exists():
                        if "environment" in pp.name.lower():
                            findings.extend(s_postman.scan_environment(pp, state.pipeline.allowlist))
                        else:
                            findings.extend(s_postman.scan_collection(pp, state.pipeline.allowlist))
                except Exception as e:
                    record_scan_failure(storage, "postman_export", str(p), str(e))
        elif surface == "cloud":
            if cfg_get(cfg, "surfaces.cloud.provider", "local") == "aws":
                findings = aws_lambda_advanced_scan(cfg, storage, state.pipeline.allowlist)
            else:
                findings = s_cloud.default_scan(cfg, state.pipeline.allowlist)
        if findings is not None:
            res = state.pipeline.ingest(findings, kind=f"realtime.{surface}")
            _log(storage, "info", "integrations", f"Realtime {surface} scan: {len(res.get('new',[]))} new", component=surface, event_type="realtime_scan", status="ok")
            return res
    except Exception as e:
        record_scan_failure(storage, f"realtime.{surface}", surface, str(e))
        _log(storage, "error", "integrations", f"Realtime {surface} scan failed: {e}", component=surface, event_type="realtime_scan", status="failed")
    return {"new": [], "known": []}


def run_full_repo_rescans(state):
    cfg = state.cfg
    if not _enabled(cfg, "full_repo_rescan", True):
        return
    paths = cfg_get(cfg, "features.full_repo_rescan.paths", []) or []
    if not paths:
        return
    for p in paths:
        try:
            state.runner.submit(str(p), "filesystem", "auto-rescan")
            _event(state.storage, "feature.full_repo_rescan", "filesystem", {"path": str(p)})
        except Exception as e:
            record_scan_failure(state.storage, "full_repo_rescan", str(p), str(e))


# ---------------- Secret validation (opt-in) ----------------

def validate_finding(state, finding: Finding):
    cfg = state.cfg
    if not _enabled(cfg, "secret_validation", False):
        return {"status": "disabled"}
    ensure_features_schema(state.storage)
    # Never exfiltrate raw secrets except to explicitly configured provider validation endpoints when enabled.
    # Use masked/format checks by default; perform API checks only where safe and configured.
    result = {"status": "not_applicable", "provider": finding.detector_id, "detail": "no validator"}
    try:
        # Placeholder safe validation: format and metadata only (no external secret transmission)
        result = {"status": "format_checked", "provider": finding.detector_id, "detail": f"validation={finding.meta.get('validation','unknown')} confidence={finding.meta.get('confidence')}"}
        # Optional GitHub token liveness check (sends token to GitHub API) ONLY if explicitly enabled
        if _enabled(cfg, "secret_validation.github_api", False) and finding.detector_id in ("github-token",):
            # cannot recover raw secret (not stored) - validation not possible without raw; record limitation
            result = {"status": "unavailable", "provider": "github", "detail": "raw secret not stored; cannot perform API validation"}
    except Exception as e:
        result = {"status": "error", "provider": finding.detector_id, "detail": str(e)}
    vid = "val-" + hashlib.sha256(f"{finding.id}|{time.time_ns()}".encode()).hexdigest()[:12]
    with state.storage._lock:
        state.storage._db.execute(
            "INSERT INTO validation_results(id,finding_id,detector_id,provider,status,detail,ts) VALUES(?,?,?,?,?,?,?)",
            (vid, finding.id, finding.detector_id, result.get("provider",""), result.get("status",""), result.get("detail",""), now_iso())
        )
        state.storage._db.commit()
    return result


# ---------------- S3 audit archival ----------------

def archive_audit_to_s3(cfg: dict, storage):
    if not _enabled(cfg, "s3_audit_archival", False):
        return {"ok": False, "error": "disabled"}
    bucket = cfg_get(cfg, "features.s3_audit_archival.bucket", "")
    prefix = cfg_get(cfg, "features.s3_audit_archival.prefix", "sentrix/audit/")
    if not bucket:
        return {"ok": False, "error": "bucket not configured"}
    try:
        import boto3
        key = f"{prefix.rstrip('/')}/audit-{int(time.time())}.json"
        payload = {
            "exported_at": now_iso(),
            "audit": storage.list_audit(1000),
            "logs": storage.list_logs(1000) if hasattr(storage, "list_logs") else [],
            "events": storage.list_events(1000) if hasattr(storage, "list_events") else [],
        }
        boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=json.dumps(payload).encode("utf-8"), ContentType="application/json")
        _log(storage, "info", "integrations", f"Archived audit bundle to s3://{bucket}/{key}", component="s3", event_type="archive", status="ok")
        return {"ok": True, "bucket": bucket, "key": key}
    except Exception as e:
        record_scan_failure(storage, "s3_archive", bucket, str(e))
        _log(storage, "error", "integrations", f"S3 audit archival failed: {e}", component="s3", event_type="archive", status="failed")
        return {"ok": False, "error": str(e)}


# ---------------- Health / coverage / missed detection ----------------

def integration_health_snapshot(state):
    from sentrix.core import integrations
    storage = state.storage
    inv = integrations.inventory(state.cfg, storage, bool(cfg_get(state.cfg, "auth.demo_mode", False)))
    jobs = storage.list_jobs(limit=200)
    failed_jobs = [j for j in jobs if j.get("status") == "failed"]
    recent_failures = list_scan_failures(storage, 50)
    webhooks = list_webhook_events(storage, limit=50)
    missed = []
    now = time.time()
    # Missed webhook detection (config-driven)
    if _enabled(state.cfg, "missed_webhook_detection", True):
        checks = [
            ("github", _enabled(state.cfg, "github_webhooks", True)),
            ("jira", _enabled(state.cfg, "realtime_jira_monitoring", True)),
            ("confluence", _enabled(state.cfg, "realtime_confluence_monitoring", True)),
            ("aws", _enabled(state.cfg, "aws_lambda_monitoring", True)),
        ]
        for provider, enabled in checks:
            if not enabled:
                continue
            evs = [w for w in webhooks if w.get("provider") == provider and w.get("status") in ("processed", "ignored")]
            if not evs:
                missed.append({"provider": provider, "issue": "no webhook events recorded", "severity": "medium"})
            else:
                try:
                    ts = evs[0].get("received_at", "")
                    t = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
                    if now - t > 24 * 3600:
                        missed.append({"provider": provider, "issue": "no recent webhook events (>24h)", "severity": "low"})
                except Exception:
                    pass
    coverage = {
        "surfaces_with_findings": len({f.surface for f in storage.list_findings(limit=5000)}),
        "integrations_connected": sum(1 for i in inv if i.get("status") == "connected"),
        "integrations_demo": sum(1 for i in inv if i.get("status") == "demo"),
        "integrations_disconnected": sum(1 for i in inv if i.get("status") == "disconnected"),
    }
    return {
        "integrations": inv,
        "coverage": coverage,
        "failed_scans": failed_jobs[:20],
        "scan_failures": recent_failures[:20],
        "recent_webhooks": webhooks[:20],
        "missed_webhooks": missed,
        "generated_at": now_iso(),
    }


# ---------------- Feature scheduler tick ----------------

_last_tick = {"realtime": 0.0, "rescan": 0.0, "archive": 0.0}

def scheduler_tick(state):
    cfg = state.cfg
    now = time.time()
    # Real-time monitoring polls (config-driven intervals)
    rt_interval = int(cfg_get(cfg, "features.realtime_monitoring.interval_seconds", 300) or 300)
    if now - _last_tick["realtime"] >= rt_interval:
        _last_tick["realtime"] = now
        for surface in ("slack", "confluence", "jira", "postman", "cloud"):
            try:
                realtime_surface_scan(state, surface)
            except Exception:
                pass
    rescan_interval = int(cfg_get(cfg, "features.full_repo_rescan.interval_seconds", 86400) or 86400)
    if now - _last_tick["rescan"] >= rescan_interval:
        _last_tick["rescan"] = now
        try:
            run_full_repo_rescans(state)
        except Exception:
            pass
    if _enabled(cfg, "s3_audit_archival", False):
        arch_interval = int(cfg_get(cfg, "features.s3_audit_archival.interval_seconds", 3600) or 3600)
        if now - _last_tick["archive"] >= arch_interval:
            _last_tick["archive"] = now
            try:
                archive_audit_to_s3(cfg, state.storage)
            except Exception:
                pass


# ---------------- HTTP helpers for server integration ----------------

def handle_feature_get(state, path: str, query: dict, user: dict | None):
    storage = state.storage
    if path == "/api/features/health":
        return integration_health_snapshot(state), 200
    if path == "/api/features/webhooks":
        provider = query.get("provider", "")
        return {"events": list_webhook_events(storage, provider, int(query.get("limit", 100)))}, 200
    if path == "/api/features/scan-failures":
        return {"failures": list_scan_failures(storage, int(query.get("limit", 100)))}, 200
    if path == "/api/features/status":
        cfg = state.cfg
        return {"features": {
            "github_pr_scanner": _enabled(cfg, "github_pr_scanner", True),
            "github_push_scanner": _enabled(cfg, "github_push_scanner", True),
            "github_actions_gate": _enabled(cfg, "github_actions_gate", True),
            "github_webhooks": _enabled(cfg, "github_webhooks", True),
            "full_repo_rescan": _enabled(cfg, "full_repo_rescan", True),
            "aws_lambda_monitoring": _enabled(cfg, "aws_lambda_monitoring", True),
            "aws_multi_account": _enabled(cfg, "aws_multi_account", True),
            "lambda_env_scan": _enabled(cfg, "lambda_env_scan", True),
            "lambda_zip_scan": _enabled(cfg, "lambda_zip_scan", True),
            "realtime_slack_monitoring": _enabled(cfg, "realtime_slack_monitoring", True),
            "slack_private_consent": _enabled(cfg, "slack_private_consent", False),
            "realtime_jira_monitoring": _enabled(cfg, "realtime_jira_monitoring", True),
            "realtime_confluence_monitoring": _enabled(cfg, "realtime_confluence_monitoring", True),
            "postman_monitoring": _enabled(cfg, "postman_monitoring", True),
            "secret_validation": _enabled(cfg, "secret_validation", False),
            "s3_audit_archival": _enabled(cfg, "s3_audit_archival", False),
            "missed_webhook_detection": _enabled(cfg, "missed_webhook_detection", True),
            "integration_health_monitoring": _enabled(cfg, "integration_health_monitoring", True),
        }}, 200
    return None


def _extract_strings(node, limit=2000):
    out = []
    stack = [node]
    while stack and len(out) < limit:
        cur = stack.pop()
        if isinstance(cur, str):
            if cur.strip():
                out.append(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def _verify_shared_token(headers: dict, body: dict, expected: str) -> bool:
    if not expected:
        return True
    token = headers.get("X-Sentrix-Token", "") or headers.get("x-sentrix-token", "") or headers.get("X-Webhook-Token", "") or headers.get("x-webhook-token", "")
    if not token:
        token = str(body.get("token", "") or "")
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = token or auth.split(" ", 1)[1].strip()
    return hmac.compare_digest(str(token), str(expected))


def handle_jira_webhook(state, headers: dict, raw_body: bytes, body: dict):
    cfg, storage = state.cfg, state.storage
    if not _enabled(cfg, "realtime_jira_monitoring", True):
        return {"ok": False, "error": "jira webhook monitoring disabled"}, 403
    secret = env_secret(cfg, "features.jira_webhook.secret_env")
    if secret and not _verify_shared_token(headers, body, secret):
        record_webhook(storage, "jira", body.get("webhookEvent", "unknown"), body.get("timestamp", ""), "rejected", "invalid token")
        return {"ok": False, "error": "invalid token"}, 401
    event = body.get("webhookEvent") or body.get("issue_event_type_name") or "jira.event"
    issue = body.get("issue") or {}
    key = issue.get("key") or body.get("key") or "jira"
    texts = _extract_strings(issue or body)
    findings = []
    for t in texts[:500]:
        findings.extend(engine.scan_text(t, f"jira:{key}", "jira", state.pipeline.allowlist))
    state.pipeline.ingest(findings, kind="webhook.jira", provenance={"issue": key, "event": event})
    record_webhook(storage, "jira", str(event), str(body.get("timestamp") or key), "processed", "", {"issue": key, "findings": len(findings)})
    _event(storage, "webhook.jira", "jira", {"issue": key, "event": event, "findings": len(findings)})
    return {"ok": True, "event": event, "issue": key, "findings": len(findings)}, 200


def handle_confluence_webhook(state, headers: dict, raw_body: bytes, body: dict):
    cfg, storage = state.cfg, state.storage
    if not _enabled(cfg, "realtime_confluence_monitoring", True):
        return {"ok": False, "error": "confluence webhook monitoring disabled"}, 403
    secret = env_secret(cfg, "features.confluence_webhook.secret_env")
    if secret and not _verify_shared_token(headers, body, secret):
        record_webhook(storage, "confluence", body.get("event", "unknown"), str(body.get("timestamp", "")), "rejected", "invalid token")
        return {"ok": False, "error": "invalid token"}, 401
    event = body.get("event") or body.get("webhookEvent") or "confluence.event"
    page = body.get("page") or body.get("content") or {}
    page_id = str(page.get("id") or body.get("pageId") or body.get("id") or "page")
    texts = _extract_strings(page or body)
    findings = []
    for t in texts[:500]:
        findings.extend(engine.scan_text(t, f"confluence:{page_id}", "confluence", state.pipeline.allowlist))
    state.pipeline.ingest(findings, kind="webhook.confluence", provenance={"page": page_id, "event": event})
    record_webhook(storage, "confluence", str(event), str(body.get("timestamp") or page_id), "processed", "", {"page": page_id, "findings": len(findings)})
    _event(storage, "webhook.confluence", "confluence", {"page": page_id, "event": event, "findings": len(findings)})
    return {"ok": True, "event": event, "page": page_id, "findings": len(findings)}, 200


def handle_aws_deployment_webhook(state, headers: dict, raw_body: bytes, body: dict):
    cfg, storage = state.cfg, state.storage
    if not _enabled(cfg, "aws_lambda_monitoring", True):
        return {"ok": False, "error": "aws deployment monitoring disabled"}, 403
    token = env_secret(cfg, "features.aws_deployment_webhook.token_env")
    if token and not _verify_shared_token(headers, body, token):
        record_webhook(storage, "aws", body.get("detail-type") or "lambda.deployment", body.get("id", ""), "rejected", "invalid token")
        return {"ok": False, "error": "invalid token"}, 401
    detail = body.get("detail") or {}
    function_name = detail.get("functionName") or detail.get("FunctionName") or body.get("functionName") or body.get("FunctionName")
    event = body.get("detail-type") or body.get("eventName") or "lambda.deployment"
    # Trigger targeted or full cloud realtime scan to detect secrets post-deployment
    findings = []
    try:
        findings_objs = aws_lambda_advanced_scan(cfg, storage, state.pipeline.allowlist)
        if function_name:
            # keep findings for the function if identifiable, else include all from scan
            filtered = [f for f in findings_objs if str(function_name) in (f.path or "")]
            findings_objs = filtered or findings_objs
        findings = findings_objs
    except Exception:
        res = realtime_surface_scan(state, "cloud")
        findings = []
    result = state.pipeline.ingest(findings, kind="webhook.aws.lambda", provenance={"function": function_name, "event": event})
    record_webhook(storage, "aws", str(event), str(body.get("id") or function_name or time.time_ns()), "processed", "", {"function": function_name, "findings": len(result.get("new", []))})
    _event(storage, "webhook.aws.lambda", "cloud", {"function": function_name, "event": event, "new": len(result.get("new", []))})
    return {"ok": True, "event": event, "function": function_name, "new": len(result.get("new", []))}, 200


def handle_feature_post(state, path: str, body: dict, headers: dict, raw_body: bytes, user: dict | None):
    if path == "/api/webhooks/github":
        return handle_github_webhook(state, headers, raw_body, body)
    if path == "/api/webhooks/jira":
        return handle_jira_webhook(state, headers, raw_body, body)
    if path == "/api/webhooks/confluence":
        return handle_confluence_webhook(state, headers, raw_body, body)
    if path == "/api/webhooks/aws/lambda":
        return handle_aws_deployment_webhook(state, headers, raw_body, body)
    if path == "/api/features/full-rescan":
        run_full_repo_rescans(state)
        return {"ok": True, "triggered": True}, 200
    if path == "/api/features/realtime-scan":
        surface = body.get("surface", "")
        res = realtime_surface_scan(state, surface)
        return {"ok": True, "surface": surface, "result": {"new": len(res.get("new",[])), "known": len(res.get("known",[]))}}, 200
    if path == "/api/features/archive-audit":
        return archive_audit_to_s3(state.cfg, state.storage), 200
    if path == "/api/features/validate-finding":
        fid = body.get("id") or body.get("finding_id")
        f = state.storage.get_finding(fid) if fid else None
        if not f:
            return {"error": "finding not found"}, 404
        return {"ok": True, "result": validate_finding(state, f)}, 200
    return None
