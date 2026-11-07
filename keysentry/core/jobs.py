"""Background scan jobs with an incremental cache, plus the scheduler loop."""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from keysentry.core.engine import scan_file, walk_files
from keysentry.core.models import Finding


class JobRunner:
    def __init__(self, storage, pipeline, cfg: dict, log=None):
        self.storage = storage
        self.pipeline = pipeline
        self.cfg = cfg
        self.log = log or (lambda *a: None)
        self._slots = threading.Semaphore(2)
        self._cancelled: set[str] = set()

    def submit(self, path: str, surface: str, triggered_by: str) -> str:
        jid = "job-" + secrets.token_hex(5)
        self.storage.add_job(jid, path, surface, triggered_by)
        self.log("info", "jobs", f"Scan job {jid} queued for {path} ({surface}) by {triggered_by}")
        threading.Thread(target=self._run, args=(jid,), daemon=True).start()
        return jid

    def cancel(self, jid: str):
        self._cancelled.add(jid)

    def _run(self, jid: str):
        with self._slots:
            try:
                job = self.storage.get_job(jid)
                if not job:
                    return
                if jid in self._cancelled:
                    self.storage.update_job(jid, status="cancelled", finished=_now())
                    return
                self.storage.update_job(jid, status="running")
                self.log("info", "scan", f"Job {jid} started: {job['path']}")
                root = Path(job["path"])
                if not root.is_absolute():
                    from keysentry.config import ROOT
                    root = ROOT / root
                findings: list[Finding] = []
                files = 0
                paths = [root] if root.is_file() else walk_files(root, self.cfg)
                for path in paths:
                    if jid in self._cancelled:
                        raise InterruptedError("cancelled")
                    files += 1
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    cached = self.storage.cache_get(str(path))
                    if cached and cached["mtime"] == stat.st_mtime and cached["size"] == stat.st_size:
                        findings += [Finding.from_dict(d) for d in json.loads(cached["findings"])]
                        continue
                    fresh = scan_file(path, job["surface"], self.cfg, self.pipeline.allowlist)
                    self.storage.cache_put(str(path), stat.st_mtime, stat.st_size,
                                           [f.to_dict() for f in fresh])
                    findings += fresh
                result = self.pipeline.ingest(findings, kind="scan.job")
                self.storage.update_job(jid, status="done", finished=_now(),
                                        files=files, findings=len(result["new"]))
                self.log("info", "scan",
                         f"Job {jid} finished: {files} files, {len(result['new'])} new findings")
            except InterruptedError:
                self.storage.update_job(jid, status="cancelled", finished=_now())
                self.log("warn", "jobs", f"Job {jid} cancelled")
            except Exception as exc:
                try:
                    self.storage.update_job(jid, status="failed", finished=_now(), error=str(exc))
                except Exception:
                    pass
                self.log("error", "jobs", f"Job {jid} failed: {exc}")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def start_scheduler(runner: JobRunner, storage, cfg: dict, router=None, log=None):
    log = log or (lambda *a: None)
    sla_hours = cfg.get("alerting", {}).get("escalate_after_hours", 24)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            if stop.wait(10):
                break
            try:
                for sched in storage.due_schedules():
                    runner.submit(sched["path"], sched["surface"], f"schedule:{sched['id']}")
                    storage.update_schedule(sched["id"], last_run=time.time())
                    log("info", "scheduler", f"Schedule {sched['id']} triggered scan of {sched['path']}")
                if router and sla_hours:
                    cutoff = time.time() - sla_hours * 3600
                    for finding in storage.list_findings(status="open", limit=500):
                        created = time.mktime(time.strptime(finding.created_at, "%Y-%m-%dT%H:%M:%S"))
                        if created < cutoff and not storage.recent_alert_for(finding.id, sla_hours * 3600):
                            router.send(finding)
                            log("warn", "escalation",
                                f"Finding {finding.id} still open after {sla_hours}h; re-alerted")
            except sqlite3.ProgrammingError:
                break
            except Exception as exc:
                log("error", "scheduler", str(exc))

    threading.Thread(target=loop, daemon=True).start()
    return stop