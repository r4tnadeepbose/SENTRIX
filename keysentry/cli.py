"""KeySentry command line: one entry point for every layer."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from keysentry import __version__
from keysentry.alerting.router import AlertRouter
from keysentry.config import ROOT, cfg_get, load_config, resolve_path
from keysentry.core.engine import scan_tree
from keysentry.core.models import Finding
from keysentry.core.pipeline import Pipeline
from keysentry.core.storage import Storage
from keysentry.core.util import at_least
from keysentry.demo import seed_demo
from keysentry.surfaces import cloud, confluence, git, ide, jira, postman, slack


def _ctx(cfg):
    from keysentry.core.extensions import ExtStorage
    storage = ExtStorage(resolve_path(cfg, cfg_get(cfg, "storage.path", "data/keysentry.db")))
    router = AlertRouter(cfg, storage)
    return storage, Pipeline(cfg, storage, router)


def _print_findings(findings: list[Finding], as_json: bool):
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        print("No secrets detected.")
        return
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.title} | {f.surface} | {f.path}:{f.line} | {f.secret_masked}")


def cmd_serve(args, cfg):
    from keysentry.server import serve_forever
    if args.port:
        cfg["server"]["port"] = args.port
    serve_forever(cfg)
    return 0


def cmd_scan(args, cfg):
    storage, pipeline = _ctx(cfg)
    target = Path(args.path)
    if not target.is_absolute():
        target = Path.cwd() / target
    findings, count = scan_tree(target, args.surface, cfg, pipeline.allowlist)
    if not args.no_store:
        pipeline.ingest(findings, kind="scan.cli")
    _print_findings(findings, args.json)
    print(f"Scanned {count} file(s).", file=sys.stderr)
    storage.close()
    if args.strict and any(at_least(f.severity, cfg_get(cfg, "scan.fail_on", "high")) for f in findings):
        return 1
    return 0


def cmd_gate(args, cfg):
    storage, pipeline = _ctx(cfg)
    repo = git.repo_root(args.repo or ".")
    if repo is None:
        print("Not inside a git repository.", file=sys.stderr)
        return 2
    if args.staged:
        findings = git.staged_findings(repo, cfg, pipeline.allowlist)
    elif args.range:
        base, _, head = args.range.partition("..")
        findings = git.range_findings(repo, base, head or "HEAD", cfg, pipeline.allowlist,
                                      surface="pre_push")
    else:
        findings = git.range_findings(repo, args.base, args.head, cfg, pipeline.allowlist)
    ignore_dirs = set(cfg_get(cfg, "scan.ignore_dirs", []))
    findings = [f for f in findings
                if not any(part in ignore_dirs for part in Path(f.path).parts)]
    pipeline.ingest(findings, kind="gate.blocked" if findings else "gate.passed")
    _print_findings(findings, args.json)
    storage.close()
    threshold = cfg_get(cfg, "scan.fail_on", "high")
    blocking = [f for f in findings if at_least(f.severity, threshold)]
    if blocking:
        print(f"BLOCKED: {len(blocking)} finding(s) at or above {threshold}. "
              "Fix, or allowlist confirmed false positives.", file=sys.stderr)
        return 1
    return 0


def cmd_hooks(args, cfg):
    repo = git.repo_root(args.repo or ".")
    if repo is None:
        print("Not inside a git repository.", file=sys.stderr)
        return 2
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    for name in ("pre-commit", "pre-push"):
        target = hooks_dir / name
        if args.action == "install":
            source = ROOT / "hooks" / name
            shutil.copyfile(source, target)
            target.chmod(0o755)
            print(f"Installed {target}")
        else:
            if target.exists() and "KeySentry" in target.read_text(encoding="utf-8"):
                target.unlink()
                print(f"Removed {target}")
            else:
                print(f"Left untouched (not KeySentry): {target}")
    return 0


def cmd_demo(args, cfg):
    storage, pipeline = _ctx(cfg)
    seeded = seed_demo(pipeline)
    print(f"Seeded {seeded} demo finding(s). Open the dashboard to explore.")
    storage.close()
    return 0


def cmd_selftest(args, cfg):
    from keysentry.core.allowlist import Allowlist
    from keysentry.core.engine import scan_text
    from keysentry.detectors import all_detectors
    checks = []
    checks.append(("detector registry", len(all_detectors()) >= 25))
    hits = scan_text('key = "AWS_KEY_REDACTED"', "selftest.py", "filesystem")
    checks.append(("aws detector", any(f.detector_id == "aws-access-key-id" for f in hits)))
    safe = scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "selftest.py", "filesystem", Allowlist())
    checks.append(("allowlist", not safe))
    storage, pipeline = _ctx(cfg)
    result = pipeline.ingest(hits, kind="selftest")
    checks.append(("pipeline dedupe", len(pipeline.ingest(hits, kind="selftest")["new"]) == 0))
    storage.close()
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return 1 if failed else 0


def cmd_report(args, cfg):
    storage, _ = _ctx(cfg)
    findings = storage.list_findings(limit=1000)
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(f"# KeySentry report - {len(findings)} finding(s)\n")
        for f in findings:
            print(f"- **{f.severity.upper()}** {f.title} ({f.surface}) "
                  f"`{f.path}:{f.line}` status={f.status}")
    storage.close()
    return 0


def cmd_watch(args, cfg):
    from keysentry.watch import watch_tree
    storage, pipeline = _ctx(cfg)
    watch_tree(Path(args.path), cfg, pipeline, interval=args.interval)
    storage.close()
    return 0


def cmd_surfaces(args, cfg):
    from keysentry.surfaces import SURFACE_MODULES
    for name in sorted(SURFACE_MODULES):
        print(name)
    return 0


def cmd_allowlist(args, cfg):
    storage, pipeline = _ctx(cfg)
    if args.action == "add":
        storage.allowlist_add(args.fingerprint, args.reason or "")
        pipeline.refresh_allowlist()
        print(f"Allowlisted {args.fingerprint}")
    else:
        for entry in storage.allowlist_entries():
            print(f"{entry['fingerprint']}  {entry['reason']}  {entry['created_at']}")
    storage.close()
    return 0


def cmd_triage(args, cfg):
    from keysentry.ai.triage import triage_finding
    storage, _ = _ctx(cfg)
    finding = storage.get_finding(args.id)
    if not finding:
        print("Finding not found.", file=sys.stderr)
        storage.close()
        return 2
    result = triage_finding(finding, cfg)
    finding.meta["triage"] = result
    storage.set_meta(finding.id, finding.meta)
    print(json.dumps(result, indent=2))
    storage.close()
    return 0


def cmd_remediate(args, cfg):
    from keysentry.remediation import playbooks
    storage, _ = _ctx(cfg)
    finding = storage.get_finding(args.id)
    if not finding:
        print("Finding not found.", file=sys.stderr)
        storage.close()
        return 2
    print(playbooks.execute(args.action, finding, cfg, storage))
    storage.close()
    return 0


def cmd_ingest(args, cfg):
    storage, pipeline = _ctx(cfg)
    if args.surface == "slack":
        findings = slack.scan_export(args.file, pipeline.allowlist) if args.file else slack.live_scan(cfg, pipeline.allowlist)
    elif args.surface == "confluence":
        findings = confluence.scan_export(args.file, pipeline.allowlist) if args.file else confluence.live_scan(cfg, pipeline.allowlist)
    elif args.surface == "jira":
        findings = jira.scan_export(args.file, pipeline.allowlist) if args.file else jira.live_scan(cfg, pipeline.allowlist)
    elif args.surface == "postman":
        findings = postman.scan_collection(args.file, pipeline.allowlist)
    elif args.surface == "postman-env":
        findings = postman.scan_environment(args.file, pipeline.allowlist)
    elif args.surface == "cloud":
        findings = cloud.live_scan(cfg, pipeline.allowlist) or cloud.default_scan(cfg, pipeline.allowlist)
    elif args.surface == "ide":
        findings = ide.scan_saved_file(args.file, cfg, pipeline.allowlist)
    else:
        print(f"Unsupported ingest surface: {args.surface}", file=sys.stderr)
        storage.close()
        return 2
    result = pipeline.ingest(findings, kind=f"ingest.{args.surface}")
    _print_findings(findings, args.json)
    print(f"{len(result['new'])} new, {len(result['known'])} known.", file=sys.stderr)
    storage.close()
    return 0


def cmd_users(args, cfg):
    from keysentry.auth import AuthManager
    storage, _ = _ctx(cfg)
    auth = AuthManager(storage, cfg)
    if args.action == "add":
        auth.add_user("cli", args.username, args.password, args.role)
        print(f"Added {args.username} ({args.role})")
    else:
        for user in storage.list_users():
            print(f"{user['username']:16} {user['role']:8} disabled={user['disabled']}")
    storage.close()
    return 0


def cmd_tokens(args, cfg):
    from keysentry.auth import AuthManager
    storage, _ = _ctx(cfg)
    auth = AuthManager(storage, cfg)
    if args.action == "create":
        print(auth.create_token("cli", args.name, args.role))
    elif args.action == "revoke":
        auth.revoke_token("cli", args.id)
        print(f"Revoked {args.id}")
    else:
        for token in storage.list_tokens():
            print(f"{token['id']}  {token['name']:16} {token['role']:8} revoked={token['revoked']}")
    storage.close()
    return 0


def cmd_backup(args, cfg):
    storage, _ = _ctx(cfg)
    dest = resolve_path(cfg, args.dest or f"data/backups/keysentry-{int(time.time())}.db")
    storage.backup(dest)
    print(f"Backup written to {dest}")
    storage.close()
    return 0


def cmd_schedules(args, cfg):
    storage, _ = _ctx(cfg)
    if args.action == "add":
        import secrets
        sid = "sch-" + secrets.token_hex(4)
        storage.add_schedule(sid, args.path, args.surface, args.interval)
        print(f"Added schedule {sid}")
    else:
        for sched in storage.list_schedules():
            print(f"{sched['id']}  {sched['path']}  every {sched['interval_seconds']}s  enabled={sched['enabled']}")
    storage.close()
    return 0


def cmd_jobs(args, cfg):
    storage, _ = _ctx(cfg)
    for job in storage.list_jobs():
        print(f"{job['id']}  {job['status']:9} {job['path']}  files={job['files']} findings={job['findings']}")
    storage.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keysentry", description="KeySentry - layered secret detection")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default=None, help="project root containing config.toml")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="run the dashboard + API server")
    p.add_argument("--port", type=int)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("scan", help="scan a file or directory")
    p.add_argument("path")
    p.add_argument("--surface", default="filesystem")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-store", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit 1 on findings at/above fail_on")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("gate", help="diff-only gate for hooks and CI")
    p.add_argument("--staged", action="store_true")
    p.add_argument("--range", help="BASE..HEAD")
    p.add_argument("--base", default="origin/main")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--repo", default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("hooks", help="install or uninstall git hooks")
    p.add_argument("action", choices=["install", "uninstall"])
    p.add_argument("--repo", default=None)
    p.set_defaults(func=cmd_hooks)

    p = sub.add_parser("demo", help="seed synthetic demo findings")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("selftest", help="run internal sanity checks")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("report", help="print a findings report")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("watch", help="poll a tree and scan on change")
    p.add_argument("path")
    p.add_argument("--interval", type=float, default=2.0)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("surfaces", help="list surface adapters")
    p.set_defaults(func=cmd_surfaces)

    p = sub.add_parser("allowlist", help="manage the false-positive registry")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("fingerprint", nargs="?")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_allowlist)

    p = sub.add_parser("triage", help="AI/heuristic triage for a finding")
    p.add_argument("id")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("remediate", help="run a remediation action")
    p.add_argument("id")
    p.add_argument("--action", required=True,
                   choices=["redact", "quarantine", "ticket", "rotate-guide"])
    p.set_defaults(func=cmd_remediate)

    p = sub.add_parser("ingest", help="scan a SaaS/cloud export or live source")
    p.add_argument("--surface", required=True)
    p.add_argument("--file", default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("users", help="manage local accounts")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("username", nargs="?")
    p.add_argument("--password", default="")
    p.add_argument("--role", default="viewer", choices=["admin", "analyst", "viewer"])
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("tokens", help="manage API tokens for CI and scripts")
    p.add_argument("action", choices=["create", "list", "revoke"])
    p.add_argument("--name", default="ci")
    p.add_argument("--role", default="analyst", choices=["admin", "analyst", "viewer"])
    p.add_argument("--id", default="")
    p.set_defaults(func=cmd_tokens)

    p = sub.add_parser("backup", help="write a SQLite backup")
    p.add_argument("--dest", default=None)
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("schedules", help="manage scheduled scans")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("--path", default=".")
    p.add_argument("--surface", default="filesystem")
    p.add_argument("--interval", type=int, default=3600)
    p.set_defaults(func=cmd_schedules)

    p = sub.add_parser("jobs", help="list background scan jobs")
    p.set_defaults(func=cmd_jobs)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.config) if args.config else ROOT
    cfg = load_config(root)
    from keysentry.core import engine
    engine.configure(cfg)
    if not args.command:
        args = parser.parse_args(["serve"])
    return args.func(args, cfg)