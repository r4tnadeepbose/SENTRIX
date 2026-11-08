"""Scan tool marketplace catalog and workflow tool ordering."""
from __future__ import annotations

TOOLS = [
    {"id": "subfinder", "name": "Subfinder", "category": "Subdomains", "kind": "built-in",
     "description": "Passive subdomain discovery using online sources; returns valid subdomains for websites."},
    {"id": "naabu", "name": "Naabu", "category": "Ports Scanner", "kind": "built-in",
     "description": "Fast port scanner written in Go with a focus on reliability and simplicity; streams open ports."},
    {"id": "nmap", "name": "Nmap", "category": "Ports Scanner", "kind": "built-in",
     "description": "Scans a single host with Nmap and streams every open port as a finding for port review."},
    {"id": "rustscan", "name": "RustScan", "category": "Ports Scanner", "kind": "built-in",
     "description": "Scans a single host in greppable mode and streams every open port as a finding."},
    {"id": "httpx", "name": "httpx", "category": "Http Probe", "kind": "built-in",
     "description": "Fast multi-purpose HTTP toolkit; probes hosts and records status, title and technologies."},
    {"id": "gau", "name": "gau", "category": "Url Discovery", "kind": "built-in",
     "description": "Discoveres historical/archived URLs for a domain using passive online sources."},
    {"id": "katana", "name": "Katana", "category": "Url Discovery", "kind": "built-in",
     "description": "Crawls a target website up to a configurable depth and streams every discovered URL."},
    {"id": "screenshot", "name": "Screenshot", "category": "Screenshot", "kind": "built-in",
     "description": "Takes a screenshot of a website for visual evidence and review."},
    {"id": "nuclei", "name": "Nuclei", "category": "Vulnerabilities", "kind": "built-in",
     "description": "Template-based scanner against target URLs to detect known vulnerabilities and exposures."},
    {"id": "nikto", "name": "Nikto", "category": "Vulnerabilities", "kind": "built-in",
     "description": "Scans a web server for known issues: dangerous files, CGIs and outdated server software."},
    {"id": "wpscan", "name": "WPScan", "category": "Vulnerabilities", "kind": "built-in",
     "description": "Scans WordPress sites to enumerate vulnerable plugins and themes and detect known CVEs."},
    {"id": "zap", "name": "ZAP", "category": "Vulnerabilities", "kind": "built-in",
     "description": "Runs an OWASP ZAP baseline scan against a target web application."},
    {"id": "acunetix", "name": "Acunetix", "category": "Vulnerabilities", "kind": "connector",
     "description": "Connects to an Acunetix instance, runs a scan against a target and streams discovered vulnerabilities."},
    {"id": "nessus", "name": "Nessus", "category": "Vulnerabilities", "kind": "connector",
     "description": "Connects to a Tenable Nessus instance, creates and runs a scan against a target and streams results."},
]

TOOL_BY_ID = {t["id"]: t for t in TOOLS}
CATEGORIES = sorted({t["category"] for t in TOOLS})

# Canonical pipeline order: discovery -> ports -> probe -> crawl -> evidence -> vulns.
TOOL_ORDER = ["subfinder", "gau", "katana", "naabu", "nmap", "rustscan",
              "httpx", "screenshot", "nuclei", "nikto", "wpscan", "zap",
              "acunetix", "nessus"]

STEP_LABEL = {
    "subfinder": "Scan Subdomain", "gau": "Archive URLs", "katana": "Crawl URLs",
    "naabu": "Port Scan", "nmap": "Port Scan", "rustscan": "Port Scan",
    "httpx": "HTTP Probe", "screenshot": "Take Screenshot",
    "nuclei": "Vulnerability Scan", "nikto": "Web Server Scan",
    "wpscan": "WordPress Scan", "zap": "Baseline Scan",
    "acunetix": "Acunetix Scan", "nessus": "Nessus Scan",
}


def ordered_tools(ids: list[str]) -> list[str]:
    known = [t for t in TOOL_ORDER if t in ids]
    return known + [i for i in ids if i not in TOOL_ORDER]