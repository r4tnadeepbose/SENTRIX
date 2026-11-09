"""Network-safety helpers: restrict outbound HTTP to public addresses, block SSRF targets."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_BLOCKED_HOSTS = {
    "localhost",
    "loopback",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "metadata.aws.internal",
}


def is_safe_outbound_url(url: str) -> bool:
    try:
        parsed = urlparse(url or "")
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host or host in _BLOCKED_HOSTS:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname: reject if it resolves to a blocked/special-use address.
        try:
            import socket
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
                except socket.gaierror:
                    continue
                for info in infos:
                    addr = info[4][0]
                    try:
                        ip = ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if not _ip_ok(ip):
                        return False
        except Exception:
            return False
        return True
    return _ip_ok(ip)


def _ip_ok(ip):
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or str(ip) == "0.0.0.0"
    )


def assert_safe_outbound_url(url: str) -> None:
    if not is_safe_outbound_url(url):
        raise ValueError(f"outbound request blocked by SSRF policy: {url!r}")
