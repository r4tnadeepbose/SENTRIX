"""Private key material, JWTs and connection-string detectors."""
from __future__ import annotations

import re

from sentrix.detectors.base import Detector, register

register(Detector(
    id="private-key",
    title="Private Key Block (RSA / EC / OPENSSH / PGP)",
    severity="critical",
    pattern=re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"
    ),
    secret_group=1,
    keywords=("-----BEGIN",),
    family="crypto",
    remediation="rotate-keypair",
))

register(Detector(
    id="jwt",
    title="JSON Web Token",
    severity="medium",
    pattern=re.compile(r"\b(eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})\b"),
    secret_group=1,
    keywords=("eyJ",),
    family="crypto",
))

register(Detector(
    id="basic-auth-url",
    title="Credentials Embedded in URL",
    severity="high",
    pattern=re.compile(r"\b[a-z][a-z0-9+.\-]*://([^/\s:@\"']+:[^/\s:@\"']+@)[^/\s\"']+"),
    secret_group=1,
    keywords=("://",),
    family="crypto",
))

register(Detector(
    id="postgres-uri",
    title="Database Connection URI with Password",
    severity="critical",
    pattern=re.compile(
        r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s\"']+:[^@\s\"']+@[^/\s\"']+)"
    ),
    secret_group=1,
    keywords=("postgres://", "postgresql://", "mysql://", "mongodb://", "redis://", "amqp://"),
    family="crypto",
    remediation="rotate-db",
))

register(Detector(
    id="ssh-private-key-body",
    title="OpenSSH Private Key Body",
    severity="critical",
    pattern=re.compile(r"(b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB[A-Za-z0-9+/=]{40,})"),
    secret_group=1,
    keywords=("b3BlbnNzaC1rZXk",),
    family="crypto",
    remediation="rotate-keypair",
))